from __future__ import annotations
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .certificate_service import CertificateService
from .jobs import JobManager
from .models import BaselineCreateRequest, TamperVerifyRequest, CertificateCreateRequest, CertificateVerifyBody
from .tamper_engine import verify_baseline_integrity, verify_verification_integrity

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"
manager = JobManager(DATA)
cert_service = CertificateService(DATA / "certificates", DATA / "keys")

app = FastAPI(
    title="Cyphox Tamper Verification & Certificate Service",
    version="1.0.0",
    description="Read-only baseline creation, tamper comparison, signed verification certificates and QR verification for Cyphox.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"service":"cyphox-tamper-verification","status":"ONLINE","version":"1.0.0","mode":"READ_ONLY_COMPARE"}

@app.get("/health")
@app.get("/api/v1/tamper/health")
def health():
    return {"status":"OK","service":"cyphox-tamper-verification","version":"1.0.0"}

@app.post("/api/v1/tamper/baselines", status_code=status.HTTP_202_ACCEPTED)
def create_baseline(req: BaselineCreateRequest):
    try:
        return manager.create_baseline_job(req).envelope()
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/api/v1/tamper/baselines/{baseline_id}")
def get_baseline(baseline_id: str):
    try:
        baseline = manager.baselines.load(baseline_id)
        return {"status":"SUCCESS","baselineId":baseline_id,"integrity":verify_baseline_integrity(baseline),"baseline":baseline}
    except FileNotFoundError:
        # May still be running; surface job state if known.
        for j in manager.jobs.values():
            if j.baselineId == baseline_id:
                return j.envelope()
        raise HTTPException(404, f"Baseline '{baseline_id}' not found")

@app.get("/api/v1/tamper/jobs/{job_id}")
def get_job(job_id: str):
    job = manager.get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found")
    return job.envelope()

@app.post("/api/v1/tamper/verifications", status_code=status.HTTP_202_ACCEPTED)
def verify_tamper(req: TamperVerifyRequest):
    try:
        return manager.create_verification_job(req).envelope()
    except FileNotFoundError:
        raise HTTPException(404, f"Baseline '{req.baselineId}' not found")
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/api/v1/tamper/verifications/{verification_id}")
def get_verification(verification_id: str):
    try:
        v = manager.verifications.load(verification_id)
        return {"status":"SUCCESS","verificationId":verification_id,"integrity":verify_verification_integrity(v),"verification":v}
    except FileNotFoundError:
        for j in manager.jobs.values():
            if j.verificationId == verification_id:
                return j.envelope()
        raise HTTPException(404, f"Verification '{verification_id}' not found")

@app.post("/api/v1/certificates", status_code=status.HTTP_201_CREATED)
def create_certificate(req: CertificateCreateRequest):
    try:
        verification = manager.verifications.load(req.verificationId)
        cert = cert_service.create(verification, certificate_id=req.certificateId, user_id=req.userId,
                                   session_id=req.sessionId, title=req.title)
        return {"status":"SUCCESS","certificate":cert}
    except FileNotFoundError:
        raise HTTPException(404, f"Verification '{req.verificationId}' not found")
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/api/v1/certificates/{certificate_id}")
def get_certificate(certificate_id: str):
    try:
        cert = cert_service.load(certificate_id)
        return {"status":"SUCCESS","certificate":cert,"verification":cert_service.verify(cert)}
    except FileNotFoundError:
        raise HTTPException(404, f"Certificate '{certificate_id}' not found")

@app.get("/api/v1/certificates/{certificate_id}/verify")
def verify_certificate(certificate_id: str, digest: str | None = Query(default=None)):
    try:
        cert = cert_service.load(certificate_id)
        return cert_service.verify(cert, digest=digest)
    except FileNotFoundError:
        raise HTTPException(404, f"Certificate '{certificate_id}' not found")

@app.post("/api/v1/certificates/verify-body")
def verify_certificate_body(req: CertificateVerifyBody):
    return cert_service.verify(req.certificate)

@app.get("/api/v1/certificates/{certificate_id}/qr")
def certificate_qr(certificate_id: str):
    try:
        cert = cert_service.load(certificate_id)
        path = Path(cert.get("artifactPaths", {}).get("qrPng", DATA / "certificates" / f"{certificate_id}-QR.png"))
        if not path.exists(): raise FileNotFoundError(certificate_id)
        return FileResponse(path, media_type="image/png", filename=path.name)
    except FileNotFoundError:
        raise HTTPException(404, f"QR for certificate '{certificate_id}' not found")

@app.get("/api/v1/certificates/{certificate_id}/html")
def certificate_html(certificate_id: str):
    try:
        cert = cert_service.load(certificate_id)
        path = Path(cert.get("artifactPaths", {}).get("html", DATA / "certificates" / f"{certificate_id}.html"))
        if not path.exists(): raise FileNotFoundError(certificate_id)
        return FileResponse(path, media_type="text/html", filename=path.name)
    except FileNotFoundError:
        raise HTTPException(404, f"HTML certificate '{certificate_id}' not found")
