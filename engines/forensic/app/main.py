from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from .devices import list_devices
from .engine import ForensicEngine, verify_report
from .jobs import JobManager
from .models import ForensicScanRequest, LegacyScanRequest, VerifyRequest
from .reporting import write_reports

BASE = Path(__file__).resolve().parents[1]
REPORTS = BASE / "reports"; REPORTS.mkdir(exist_ok=True)
jobs = JobManager(REPORTS)

app = FastAPI(title="Cyphox Digital Forensic Service", version="2.0.0", description="Read-only forensic scanning, findings, artifacts, evidence manifest and integrity-verified reporting for Cyphox.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"service":"cyphox-forensics","status":"ONLINE","version":"2.0.0","mode":"READ_ONLY"}

@app.get("/health")
@app.get("/api/v1/forensics/health")
def health():
    return {"status":"OK","service":"cyphox-forensics","version":"2.0.0"}

@app.get("/api/v1/forensics/devices")
def devices():
    return {"status":"SUCCESS","devices":list_devices()}

@app.post("/api/v1/forensics/jobs", status_code=status.HTTP_202_ACCEPTED)
def create_job(req: ForensicScanRequest):
    try:
        job = jobs.create(req); jobs.start(job); return job.envelope()
    except ValueError as e: raise HTTPException(400, str(e))

@app.get("/api/v1/forensics/jobs/{job_id}")
def job_status(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, f"Forensic job '{job_id}' not found")
    return job.envelope()

@app.get("/api/v1/forensics/jobs/{job_id}/report")
def job_report(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, f"Forensic job '{job_id}' not found")
    if not job.result: raise HTTPException(409, f"Report is not available while job is {job.status.value}")
    return {"status":job.status.value,"jobId":job.jobId,"report":job.result.get("report"),"reportPaths":job.result.get("reportPaths",{})}

@app.get("/api/v1/forensics/jobs/{job_id}/findings")
def job_findings(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, f"Forensic job '{job_id}' not found")
    if not job.result: return {"status":job.status.value,"jobId":job.jobId,"findings":[]}
    return {"status":job.status.value,"jobId":job.jobId,"summary":job.result.get("summary"),"findings":job.result.get("findings",[]),"artifacts":job.result.get("artifacts",{}),"residualDataAnalysis":job.result.get("residualDataAnalysis",{})}

@app.post("/api/v1/forensics/verify")
def verify(req: VerifyRequest):
    return verify_report(req.report)

# Compatibility endpoint retained for the earlier standalone engine and Swagger demos.
@app.post("/api/v1/forensics/scan")
def legacy_scan(req: LegacyScanRequest):
    try:
        jid = req.jobId or f"LEGACY-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        eng = ForensicEngine(max_files=req.max_files, include_hashes=req.include_hashes, user_id=req.userId, device_id=req.deviceId, session_id=req.sessionId, job_id=jid)
        report = eng.analyze(req.target)
        paths = {}
        if req.save_report:
            paths = write_reports(report, REPORTS / jid, ["json","csv","txt","html"])
        return {"status":"SUCCESS","jobId":jid,"report_paths":paths,"report":report}
    except FileNotFoundError as e: raise HTTPException(404, str(e))
    except (ValueError, PermissionError) as e: raise HTTPException(400, str(e))
    except Exception as e: raise HTTPException(500, f"Forensic scan failed: {type(e).__name__}: {e}")
