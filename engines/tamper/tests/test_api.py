import time
from pathlib import Path
from fastapi.testclient import TestClient
import tamper_app.main as main
from tamper_app.jobs import JobManager
from tamper_app.certificate_service import CertificateService


def setup_isolated(tmp_path):
    main.manager = JobManager(tmp_path/"data")
    main.cert_service = CertificateService(tmp_path/"data"/"certificates",tmp_path/"data"/"keys")
    return TestClient(main.app)


def wait_job(client, job_id):
    last=None
    for _ in range(100):
        last=client.get(f"/api/v1/tamper/jobs/{job_id}").json()
        if last["status"] in ("SUCCESS","FAILED"): return last
        time.sleep(0.01)
    return last


def test_full_api_flow(tmp_path):
    client=setup_isolated(tmp_path)
    target=tmp_path/"target"; target.mkdir(); (target/"a.txt").write_text("hello",encoding="utf-8")
    r=client.post("/api/v1/tamper/baselines",json={"targetPath":str(target),"jobId":"J1","baselineId":"B1","checkMetadata":False})
    assert r.status_code==202
    assert wait_job(client,"J1")["status"]=="SUCCESS"
    (target/"a.txt").write_text("changed",encoding="utf-8")
    r=client.post("/api/v1/tamper/verifications",json={"baselineId":"B1","targetPath":str(target),"jobId":"J2","verificationId":"V1","checkMetadata":False})
    assert r.status_code==202
    out=wait_job(client,"J2"); assert out["status"]=="SUCCESS"; assert out["result"]["tamperStatus"]=="TAMPERED"
    r=client.post("/api/v1/certificates",json={"verificationId":"V1","certificateId":"C1"})
    assert r.status_code==201
    cert=r.json()["certificate"]
    assert cert["certificateId"]=="C1"
    assert client.get("/api/v1/certificates/C1/verify").json()["valid"] is True
    assert client.get("/api/v1/certificates/C1/qr").status_code==200


def test_duplicate_job_rejected(tmp_path):
    client=setup_isolated(tmp_path); target=tmp_path/"t"; target.mkdir(); (target/"a").write_text("x")
    assert client.post("/api/v1/tamper/baselines",json={"targetPath":str(target),"jobId":"J1","baselineId":"B1"}).status_code==202
    assert client.post("/api/v1/tamper/baselines",json={"targetPath":str(target),"jobId":"J1","baselineId":"B2"}).status_code==400
