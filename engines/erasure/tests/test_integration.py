"""
Integration tests for SIH26149 Person 1 module
"""

import os
import time
import pytest
from starlette.testclient import TestClient
from api.main import app
from models.contracts import JobStatus, ErasureMethod, TargetType
from engine.job_manager import job_manager


client = TestClient(app)


def test_full_integration_pipeline_with_custom_ids(sample_folder):
    """
    Validates end-to-end flow:
    Client Request -> Pre-validation -> Multi-pass Overwrite -> Verification -> Result & Evidence retrieval.
    Includes verificationId and certificateId pass-through.
    """
    payload = {
        "userId": "AGENT-007",
        "deviceId": "DEVICE-FORENSIC-01",
        "sessionId": "SESSION-INTEGRATION-99",
        "jobId": "ERASE-JOB-CUSTOM-001",
        "targetPath": sample_folder,
        "targetType": "FOLDER",
        "method": "NIST_800_88_CLEAR",
        "verificationId": "VERIFY-SIH-999",
        "certificateId": "CERT-SIH-001"
    }

    # 1. Submit erasure request
    init_resp = client.post("/erase", json=payload)
    assert init_resp.status_code == 200
    init_data = init_resp.json()
    assert init_data["jobId"] == "ERASE-JOB-CUSTOM-001"
    assert init_data["verificationId"] == "VERIFY-SIH-999"
    assert init_data["certificateId"] == "CERT-SIH-001"

    # 2. Wait for completion
    time.sleep(1.0)

    # 3. Query final status
    status_resp = client.get("/erase/ERASE-JOB-CUSTOM-001")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["status"] == "SUCCESS"
    assert status_data["result"]["erasureVerified"] is True
    assert status_data["result"]["filesSucceeded"] >= 6
    assert status_data["result"]["filesFailed"] == 0

    # 4. Verify evidence endpoint
    verify_resp = client.get("/erase/ERASE-JOB-CUSTOM-001/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["result"]["erasureVerified"] is True
    assert v_data["result"]["verificationDetails"]["existenceCheckPassed"] is True
    assert v_data["result"]["verificationDetails"]["accessibilityCheckPassed"] is True

    # 5. Confirm folder completely wiped from disk
    assert not os.path.exists(sample_folder)


def test_integration_batch_erasure(temp_test_dir):
    """
    Validates batch erasure across multiple files and directories.
    """
    f1 = os.path.join(temp_test_dir, "batch_target_1.txt")
    f2 = os.path.join(temp_test_dir, "batch_target_2.txt")
    with open(f1, "w") as f: f.write("Data 1")
    with open(f2, "w") as f: f.write("Data 2")

    payload = {
        "userId": "USER-BATCH",
        "deviceId": "DEVICE-01",
        "sessionId": "SESSION-01",
        "targetPaths": [f1, f2],
        "targetType": "BATCH",
        "method": "SECURE_OVERWRITE"
    }

    resp = client.post("/erase", json=payload)
    assert resp.status_code == 200
    job_id = resp.json()["jobId"]

    time.sleep(0.5)

    status_resp = client.get(f"/erase/{job_id}")
    status_data = status_resp.json()
    assert status_data["status"] == "SUCCESS"
    assert status_data["result"]["filesProcessed"] == 2
    assert not os.path.exists(f1)
    assert not os.path.exists(f2)


def test_integration_cancellation(sample_file):
    """
    Validates cancellation flow.
    """
    job = job_manager.create_job(
        type("Req", (), {
            "userId": "U1",
            "deviceId": "D1",
            "sessionId": "S1",
            "jobId": "CANCEL-TEST-01",
            "targetType": TargetType.FILE,
            "method": ErasureMethod.GUTMANN_LIGHT,
            "targetPath": sample_file,
            "targetPaths": None,
            "verificationId": None,
            "certificateId": None
        })()
    )
    
    # Request cancel while pending
    cancel_resp = client.post(f"/erase/{job.jobId}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"
