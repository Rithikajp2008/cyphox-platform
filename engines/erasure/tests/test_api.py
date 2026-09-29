"""
Unit tests for FastAPI REST API endpoints
"""

import os
import time
import pytest
from starlette.testclient import TestClient
from api.main import app
from models.contracts import JobStatus, ErasureMethod, TargetType


client = TestClient(app)


def test_health_check():
    """Test GET / health endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "supportedMethods" in data
    assert "capabilities" in data
    assert data["capabilities"]["standardEnvelopeCompliant"] is True


def test_api_erase_file_success(sample_file):
    """Test POST /erase initiating file erasure and checking status."""
    payload = {
        "userId": "USER-001",
        "deviceId": "DEVICE-TEST",
        "sessionId": "SESSION-100",
        "targetPath": sample_file,
        "targetType": "FILE",
        "method": "SECURE_OVERWRITE"
    }

    response = client.post("/erase", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Validate SIH26149 Common Response Envelope
    assert data["userId"] == "USER-001"
    assert data["deviceId"] == "DEVICE-TEST"
    assert data["sessionId"] == "SESSION-100"
    assert "jobId" in data
    assert data["status"] in ("PENDING", "RUNNING", "SUCCESS")
    assert data["error"] is None

    job_id = data["jobId"]

    # Wait for background job to finish
    time.sleep(0.5)

    status_resp = client.get(f"/erase/{job_id}")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["status"] == "SUCCESS"
    assert status_data["result"]["erasureVerified"] is True

    # Check verification endpoint
    verify_resp = client.get(f"/erase/{job_id}/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["result"]["erasureVerified"] is True

    # Check result endpoint
    result_resp = client.get(f"/erase/{job_id}/result")
    assert result_resp.status_code == 200
    result_data = result_resp.json()
    assert result_data["result"]["operation"] == "SECURE_ERASURE"


def test_api_erase_dangerous_target_rejection():
    """Test that POST /erase rejects OS-critical paths safely."""
    payload = {
        "userId": "USER-001",
        "deviceId": "DEVICE-TEST",
        "sessionId": "SESSION-100",
        "targetPath": "C:\\Windows",
        "targetType": "FOLDER",
        "method": "ZERO_OVERWRITE"
    }

    response = client.post("/erase", json=payload)
    assert response.status_code == 200
    data = response.json()
    job_id = data["jobId"]

    time.sleep(0.3)
    status_resp = client.get(f"/erase/{job_id}")
    status_data = status_resp.json()
    assert status_data["status"] == "FAILED"
    assert "Safety Validation Failed" in status_data["error"]


def test_api_job_not_found():
    """Test querying a non-existent jobId returns 404."""
    response = client.get("/erase/NON_EXISTENT_JOB_999")
    assert response.status_code == 404
