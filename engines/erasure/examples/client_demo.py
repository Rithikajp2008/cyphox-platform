"""
SIH26149 - Person 1 Secure Erasure API Demonstration & Client Example
"""

import time
import tempfile
import os
import requests

BASE_URL = "http://127.0.0.1:8765"


def main():
    print("=" * 70)
    print("SIH26149 - PERSON 1 SECURE ERASURE API CLIENT DEMO")
    print("=" * 70)

    # 1. Health check
    print("\n1. Querying Health Endpoint (GET /)...")
    try:
        health_resp = requests.get(f"{BASE_URL}/")
        print("Response:", health_resp.json())
    except Exception as e:
        print(f"Could not connect to {BASE_URL}. Ensure the server is running with 'python run_server.py'. Error: {e}")
        return

    # 2. Create a temporary file to erase
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"TOP SECRET EVIDENCE TO ERASE " * 50)
        test_file_path = tmp.name

    print(f"\n2. Created sample test file for erasure: {test_file_path}")
    print(f"File exists before erasure: {os.path.exists(test_file_path)}")

    # 3. Submit erasure request (POST /erase)
    print("\n3. Submitting Secure Erasure Request (POST /erase)...")
    payload = {
        "userId": "AGENT-FORENSIC-01",
        "deviceId": "DEVICE-WIN-11",
        "sessionId": "SESSION-DEMO-2026",
        "jobId": "ERASE-DEMO-001",
        "targetPath": test_file_path,
        "targetType": "FILE",
        "method": "DOD_5220_22_M",
        "verificationId": "VERIFY-RECORD-123"
    }
    erase_resp = requests.post(f"{BASE_URL}/erase", json=payload)
    print("Initiate Response:", erase_resp.json())

    # 4. Poll job status (GET /erase/{jobId})
    print("\n4. Polling Job Status (GET /erase/ERASE-DEMO-001)...")
    for _ in range(10):
        time.sleep(0.3)
        status_resp = requests.get(f"{BASE_URL}/erase/ERASE-DEMO-001")
        status_data = status_resp.json()
        print(f"Current Status: {status_data['status']}")
        if status_data["status"] in ("SUCCESS", "FAILED", "CANCELLED"):
            break

    # 5. Query verification evidence (GET /erase/{jobId}/verify)
    print("\n5. Querying Verification Evidence (GET /erase/ERASE-DEMO-001/verify)...")
    verify_resp = requests.get(f"{BASE_URL}/erase/ERASE-DEMO-001/verify")
    print("Verification Response:", verify_resp.json())

    # 6. Query complete result payload (GET /erase/{jobId}/result)
    print("\n6. Querying Complete Erasure Result (GET /erase/ERASE-DEMO-001/result)...")
    result_resp = requests.get(f"{BASE_URL}/erase/ERASE-DEMO-001/result")
    print("Final Result Payload:", result_resp.json())

    print(f"\nFile exists after erasure: {os.path.exists(test_file_path)}")
    print("\n=" * 70)
    print("DEMONSTRATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
