# SIH26149 — Person 1: Secure Erasure Engine & REST API

> **Problem Statement:** *Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization*  
> **Assigned Role:** **PERSON 1** — Secure Erasure Engine + Secure Erasure API + Automated Testing

---

## 1. Requirement Analysis & Scope Boundaries

### Strictly Owned by Person 1:
- **Secure Erasure Engine:** Single file, recursive folder, batch list, and removable storage erasure.
- **Sanitization Overwrite Algorithms:** Single-pass Zero, Single-pass Cryptographic Random, 2-Pass Secure Overwrite, DoD 5220.22-M (3-pass), NIST SP 800-88 Rev 1 Clear & Purge, Gutmann Light (7-pass).
- **Safety Validator:** Rejection of operating system roots (`C:\`, `/`), Windows system directories (`C:\Windows`, `C:\Program Files`, `C:\ProgramData`), permission checks, and target type validations.
- **Erasure Operation Verifier:** Target non-existence verification, sector accessibility checks, unlinking confirmation, setting `erasureVerified: true/false`.
- **Async Job Manager:** Thread-safe job state lifecycle (`PENDING` $\rightarrow$ `RUNNING` $\rightarrow$ `SUCCESS` / `FAILED` / `CANCELLED`), cancellation token handling, and result evidence storage.
- **REST API:** Standalone FastAPI application conforming to the SIH26149 Common Team Response Envelope.
- **Automated Test Suite:** Safe unit, safety, verification, API, and integration tests using isolated temporary files.

### Strictly NOT Owned by Person 1:
- ❌ Advanced Recovery Engine & Recovery API (Person 2)
- ❌ Digital Forensic Report & Tamper Verification Engine (Person 3)
- ❌ Main Database / Authentication / Master Backend
- ❌ Frontend / Web UI
- ❌ Final Certificate Generation

---

## 2. System Architecture

```text
       ┌─────────────────────────────────────────────────────────┐
       │             Frontend / Common SIH Integration           │
       └────────────────────────────┬────────────────────────────┘
                                    │ HTTP / JSON
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │            Person 1 REST API (FastAPI)                  │
       │   GET /  |  POST /erase  |  GET /erase/{jobId}          │
       │   POST /erase/{jobId}/cancel                            │
       │   GET /erase/{jobId}/verify  |  GET /erase/{jobId}/result │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │                     Job Manager                         │
       │   • ThreadPoolExecutor (Background Workers)             │
       │   • Lifecycle: PENDING -> RUNNING -> SUCCESS/FAILED     │
       │   • Cancellation Token Support                          │
       └────────────────────────────┬────────────────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
       ┌───────────────────────────┐ ┌───────────────────────────┐
       │     Safety Validator      │ │   Secure Erasure Engine   │
       │ • Reject OS/System Roots  │ │ • Multi-Pass Overwrites   │
       │ • Permissions Check       │ │ • Metadata Obfuscation    │
       │ • Target Type Validation  │ │ • Zero-Byte Truncation    │
       └───────────────────────────┘ │ • Recursive Tree Unlink   │
                                     └─────────────┬─────────────┘
                                                   │
                                                   ▼
                                     ┌───────────────────────────┐
                                     │ Erasure Verifier          │
                                     │ • Non-existence check     │
                                     │ • Accessibility test      │
                                     │ • erasureVerified: bool   │
                                     └───────────────────────────┘
```

---

## 3. SIH26149 Common Team Contract

### 3.1 Common Identifiers
All external requests and responses strictly use these exact shared keys:
- `userId`: Identifier of the user triggering the operation (e.g. `"USER-001"`).
- `deviceId`: Identifier of the target device/host (e.g. `"DEVICE-001"`).
- `sessionId`: Session grouping identifier (e.g. `"SESSION-001"`).
- `jobId`: Unique identifier for the individual erasure operation (e.g. `"ERASE-001"`).
- `verificationId`: Common tamper-verification record ID (optional pass-through).
- `certificateId`: Common certificate ID (optional pass-through).

### 3.2 Common Statuses
Every job record and response envelope exposes ONLY these 5 statuses:
```text
PENDING   -> Operation is queued
RUNNING   -> Active overwriting / erasure in progress
SUCCESS   -> All targets sanitized, unlinked, and erasureVerified == True
FAILED    -> Validation error, permission denial, or unlinking failure
CANCELLED -> Safely aborted by user cancellation request
```

### 3.3 Common Response Envelope
```json
{
  "userId": "USER-001",
  "deviceId": "DEVICE-001",
  "sessionId": "SESSION-001",
  "jobId": "ERASE-8F3A2B1C",
  "status": "SUCCESS",
  "timestamp": "2026-09-23T15:30:00.000000+00:00",
  "result": {
    "operation": "SECURE_ERASURE",
    "targetPath": "D:\\testing\\sensitive_file.pdf",
    "targetType": "FILE",
    "method": "DOD_5220_22_M",
    "erasureVerified": true,
    "message": "Secure erasure completed successfully (DoD 5220.22-M (3-Pass ECE Sanitization)).",
    "startedAt": "2026-09-23T15:29:59.100000+00:00",
    "completedAt": "2026-09-23T15:30:00.000000+00:00",
    "durationSeconds": 0.045,
    "totalTargets": 1,
    "filesProcessed": 1,
    "filesSucceeded": 1,
    "filesFailed": 0,
    "totalBytesErased": 1048576,
    "passesExecuted": 3,
    "targetDetails": [
      {
        "path": "D:\\testing\\sensitive_file.pdf",
        "targetType": "FILE",
        "originalSize": 1048576,
        "passesCompleted": 3,
        "erasureVerified": true,
        "status": "SUCCESS",
        "error": null
      }
    ],
    "verificationDetails": {
      "erasureVerified": true,
      "existenceCheckPassed": true,
      "accessibilityCheckPassed": true,
      "zeroByteTruncated": true,
      "unlinked": true,
      "verificationTimestamp": "2026-09-23T15:30:00.000000+00:00"
    },
    "warnings": [],
    "errors": []
  },
  "error": null,
  "verificationId": "VERIFY-99",
  "certificateId": null
}
```

---

## 4. API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health check, module status, and supported methods |
| `POST` | `/erase` | Initiate secure erasure (File, Folder, Batch) |
| `GET` | `/erase/{jobId}` | Get real-time status and progress of a job |
| `POST` | `/erase/{jobId}/cancel` | Request cancellation of a pending or running job |
| `GET` | `/erase/{jobId}/verify` | Retrieve erasure-operation verification evidence (`erasureVerified`) |
| `GET` | `/erase/{jobId}/result` | Retrieve full structured result and forensic metadata |

---

## 5. Directory Structure

```text
Erase&api/
├── api/
│   ├── __init__.py
│   ├── main.py              # FastAPI app configuration & CORS
│   ├── routes.py            # All REST API endpoints
│   └── schemas.py           # Pydantic v2 schemas and shared envelope
├── engine/
│   ├── __init__.py
│   ├── overwrite_methods.py # Cryptographic multi-pass overwrite algorithms
│   ├── validator.py         # Safety validator & OS-critical path protection
│   ├── verifier.py          # Post-erasure verification & evidence builder
│   ├── erasure_engine.py    # Core execution for file, folder, batch erasure
│   └── job_manager.py       # Thread-safe background job lifecycle & cancellation
├── models/
│   ├── __init__.py
│   └── contracts.py         # Shared enums and data contracts
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures for safe isolated test files
│   ├── test_validator.py    # Unit tests for safety validation
│   ├── test_verifier.py     # Unit tests for erasure verifier
│   ├── test_engine.py       # Unit tests for multi-pass overwrite & erasure engine
│   ├── test_api.py          # Unit tests for FastAPI endpoints
│   └── test_integration.py  # End-to-end integration tests
├── examples/
│   └── client_demo.py       # End-to-end client usage example
├── requirements.txt         # Production dependencies
├── run_server.py            # Local server runner
└── README.md                # Comprehensive documentation
```

---

## 6. Windows Setup & Run Instructions

### 6.1 Install Dependencies
```powershell
pip install -r requirements.txt
```

### 6.2 Run Automated Tests
```powershell
pytest -v tests/
```

### 6.3 Launch the API Server
```powershell
python run_server.py
```
The server will start at: `http://127.0.0.1:8765`  
Interactive Swagger Docs: `http://127.0.0.1:8765/docs`  
ReDoc: `http://127.0.0.1:8765/redoc`

---

## 7. Example Requests

### 7.1 Single File Erasure (cURL)
```bash
curl -X POST "http://127.0.0.1:8765/erase" \
     -H "Content-Type: application/json" \
     -d '{
       "userId": "USER-001",
       "deviceId": "DEVICE-001",
       "sessionId": "SESSION-001",
       "jobId": "ERASE-FILE-001",
       "targetPath": "D:\\test\\sample.pdf",
       "targetType": "FILE",
       "method": "SECURE_OVERWRITE"
     }'
```

### 7.2 Folder Erasure (cURL)
```bash
curl -X POST "http://127.0.0.1:8765/erase" \
     -H "Content-Type: application/json" \
     -d '{
       "userId": "USER-001",
       "deviceId": "DEVICE-001",
       "sessionId": "SESSION-001",
       "targetPath": "D:\\test\\case_folder",
       "targetType": "FOLDER",
       "method": "DOD_5220_22_M"
     }'
```

### 7.3 Batch Erasure (Python)
```python
import requests

payload = {
    "userId": "USER-001",
    "deviceId": "DEVICE-001",
    "sessionId": "SESSION-001",
    "targetPaths": [
        "D:\\test\\file1.txt",
        "D:\\test\\file2.txt",
        "D:\\test\\subfolder"
    ],
    "targetType": "BATCH",
    "method": "NIST_800_88_CLEAR"
}

response = requests.post("http://127.0.0.1:8765/erase", json=payload)
print(response.json())
```

---

## 8. Integration Guide for Person 2 & Person 3

Person 2 (Advanced File Recovery) and Person 3 (Digital Forensics & Tamper Verification) or the common backend can integrate with Person 1 through standard HTTP REST calls:

1. **Step 1 (Trigger Erasure):** Call `POST /erase` with the target file/folder path and desired overwrite method.
2. **Step 2 (Poll Status):** Poll `GET /erase/{jobId}` until `status` becomes `"SUCCESS"` or `"FAILED"`.
3. **Step 3 (Retrieve Verification Evidence):** Call `GET /erase/{jobId}/verify` to retrieve the `erasureVerified` boolean and file-level existence check breakdown for forensic audit logging.
4. **Step 4 (Pass-Through Identifiers):** Provide `verificationId` and `certificateId` in the request body to maintain correlation across the master SIH26149 audit trail.

---

## 9. Filesystem & Storage Limitations (Honest Disclosure)

1. **Solid State Drives (SSDs) & Flash Media:** Modern SSDs utilize Wear Leveling, Over-provisioning, and Flash Translation Layers (FTL). Direct logical file overwriting modifies data at the filesystem sector level, but physical flash blocks may retain remnant electrical charges until a hardware-level ATA Secure Erase or NVMe Format command is executed.
2. **Copy-on-Write (CoW) & Journaling Filesystems:** On filesystems such as Btrfs, ZFS, or NTFS volume shadow copies, overwritten data may be redirected to a new sector before the old pointer is freed.
3. **Locked / Read-Only Files:** Files held open by other system processes cannot be unlinked until released.
4. **Scope Integrity:** Person 1 performs software-level multi-pass cryptographic data sanitization, metadata scrambling, zero truncation, and unlinking, and accurately reports `erasureVerified` based on filesystem-level verification.
