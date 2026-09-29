"""
SIH26149 - Person 2: Advanced File Recovery API Application Entry Point
Problem Statement:
"Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool
for Digital Forensics and Data Sanitization"
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.recovery_routes import router as recovery_router

app = FastAPI(
    title="SIH26149 — Person 2: Advanced File Recovery API",
    description="""
## Advanced File Recovery Module (Person 2)
Independently runnable, testable, and integration-ready API for:
- ♻️ **File & Directory Recovery Workflow** (Read-oriented, isolated destination)
- 🔍 **Deleted-File & Remnant Detection** (Where filesystem/permissions permit)
- 🧬 **Signature/Magic-Byte File Carving Layer** (PDF, JPEG, PNG, DOCX, ZIP, GIF, MP4, MP3, WAV, SQLite)
- 🛡️ **Cryptographic SHA-256 Checksum Calculation**
- 📊 **Shannon Entropy Analysis** ($0.0000$ to $8.0000$)
- ⚡ **Common Team Contract**: `userId`, `deviceId`, `sessionId`, `jobId`, `verificationId`, `certificateId`
- 🚥 **Strict Common Execution Status**: `PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `CANCELLED`
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for integration with Frontend / API Clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Person 2 Recovery Router
app.include_router(recovery_router)


@app.get("/", tags=["Root"])
def root():
    return {
        "project": "SIH26149",
        "module": "PERSON 2 — ADVANCED FILE RECOVERY",
        "status": "OPERATIONAL",
        "docs": "/docs",
        "endpoints": {
            "health": "GET /recovery/",
            "createJob": "POST /recovery/jobs",
            "listJobs": "GET /recovery/jobs",
            "getJob": "GET /recovery/jobs/{jobId}",
            "cancelJob": "POST /recovery/jobs/{jobId}/cancel"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
