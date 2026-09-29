from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ForensicScanRequest(BaseModel):
    userId: str = Field(default="LOCAL-USER")
    deviceId: str = Field(default="LOCAL-DEVICE")
    sessionId: str = Field(default="LOCAL-SESSION")
    jobId: Optional[str] = None
    targetPath: str
    includeHashes: bool = True
    includeMd5: bool = False
    includeSha1: bool = False
    maxFiles: int = Field(default=10000, ge=1, le=250000)
    saveReport: bool = True
    reportFormats: list[str] = Field(default_factory=lambda: ["json", "csv", "txt", "html"])
    keywords: list[str] = Field(default_factory=list)


class LegacyScanRequest(BaseModel):
    target: str
    include_hashes: bool = True
    max_files: int = Field(default=10000, ge=1, le=250000)
    save_report: bool = True
    userId: str = "LOCAL-USER"
    deviceId: str = "LOCAL-DEVICE"
    sessionId: str = "LOCAL-SESSION"
    jobId: Optional[str] = None


class VerifyRequest(BaseModel):
    report: dict[str, Any]


class CommonResponseEnvelope(BaseModel):
    userId: str
    deviceId: str
    sessionId: str
    jobId: str
    status: JobStatus
    timestamp: str
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
