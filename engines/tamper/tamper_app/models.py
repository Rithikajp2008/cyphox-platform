from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class TamperStatus(str, Enum):
    INTACT = "INTACT"
    TAMPERED = "TAMPERED"
    INDETERMINATE = "INDETERMINATE"


class VerificationState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"


class BaselineCreateRequest(BaseModel):
    userId: str = "LOCAL-USER"
    deviceId: str = "LOCAL-DEVICE"
    sessionId: str = "LOCAL-SESSION"
    jobId: Optional[str] = None
    baselineId: Optional[str] = None
    targetPath: str
    maxFiles: int = Field(default=10000, ge=1, le=250000)
    checkMetadata: bool = True
    notes: Optional[str] = None


class TamperVerifyRequest(BaseModel):
    userId: str = "LOCAL-USER"
    deviceId: str = "LOCAL-DEVICE"
    sessionId: str = "LOCAL-SESSION"
    jobId: Optional[str] = None
    verificationId: Optional[str] = None
    baselineId: str
    targetPath: Optional[str] = None
    maxFiles: Optional[int] = Field(default=None, ge=1, le=250000)
    checkMetadata: Optional[bool] = None


class CertificateCreateRequest(BaseModel):
    userId: str = "LOCAL-USER"
    sessionId: str = "LOCAL-SESSION"
    verificationId: str
    certificateId: Optional[str] = None
    title: str = "Cyphox Tamper Verification Certificate"


class CertificateVerifyBody(BaseModel):
    certificate: dict[str, Any]
