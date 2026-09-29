"""
SIH26149 - Person 1 REST API Pydantic Schemas & Shared Envelope
"""

from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field
from models.contracts import JobStatus, TargetType, ErasureMethod


class TargetItemResult(BaseModel):
    """Metadata and outcome for an individual file/target within an erasure job."""
    path: str
    targetType: str = "FILE"
    originalSize: int = 0
    passesCompleted: int = 0
    erasureVerified: bool = False
    status: str = "SUCCESS"
    error: Optional[str] = None


class VerificationSummary(BaseModel):
    """Erasure operation verification summary."""
    erasureVerified: bool
    existenceCheckPassed: bool
    accessibilityCheckPassed: bool
    zeroByteTruncated: bool
    unlinked: bool
    verificationTimestamp: str
    details: Optional[Dict[str, Any]] = None


class ErasureResultPayload(BaseModel):
    """Person 1 specific execution outcome inside the 'result' envelope field."""
    operation: str = "SECURE_ERASURE"
    targetPath: Optional[str] = None
    targetPaths: Optional[List[str]] = None
    targetType: TargetType
    method: ErasureMethod
    erasureVerified: bool = False
    message: str = ""
    startedAt: Optional[str] = None
    completedAt: Optional[str] = None
    durationSeconds: Optional[float] = None
    totalTargets: int = 0
    filesProcessed: int = 0
    filesSucceeded: int = 0
    filesFailed: int = 0
    totalBytesErased: int = 0
    passesExecuted: int = 0
    targetDetails: List[TargetItemResult] = Field(default_factory=list)
    verificationDetails: Optional[VerificationSummary] = None
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class EraseRequest(BaseModel):
    """
    Standard request payload for initiating an erasure job.
    """
    userId: str = Field(..., description="Identifier of the user requesting operation", json_schema_extra={"example": "USER-001"})
    deviceId: str = Field(..., description="Identifier of the host/device/drive", json_schema_extra={"example": "DEVICE-001"})
    sessionId: str = Field(..., description="Session grouping identifier", json_schema_extra={"example": "SESSION-001"})
    jobId: Optional[str] = Field(None, description="Optional caller-provided job ID", json_schema_extra={"example": "ERASE-001"})
    
    # Target definition
    targetPath: Optional[str] = Field(None, description="Target path for single file/folder", json_schema_extra={"example": "D:\\testing\\testfile.pdf"})
    targetPaths: Optional[List[str]] = Field(None, description="Target paths for batch erasure", json_schema_extra={"example": ["D:\\testing\\f1.txt", "D:\\testing\\f2.txt"]})
    targetType: TargetType = Field(default=TargetType.FILE, description="FILE, FOLDER, BATCH, or DEVICE")
    method: ErasureMethod = Field(default=ErasureMethod.SECURE_OVERWRITE, description="Sanitization overwrite method")
    
    # Optional integration metadata
    verificationId: Optional[str] = Field(None, description="Common tamper-verification ID (integration pass-through)")
    certificateId: Optional[str] = Field(None, description="Certificate ID (integration pass-through)")
    
    # Safety options
    allowRemovableDrive: bool = Field(default=False, description="Explicit flag required to target removable drive roots")


class CommonResponseEnvelope(BaseModel):
    """
    SIH26149 Common Team Response Envelope.
    Must strictly use: userId, deviceId, sessionId, jobId, status, timestamp, result, error.
    """
    userId: str
    deviceId: str
    sessionId: str
    jobId: str
    status: JobStatus
    timestamp: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    verificationId: Optional[str] = None
    certificateId: Optional[str] = None


class HealthResponse(BaseModel):
    """System health check and module status."""
    module: str = "SIH26149 - Person 1: Secure Erasure Engine & API"
    version: str = "1.0.0"
    status: str = "ONLINE"
    timestamp: str
    supportedMethods: List[str]
    supportedTargetTypes: List[str]
    capabilities: Dict[str, Any]
