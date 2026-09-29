"""
SIH26149 - Person 2: Advanced File Recovery Models
Strict Common Team Contract compliance:
- External identifiers: userId, deviceId, sessionId, jobId, verificationId, certificateId
- Execution status: PENDING, RUNNING, SUCCESS, FAILED, CANCELLED
- Envelope structure: { userId, deviceId, sessionId, jobId, status, timestamp, result, error }
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class JobStatusEnum(str, Enum):
    """
    Strict Common Execution Status.
    Allowed only: PENDING, RUNNING, SUCCESS, FAILED, CANCELLED
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RecoveryOptions(BaseModel):
    """
    Options controlling the recovery workflow.
    """
    model_config = ConfigDict(populate_by_name=True)

    recursive: bool = Field(default=True, description="Scan subdirectories recursively")
    fileCarving: bool = Field(default=True, description="Enable signature-based magic byte carving")
    recoverDeleted: bool = Field(default=True, description="Scan for deleted/unlinked remnants and shadow copies where available")
    targetExtensions: Optional[List[str]] = Field(default=None, description="Optional filter for specific extensions (e.g. ['pdf', 'jpg', 'docx'])")
    maxCarveSizeMb: int = Field(default=100, description="Max allowable size for carved file in MB")


class RecoveryRequest(BaseModel):
    """
    Common team contract for initiating a recovery job.
    """
    model_config = ConfigDict(populate_by_name=True)

    userId: str = Field(..., description="User performing the operation (e.g. USER-001)")
    deviceId: str = Field(..., description="Device/Drive involved (e.g. DEVICE-001)")
    sessionId: str = Field(..., description="Operation session identifier (e.g. SESSION-001)")
    jobId: Optional[str] = Field(default=None, description="Optional pre-assigned job ID (e.g. RECOVERY-001). Auto-generated if not supplied.")
    sourcePath: str = Field(..., description="Source path or device mount point to recover from (e.g. D:\\testing)")
    destinationPath: str = Field(..., description="Dedicated separate destination path for recovered files (e.g. D:\\recovered)")
    options: RecoveryOptions = Field(default_factory=RecoveryOptions, description="Recovery execution options")


class RecoveredFileItem(BaseModel):
    """
    Detailed metadata for each successfully or partially recovered file.
    """
    model_config = ConfigDict(populate_by_name=True)

    fileName: str = Field(..., description="Name of the recovered file")
    originalPath: str = Field(..., description="Original path or offset identifier on source")
    recoveredPath: str = Field(..., description="Absolute path where the recovered file was written")
    fileType: str = Field(..., description="MIME type or category (e.g. application/pdf, image/jpeg)")
    fileSize: int = Field(..., description="Size in bytes")
    sha256: str = Field(..., description="Calculated SHA-256 cryptographic hash of recovered file")
    status: str = Field(default="RECOVERED", description="Per-file recovery status (RECOVERED, PARTIAL, CORRUPTED)")
    entropy: Optional[float] = Field(default=None, description="Calculated Shannon entropy (0.0000 to 8.0000)")
    recoverability: Optional[str] = Field(default="High", description="Integrity assessment (High, Medium, Low, Corrupted)")
    carved: bool = Field(default=False, description="True if recovered via raw signature carving")
    recoveredAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Timestamp of recovery")


class ErrorDetails(BaseModel):
    """
    Standard error object.
    """
    model_config = ConfigDict(populate_by_name=True)

    code: str = Field(..., description="Error code (e.g. RECOVERY_FAILED, INVALID_SOURCE)")
    message: str = Field(..., description="Human-readable error description")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Optional extra diagnostic details")


class RecoveryResultSummary(BaseModel):
    """
    Structured recovery result inside envelope's `result` field.
    """
    model_config = ConfigDict(populate_by_name=True)

    filesScanned: int = Field(default=0, description="Total files and blocks evaluated")
    filesFound: int = Field(default=0, description="Recoverable and carveable files identified")
    filesRecovered: int = Field(default=0, description="Files successfully written to destination")
    filesFailed: int = Field(default=0, description="Files that could not be recovered")
    carvedFilesCount: int = Field(default=0, description="Number of files recovered via magic byte carving")
    outputPath: str = Field(..., description="Destination directory where files were written")
    startedAt: str = Field(..., description="Job start timestamp ISO-8601")
    completedAt: Optional[str] = Field(default=None, description="Job completion timestamp ISO-8601")
    durationSeconds: Optional[float] = Field(default=None, description="Total execution duration in seconds")
    recoveredFiles: List[RecoveredFileItem] = Field(default_factory=list, description="List of individual recovered files metadata")
    errors: List[str] = Field(default_factory=list, description="List of per-file non-fatal error notices encountered")
    limitationsNote: Optional[str] = Field(
        default="Recovery depends on filesystem structures, permissions, non-overwritten sectors, and TRIM states.",
        description="Technical boundary notice"
    )


class DeleteFileRequest(BaseModel):
    """
    Request model for deleting a file and registering it in recovery vault.
    """
    model_config = ConfigDict(populate_by_name=True)

    userId: str = Field(default="USER-001", description="User ID")
    deviceId: Optional[str] = Field(default="DEVICE-001", description="Device ID")
    filePath: Optional[str] = Field(default=None, description="Path of existing file to delete")
    fileName: Optional[str] = Field(default=None, description="Name of file (when providing content)")
    content: Optional[str] = Field(default=None, description="Content of file (for simulated deletion / test files)")


class DeletedFileItem(BaseModel):
    """
    Metadata for a deleted file stored in recovery vault.
    """
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Unique deleted file identifier")
    name: str = Field(..., description="File name")
    originalPath: str = Field(default="", description="Original file path")
    vaultPath: str = Field(default="", description="Path in deleted files vault")
    size: int = Field(default=0, description="Size in bytes")
    sizeFormatted: str = Field(default="0 B", description="Formatted file size")
    mime: str = Field(default="application/octet-stream", description="MIME type")
    category: str = Field(default="Documents", description="File category")
    sha256: str = Field(default="", description="SHA-256 hash")
    entropy: float = Field(default=0.0, description="Shannon entropy")
    recoverability: str = Field(default="High", description="Recoverability rating")
    status: str = Field(default="DELETED", description="DELETED or RECOVERED")
    userId: str = Field(default="guest", description="User ID")
    deletedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Deletion timestamp")
    recoveredAt: Optional[str] = Field(default=None, description="Recovery timestamp")
    recoveredPath: Optional[str] = Field(default=None, description="Restored file path")


class RecoveryResponseEnvelope(BaseModel):
    """
    Strict common response envelope required across SIH26149 team.
    """
    model_config = ConfigDict(populate_by_name=True)

    userId: str = Field(..., description="User ID")
    deviceId: str = Field(..., description="Device ID")
    sessionId: str = Field(..., description="Session ID")
    jobId: str = Field(..., description="Recovery Job ID")
    status: JobStatusEnum = Field(..., description="Execution status: PENDING, RUNNING, SUCCESS, FAILED, CANCELLED")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO-8601 timestamp")
    result: Optional[Any] = Field(default=None, description="Recovery result payload")
    error: Optional[ErrorDetails] = Field(default=None, description="Error object if failed")

