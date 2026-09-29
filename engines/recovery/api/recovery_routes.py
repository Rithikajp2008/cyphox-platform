from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, status, HTTPException
from fastapi.responses import JSONResponse

from ..models.recovery_models import (
    RecoveryRequest,
    RecoveryResponseEnvelope,
    JobStatusEnum,
    ErrorDetails,
    RecoveryResultSummary,
    DeleteFileRequest,
    DeletedFileItem
)
from ..services.recovery_manager import recovery_manager
from ..services.recovery_engine import RecoveryEngine

router = APIRouter(prefix="/recovery", tags=["Advanced File Recovery (Person 2)"])


@router.get(
    "/",
    response_model=RecoveryResponseEnvelope,
    summary="Recovery Module Info & Health Check",
    description="Returns service status, capabilities, and health check inside the common response envelope."
)
async def get_recovery_root():
    """
    Root info and health check for Person 2 Recovery API.
    """
    summary = RecoveryResultSummary(
        filesScanned=0,
        filesFound=0,
        filesRecovered=0,
        filesFailed=0,
        carvedFilesCount=0,
        outputPath="STANDBY",
        startedAt=datetime.now(timezone.utc).isoformat(),
        completedAt=datetime.now(timezone.utc).isoformat(),
        durationSeconds=0.0,
        recoveredFiles=[],
        errors=[],
        limitationsNote="SIH26149 Person 2 Advanced Recovery Engine is active and ready."
    )

    return RecoveryResponseEnvelope(
        userId="SYSTEM",
        deviceId="HOST_DEVICE",
        sessionId="SESSION_HEALTH",
        jobId="RECOVERY_INIT",
        status=JobStatusEnum.SUCCESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        result=summary,
        error=None
    )


# ---------------------------------------------------------------------------
# 1. FILE DELETION & RECOVERY VAULT
# ---------------------------------------------------------------------------

@router.post(
    "/delete",
    response_model=RecoveryResponseEnvelope,
    status_code=status.HTTP_200_OK,
    summary="Delete File & Index in Recovery Vault",
    description="Safely removes a file and stores its binary snapshot and forensic metadata in the recovery vault."
)
async def delete_file(req: DeleteFileRequest):
    """Deletes a file and indexes it in the recovery engine vault."""
    try:
        record = RecoveryEngine.delete_file_and_record(
            file_path=req.filePath,
            file_name=req.fileName,
            content=req.content,
            user_id=req.userId
        )
        return RecoveryResponseEnvelope(
            userId=req.userId,
            deviceId=req.deviceId or "DEVICE-001",
            sessionId="SESSION_DEL",
            jobId=record["id"],
            status=JobStatusEnum.SUCCESS,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result=record,
            error=None
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RecoveryResponseEnvelope(
                userId=req.userId,
                deviceId=req.deviceId or "DEVICE-001",
                sessionId="SESSION_DEL",
                jobId="JOB_DEL_ERR",
                status=JobStatusEnum.FAILED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                result=None,
                error=ErrorDetails(code="DELETE_FAILED", message=str(e))
            ).model_dump(by_alias=True)
        )


@router.get(
    "/deleted",
    response_model=RecoveryResponseEnvelope,
    summary="List All Deleted Files",
    description="Returns all recorded deleted files available for instant recovery."
)
async def list_deleted_files(userId: Optional[str] = None):
    """Lists all deleted files recorded in the vault."""
    files = RecoveryEngine.get_deleted_files(user_id=userId)
    return RecoveryResponseEnvelope(
        userId=userId or "SYSTEM",
        deviceId="HOST_DEVICE",
        sessionId="SESSION_DELETED_LIST",
        jobId="DELETED_LIST",
        status=JobStatusEnum.SUCCESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        result={"total": len(files), "deletedFiles": files},
        error=None
    )


# ---------------------------------------------------------------------------
# 2. OPTION 2: RECOVER LAST DELETED FILE
# ---------------------------------------------------------------------------

@router.post(
    "/deleted/recover-last",
    response_model=RecoveryResponseEnvelope,
    summary="Option 2: Recover Last Deleted File",
    description="Recovers the single most recently deleted file and restores it to destination directory."
)
async def recover_last_deleted_file(userId: str = "USER-001", destinationDir: str = "data/recovered"):
    """Recovers the last deleted file."""
    res = RecoveryEngine.recover_last_deleted(user_id=userId, destination_dir=destinationDir)
    if not res.get("success"):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=RecoveryResponseEnvelope(
                userId=userId,
                deviceId="HOST_DEVICE",
                sessionId="SESSION_REC_LAST",
                jobId="REC_LAST",
                status=JobStatusEnum.FAILED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                result=None,
                error=ErrorDetails(code="NO_DELETED_FILES", message=res.get("message", "No files found."))
            ).model_dump(by_alias=True)
        )

    return RecoveryResponseEnvelope(
        userId=userId,
        deviceId="HOST_DEVICE",
        sessionId="SESSION_REC_LAST",
        jobId="REC_LAST_SUCCESS",
        status=JobStatusEnum.SUCCESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        result=res,
        error=None
    )


# ---------------------------------------------------------------------------
# 3. OPTION 1: RECOVER ALL DELETED FILES SO FAR
# ---------------------------------------------------------------------------

@router.post(
    "/deleted/recover-all",
    response_model=RecoveryResponseEnvelope,
    summary="Option 1: Recover ALL Deleted Files",
    description="Recovers all deleted files recorded so far and restores them to destination directory."
)
async def recover_all_deleted_files(userId: str = "USER-001", destinationDir: str = "data/recovered"):
    """Recovers ALL deleted files so far."""
    res = RecoveryEngine.recover_all_deleted(user_id=userId, destination_dir=destinationDir)
    if not res.get("success") and res.get("restoredCount", 0) == 0:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=RecoveryResponseEnvelope(
                userId=userId,
                deviceId="HOST_DEVICE",
                sessionId="SESSION_REC_ALL",
                jobId="REC_ALL",
                status=JobStatusEnum.FAILED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                result=None,
                error=ErrorDetails(code="NO_DELETED_FILES", message=res.get("message", "No files found."))
            ).model_dump(by_alias=True)
        )

    return RecoveryResponseEnvelope(
        userId=userId,
        deviceId="HOST_DEVICE",
        sessionId="SESSION_REC_ALL",
        jobId="REC_ALL_SUCCESS",
        status=JobStatusEnum.SUCCESS,
        timestamp=datetime.now(timezone.utc).isoformat(),
        result=res,
        error=None
    )


# ---------------------------------------------------------------------------
# 4. RECOVERY JOBS (SCAN & CARVE)
# ---------------------------------------------------------------------------

@router.post(
    "/jobs",
    response_model=RecoveryResponseEnvelope,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create & Start Recovery Job",
    description="Validates source/destination, generates a jobId if not provided, and executes recovery asynchronously."
)
async def create_recovery_job(request: RecoveryRequest):
    """
    Creates and initiates an advanced file recovery job.
    """
    envelope = recovery_manager.create_and_start_job(request)
    return envelope


@router.get(
    "/jobs",
    response_model=List[RecoveryResponseEnvelope],
    summary="List All Recovery Jobs",
    description="Lists all current and past recovery jobs with their execution statuses and summary results."
)
async def list_recovery_jobs():
    """
    Lists all recovery jobs.
    """
    return recovery_manager.list_jobs()


@router.get(
    "/jobs/{jobId}",
    response_model=RecoveryResponseEnvelope,
    summary="Get Recovery Job Status & Details",
    description="Fetches detailed status, progress, and recovered file items for a specific recovery job."
)
async def get_recovery_job(jobId: str):
    """
    Gets details of a specific recovery job by jobId.
    """
    job = recovery_manager.get_job(jobId)
    if not job:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=RecoveryResponseEnvelope(
                userId="UNKNOWN",
                deviceId="UNKNOWN",
                sessionId="UNKNOWN",
                jobId=jobId,
                status=JobStatusEnum.FAILED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                result=None,
                error=ErrorDetails(
                    code="JOB_NOT_FOUND",
                    message=f"Recovery job with ID '{jobId}' was not found."
                )
            ).model_dump(by_alias=True)
        )
    return job


@router.post(
    "/jobs/{jobId}/cancel",
    response_model=RecoveryResponseEnvelope,
    summary="Cancel a Recovery Job",
    description="Safely requests cancellation of a running or pending recovery job."
)
async def cancel_recovery_job(jobId: str):
    """
    Cancels an active recovery job.
    """
    success, job, error_msg = recovery_manager.cancel_job(jobId)
    if not success and job is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=RecoveryResponseEnvelope(
                userId="UNKNOWN",
                deviceId="UNKNOWN",
                sessionId="UNKNOWN",
                jobId=jobId,
                status=JobStatusEnum.FAILED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                result=None,
                error=ErrorDetails(
                    code="JOB_NOT_FOUND",
                    message=error_msg or f"Job '{jobId}' not found."
                )
            ).model_dump(by_alias=True)
        )

    return job

