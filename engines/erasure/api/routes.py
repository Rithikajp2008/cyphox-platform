"""
SIH26149 - Person 1 REST API Routes

Defines all endpoints for initiating erasure, querying status,
requesting cancellation, retrieving verification evidence, and inspecting results.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from typing import Dict, Any

from models.contracts import JobStatus, ErasureMethod, TargetType
from api.schemas import (
    EraseRequest,
    CommonResponseEnvelope,
    HealthResponse
)
from engine.job_manager import job_manager
from engine.overwrite_methods import STRATEGIES

router = APIRouter()


@router.get("/", response_model=HealthResponse, tags=["Health & Info"])
def health_check():
    """
    Returns system health status, version, supported overwrite techniques, and capabilities.
    """
    return HealthResponse(
        module="SIH26149 - Person 1: Secure Erasure Engine & API",
        version="1.0.0",
        status="ONLINE",
        timestamp=datetime.now(timezone.utc).isoformat(),
        supportedMethods=[m.value for m in ErasureMethod],
        supportedTargetTypes=[t.value for t in TargetType],
        capabilities={
            "fileErasure": True,
            "folderErasure": True,
            "batchErasure": True,
            "removableStorageSafeWipe": True,
            "multiPassOverwrite": True,
            "erasureVerification": True,
            "cancellationSupport": True,
            "osRootProtection": True,
            "standardEnvelopeCompliant": True
        }
    )


@router.post(
    "/erase",
    response_model=CommonResponseEnvelope,
    status_code=status.HTTP_200_OK,
    tags=["Secure Erasure"]
)
def initiate_erasure(request: EraseRequest):
    """
    Initiates an asynchronous secure erasure job for a file, folder, or batch of paths.
    Conforms strictly to the SIH26149 Common Response Envelope.
    """
    try:
        # Create job record
        job = job_manager.create_job(request)
        # Launch background execution
        job_manager.start_job(
            job_id=job.jobId,
            allow_removable_drive=request.allowRemovableDrive,
            synchronous=False
        )
        return job.to_envelope()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to initiate erasure job: {str(e)}"
        )


@router.get(
    "/erase/{jobId}",
    response_model=CommonResponseEnvelope,
    tags=["Secure Erasure"]
)
def get_job_status(jobId: str):
    """
    Retrieves current status and progress of an erasure job by its unique jobId.
    """
    job = job_manager.get_job(jobId)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Erasure job '{jobId}' not found."
        )
    return job.to_envelope()


@router.post(
    "/erase/{jobId}/cancel",
    response_model=CommonResponseEnvelope,
    tags=["Secure Erasure"]
)
def cancel_job(jobId: str):
    """
    Requests safe cancellation of a PENDING or RUNNING erasure job.
    """
    job = job_manager.get_job(jobId)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Erasure job '{jobId}' not found."
        )

    job_manager.cancel_job(jobId)
    return job.to_envelope()


@router.get(
    "/erase/{jobId}/verify",
    response_model=CommonResponseEnvelope,
    tags=["Secure Erasure"]
)
def get_job_verification(jobId: str):
    """
    Returns erasure-operation verification evidence ('erasureVerified: true/false')
    and forensic accessibility check breakdown for the specified job.
    """
    job = job_manager.get_job(jobId)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Erasure job '{jobId}' not found."
        )

    envelope = job.to_envelope()
    # Ensure verification summary is prominent in response
    if job.result:
        envelope.result = {
            "operation": "ERASURE_VERIFICATION",
            "erasureVerified": job.result.erasureVerified,
            "verificationDetails": job.result.verificationDetails.model_dump() if job.result.verificationDetails else None,
            "targetDetails": [t.model_dump() for t in job.result.targetDetails],
            "message": "Erasure operation verified successfully." if job.result.erasureVerified else "Erasure verification failed or pending."
        }
    else:
        envelope.result = {
            "operation": "ERASURE_VERIFICATION",
            "erasureVerified": False,
            "message": f"Job is in '{job.status.value}' state. Verification is not yet available."
        }
    return envelope


@router.get(
    "/erase/{jobId}/result",
    response_model=CommonResponseEnvelope,
    tags=["Secure Erasure"]
)
def get_job_result(jobId: str):
    """
    Retrieves the final detailed result payload and metrics for the specified job.
    """
    job = job_manager.get_job(jobId)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Erasure job '{jobId}' not found."
        )
    return job.to_envelope()
