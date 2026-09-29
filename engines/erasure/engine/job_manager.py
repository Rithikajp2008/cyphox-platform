"""
SIH26149 - Person 1 Job Manager

Manages asynchronous job lifecycle (PENDING -> RUNNING -> SUCCESS/FAILED/CANCELLED),
thread-safe state storage, cancellation flags, and result retrieval.
"""

import uuid
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any

from models.contracts import JobStatus, TargetType, ErasureMethod
from api.schemas import EraseRequest, CommonResponseEnvelope, ErasureResultPayload
from engine.validator import validate_erasure_targets, SafetyValidationError
from engine.erasure_engine import SecureErasureEngine


class JobRecord:
    """Internal state record for an individual erasure job."""
    def __init__(
        self,
        job_id: str,
        user_id: str,
        device_id: str,
        session_id: str,
        target_type: TargetType,
        method: ErasureMethod,
        target_path: Optional[str] = None,
        target_paths: Optional[List[str]] = None,
        verification_id: Optional[str] = None,
        certificate_id: Optional[str] = None
    ):
        self.jobId = job_id
        self.userId = user_id
        self.deviceId = device_id
        self.sessionId = session_id
        self.targetType = target_type
        self.method = method
        self.targetPath = target_path
        self.targetPaths = target_paths
        self.verificationId = verification_id
        self.certificateId = certificate_id

        self.status = JobStatus.PENDING
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.result: Optional[ErasureResultPayload] = None
        self.error: Optional[str] = None
        
        self.cancel_requested = False
        self._lock = threading.Lock()

    def to_envelope(self) -> CommonResponseEnvelope:
        """Converts internal record to the standard SIH26149 response envelope."""
        with self._lock:
            res_dict = self.result.model_dump() if self.result else None
            return CommonResponseEnvelope(
                userId=self.userId,
                deviceId=self.deviceId,
                sessionId=self.sessionId,
                jobId=self.jobId,
                status=self.status,
                timestamp=self.timestamp,
                result=res_dict,
                error=self.error,
                verificationId=self.verificationId,
                certificateId=self.certificateId
            )


class JobManager:
    """
    Thread-safe manager for job registration, background execution, and lifecycle queries.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(JobManager, cls).__new__(cls)
                cls._instance._jobs: Dict[str, JobRecord] = {}
                cls._instance._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
            return cls._instance

    def create_job(self, req: EraseRequest) -> JobRecord:
        """
        Registers and initializes a new erasure job.
        Generates unique jobId if omitted.
        """
        job_id = req.jobId if req.jobId and req.jobId.strip() else f"ERASE-{uuid.uuid4().hex[:10].upper()}"
        
        job = JobRecord(
            job_id=job_id,
            user_id=req.userId,
            device_id=req.deviceId,
            session_id=req.sessionId,
            target_type=req.targetType,
            method=req.method,
            target_path=req.targetPath,
            target_paths=req.targetPaths,
            verification_id=req.verificationId,
            certificate_id=req.certificateId
        )
        
        self._jobs[job_id] = job
        return job

    def start_job(self, job_id: str, allow_removable_drive: bool = False, synchronous: bool = False):
        """
        Starts job execution in background thread pool (or synchronously for testing).
        """
        job = self.get_job(job_id)
        if not job:
            raise KeyError(f"Job ID '{job_id}' not found.")

        if synchronous:
            self._run_job(job, allow_removable_drive)
        else:
            self._executor.submit(self._run_job, job, allow_removable_drive)

    def _run_job(self, job: JobRecord, allow_removable_drive: bool):
        """Worker thread executing validation and erasure."""
        with job._lock:
            job.status = JobStatus.RUNNING
            job.timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # 1. Pre-operation Safety Validation
            validated_paths = validate_erasure_targets(
                target_type=job.targetType,
                target_path=job.targetPath,
                target_paths=job.targetPaths,
                allow_removable_drive=allow_removable_drive
            )

            # 2. Check for early cancellation
            if job.cancel_requested:
                with job._lock:
                    job.status = JobStatus.CANCELLED
                    job.timestamp = datetime.now(timezone.utc).isoformat()
                    job.error = "Operation was cancelled before starting."
                return

            # 3. Execute Erasure Engine
            result = SecureErasureEngine.execute_job(
                target_type=job.targetType,
                validated_paths=validated_paths,
                method=job.method,
                cancel_check=lambda: job.cancel_requested
            )

            with job._lock:
                job.result = result
                job.timestamp = datetime.now(timezone.utc).isoformat()
                if job.cancel_requested:
                    job.status = JobStatus.CANCELLED
                    job.error = "Job cancelled during processing."
                elif result.filesFailed > 0 or not result.erasureVerified:
                    job.status = JobStatus.FAILED
                    job.error = "; ".join(result.errors) if result.errors else "Erasure verification failed."
                else:
                    job.status = JobStatus.SUCCESS
                    job.error = None

        except SafetyValidationError as sve:
            with job._lock:
                job.status = JobStatus.FAILED
                job.timestamp = datetime.now(timezone.utc).isoformat()
                job.error = f"Safety Validation Failed: {str(sve)}"
        except InterruptedError as ie:
            with job._lock:
                job.status = JobStatus.CANCELLED
                job.timestamp = datetime.now(timezone.utc).isoformat()
                job.error = str(ie)
        except Exception as ex:
            with job._lock:
                job.status = JobStatus.FAILED
                job.timestamp = datetime.now(timezone.utc).isoformat()
                job.error = f"Execution error: {str(ex)}"

    def cancel_job(self, job_id: str) -> bool:
        """Flags job for cancellation."""
        job = self.get_job(job_id)
        if not job:
            return False
        with job._lock:
            if job.status in (JobStatus.SUCCESS, JobStatus.FAILED, JobStatus.CANCELLED):
                return False
            job.cancel_requested = True
            if job.status == JobStatus.PENDING:
                job.status = JobStatus.CANCELLED
                job.error = "Cancelled while in PENDING state."
                job.timestamp = datetime.now(timezone.utc).isoformat()
            return True

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        """Fetches job record by ID."""
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[JobRecord]:
        """Returns all recorded jobs."""
        return list(self._jobs.values())


# Global singleton
job_manager = JobManager()
