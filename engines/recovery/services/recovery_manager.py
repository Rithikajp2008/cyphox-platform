"""
SIH26149 - Person 2: Recovery Job Manager
Maintains thread-safe in-memory lifecycle state for all recovery jobs.
Transitions: PENDING -> RUNNING -> SUCCESS | FAILED | CANCELLED
"""
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..models.recovery_models import (
    RecoveryRequest,
    RecoveryResponseEnvelope,
    JobStatusEnum,
    ErrorDetails
)
from .recovery_engine import RecoveryEngine


class RecoveryManager:
    def __init__(self):
        self._jobs: Dict[str, RecoveryResponseEnvelope] = {}
        self._cancellation_flags: Dict[str, bool] = {}
        self._lock = threading.Lock()
        self._engine = RecoveryEngine()

    def create_and_start_job(self, request: RecoveryRequest) -> RecoveryResponseEnvelope:
        """
        Creates a new recovery job and launches execution asynchronously in a background thread.
        """
        job_id = request.jobId or f"RECOVERY-{uuid.uuid4().hex[:8].upper()}"

        envelope = RecoveryResponseEnvelope(
            userId=request.userId,
            deviceId=request.deviceId,
            sessionId=request.sessionId,
            jobId=job_id,
            status=JobStatusEnum.PENDING,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result=None,
            error=None
        )

        with self._lock:
            self._jobs[job_id] = envelope
            self._cancellation_flags[job_id] = False

        # Launch worker thread
        thread = threading.Thread(
            target=self._run_job_worker,
            args=(job_id, request),
            daemon=True
        )
        thread.start()

        return envelope

    def _run_job_worker(self, job_id: str, request: RecoveryRequest):
        """
        Worker thread function executing recovery.
        """
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatusEnum.RUNNING
                self._jobs[job_id].timestamp = datetime.now(timezone.utc).isoformat()

        def is_cancelled() -> bool:
            with self._lock:
                return self._cancellation_flags.get(job_id, False)

        # Execute recovery engine
        status, result, error = self._engine.execute_recovery(
            request=request,
            is_cancelled_check=is_cancelled
        )

        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = status
                self._jobs[job_id].timestamp = datetime.now(timezone.utc).isoformat()
                self._jobs[job_id].result = result
                self._jobs[job_id].error = error

    def get_job(self, job_id: str) -> Optional[RecoveryResponseEnvelope]:
        """
        Retrieves job status and result by jobId.
        """
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> List[RecoveryResponseEnvelope]:
        """
        Lists all managed recovery jobs.
        """
        with self._lock:
            return list(self._jobs.values())

    def cancel_job(self, job_id: str) -> Tuple[bool, Optional[RecoveryResponseEnvelope], Optional[str]]:
        """
        Cancels an active or pending job.
        """
        with self._lock:
            if job_id not in self._jobs:
                return False, None, f"Job {job_id} not found."

            job = self._jobs[job_id]
            if job.status in [JobStatusEnum.SUCCESS, JobStatusEnum.FAILED, JobStatusEnum.CANCELLED]:
                return False, job, f"Job {job_id} has already finished with status {job.status}."

            self._cancellation_flags[job_id] = True
            job.status = JobStatusEnum.CANCELLED
            job.timestamp = datetime.now(timezone.utc).isoformat()
            job.error = ErrorDetails(
                code="JOB_CANCELLED_BY_USER",
                message="Recovery job execution was cancelled by user request."
            )
            return True, job, None


# Global singleton instance
recovery_manager = RecoveryManager()

