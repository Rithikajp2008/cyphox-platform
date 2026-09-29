from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from .models import JobStatus
from .storage import JsonStore
from .tamper_engine import create_baseline, new_id, verify_target_against_baseline


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class JobRecord:
    userId: str
    deviceId: str
    sessionId: str
    jobId: str
    status: JobStatus = JobStatus.PENDING
    operation: str = ""
    baselineId: str | None = None
    verificationId: str | None = None
    timestamp: str = field(default_factory=now)
    result: dict[str, Any] | None = None
    error: str | None = None

    def envelope(self):
        data = {
            "userId": self.userId,
            "deviceId": self.deviceId,
            "sessionId": self.sessionId,
            "jobId": self.jobId,
            "operation": self.operation,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "result": self.result,
            "error": self.error,
        }
        if self.baselineId: data["baselineId"] = self.baselineId
        if self.verificationId: data["verificationId"] = self.verificationId
        return data


class JobManager:
    def __init__(self, data_root: Path):
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cyphox-tamper")
        self.jobs: dict[str, JobRecord] = {}
        self.baselines = JsonStore(data_root / "baselines")
        self.verifications = JsonStore(data_root / "verifications")

    def get_job(self, job_id: str):
        with self.lock:
            return self.jobs.get(job_id)

    def _register(self, job: JobRecord):
        with self.lock:
            if job.jobId in self.jobs:
                raise ValueError(f"jobId already exists: {job.jobId}")
            self.jobs[job.jobId] = job
        return job

    def create_baseline_job(self, req):
        job_id = req.jobId or new_id("TAMPER-BASELINE-JOB")
        baseline_id = req.baselineId or new_id("BASELINE")
        if self.baselines.exists(baseline_id):
            raise ValueError(f"baselineId already exists: {baseline_id}")
        job = self._register(JobRecord(req.userId, req.deviceId, req.sessionId, job_id,
                                       operation="CREATE_TAMPER_BASELINE", baselineId=baseline_id))

        def run():
            job.status = JobStatus.RUNNING; job.timestamp = now()
            try:
                baseline = create_baseline(target_path=req.targetPath, user_id=req.userId, device_id=req.deviceId,
                                           session_id=req.sessionId, baseline_id=baseline_id, job_id=job_id,
                                           max_files=req.maxFiles, check_metadata=req.checkMetadata, notes=req.notes)
                path = self.baselines.save(baseline_id, baseline)
                job.result = {
                    "baselineId": baseline_id,
                    "target": baseline["target"],
                    "summary": baseline["summary"],
                    "baselineIntegritySha256": baseline["baselineIntegritySha256"],
                    "baselinePath": str(path),
                    "baseline": baseline,
                }
                job.status = JobStatus.SUCCESS
            except Exception as e:
                job.status = JobStatus.FAILED
                job.error = f"{type(e).__name__}: {e}"
            job.timestamp = now()
        self.executor.submit(run)
        return job

    def create_verification_job(self, req):
        job_id = req.jobId or new_id("TAMPER-VERIFY-JOB")
        verification_id = req.verificationId or new_id("VERIFY")
        if self.verifications.exists(verification_id):
            raise ValueError(f"verificationId already exists: {verification_id}")
        job = self._register(JobRecord(req.userId, req.deviceId, req.sessionId, job_id,
                                       operation="VERIFY_TAMPER", verificationId=verification_id,
                                       baselineId=req.baselineId))

        def run():
            job.status = JobStatus.RUNNING; job.timestamp = now()
            try:
                baseline = self.baselines.load(req.baselineId)
                result = verify_target_against_baseline(
                    baseline=baseline, target_path=req.targetPath, verification_id=verification_id,
                    job_id=job_id, user_id=req.userId, device_id=req.deviceId, session_id=req.sessionId,
                    max_files=req.maxFiles, check_metadata=req.checkMetadata,
                )
                path = self.verifications.save(verification_id, result)
                job.result = {**result, "verificationPath": str(path)}
                job.status = JobStatus.SUCCESS
            except Exception as e:
                job.status = JobStatus.FAILED
                job.error = f"{type(e).__name__}: {e}"
            job.timestamp = now()
        self.executor.submit(run)
        return job
