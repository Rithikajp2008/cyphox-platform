from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from .engine import ForensicEngine
from .models import ForensicScanRequest, JobStatus
from .reporting import write_reports

UTC = timezone.utc

@dataclass
class ForensicJob:
    request: ForensicScanRequest
    jobId: str
    status: JobStatus = JobStatus.PENDING
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    result: dict[str, Any] | None = None
    error: str | None = None

    def envelope(self):
        return {
            "userId": self.request.userId, "deviceId": self.request.deviceId,
            "sessionId": self.request.sessionId, "jobId": self.jobId,
            "status": self.status.value, "timestamp": self.timestamp,
            "result": self.result, "error": self.error,
        }

class JobManager:
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.jobs: dict[str, ForensicJob] = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="forensics")

    def create(self, req: ForensicScanRequest) -> ForensicJob:
        jid = req.jobId or f"FORENSICS-{uuid4().hex[:10].upper()}"
        with self.lock:
            if jid in self.jobs: raise ValueError(f"jobId already exists: {jid}")
            job = ForensicJob(req, jid); self.jobs[jid] = job
        return job

    def get(self, jid: str) -> ForensicJob | None:
        with self.lock: return self.jobs.get(jid)

    def start(self, job: ForensicJob):
        self.pool.submit(self._run, job.jobId)

    def _run(self, jid: str):
        job = self.get(jid)
        if not job: return
        job.status = JobStatus.RUNNING; job.timestamp = datetime.now(UTC).isoformat()
        try:
            r = job.request
            eng = ForensicEngine(max_files=r.maxFiles, include_hashes=r.includeHashes, include_md5=r.includeMd5, include_sha1=r.includeSha1, keywords=r.keywords, user_id=r.userId, device_id=r.deviceId, session_id=r.sessionId, job_id=jid)
            report = eng.analyze(r.targetPath)
            paths = {}
            if r.saveReport:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                paths = write_reports(report, self.reports_dir / f"{jid}-{stamp}", r.reportFormats)
            job.result = {
                "operation": "DIGITAL_FORENSICS", "readOnly": True,
                "targetPath": report["target"]["path"], "targetType": report["target"]["kind"],
                "summary": report["summary"], "findings": report["findings"],
                "artifacts": report["artifacts"], "residualDataAnalysis": report["residual_data_analysis"],
                "reportIntegritySha256": report["report_integrity_sha256"], "reportPaths": paths,
                "report": report,
            }
            job.status = JobStatus.SUCCESS
        except Exception as e:
            job.error = f"{type(e).__name__}: {e}"; job.status = JobStatus.FAILED
        finally:
            job.timestamp = datetime.now(UTC).isoformat()
