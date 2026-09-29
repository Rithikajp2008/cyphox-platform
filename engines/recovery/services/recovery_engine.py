"""
SIH26149 - Person 2: Advanced Recovery Engine
Orchestrates path validation, filesystem discovery, safe read-oriented file extraction,
magic-byte signature carving, SHA-256 integrity calculation, and structured result compilation.
"""

import shutil
import time
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, List, Dict, Any, Tuple

from ..models.recovery_models import (
    RecoveryRequest,
    RecoveryResultSummary,
    RecoveredFileItem,
    JobStatusEnum,
    ErrorDetails,
    RecoveryResponseEnvelope
)
from .file_scanner import FileScanner
from .file_carver import FileCarver
from .hash_service import HashService


class RecoveryEngine:
    """
    Main Recovery Execution Engine for Person 2.
    """

    def __init__(self):
        mimetypes.init()

    def execute_recovery(
        self,
        request: RecoveryRequest,
        is_cancelled_check: Optional[Callable[[], bool]] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Tuple[JobStatusEnum, Optional[RecoveryResultSummary], Optional[ErrorDetails]]:
        """
        Executes complete recovery operation synchronously.
        """

        started_at = datetime.now(timezone.utc).isoformat()
        start_time_perf = time.time()

        # Step 1: Validate paths
        is_valid, err_msg, source_path, dest_path = FileScanner.validate_paths(
            request.sourcePath,
            request.destinationPath
        )

        if not is_valid or source_path is None or dest_path is None:
            return (
                JobStatusEnum.FAILED,
                None,
                ErrorDetails(
                    code="INVALID_PATHS",
                    message=err_msg or "Path validation failed.",
                    details={
                        "source": request.sourcePath,
                        "destination": request.destinationPath
                    }
                )
            )

        recovered_items: List[RecoveredFileItem] = []
        errors_list: List[str] = []
        files_scanned = 0
        files_found = 0
        files_recovered = 0
        files_failed = 0
        carved_count = 0

        # Create structured subdirectories in destination
        regular_output_dir = dest_path / "recovered_files"
        carved_output_dir = dest_path / "carved_items"

        regular_output_dir.mkdir(parents=True, exist_ok=True)
        carved_output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Step 2: Scan source for candidate files
            candidates = FileScanner.scan_directory(
                source_path=source_path,
                recursive=request.options.recursive,
                target_extensions=request.options.targetExtensions,
                recover_deleted_traces=request.options.recoverDeleted
            )

            files_found = len(candidates)
            total_candidates = len(candidates)

            # Step 3: Extract / Recover scanned files
            for idx, item in enumerate(candidates):

                if is_cancelled_check and is_cancelled_check():
                    return (
                        JobStatusEnum.CANCELLED,
                        self._build_summary(
                            files_scanned,
                            files_found,
                            files_recovered,
                            files_failed,
                            carved_count,
                            str(dest_path),
                            started_at,
                            start_time_perf,
                            recovered_items,
                            errors_list
                        ),
                        None
                    )

                files_scanned += 1
                src_file = item["path"]

                try:
                    # Determine destination subpath
                    # Preserve relative folder structure where possible
                    try:
                        rel_path = src_file.relative_to(source_path)
                        target_file_path = regular_output_dir / rel_path
                    except ValueError:
                        target_file_path = regular_output_dir / src_file.name

                    target_file_path.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    # Raw disk images are recovery sources,
                    # not files to copy directly.
                    if item.get("is_image"):
                        if progress_callback:
                            progress_callback(
                                idx + 1,
                                total_candidates,
                                f"Queued raw image for carving: {src_file.name}"
                            )
                        continue

                    # Safe read-oriented copy for normal files
                    shutil.copy2(
                        src_file,
                        target_file_path
                    )

                    # Compute SHA-256 for recovered file
                    sha256 = HashService.compute_sha256_file(
                        target_file_path
                    )

                    # Compute entropy on file header / sample
                    with open(target_file_path, "rb") as f:
                        header_sample = f.read(65536)
                        entropy = FileCarver.calculate_entropy(
                            header_sample
                        )

                    mime_type, _ = mimetypes.guess_type(
                        str(target_file_path)
                    )

                    mime_type = (
                        mime_type
                        or "application/octet-stream"
                    )

                    recoverability_rating = (
                        "High"
                        if entropy > 2.0
                        else "Medium"
                    )

                    if item.get("is_deleted_trace"):
                        recoverability_rating = (
                            "High (Deleted Trace Recovered)"
                        )

                    recovered_items.append(
                        RecoveredFileItem(
                            fileName=target_file_path.name,
                            originalPath=str(src_file),
                            recoveredPath=str(
                                target_file_path.resolve()
                            ),
                            fileType=mime_type,
                            fileSize=item["size"],
                            sha256=sha256,
                            status="RECOVERED",
                            entropy=entropy,
                            recoverability=recoverability_rating,
                            carved=False
                        )
                    )

                    files_recovered += 1

                except Exception as file_err:
                    files_failed += 1

                    errors_list.append(
                        f"Failed to recover "
                        f"{src_file.name}: {str(file_err)}"
                    )

                if progress_callback:
                    progress_callback(
                        idx + 1,
                        total_candidates,
                        f"Extracted {src_file.name}"
                    )

            # Step 4: Perform Signature-Based File Carving if enabled
            if request.options.fileCarving:

                # Find binary files, images, or disk dumps
                # in candidates for deep carving.
                carve_sources = [
                    c["path"]
                    for c in candidates
                    if c.get("is_image") or c["size"] > 0
                ]

                if not carve_sources and source_path.is_file():
                    carve_sources = [source_path]

                for c_src in carve_sources:

                    if is_cancelled_check and is_cancelled_check():
                        break

                    carved_results = (
                        FileCarver.carve_file_to_destination(
                            source_file=c_src,
                            destination_dir=carved_output_dir,
                            target_extensions=request.options.targetExtensions,
                            max_carve_size_mb=request.options.maxCarveSizeMb
                        )
                    )

                    for c_item in carved_results:
                        recovered_items.append(c_item)

                        carved_count += 1
                        files_recovered += 1
                        files_found += 1

            # Build final successful summary
            summary = self._build_summary(
                files_scanned,
                files_found,
                files_recovered,
                files_failed,
                carved_count,
                str(dest_path),
                started_at,
                start_time_perf,
                recovered_items,
                errors_list
            )

            return JobStatusEnum.SUCCESS, summary, None

        except Exception as e:
            return (
                JobStatusEnum.FAILED,
                None,
                ErrorDetails(
                    code="RECOVERY_EXECUTION_ERROR",
                    message=(
                        "An error occurred during recovery execution: "
                        f"{str(e)}"
                    ),
                    details={
                        "exception": str(e)
                    }
                )
            )

    def _build_summary(
        self,
        files_scanned: int,
        files_found: int,
        files_recovered: int,
        files_failed: int,
        carved_count: int,
        output_path: str,
        started_at: str,
        start_time_perf: float,
        recovered_files: List[RecoveredFileItem],
        errors: List[str]
    ) -> RecoveryResultSummary:

        completed_at = datetime.now(timezone.utc).isoformat()

        duration = round(
            time.time() - start_time_perf,
            3
        )

        return RecoveryResultSummary(
            filesScanned=files_scanned,
            filesFound=files_found,
            filesRecovered=files_recovered,
            filesFailed=files_failed,
            carvedFilesCount=carved_count,
            outputPath=output_path,
            startedAt=started_at,
            completedAt=completed_at,
            durationSeconds=duration,
            recoveredFiles=recovered_files,
            errors=errors
        )

    # ---------------------------------------------------------
    # Targeted Deleted Files Vault & Recovery (Options 1 & 2)
    # ---------------------------------------------------------
    _deleted_vault: List[Dict[str, Any]] = []

    @classmethod
    def delete_file_and_record(
        cls,
        file_path: Optional[str] = None,
        file_name: Optional[str] = None,
        content: Optional[str] = None,
        user_id: str = "USER-001"
    ) -> Dict[str, Any]:
        """
        Deletes a file, archives its bytes in the recovery vault, and records full forensic metadata.
        """
        import uuid
        import hashlib

        vault_dir = Path("data/deleted_vault")
        vault_dir.mkdir(parents=True, exist_ok=True)

        file_bytes: bytes = b""
        actual_name = file_name or ""
        orig_path = file_path or ""

        if file_path and Path(file_path).exists():
            p = Path(file_path)
            if p.is_dir():
                raise ValueError("Target is a directory. Specify a file path.")
            file_bytes = p.read_bytes()
            actual_name = actual_name or p.name
            orig_path = str(p.resolve())
            try:
                p.unlink()
            except Exception:
                pass
        elif content is not None:
            actual_name = actual_name or f"deleted_test_{int(time.time())}.txt"
            file_bytes = content.encode("utf-8")
            orig_path = orig_path or str(Path("data/storage") / actual_name)
        else:
            raise ValueError("No valid file path or content provided for deletion.")

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        entropy = FileCarver.calculate_entropy(file_bytes)
        file_id = f"del_{int(time.time())}_{uuid.uuid4().hex[:6]}"

        safe_vault_name = f"{file_id}_{Path(actual_name).name}"
        vault_path = vault_dir / safe_vault_name
        vault_path.write_bytes(file_bytes)

        record = {
            "id": file_id,
            "name": actual_name,
            "originalPath": orig_path,
            "vaultPath": str(vault_path.resolve()),
            "size": len(file_bytes),
            "sizeFormatted": f"{len(file_bytes)} Bytes" if len(file_bytes) < 1024 else f"{round(len(file_bytes)/1024, 2)} KB",
            "mime": mimetypes.guess_type(actual_name)[0] or "application/octet-stream",
            "category": "Documents" if actual_name.endswith((".txt", ".pdf", ".docx", ".json")) else "Media",
            "sha256": sha256,
            "entropy": entropy,
            "recoverability": "High",
            "status": "DELETED",
            "userId": user_id,
            "deletedAt": datetime.now(timezone.utc).isoformat(),
            "recoveredAt": None,
            "recoveredPath": None
        }

        cls._deleted_vault.insert(0, record)
        return record

    @classmethod
    def get_deleted_files(cls, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all recorded deleted files, newest first."""
        if user_id and user_id != "all":
            return [f for f in cls._deleted_vault if f.get("userId") == user_id or f.get("userId") == "guest"]
        return cls._deleted_vault

    @classmethod
    def recover_last_deleted(
        cls,
        user_id: str = "USER-001",
        destination_dir: str = "data/recovered"
    ) -> Dict[str, Any]:
        """Option 2: Recovers the single most recently deleted file."""
        files = cls.get_deleted_files(user_id)
        active_deleted = next((f for f in files if f["status"] == "DELETED"), None) or (files[0] if files else None)

        if not active_deleted:
            return {
                "success": False,
                "message": "No deleted files found in system records to recover.",
                "file": None
            }

        dest_dir = Path(destination_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        vault_p = Path(active_deleted["vaultPath"])
        if not vault_p.exists():
            return {
                "success": False,
                "message": f"Vault archive missing for {active_deleted['name']}",
                "file": active_deleted
            }

        file_bytes = vault_p.read_bytes()
        target_file = dest_dir / f"{int(time.time())}_{active_deleted['name']}"
        target_file.write_bytes(file_bytes)

        import hashlib
        restored_hash = hashlib.sha256(file_bytes).hexdigest()

        active_deleted["status"] = "RECOVERED"
        active_deleted["recoveredAt"] = datetime.now(timezone.utc).isoformat()
        active_deleted["recoveredPath"] = str(target_file.resolve())

        return {
            "success": True,
            "message": f"Successfully recovered the last deleted file '{active_deleted['name']}'.",
            "destinationDirectory": str(dest_dir.resolve()),
            "file": {
                "fileId": active_deleted["id"],
                "name": active_deleted["name"],
                "originalPath": active_deleted["originalPath"],
                "restoredPath": str(target_file.resolve()),
                "size": len(file_bytes),
                "sizeFormatted": active_deleted["sizeFormatted"],
                "sha256": restored_hash,
                "hashMatched": (restored_hash == active_deleted["sha256"]),
                "recoveredAt": active_deleted["recoveredAt"]
            }
        }

    @classmethod
    def recover_all_deleted(
        cls,
        user_id: str = "USER-001",
        destination_dir: str = "data/recovered"
    ) -> Dict[str, Any]:
        """Option 1: Recovers ALL deleted files recorded so far."""
        files = cls.get_deleted_files(user_id)
        if not files:
            return {
                "success": False,
                "message": "No deleted files recorded so far to recover.",
                "restoredCount": 0,
                "restoredFiles": []
            }

        dest_dir = Path(destination_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        restored_list = []
        import hashlib

        for f in files:
            vault_p = Path(f["vaultPath"])
            if vault_p.exists():
                file_bytes = vault_p.read_bytes()
                target_file = dest_dir / f"{int(time.time())}_{f['name']}"
                target_file.write_bytes(file_bytes)
                restored_hash = hashlib.sha256(file_bytes).hexdigest()

                f["status"] = "RECOVERED"
                f["recoveredAt"] = datetime.now(timezone.utc).isoformat()
                f["recoveredPath"] = str(target_file.resolve())

                restored_list.append({
                    "fileId": f["id"],
                    "name": f["name"],
                    "originalPath": f["originalPath"],
                    "restoredPath": str(target_file.resolve()),
                    "size": len(file_bytes),
                    "sizeFormatted": f["sizeFormatted"],
                    "sha256": restored_hash,
                    "hashMatched": (restored_hash == f["sha256"]),
                    "recoveredAt": f["recoveredAt"]
                })

        return {
            "success": True,
            "message": f"Successfully recovered all {len(restored_list)} deleted files.",
            "destinationDirectory": str(dest_dir.resolve()),
            "totalTracked": len(files),
            "restoredCount": len(restored_list),
            "restoredFiles": restored_list
        }