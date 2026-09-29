"""
SIH26149 - Person 1 Secure Erasure Core Engine

Executes file, folder, and batch sanitization with multi-pass overwrites,
cancellation checks, progress tracking, and verification evidence generation.
"""

import os
import shutil
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable

from models.contracts import ErasureMethod, TargetType
from api.schemas import ErasureResultPayload, TargetItemResult
from engine.overwrite_methods import overwrite_file, STRATEGIES
from engine.verifier import ErasureVerifier


class SecureErasureEngine:
    """
    Core execution engine for file, folder, batch, and device-level secure erasure.
    """

    @classmethod
    def erase_file(
        cls,
        file_path: str,
        method: ErasureMethod,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> TargetItemResult:
        """
        Safely erases a single file via multi-pass overwrite, truncation, and unlinking.
        """
        if not os.path.isfile(file_path):
            return TargetItemResult(
                path=file_path,
                targetType="FILE",
                originalSize=0,
                passesCompleted=0,
                erasureVerified=False,
                status="FAILED",
                error=f"File not found: {file_path}"
            )

        orig_size = os.path.getsize(file_path)
        try:
            bytes_written, passes = overwrite_file(
                file_path=file_path,
                method=method,
                cancel_check=cancel_check
            )
            v_check = ErasureVerifier.verify_target_removal(file_path)
            return TargetItemResult(
                path=file_path,
                targetType="FILE",
                originalSize=orig_size,
                passesCompleted=passes,
                erasureVerified=v_check["erasureVerified"],
                status="SUCCESS" if v_check["erasureVerified"] else "FAILED",
                error=None
            )
        except InterruptedError as ie:
            return TargetItemResult(
                path=file_path,
                targetType="FILE",
                originalSize=orig_size,
                passesCompleted=0,
                erasureVerified=False,
                status="CANCELLED",
                error=str(ie)
            )
        except Exception as e:
            return TargetItemResult(
                path=file_path,
                targetType="FILE",
                originalSize=orig_size,
                passesCompleted=0,
                erasureVerified=False,
                status="FAILED",
                error=str(e)
            )

    @classmethod
    def erase_folder(
        cls,
        folder_path: str,
        method: ErasureMethod,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> List[TargetItemResult]:
        """
        Recursively processes and erases all files inside a folder,
        then unlinks directory structures from bottom up.
        """
        results: List[TargetItemResult] = []
        if not os.path.isdir(folder_path):
            results.append(TargetItemResult(
                path=folder_path,
                targetType="FOLDER",
                originalSize=0,
                passesCompleted=0,
                erasureVerified=False,
                status="FAILED",
                error=f"Directory not found: {folder_path}"
            ))
            return results

        # 1. Collect all files and subdirectories
        all_files = []
        all_dirs = []

        for root, dirs, files in os.walk(folder_path, topdown=False):
            for name in files:
                all_files.append(os.path.join(root, name))
            for name in dirs:
                all_dirs.append(os.path.join(root, name))

        # 2. Erase all files individually
        for f_path in all_files:
            if cancel_check and cancel_check():
                raise InterruptedError("Erasure cancelled during folder processing.")
            item_res = cls.erase_file(f_path, method, cancel_check)
            results.append(item_res)

        # 3. Remove subdirectories and root folder
        for d_path in all_dirs:
            try:
                if os.path.exists(d_path):
                    os.rmdir(d_path)
            except Exception as ex:
                pass

        try:
            if os.path.exists(folder_path):
                os.rmdir(folder_path)
            folder_v = ErasureVerifier.verify_target_removal(folder_path)
            results.append(TargetItemResult(
                path=folder_path,
                targetType="FOLDER",
                originalSize=0,
                passesCompleted=1,
                erasureVerified=folder_v["erasureVerified"],
                status="SUCCESS" if folder_v["erasureVerified"] else "FAILED",
                error=None
            ))
        except Exception as e:
            results.append(TargetItemResult(
                path=folder_path,
                targetType="FOLDER",
                originalSize=0,
                passesCompleted=0,
                erasureVerified=False,
                status="FAILED",
                error=f"Failed to remove folder root: {str(e)}"
            ))

        return results

    @classmethod
    def execute_job(
        cls,
        target_type: TargetType,
        validated_paths: List[str],
        method: ErasureMethod,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> ErasureResultPayload:
        """
        Executes complete erasure across all validated paths and returns structured payload.
        """
        start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()
        target_items: List[TargetItemResult] = []
        warnings: List[str] = []
        errors: List[str] = []

        strategy = STRATEGIES.get(method, STRATEGIES[ErasureMethod.SECURE_OVERWRITE])
        passes_executed = strategy.pass_count

        total_bytes = 0

        for path in validated_paths:
            if cancel_check and cancel_check():
                raise InterruptedError("Job cancelled before processing next target.")

            if os.path.isfile(path):
                res = cls.erase_file(path, method, cancel_check)
                target_items.append(res)
                if res.status == "SUCCESS":
                    total_bytes += res.originalSize
                else:
                    if res.error:
                        errors.append(f"Target '{path}' failed: {res.error}")
            elif os.path.isdir(path):
                f_results = cls.erase_folder(path, method, cancel_check)
                target_items.extend(f_results)
                for r in f_results:
                    if r.status == "SUCCESS":
                        total_bytes += r.originalSize
                    else:
                        if r.error:
                            errors.append(f"Folder item '{r.path}' failed: {r.error}")

        # Verification step
        v_summary = ErasureVerifier.verify_job_results(target_items)

        files_succeeded = sum(1 for i in target_items if i.status == "SUCCESS")
        files_failed = sum(1 for i in target_items if i.status in ("FAILED", "CANCELLED"))
        duration = round(time.time() - start_time, 4)
        completed_at = datetime.now(timezone.utc).isoformat()

        all_ok = (files_failed == 0) and v_summary.erasureVerified

        message = (
            f"Secure erasure completed successfully ({strategy.name})."
            if all_ok else
            f"Secure erasure finished with {files_failed} issues."
        )

        return ErasureResultPayload(
            operation="SECURE_ERASURE",
            targetPath=validated_paths[0] if len(validated_paths) == 1 else None,
            targetPaths=validated_paths if len(validated_paths) > 1 else None,
            targetType=target_type,
            method=method,
            erasureVerified=v_summary.erasureVerified,
            message=message,
            startedAt=started_at,
            completedAt=completed_at,
            durationSeconds=duration,
            totalTargets=len(validated_paths),
            filesProcessed=len(target_items),
            filesSucceeded=files_succeeded,
            filesFailed=files_failed,
            totalBytesErased=total_bytes,
            passesExecuted=passes_executed,
            targetDetails=target_items,
            verificationDetails=v_summary,
            warnings=warnings,
            errors=errors
        )
