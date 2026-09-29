"""
SIH26149 - Person 2: File Scanner Service
Performs safe, read-only scanning of target devices and directories.
Validates boundaries to ensure destination is completely separate from source.
"""
import os
import shutil
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional


class FileScanner:
    """
    Validates source/destination paths and enumerates candidate files for recovery.
    """

    @staticmethod
    def validate_paths(source_str: str, destination_str: str) -> Tuple[bool, Optional[str], Optional[Path], Optional[Path]]:
        """
        Ensures:
        1. Source path exists and is readable.
        2. Destination path is valid and creatable.
        3. Destination is NOT inside source and NOT identical to source (Strict safety requirement).
        """
        if not source_str or not source_str.strip():
            return False, "sourcePath cannot be empty.", None, None

        if not destination_str or not destination_str.strip():
            return False, "destinationPath cannot be empty.", None, None

        try:
            source_path = Path(source_str).resolve()
        except Exception as e:
            return False, f"Invalid sourcePath syntax: {str(e)}", None, None

        try:
            dest_path = Path(destination_str).resolve()
        except Exception as e:
            return False, f"Invalid destinationPath syntax: {str(e)}", None, None

        if not source_path.exists():
            return False, f"Source path does not exist: {source_path}", None, None

        if source_path == dest_path:
            return False, "Destination path cannot be identical to source path. Dedicated separate destination required.", None, None

        # Check if destination is inside source directory
        try:
            dest_path.relative_to(source_path)
            return False, "Destination directory cannot reside inside the source directory to prevent recursive recovery loops.", None, None
        except ValueError:
            # Good: destination is not inside source
            pass

        # Try to ensure destination path is creatable
        try:
            dest_path.mkdir(parents=True, exist_ok=True)
            # Test write access with a temporary marker
            test_file = dest_path / ".cyphox_write_test.tmp"
            test_file.touch()
            test_file.unlink()
        except Exception as e:
            return False, f"Destination path is not writable or cannot be created: {str(e)}", None, None

        return True, None, source_path, dest_path

    @staticmethod
    def scan_directory(
        source_path: Path,
        recursive: bool = True,
        target_extensions: Optional[List[str]] = None,
        recover_deleted_traces: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Traverses the source path in read-only mode and discovers all files and disk image containers.
        """
        candidates: List[Dict[str, Any]] = []
        ext_filter = [e.lower().lstrip(".") for e in target_extensions] if target_extensions else None

        if source_path.is_file():
            # Source is a single file or raw disk image (.img, .dd, .raw, .bin)
            try:
                stat = source_path.stat()
                ext = source_path.suffix.lower().lstrip(".")
                candidates.append({
                    "path": source_path,
                    "name": source_path.name,
                    "size": stat.st_size,
                    "ext": ext,
                    "is_image": ext in ["img", "dd", "raw", "bin", "iso", "vhd"],
                    "is_deleted_trace": False
                })
            except Exception:
                pass
            return candidates

        # Source is a directory
        walk_generator = os.walk(source_path) if recursive else [next(os.walk(source_path))]

        for root, dirs, files in walk_generator:
            current_root = Path(root)

            # Check for recycle bin or deleted file traces if permitted
            is_recycle_bin = "$recycle.bin" in str(current_root).lower()

            for file_name in files:
                try:
                    file_path = current_root / file_name
                    ext = file_path.suffix.lower().lstrip(".")

                    if ext_filter and ext not in ext_filter and not is_recycle_bin:
                        continue

                    # Read file metadata safely
                    stat = file_path.stat()
                    candidates.append({
                        "path": file_path,
                        "name": file_name,
                        "size": stat.st_size,
                        "ext": ext,
                        "is_image": ext in ["img", "dd", "raw", "bin", "iso", "vhd"],
                        "is_deleted_trace": is_recycle_bin or file_name.startswith("~") or file_name.endswith(".tmp")
                    })
                except (PermissionError, FileNotFoundError, OSError):
                    # Continue scanning remaining files on permission issues
                    continue

        return candidates
