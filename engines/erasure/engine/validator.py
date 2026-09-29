"""
SIH26149 - Person 1 Safety Validator

Implements pre-operation validation, dangerous path rejection, OS root protection,
permission verification, and target consistency checks.
"""

import os
import sys
import string
from typing import List, Tuple, Optional
from models.contracts import TargetType


# Disallowed system critical root directories and paths
FORBIDDEN_EXACT_PATHS = {
    "/", "\\", "c:\\", "c:/", "c:",
    r"c:\users", r"c:\users\\", r"c:/users",
}

FORBIDDEN_PREFIXES_WINDOWS = [
    os.environ.get("SystemRoot", r"C:\Windows").lower(),
    os.environ.get("ProgramFiles", r"C:\Program Files").lower(),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower(),
    r"c:\programdata",
    r"c:\system volume information",
    os.environ.get("SystemDrive", "C:").lower() + r"\boot",
    os.environ.get("SystemDrive", "C:").lower() + r"\recovery",
    os.environ.get("SystemDrive", "C:").lower() + r"\pagefile.sys",
    os.environ.get("SystemDrive", "C:").lower() + r"\swapfile.sys",
    os.environ.get("SystemDrive", "C:").lower() + r"\hiberfil.sys",
]

FORBIDDEN_PREFIXES_POSIX = [
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
    "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"
]


class SafetyValidationError(Exception):
    """Raised when safety validation fails."""
    pass


def normalize_path(path: str) -> str:
    """Returns clean, absolute, normalized filesystem path."""
    if not path or not isinstance(path, str) or not path.strip():
        raise SafetyValidationError("Target path cannot be empty.")
    try:
        norm = os.path.abspath(os.path.normpath(path.strip()))
        return norm
    except Exception as e:
        raise SafetyValidationError(f"Invalid path format '{path}': {str(e)}")


def is_system_root_or_drive(normalized_path: str) -> bool:
    """Checks if path is a drive root (e.g., C:\\, D:\\, /)."""
    drive, tail = os.path.splitdrive(normalized_path)
    if drive and tail in ("\\", "/", ""):
        return True
    if normalized_path.lower() in FORBIDDEN_EXACT_PATHS:
        return True
    return False


def validate_single_target(
    path: str,
    expected_type: TargetType,
    allow_removable_drive: bool = False
) -> str:
    """
    Validates a single target path against safety rules and filesystem existence.
    Returns normalized path if valid; raises SafetyValidationError if invalid.
    """
    norm_path = normalize_path(path)
    norm_lower = norm_path.lower()

    # 1. Reject OS Root / Drive Roots unless explicit removable drive allowed (and not SystemDrive)
    sys_drive = os.environ.get("SystemDrive", "C:").lower()
    drive, _ = os.path.splitdrive(norm_lower)

    if is_system_root_or_drive(norm_path):
        if drive.startswith(sys_drive):
            raise SafetyValidationError(
                f"Dangerous operation rejected: Cannot target the operating system drive root '{norm_path}'."
            )
        if not allow_removable_drive:
            raise SafetyValidationError(
                f"Dangerous operation rejected: Targeting drive root '{norm_path}' requires 'allowRemovableDrive=true'."
            )

    # 2. Check exact forbidden directories (like C:\Users directly)
    if norm_lower in FORBIDDEN_EXACT_PATHS or norm_lower.rstrip("\\/") in (r"c:\users", "c:/users"):
        raise SafetyValidationError(f"Dangerous operation rejected: Cannot target root Users directory '{norm_path}'.")

    # 3. Check existence first
    if not os.path.exists(norm_path):
        raise SafetyValidationError(f"Target path does not exist: '{norm_path}'")

    # 4. Reject OS and System-critical directories
    if sys.platform.startswith("win"):
        for forbidden in FORBIDDEN_PREFIXES_WINDOWS:
            # Check exact match or subpath
            if norm_lower == forbidden or norm_lower.startswith(forbidden + "\\") or norm_lower.startswith(forbidden + "/"):
                raise SafetyValidationError(
                    f"Dangerous operation rejected: Target '{norm_path}' is inside a protected OS / System folder."
                )
    else:
        for forbidden in FORBIDDEN_PREFIXES_POSIX:
            if norm_lower == forbidden or norm_lower.startswith(forbidden + "/"):
                raise SafetyValidationError(
                    f"Dangerous operation rejected: Target '{norm_path}' is a protected system directory."
                )

    # 5. Check target type consistency
    if expected_type == TargetType.FILE:
        if not os.path.isfile(norm_path):
            raise SafetyValidationError(f"Expected a regular file, but found a directory/device: '{norm_path}'")
    elif expected_type == TargetType.FOLDER:
        if not os.path.isdir(norm_path):
            raise SafetyValidationError(f"Expected a directory/folder, but found a file: '{norm_path}'")
    
    # 6. Permission / Access check
    if not os.access(norm_path, os.W_OK):
        raise SafetyValidationError(f"Permission denied: Target '{norm_path}' is not writable or access is restricted.")

    return norm_path


def validate_erasure_targets(
    target_type: TargetType,
    target_path: Optional[str] = None,
    target_paths: Optional[List[str]] = None,
    allow_removable_drive: bool = False
) -> List[str]:
    """
    Validates all targets for single, folder, or batch operations.
    Returns list of normalized, validated paths.
    """
    validated: List[str] = []

    if target_type in (TargetType.FILE, TargetType.FOLDER, TargetType.DEVICE):
        if not target_path:
            raise SafetyValidationError(f"Target path ('targetPath') is required for targetType '{target_type.value}'.")
        validated_path = validate_single_target(
            target_path,
            target_type,
            allow_removable_drive=allow_removable_drive
        )
        validated.append(validated_path)

    elif target_type == TargetType.BATCH:
        if not target_paths or len(target_paths) == 0:
            raise SafetyValidationError("Batch erasure requires a non-empty list of paths ('targetPaths').")
        for p in target_paths:
            norm = normalize_path(p)
            if not os.path.exists(norm):
                raise SafetyValidationError(f"Batch item does not exist: '{norm}'")
            item_type = TargetType.FOLDER if os.path.isdir(norm) else TargetType.FILE
            v_path = validate_single_target(
                p,
                item_type,
                allow_removable_drive=allow_removable_drive
            )
            validated.append(v_path)

    else:
        raise SafetyValidationError(f"Unsupported target type: '{target_type}'")

    return validated
