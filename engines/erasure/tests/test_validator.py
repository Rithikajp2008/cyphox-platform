"""
Unit tests for Safety Validator
"""

import os
import pytest
from models.contracts import TargetType
from engine.validator import (
    validate_single_target,
    validate_erasure_targets,
    SafetyValidationError,
    is_system_root_or_drive
)


def test_validate_valid_file(sample_file):
    """Test validating an existing regular file."""
    validated = validate_single_target(sample_file, TargetType.FILE)
    assert validated == os.path.abspath(sample_file)


def test_validate_nonexistent_file(temp_test_dir):
    """Test that non-existent paths raise SafetyValidationError."""
    missing = os.path.join(temp_test_dir, "nonexistent.dat")
    with pytest.raises(SafetyValidationError, match="does not exist"):
        validate_single_target(missing, TargetType.FILE)


def test_validate_type_mismatch_folder_as_file(sample_folder):
    """Test that a folder provided when expecting a FILE is rejected."""
    with pytest.raises(SafetyValidationError, match="Expected a regular file"):
        validate_single_target(sample_folder, TargetType.FILE)


def test_validate_type_mismatch_file_as_folder(sample_file):
    """Test that a file provided when expecting a FOLDER is rejected."""
    with pytest.raises(SafetyValidationError, match="Expected a directory"):
        validate_single_target(sample_file, TargetType.FOLDER)


def test_reject_system_root_drive():
    """Test that system drive root (e.g., C:\\) is rejected unconditionally."""
    assert is_system_root_or_drive("C:\\") is True
    assert is_system_root_or_drive("c:/") is True
    
    with pytest.raises(SafetyValidationError, match="operating system drive root"):
        validate_single_target("C:\\", TargetType.FOLDER, allow_removable_drive=True)


def test_reject_windows_system_directories():
    """Test that Windows system directories (Windows, Program Files) are rejected."""
    win_dir = os.environ.get("SystemRoot", r"C:\Windows")
    with pytest.raises(SafetyValidationError, match="protected OS / System folder"):
        validate_single_target(win_dir, TargetType.FOLDER)

    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    with pytest.raises(SafetyValidationError, match="protected OS / System folder"):
        validate_single_target(prog_files, TargetType.FOLDER)


def test_validate_batch_targets(temp_test_dir):
    """Test validating a batch list of files."""
    f1 = os.path.join(temp_test_dir, "batch1.txt")
    f2 = os.path.join(temp_test_dir, "batch2.txt")
    with open(f1, "w") as f: f.write("1")
    with open(f2, "w") as f: f.write("2")

    validated = validate_erasure_targets(
        target_type=TargetType.BATCH,
        target_paths=[f1, f2]
    )
    assert len(validated) == 2
    assert os.path.abspath(f1) in validated
    assert os.path.abspath(f2) in validated


def test_validate_batch_empty():
    """Test that an empty batch list is rejected."""
    with pytest.raises(SafetyValidationError, match="non-empty list"):
        validate_erasure_targets(target_type=TargetType.BATCH, target_paths=[])
