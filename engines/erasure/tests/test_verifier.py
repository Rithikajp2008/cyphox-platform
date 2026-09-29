"""
Unit tests for Erasure Verifier
"""

import os
import pytest
from engine.verifier import ErasureVerifier
from api.schemas import TargetItemResult


def test_verify_non_existent_target(temp_test_dir):
    """Test verifying a target that has been deleted."""
    deleted_path = os.path.join(temp_test_dir, "ghost.txt")
    res = ErasureVerifier.verify_target_removal(deleted_path)
    assert res["exists"] is False
    assert res["accessible"] is False
    assert res["erasureVerified"] is True


def test_verify_existing_target(sample_file):
    """Test verifying a target that still exists (should fail verification)."""
    res = ErasureVerifier.verify_target_removal(sample_file)
    assert res["exists"] is True
    assert res["accessible"] is True
    assert res["erasureVerified"] is False


def test_verify_job_summary():
    """Test aggregating job results into a verification summary."""
    items = [
        TargetItemResult(path="C:\\nonexistent1.txt", erasureVerified=True, status="SUCCESS"),
        TargetItemResult(path="C:\\nonexistent2.txt", erasureVerified=True, status="SUCCESS"),
    ]
    summary = ErasureVerifier.verify_job_results(items)
    assert summary.erasureVerified is True
    assert summary.existenceCheckPassed is True
    assert summary.accessibilityCheckPassed is True
