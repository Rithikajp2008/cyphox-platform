"""
Unit tests for Secure Erasure Engine and Overwrite Methods
"""

import os
import pytest
from models.contracts import ErasureMethod, TargetType
from engine.overwrite_methods import overwrite_file, STRATEGIES
from engine.erasure_engine import SecureErasureEngine


@pytest.mark.parametrize("method", [
    ErasureMethod.ZERO_OVERWRITE,
    ErasureMethod.RANDOM_OVERWRITE,
    ErasureMethod.SECURE_OVERWRITE,
    ErasureMethod.DOD_5220_22_M,
    ErasureMethod.NIST_800_88_CLEAR,
    ErasureMethod.NIST_800_88_PURGE,
    ErasureMethod.GUTMANN_LIGHT
])
def test_all_overwrite_methods(temp_test_dir, method):
    """Tests each overwrite method on a temporary file."""
    fpath = os.path.join(temp_test_dir, f"test_sanitize_{method.value}.bin")
    with open(fpath, "wb") as f:
        f.write(b"SAMPLE DATA TO SANITIZE" * 50)
    
    orig_size = os.path.getsize(fpath)
    bytes_written, passes = overwrite_file(fpath, method=method)

    assert passes == STRATEGIES[method].pass_count
    assert bytes_written >= orig_size
    # Verify file was deleted/unlinked
    assert not os.path.exists(fpath)


def test_erase_file_engine(sample_file):
    """Test SecureErasureEngine.erase_file execution."""
    assert os.path.exists(sample_file)
    res = SecureErasureEngine.erase_file(sample_file, method=ErasureMethod.SECURE_OVERWRITE)
    assert res.status == "SUCCESS"
    assert res.erasureVerified is True
    assert not os.path.exists(sample_file)


def test_erase_folder_engine(sample_folder):
    """Test SecureErasureEngine.erase_folder recursive execution."""
    assert os.path.exists(sample_folder)
    results = SecureErasureEngine.erase_folder(sample_folder, method=ErasureMethod.ZERO_OVERWRITE)
    
    assert len(results) >= 6  # 3 files + 2 subfolder files + folder root
    assert all(r.status == "SUCCESS" for r in results)
    assert not os.path.exists(sample_folder)


def test_erase_batch_engine(temp_test_dir):
    """Test SecureErasureEngine.execute_job with batch targets."""
    f1 = os.path.join(temp_test_dir, "batch_file_1.txt")
    f2 = os.path.join(temp_test_dir, "batch_file_2.txt")
    with open(f1, "wb") as f: f.write(b"Batch 1 data")
    with open(f2, "wb") as f: f.write(b"Batch 2 data")

    result = SecureErasureEngine.execute_job(
        target_type=TargetType.BATCH,
        validated_paths=[f1, f2],
        method=ErasureMethod.DOD_5220_22_M
    )

    assert result.erasureVerified is True
    assert result.filesProcessed == 2
    assert result.filesSucceeded == 2
    assert result.filesFailed == 0
    assert not os.path.exists(f1)
    assert not os.path.exists(f2)


def test_cancellation_during_overwrite(sample_file):
    """Test cancellation check interrupts overwrite execution."""
    with pytest.raises(InterruptedError):
        overwrite_file(sample_file, method=ErasureMethod.DOD_5220_22_M, cancel_check=lambda: True)
