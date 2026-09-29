"""
SIH26149 - Person 1 Pytest Configuration & Test Fixtures
"""

import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture
def temp_test_dir():
    """Provides a safe isolated temporary directory for test file operations."""
    with tempfile.TemporaryDirectory(prefix="sih_erasure_test_") as tmp_dir:
        yield tmp_dir


@pytest.fixture
def sample_file(temp_test_dir):
    """Creates a sample file populated with identifiable test data."""
    fpath = os.path.join(temp_test_dir, "confidential_document.txt")
    with open(fpath, "wb") as f:
        f.write(b"TOP SECRET DIGITAL FORENSICS EVIDENCE DATA " * 100)
    return fpath


@pytest.fixture
def sample_folder(temp_test_dir):
    """Creates a nested directory tree with multiple files for folder erasure testing."""
    folder = os.path.join(temp_test_dir, "case_files")
    os.makedirs(os.path.join(folder, "subfolder1"), exist_ok=True)
    os.makedirs(os.path.join(folder, "subfolder2"), exist_ok=True)

    for i in range(3):
        with open(os.path.join(folder, f"file_{i}.dat"), "wb") as f:
            f.write(b"DATA CHUNK " * 50)

    with open(os.path.join(folder, "subfolder1", "nested1.log"), "wb") as f:
        f.write(b"NESTED LOG ENTRY " * 30)

    with open(os.path.join(folder, "subfolder2", "nested2.log"), "wb") as f:
        f.write(b"ANOTHER NESTED RECORD " * 30)

    return folder
