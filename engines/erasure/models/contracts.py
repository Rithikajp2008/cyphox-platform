"""
SIH26149 - Person 1 Models & Common Contract Definitions
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """
    Common team status contract.
    Allowed: PENDING, RUNNING, SUCCESS, FAILED, CANCELLED
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TargetType(str, Enum):
    """Supported erasure target types."""
    FILE = "FILE"
    FOLDER = "FOLDER"
    BATCH = "BATCH"
    DEVICE = "DEVICE"


class ErasureMethod(str, Enum):
    """
    Supported sanitization / overwrite techniques.
    """
    SECURE_OVERWRITE = "SECURE_OVERWRITE"  # 1-pass random + zero overwrite
    ZERO_OVERWRITE = "ZERO_OVERWRITE"      # 1-pass binary zero (0x00)
    RANDOM_OVERWRITE = "RANDOM_OVERWRITE"  # 1-pass cryptographically secure pseudo-random bytes
    DOD_5220_22_M = "DOD_5220_22_M"        # 3-pass: zeros (0x00), ones (0xFF), pseudo-random + verify
    NIST_800_88_CLEAR = "NIST_800_88_CLEAR"# 1-pass overwrite with fixed/random pattern + zero
    NIST_800_88_PURGE = "NIST_800_88_PURGE"# 3-pass multi-pattern overwrite + cryptographic verify
    GUTMANN_LIGHT = "GUTMANN_LIGHT"        # 7-pass structured pattern overwrite
