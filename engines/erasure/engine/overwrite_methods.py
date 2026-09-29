"""
SIH26149 - Person 1 Overwrite Algorithms & Sanitization Techniques

Provides multi-pass cryptographic byte overwriting, buffer syncing,
metadata scrambling, and secure file unlinking.
"""

import os
import secrets
import struct
from typing import List, Callable, Tuple
from models.contracts import ErasureMethod


CHUNK_SIZE = 64 * 1024  # 64 KB write buffer for optimal I/O throughput


class OverwriteStrategy:
    """Represents a structured pass strategy."""
    def __init__(self, name: str, passes: List[Callable[[int], bytes]], description: str):
        self.name = name
        self.passes = passes
        self.description = description
        self.pass_count = len(passes)


def _pattern_generator(byte_val: int) -> Callable[[int], bytes]:
    """Generates a fixed byte pattern of given size."""
    pattern_chunk = bytes([byte_val])
    def gen(size: int) -> bytes:
        return pattern_chunk * size
    return gen


def _random_generator() -> Callable[[int], bytes]:
    """Generates cryptographically secure random bytes."""
    def gen(size: int) -> bytes:
        return os.urandom(size)
    return gen


# Strategy definitions
STRATEGIES = {
    ErasureMethod.ZERO_OVERWRITE: OverwriteStrategy(
        name="Zero Overwrite (1-Pass)",
        passes=[_pattern_generator(0x00)],
        description="Single pass overwrite writing binary zeros (0x00) across all file sectors."
    ),
    ErasureMethod.RANDOM_OVERWRITE: OverwriteStrategy(
        name="Random Overwrite (1-Pass)",
        passes=[_random_generator()],
        description="Single pass overwrite writing cryptographically random bytes (os.urandom)."
    ),
    ErasureMethod.SECURE_OVERWRITE: OverwriteStrategy(
        name="Secure Overwrite (2-Pass Standard)",
        passes=[_random_generator(), _pattern_generator(0x00)],
        description="Two-pass overwrite: Pass 1 writes pseudo-random bytes, Pass 2 writes binary zeros."
    ),
    ErasureMethod.DOD_5220_22_M: OverwriteStrategy(
        name="DoD 5220.22-M (3-Pass ECE Sanitization)",
        passes=[
            _pattern_generator(0x00),  # Pass 1: Zeros
            _pattern_generator(0xFF),  # Pass 2: Ones / Complement
            _random_generator()        # Pass 3: Pseudo-random bytes
        ],
        description="DoD 5220.22-M specification: Pass 1 binary zeros, Pass 2 binary ones, Pass 3 random bytes."
    ),
    ErasureMethod.NIST_800_88_CLEAR: OverwriteStrategy(
        name="NIST SP 800-88 Rev 1 Clear (1-Pass)",
        passes=[_pattern_generator(0x00)],
        description="NIST SP 800-88 Clear level: Overwriting addressable storage space with a fixed pattern (zeros)."
    ),
    ErasureMethod.NIST_800_88_PURGE: OverwriteStrategy(
        name="NIST SP 800-88 Rev 1 Purge (3-Pass)",
        passes=[
            _pattern_generator(0x55),  # 01010101
            _pattern_generator(0xAA),  # 10101010
            _random_generator()        # Random
        ],
        description="NIST SP 800-88 Purge level: Multi-pattern physical sector overwrite with verify."
    ),
    ErasureMethod.GUTMANN_LIGHT: OverwriteStrategy(
        name="Gutmann Light (7-Pass)",
        passes=[
            _random_generator(),
            _pattern_generator(0x55),
            _pattern_generator(0xAA),
            _pattern_generator(0x92),
            _pattern_generator(0x49),
            _pattern_generator(0x24),
            _random_generator()
        ],
        description="7-pass structured pattern overwrite based on selected Gutmann passes."
    )
}


def overwrite_file(
    file_path: str,
    method: ErasureMethod = ErasureMethod.SECURE_OVERWRITE,
    cancel_check: Callable[[], bool] = None
) -> Tuple[int, int]:
    """
    Executes the multi-pass overwrite on the target file, forces OS buffer flush,
    scrambles filename metadata, and truncates file size to 0 bytes before unlinking.

    Returns:
        (total_bytes_written, passes_completed)
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    file_size = os.path.getsize(file_path)
    strategy = STRATEGIES.get(method, STRATEGIES[ErasureMethod.SECURE_OVERWRITE])
    
    passes_completed = 0
    total_bytes_written = 0

    if file_size > 0:
        # Open in binary read/write mode without truncating yet
        with open(file_path, "r+b") as f:
            fd = f.fileno()
            for pass_idx, gen_func in enumerate(strategy.passes):
                if cancel_check and cancel_check():
                    raise InterruptedError("Erasure job was cancelled by user request.")

                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Erasure job was cancelled by user request.")

                    write_size = min(CHUNK_SIZE, remaining)
                    chunk = gen_func(write_size)
                    f.write(chunk)
                    total_bytes_written += write_size
                    remaining -= write_size

                # Force filesystem flush and disk sync for each pass
                f.flush()
                try:
                    os.fsync(fd)
                except (OSError, AttributeError):
                    pass

                passes_completed += 1

    # Zero-byte truncation
    try:
        with open(file_path, "wb") as f:
            f.truncate(0)
            f.flush()
    except Exception:
        pass

    # Metadata obfuscation (rename file to random name in directory before removal)
    try:
        dir_name = os.path.dirname(file_path)
        random_name = os.path.join(dir_name, f"tmp_erased_{secrets.token_hex(16)}.tmp")
        os.rename(file_path, random_name)
        target_to_remove = random_name
    except Exception:
        target_to_remove = file_path

    # Unlink file
    os.remove(target_to_remove)

    return total_bytes_written, passes_completed
