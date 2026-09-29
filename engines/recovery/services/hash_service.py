"""
SIH26149 - Person 2: Cryptographic Hash Service
Computes SHA-256 checksums for files and byte streams safely.
"""
import hashlib
from typing import Optional
from pathlib import Path


class HashService:
    @staticmethod
    def compute_sha256_file(file_path: Path, chunk_size: int = 65536) -> str:
        """
        Computes SHA-256 for a file on disk using buffered streaming.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(chunk_size), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"HASH_ERROR: {str(e)}"

    @staticmethod
    def compute_sha256_bytes(data: bytes) -> str:
        """
        Computes SHA-256 for an in-memory byte buffer.
        """
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def compute_md5_file(file_path: Path, chunk_size: int = 65536) -> Optional[str]:
        """
        Computes MD5 hash for auxiliary verification.
        """
        md5_hash = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(chunk_size), b""):
                    md5_hash.update(byte_block)
            return md5_hash.hexdigest()
        except Exception:
            return None
