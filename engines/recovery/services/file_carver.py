"""
SIH26149 - Person 2: Advanced Signature/Magic-Byte File Carving Engine
Supports deep signature carving for PDF, JPG, PNG, DOCX/ZIP, GIF, MP4, MP3, WAV, SQLite, BMP.
Calculates Shannon entropy and integrity assessments.
"""
import math
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..models.recovery_models import RecoveredFileItem
from .hash_service import HashService


class FileSignature:
    def __init__(
        self,
        name: str,
        ext: str,
        mime: str,
        header: bytes,
        footer: Optional[bytes] = None,
        header_offset: int = 0,
        footer_slack: int = 0,
        max_size: int = 50 * 1024 * 1024
    ):
        self.name = name
        self.ext = ext
        self.mime = mime
        self.header = header
        self.footer = footer
        self.header_offset = header_offset
        self.footer_slack = footer_slack
        self.max_size = max_size


CARVE_SIGNATURES: List[FileSignature] = [
    FileSignature(
        name="PDF Document",
        ext="pdf",
        mime="application/pdf",
        header=b"%PDF-",
        footer=b"%%EOF",
        max_size=100 * 1024 * 1024
    ),
    FileSignature(
        name="JPEG Image",
        ext="jpg",
        mime="image/jpeg",
        header=b"\xFF\xD8\xFF",
        footer=b"\xFF\xD9",
        max_size=30 * 1024 * 1024
    ),
    FileSignature(
        name="PNG Image",
        ext="png",
        mime="image/png",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"IEND\xaeB`\x82",
        max_size=30 * 1024 * 1024
    ),
    FileSignature(
        name="ZIP / Office OpenXML (DOCX/XLSX/PPTX)",
        ext="zip",
        mime="application/zip",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
        footer_slack=18,
        max_size=150 * 1024 * 1024
    ),
    FileSignature(
        name="GIF Image",
        ext="gif",
        mime="image/gif",
        header=b"GIF89a",
        footer=b"\x00;",
        max_size=20 * 1024 * 1024
    ),
    FileSignature(
        name="GIF87a Image",
        ext="gif",
        mime="image/gif",
        header=b"GIF87a",
        footer=b"\x00;",
        max_size=20 * 1024 * 1024
    ),
    FileSignature(
        name="MP4 Video",
        ext="mp4",
        mime="video/mp4",
        header=b"ftyp",
        header_offset=4,
        max_size=250 * 1024 * 1024
    ),
    FileSignature(
        name="MP3 Audio",
        ext="mp3",
        mime="audio/mpeg",
        header=b"ID3",
        max_size=50 * 1024 * 1024
    ),
    FileSignature(
        name="WAV Audio",
        ext="wav",
        mime="audio/wav",
        header=b"RIFF",
        max_size=100 * 1024 * 1024
    ),
    FileSignature(
        name="SQLite Database",
        ext="sqlite",
        mime="application/x-sqlite3",
        header=b"SQLite format 3\0",
        max_size=200 * 1024 * 1024
    ),
    FileSignature(
        name="Bitmap Image",
        ext="bmp",
        mime="image/bmp",
        header=b"BM",
        max_size=40 * 1024 * 1024
    )
]


class FileCarver:
    """
    Signature-based File Carving Engine.
    Scans raw byte streams / sector buffers and reconstructs known file formats.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon Entropy (0.0000 to 8.0000) using fast sampling.
        """
        if not data:
            return 0.0
        # Fast representative sample up to 64KB for maximum speed
        sample = data if len(data) <= 65536 else data[:65536]
        length = len(sample)
        unique_bytes = set(sample)
        entropy = 0.0
        for b in unique_bytes:
            count = sample.count(b)
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def evaluate_recoverability(cls, data: bytes, sig: FileSignature) -> Dict[str, Any]:
        """
        Estimates recoverability probability based on entropy, header validity, and footer completeness.
        """
        entropy = cls.calculate_entropy(data)
        score = 90

        if entropy < 1.0:
            score -= 40
        elif entropy > 7.95 and sig.ext in ["txt", "log", "xml"]:
            score -= 30

        if sig.footer:
            if sig.footer in data[-64:]:
                score += 10
            else:
                score -= 20

        score = max(10, min(100, score))

        if score >= 80:
            rating = "High"
        elif score >= 55:
            rating = "Medium"
        elif score >= 35:
            rating = "Low"
        else:
            rating = "Corrupted"

        return {"score": score, "rating": rating, "entropy": entropy}

    @classmethod
    def carve_bytes(
        cls,
        data: bytes,
        base_offset: int = 0,
        target_extensions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Scans an in-memory byte buffer and carves all matched file signatures.
        """
        carved_items = []
        ext_filter = [e.lower().lstrip(".") for e in target_extensions] if target_extensions else None

        for sig in CARVE_SIGNATURES:
            if ext_filter and sig.ext.lower() not in ext_filter:
                continue

            search_pos = 0
            h_offset = sig.header_offset

            while search_pos < len(data) - len(sig.header) - h_offset:
                match_idx = data.find(sig.header, search_pos + h_offset)
                if match_idx == -1:
                    break

                start_pos = match_idx - h_offset
                if start_pos < 0:
                    search_pos = match_idx + 1
                    continue

                end_pos = -1
                if sig.footer:
                    footer_idx = data.find(sig.footer, start_pos + len(sig.header))
                    if footer_idx != -1:
                        end_pos = footer_idx + len(sig.footer) + sig.footer_slack

                # If no footer found or beyond max_size, bound to reasonable default block
                if end_pos == -1 or end_pos > start_pos + sig.max_size:
                    end_pos = min(len(data), start_pos + min(sig.max_size, 512 * 1024))

                file_slice = data[start_pos:end_pos]
                if len(file_slice) >= 16:
                    assessment = cls.evaluate_recoverability(file_slice, sig)
                    sha256 = HashService.compute_sha256_bytes(file_slice)

                    carved_items.append({
                        "signature": sig,
                        "startOffset": base_offset + start_pos,
                        "endOffset": base_offset + end_pos,
                        "size": len(file_slice),
                        "data": file_slice,
                        "sha256": sha256,
                        "entropy": assessment["entropy"],
                        "score": assessment["score"],
                        "recoverability": assessment["rating"]
                    })

                search_pos = start_pos + max(1, len(sig.header))

        return carved_items

    @classmethod
    def carve_file_to_destination(
        cls,
        source_file: Path,
        destination_dir: Path,
        target_extensions: Optional[List[str]] = None,
        max_carve_size_mb: int = 100
    ) -> List[RecoveredFileItem]:
        """
        Reads a raw disk dump / binary file in chunked streams and carves files to destination.
        """
        recovered_files: List[RecoveredFileItem] = []
        destination_dir.mkdir(parents=True, exist_ok=True)

        chunk_size = 4 * 1024 * 1024  # 4MB chunks
        overlap = 64 * 1024           # 64KB overlap to catch header boundaries

        try:
            with open(source_file, "rb") as f:
                offset = 0
                prev_tail = b""

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    combined_buffer = prev_tail + chunk
                    buffer_base_offset = max(0, offset - len(prev_tail))

                    carved_results = cls.carve_bytes(
                        combined_buffer,
                        base_offset=buffer_base_offset,
                        target_extensions=target_extensions
                    )

                    for item in carved_results:
                        sig = item["signature"]
                        file_name = f"carved_{offset}_{sig.ext.upper()}_{uuid.uuid4().hex[:6]}.{sig.ext}"
                        output_file_path = destination_dir / file_name

                        with open(output_file_path, "wb") as out_f:
                            out_f.write(item["data"])

                        rec_item = RecoveredFileItem(
                            fileName=file_name,
                            originalPath=f"{source_file} (offset: 0x{item['startOffset']:X})",
                            recoveredPath=str(output_file_path.resolve()),
                            fileType=sig.mime,
                            fileSize=item["size"],
                            sha256=item["sha256"],
                            status="RECOVERED",
                            entropy=item["entropy"],
                            recoverability=item["recoverability"],
                            carved=True
                        )
                        recovered_files.append(rec_item)

                    offset += len(chunk)
                    prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk

        except Exception as e:
            # Handle non-fatal carve stream errors
            pass

        return recovered_files
