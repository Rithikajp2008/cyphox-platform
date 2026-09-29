from __future__ import annotations
import hashlib
import json
import mimetypes
import os
import platform
import socket
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from .devices import device_for_path, list_devices

UTC = timezone.utc

SIGNATURES = [
    (b"MZ", "EXECUTABLE", {".exe", ".dll", ".sys", ".scr"}),
    (b"%PDF-", "PDF", {".pdf"}),
    (b"\x89PNG\r\n\x1a\n", "PNG", {".png"}),
    (b"\xff\xd8\xff", "JPEG", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF", {".gif"}), (b"GIF89a", "GIF", {".gif"}),
    (b"PK\x03\x04", "ZIP_CONTAINER", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
]


def iso(ts: float | None):
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def hash_file(path: Path, algorithm: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk_size), b""):
            h.update(block)
    return h.hexdigest()


def canonical_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def classify(name: str, mime: str | None) -> str:
    ext = Path(name).suffix.lower()
    if mime:
        if mime.startswith("image/"): return "IMAGE"
        if mime.startswith("video/"): return "VIDEO"
        if mime.startswith("audio/"): return "AUDIO"
        if mime.startswith("text/"): return "TEXT"
        if mime == "application/pdf": return "DOCUMENT"
    if ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf"}: return "DOCUMENT"
    if ext in {".zip", ".7z", ".rar", ".tar", ".gz"}: return "ARCHIVE"
    if ext in {".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".sys", ".scr"}: return "EXECUTABLE_OR_SCRIPT"
    return "OTHER"


def content_signature(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except OSError:
        return None
    for sig, kind, expected in SIGNATURES:
        if head.startswith(sig):
            return {"detectedType": kind, "expectedExtensions": sorted(expected), "matchesExtension": path.suffix.lower() in expected}
    return None


def windows_attributes(path: Path) -> list[str]:
    if os.name != "nt":
        attrs = []
        if path.name.startswith("."): attrs.append("HIDDEN")
        return attrs
    try:
        import ctypes
        v = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if v == 0xFFFFFFFF: return []
        mapping = [(0x1,"READONLY"),(0x2,"HIDDEN"),(0x4,"SYSTEM"),(0x20,"ARCHIVE"),(0x400,"REPARSE_POINT")]
        return [name for bit, name in mapping if v & bit]
    except Exception:
        return []


def keyword_hits(path: Path, keywords: list[str], max_bytes: int = 2 * 1024 * 1024) -> list[str]:
    if not keywords or path.stat().st_size > max_bytes:
        return []
    try:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="ignore").lower()
        return [k for k in keywords if k.lower() in text]
    except OSError:
        return []


@dataclass
class ForensicEngine:
    max_files: int = 10000
    include_hashes: bool = True
    include_md5: bool = False
    include_sha1: bool = False
    keywords: list[str] = field(default_factory=list)
    user_id: str = "LOCAL-USER"
    device_id: str = "LOCAL-DEVICE"
    session_id: str = "LOCAL-SESSION"
    job_id: str = "LOCAL-JOB"

    def validate(self, target: str | Path) -> Path:
        p = Path(target).expanduser().resolve()
        if not p.exists(): raise FileNotFoundError(f"Target not found: {p}")
        if p.is_symlink(): raise ValueError("Symlink targets are not scanned directly")
        if not (p.is_file() or p.is_dir()): raise ValueError("Target must be a regular file or directory")
        return p

    def _one(self, p: Path, root: Path) -> dict[str, Any]:
        st = p.stat(follow_symlinks=False)
        mime, _ = mimetypes.guess_type(p.name)
        attrs = windows_attributes(p)
        item = {
            "evidence_id": f"EVID-{uuid4().hex[:12].upper()}",
            "jobId": self.job_id, "sessionId": self.session_id, "deviceId": self.device_id,
            "name": p.name, "path": str(p),
            "relative_path": p.name if root.is_file() else str(p.relative_to(root)),
            "extension": p.suffix.lower() or None,
            "mime_type": mime or "application/octet-stream", "category": classify(p.name, mime),
            "size_bytes": st.st_size,
            "timestamps": {"created_utc": iso(getattr(st, "st_birthtime", None) or st.st_ctime), "modified_utc": iso(st.st_mtime), "accessed_utc": iso(st.st_atime)},
            "permissions": stat.filemode(st.st_mode), "attributes": attrs,
            "hidden": "HIDDEN" in attrs or p.name.startswith("."),
            "content_signature": content_signature(p),
        }

        # Hash failures must not remove an otherwise valid evidence record.
        # This matters for large/removable-media files where Windows can report
        # transient read errors. The report records the failed inspection stage.
        inspection_errors: list[dict[str, str]] = []
        if self.include_hashes:
            try:
                item["sha256"] = hash_file(p, "sha256")
            except OSError as e:
                item["sha256"] = None
                inspection_errors.append({"stage": "SHA256", "error": f"{type(e).__name__}: {e}"})
        if self.include_md5:
            try:
                item["md5"] = hash_file(p, "md5")
            except OSError as e:
                item["md5"] = None
                inspection_errors.append({"stage": "MD5", "error": f"{type(e).__name__}: {e}"})
        if self.include_sha1:
            try:
                item["sha1"] = hash_file(p, "sha1")
            except OSError as e:
                item["sha1"] = None
                inspection_errors.append({"stage": "SHA1", "error": f"{type(e).__name__}: {e}"})

        hits = keyword_hits(p, self.keywords)
        if hits:
            item["keyword_hits"] = hits
        if inspection_errors:
            item["inspection_errors"] = inspection_errors
        return item

    def _iter_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for current, dirs, files in os.walk(root, followlinks=False):
            # Exclude symlink/junction/reparse directories from traversal.
            keep = []
            for name in dirs:
                p = Path(current) / name
                attrs = windows_attributes(p)
                if p.is_symlink() or "REPARSE_POINT" in attrs:
                    continue
                keep.append(name)
            dirs[:] = keep
            for name in files:
                p = Path(current) / name
                attrs = windows_attributes(p)
                if p.is_symlink() or "REPARSE_POINT" in attrs:
                    continue
                yield p

    def analyze(self, target: str | Path) -> dict[str, Any]:
        root = self.validate(target)
        scan_started = datetime.now(UTC).isoformat()
        inventory: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        total_bytes = 0; ext_counts: dict[str,int] = {}; category_counts: dict[str,int] = {}
        hash_seen: dict[str,str] = {}; duplicates = []; limit_hit = False
        for idx, p in enumerate(self._iter_files(root)):
            if idx >= self.max_files:
                errors.append({"path": str(root), "error": f"File limit reached ({self.max_files}); report is partial."})
                limit_hit = True; break
            try:
                item = self._one(p, root); inventory.append(item); total_bytes += item["size_bytes"]
                ext = item["extension"] or "[no extension]"; ext_counts[ext] = ext_counts.get(ext, 0) + 1
                cat = item["category"]; category_counts[cat] = category_counts.get(cat, 0) + 1
                for ie in item.get("inspection_errors", []):
                    errors.append({"path": item["path"], "stage": ie.get("stage"), "error": ie.get("error", "Inspection error")})
                if self.include_hashes:
                    h = item.get("sha256")
                    if h:
                        if h in hash_seen: duplicates.append({"sha256": h, "first_path": hash_seen[h], "duplicate_path": item["path"]})
                        else: hash_seen[h] = item["path"]
            except (PermissionError, OSError) as e:
                errors.append({"path": str(p), "stage": "METADATA", "error": f"{type(e).__name__}: {e}"})

        findings: list[dict[str, Any]] = []
        def add(sev, typ, items, desc):
            if items: findings.append({"severity": sev, "type": typ, "count": len(items), "description": desc, "items": items[:100]})
        zero = [x["path"] for x in inventory if x["size_bytes"] == 0]
        hidden = [x["path"] for x in inventory if x["hidden"] or "SYSTEM" in x["attributes"]]
        mismatch = [x["path"] for x in inventory if x.get("content_signature") and not x["content_signature"]["matchesExtension"]]
        executable = [x["path"] for x in inventory if x["category"] == "EXECUTABLE_OR_SCRIPT"]
        keyword_items = [{"path": x["path"], "keywords": x.get("keyword_hits", [])} for x in inventory if x.get("keyword_hits")]
        add("INFO", "ZERO_BYTE_FILES", zero, "Zero-byte allocated files were found.")
        add("INFO", "HIDDEN_OR_SYSTEM_FILES", hidden, "Hidden or system-attributed files were found.")
        add("WARNING", "CONTENT_EXTENSION_MISMATCH", mismatch, "File content signature does not match its extension.")
        add("INFO", "EXECUTABLE_OR_SCRIPT_FILES", executable, "Executable or script files are present; this is not a malware verdict.")
        add("INFO", "KEYWORD_HITS", keyword_items, "Configured keywords were found in readable small files.")
        if duplicates: findings.append({"severity":"INFO","type":"DUPLICATE_CONTENT","count":len(duplicates),"description":"Files with identical SHA-256 hashes were found.","items":duplicates[:100]})
        if errors: findings.append({"severity":"WARNING","type":"SCAN_ERRORS","count":len(errors),"description":"Some items could not be fully inspected.","items":errors[:100]})

        device = device_for_path(str(root))
        if device is None:
            # Fallback by requested deviceId so reports remain useful even if
            # Path.resolve()/drive normalization behaves differently on Windows.
            device = next((d for d in list_devices() if d.get("deviceId") == self.device_id), None)
        report = {
            "schema_version": "2.0", "report_type": "DIGITAL_FORENSIC_REPORT",
            "identifiers": {"userId": self.user_id, "deviceId": self.device_id, "sessionId": self.session_id, "jobId": self.job_id},
            "target": {"path": str(root), "kind": "FILE" if root.is_file() else "FOLDER", "readOnly": True},
            "device": device,
            "collection": {"started_at_utc": scan_started, "completed_at_utc": datetime.now(UTC).isoformat(), "host": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version(), "linksFollowed": False},
            "summary": {
                "file_count": len(inventory), "total_bytes": total_bytes,
                "finding_count": len(findings), "scan_error_count": len(errors),
                "hash_algorithm": "SHA-256" if self.include_hashes else None,
                "traversalComplete": not limit_hit,
                "complete": (not limit_hit and len(errors) == 0),
                "completedWithWarnings": (not limit_hit and len(errors) > 0),
            },
            "statistics": {"extensions": dict(sorted(ext_counts.items())), "categories": dict(sorted(category_counts.items()))},
            "findings": findings,
            "artifacts": {"executablesAndScripts": executable, "keywordMatches": keyword_items, "hiddenOrSystem": hidden},
            "residual_data_analysis": {
                "scope": "ALLOCATED_FILES_ONLY",
                "zeroByteFiles": len(zero),
                "contentExtensionMismatches": len(mismatch),
                "note": "This service does not carve deleted/unallocated space; that remains the recovery-engine responsibility."
            },
            "duplicates": duplicates, "scan_errors": errors, "evidence_manifest": inventory,
        }
        report["report_integrity_sha256"] = canonical_hash(report)
        return report


def verify_report(report: dict[str, Any]) -> dict[str, Any]:
    expected = report.get("report_integrity_sha256")
    if not expected: return {"valid": False, "reason": "report_integrity_sha256 missing"}
    copy = dict(report); copy.pop("report_integrity_sha256", None)
    actual = canonical_hash(copy)
    return {"valid": actual == expected, "expected_sha256": expected, "actual_sha256": actual}
