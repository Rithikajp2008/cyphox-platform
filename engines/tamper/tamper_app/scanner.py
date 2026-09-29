from __future__ import annotations
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK = 1024 * 1024


def utc_iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _entry(path: Path, base: Path) -> dict[str, Any]:
    st = path.stat()
    try:
        rel = path.relative_to(base).as_posix() if path != base else path.name
    except ValueError:
        rel = path.name
    return {
        "name": path.name,
        "relativePath": rel,
        "sizeBytes": st.st_size,
        "modifiedUtc": utc_iso_from_ts(st.st_mtime),
        "modifiedNs": st.st_mtime_ns,
        "extension": path.suffix.lower() or None,
        "sha256": sha256_file(path),
    }


def scan_target(target: str, max_files: int = 10000) -> dict[str, Any]:
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    if p.is_symlink():
        raise ValueError("Direct symlink/reparse targets are not allowed for tamper baselines")

    entries: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    traversal_complete = True

    if p.is_file():
        try:
            entries.append(_entry(p, p))
        except Exception as e:
            errors.append({"path": str(p), "stage": "SCAN", "error": f"{type(e).__name__}: {e}"})
    elif p.is_dir():
        base = p
        count = 0
        for dirpath, dirnames, filenames in os.walk(p, topdown=True, followlinks=False):
            safe_dirs = []
            for d in dirnames:
                dp = Path(dirpath) / d
                try:
                    if not dp.is_symlink():
                        safe_dirs.append(d)
                except OSError:
                    continue
            dirnames[:] = safe_dirs

            for name in filenames:
                if count >= max_files:
                    traversal_complete = False
                    errors.append({
                        "path": str(p),
                        "stage": "LIMIT",
                        "error": f"maxFiles limit reached ({max_files})",
                    })
                    break
                fp = Path(dirpath) / name
                try:
                    if fp.is_symlink():
                        continue
                    entries.append(_entry(fp, base))
                    count += 1
                except Exception as e:
                    errors.append({"path": str(fp), "stage": "SCAN", "error": f"{type(e).__name__}: {e}"})
            if count >= max_files:
                break
    else:
        raise ValueError(f"Unsupported target type: {target}")

    entries.sort(key=lambda x: x["relativePath"].casefold())
    return {
        "targetPath": str(p),
        "targetType": "FILE" if p.is_file() else "FOLDER",
        "entries": entries,
        "errors": errors,
        "traversalComplete": traversal_complete,
        "fileCount": len(entries),
        "totalBytes": sum(e["sizeBytes"] for e in entries),
    }
