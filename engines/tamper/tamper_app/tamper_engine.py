from __future__ import annotations
import copy
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any
from .scanner import scan_target


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(obj: dict[str, Any], excluded: set[str] | None = None) -> str:
    excluded = excluded or set()
    cloned = {k: v for k, v in obj.items() if k not in excluded}
    payload = json.dumps(cloned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def new_id(prefix: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{secrets.token_hex(3).upper()}"


def create_baseline(*, target_path: str, user_id: str, device_id: str, session_id: str,
                    baseline_id: str, job_id: str, max_files: int, check_metadata: bool,
                    notes: str | None = None) -> dict[str, Any]:
    scan = scan_target(target_path, max_files=max_files)
    baseline = {
        "schemaVersion": "1.0",
        "recordType": "TAMPER_BASELINE",
        "identifiers": {
            "userId": user_id,
            "deviceId": device_id,
            "sessionId": session_id,
            "jobId": job_id,
            "baselineId": baseline_id,
        },
        "target": {
            "path": scan["targetPath"],
            "type": scan["targetType"],
            "readOnly": True,
        },
        "createdAtUtc": now_utc(),
        "options": {
            "hashAlgorithm": "SHA-256",
            "checkMetadata": check_metadata,
            "maxFiles": max_files,
            "linksFollowed": False,
        },
        "summary": {
            "fileCount": scan["fileCount"],
            "totalBytes": scan["totalBytes"],
            "scanErrorCount": len(scan["errors"]),
            "traversalComplete": scan["traversalComplete"],
            "complete": scan["traversalComplete"] and not scan["errors"],
        },
        "entries": scan["entries"],
        "scanErrors": scan["errors"],
        "notes": notes,
    }
    baseline["baselineIntegritySha256"] = canonical_hash(baseline)
    return baseline


def verify_baseline_integrity(baseline: dict[str, Any]) -> dict[str, Any]:
    expected = baseline.get("baselineIntegritySha256")
    actual = canonical_hash(baseline, {"baselineIntegritySha256"})
    return {"valid": bool(expected) and expected == actual, "expected": expected, "actual": actual}


def _map_entries(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["relativePath"]: e for e in entries}


def _detect_renames(deleted: list[dict[str, Any]], added: list[dict[str, Any]]):
    deleted_by_hash: dict[str, list[dict[str, Any]]] = {}
    added_by_hash: dict[str, list[dict[str, Any]]] = {}
    for e in deleted:
        deleted_by_hash.setdefault(e.get("sha256"), []).append(e)
    for e in added:
        added_by_hash.setdefault(e.get("sha256"), []).append(e)

    renamed = []
    used_del = set()
    used_add = set()
    for digest, ds in deleted_by_hash.items():
        ads = added_by_hash.get(digest, [])
        if digest and len(ds) == 1 and len(ads) == 1:
            d, a = ds[0], ads[0]
            renamed.append({
                "from": d["relativePath"],
                "to": a["relativePath"],
                "sha256": digest,
                "sizeBytes": a["sizeBytes"],
            })
            used_del.add(d["relativePath"])
            used_add.add(a["relativePath"])
    deleted2 = [d for d in deleted if d["relativePath"] not in used_del]
    added2 = [a for a in added if a["relativePath"] not in used_add]
    return renamed, deleted2, added2


def verify_target_against_baseline(*, baseline: dict[str, Any], target_path: str | None,
                                   verification_id: str, job_id: str, user_id: str,
                                   device_id: str, session_id: str, max_files: int | None,
                                   check_metadata: bool | None) -> dict[str, Any]:
    integrity = verify_baseline_integrity(baseline)
    if not integrity["valid"]:
        raise ValueError("Baseline integrity verification failed; baseline may have been modified")

    baseline_target = baseline["target"]["path"]
    target = target_path or baseline_target
    opts = baseline.get("options", {})
    limit = max_files or int(opts.get("maxFiles", 10000))
    metadata_check = opts.get("checkMetadata", True) if check_metadata is None else check_metadata
    current = scan_target(target, max_files=limit)

    before = _map_entries(baseline.get("entries", []))
    after = _map_entries(current.get("entries", []))
    before_paths = set(before)
    after_paths = set(after)

    deleted = [before[p] for p in sorted(before_paths - after_paths)]
    added = [after[p] for p in sorted(after_paths - before_paths)]
    modified = []
    metadata_changed = []
    unchanged = []

    for p in sorted(before_paths & after_paths):
        b, a = before[p], after[p]
        if b.get("sha256") != a.get("sha256"):
            modified.append({
                "path": p,
                "beforeSha256": b.get("sha256"),
                "afterSha256": a.get("sha256"),
                "beforeSizeBytes": b.get("sizeBytes"),
                "afterSizeBytes": a.get("sizeBytes"),
            })
        elif metadata_check and (
            b.get("sizeBytes") != a.get("sizeBytes") or
            b.get("modifiedNs") != a.get("modifiedNs")
        ):
            metadata_changed.append({
                "path": p,
                "sha256": a.get("sha256"),
                "beforeModifiedUtc": b.get("modifiedUtc"),
                "afterModifiedUtc": a.get("modifiedUtc"),
                "beforeSizeBytes": b.get("sizeBytes"),
                "afterSizeBytes": a.get("sizeBytes"),
            })
        else:
            unchanged.append(p)

    renamed, deleted, added = _detect_renames(deleted, added)
    errors = current.get("errors", [])
    comparison_complete = bool(current.get("traversalComplete")) and not errors
    change_count = len(added) + len(deleted) + len(modified) + len(renamed) + len(metadata_changed)

    if not comparison_complete:
        tamper_status = "INDETERMINATE"
        verification_state = "NOT_VERIFIED"
    elif change_count:
        tamper_status = "TAMPERED"
        verification_state = "VERIFIED"
    else:
        tamper_status = "INTACT"
        verification_state = "VERIFIED"

    result = {
        "schemaVersion": "1.0",
        "recordType": "TAMPER_VERIFICATION_RESULT",
        "identifiers": {
            "userId": user_id,
            "deviceId": device_id,
            "sessionId": session_id,
            "jobId": job_id,
            "baselineId": baseline["identifiers"]["baselineId"],
            "verificationId": verification_id,
        },
        "target": {"path": current["targetPath"], "type": current["targetType"], "readOnly": True},
        "verifiedAtUtc": now_utc(),
        "verificationState": verification_state,
        "tamperStatus": tamper_status,
        "baselineIntegrity": integrity,
        "options": {"hashAlgorithm": "SHA-256", "checkMetadata": metadata_check, "maxFiles": limit},
        "summary": {
            "baselineFiles": len(before),
            "currentFiles": len(after),
            "added": len(added),
            "deleted": len(deleted),
            "modified": len(modified),
            "renamed": len(renamed),
            "metadataChanged": len(metadata_changed),
            "unchanged": len(unchanged),
            "scanErrorCount": len(errors),
            "traversalComplete": current.get("traversalComplete", False),
            "complete": comparison_complete,
            "changeCount": change_count,
        },
        "changes": {
            "added": [{"path": e["relativePath"], "sha256": e.get("sha256"), "sizeBytes": e.get("sizeBytes")} for e in added],
            "deleted": [{"path": e["relativePath"], "sha256": e.get("sha256"), "sizeBytes": e.get("sizeBytes")} for e in deleted],
            "modified": modified,
            "renamed": renamed,
            "metadataChanged": metadata_changed,
        },
        "scanErrors": errors,
    }
    result["verificationIntegritySha256"] = canonical_hash(result)
    return result


def verify_verification_integrity(record: dict[str, Any]) -> dict[str, Any]:
    expected = record.get("verificationIntegritySha256")
    actual = canonical_hash(record, {"verificationIntegritySha256"})
    return {"valid": bool(expected) and expected == actual, "expected": expected, "actual": actual}
