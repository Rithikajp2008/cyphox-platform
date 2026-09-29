from __future__ import annotations
import csv
import html
import json
from pathlib import Path
from typing import Any


def write_reports(report: dict[str, Any], base_path: Path, formats: list[str]) -> dict[str, str]:
    base_path.parent.mkdir(parents=True, exist_ok=True)
    wanted = {x.lower() for x in formats}
    out: dict[str, str] = {}
    if "json" in wanted:
        p = base_path.with_suffix(".json")
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        out["json"] = str(p)
    if "csv" in wanted:
        p = base_path.with_suffix(".csv")
        rows = report.get("evidence_manifest", [])
        fields = ["evidence_id","jobId","sessionId","deviceId","name","path","relative_path","extension","mime_type","category","size_bytes","created_utc","modified_utc","accessed_utc","permissions","attributes","hidden","sha256","md5","sha1"]
        with p.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
            for x in rows:
                t = x.get("timestamps", {})
                row = {k: x.get(k) for k in fields}
                row["created_utc"] = t.get("created_utc"); row["modified_utc"] = t.get("modified_utc"); row["accessed_utc"] = t.get("accessed_utc")
                row["attributes"] = ",".join(x.get("attributes", []))
                w.writerow(row)
        out["csv"] = str(p)
    if "txt" in wanted:
        p = base_path.with_suffix(".txt")
        s = report.get("summary", {})
        lines = [
            "CYPHOX DIGITAL FORENSIC REPORT",
            "=" * 32,
            f"Job ID: {report.get('identifiers',{}).get('jobId')}",
            f"Target: {report.get('target',{}).get('path')}",
            f"Read-only: {report.get('target',{}).get('readOnly')}",
            f"Files: {s.get('file_count')}", f"Bytes: {s.get('total_bytes')}",
            f"Findings: {s.get('finding_count')}", f"Errors: {s.get('scan_error_count')}",
            f"Integrity SHA-256: {report.get('report_integrity_sha256')}", "", "FINDINGS"
        ]
        for fnd in report.get("findings", []): lines.append(f"- [{fnd.get('severity')}] {fnd.get('type')} ({fnd.get('count')}): {fnd.get('description')}")
        p.write_text("\n".join(lines), encoding="utf-8")
        out["txt"] = str(p)
    if "html" in wanted:
        p = base_path.with_suffix(".html")
        s = report.get("summary", {}); ident = report.get("identifiers", {})
        finding_rows = "".join(f"<tr><td>{html.escape(str(x.get('severity')))}</td><td>{html.escape(str(x.get('type')))}</td><td>{x.get('count')}</td><td>{html.escape(str(x.get('description')))}</td></tr>" for x in report.get("findings", []))
        evidence_rows = "".join(f"<tr><td>{html.escape(str(x.get('evidence_id')))}</td><td>{html.escape(str(x.get('relative_path')))}</td><td>{x.get('size_bytes')}</td><td><code>{html.escape(str(x.get('sha256','')))}</code></td></tr>" for x in report.get("evidence_manifest", [])[:500])
        body = f"""<!doctype html><html><head><meta charset='utf-8'><title>Cyphox Forensic Report</title><style>body{{font-family:Arial,sans-serif;margin:32px;background:#0b1220;color:#e8eefc}}h1,h2{{color:#32e6a1}}.card{{background:#121d31;border:1px solid #283850;border-radius:10px;padding:16px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border-bottom:1px solid #283850;text-align:left;font-size:13px}}code{{font-size:11px;word-break:break-all}}</style></head><body>
<h1>Cyphox Digital Forensic Report</h1><div class='card'><b>Job:</b> {html.escape(str(ident.get('jobId')))}<br><b>Target:</b> {html.escape(str(report.get('target',{}).get('path')))}<br><b>Read-only:</b> {report.get('target',{}).get('readOnly')}<br><b>Files:</b> {s.get('file_count')} &nbsp; <b>Findings:</b> {s.get('finding_count')} &nbsp; <b>Errors:</b> {s.get('scan_error_count')}<br><b>Integrity:</b> <code>{report.get('report_integrity_sha256')}</code></div>
<h2>Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Count</th><th>Description</th></tr>{finding_rows}</table>
<h2>Evidence Manifest</h2><table><tr><th>Evidence ID</th><th>Path</th><th>Size</th><th>SHA-256</th></tr>{evidence_rows}</table></body></html>"""
        p.write_text(body, encoding="utf-8")
        out["html"] = str(p)
    return out
