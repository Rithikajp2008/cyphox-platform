from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from app.devices import list_devices
from app.engine import ForensicEngine, verify_report
from app.reporting import write_reports


def main():
    ap = argparse.ArgumentParser(description="Cyphox safe read-only USB/file-system forensic scanner")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--list", action="store_true", help="List visible drives/devices")
    ap.add_argument("--max-files", type=int, default=10000)
    ap.add_argument("--keyword", action="append", default=[])
    a = ap.parse_args()
    if a.list:
        print(json.dumps(list_devices(), indent=2)); return
    if not a.target: ap.error("target is required unless --list is used")
    print("[SAFE MODE] Read-only allocated-file forensic scan; links are not followed.")
    eng = ForensicEngine(max_files=a.max_files, keywords=a.keyword, job_id="USB-LOCAL", session_id="LOCAL-USB-SESSION", device_id="LOCAL-USB")
    report = eng.analyze(a.target)
    paths = write_reports(report, ROOT / "reports" / "USB-FORENSICS", ["json","csv","txt","html"])
    print("\n=== RESULT ===")
    print("Files scanned :", report["summary"]["file_count"])
    print("Total bytes   :", report["summary"]["total_bytes"])
    print("Findings      :", report["summary"]["finding_count"])
    print("Scan errors   :", report["summary"]["scan_error_count"])
    print("Complete      :", report["summary"]["complete"])
    print("Integrity     :", "VALID" if verify_report(report)["valid"] else "INVALID")
    for k,v in paths.items(): print(f"{k.upper():5}: {v}")

if __name__ == "__main__": main()
