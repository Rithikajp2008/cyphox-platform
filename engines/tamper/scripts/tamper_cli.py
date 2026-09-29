from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tamper_app.storage import JsonStore
from tamper_app.tamper_engine import create_baseline, new_id, verify_target_against_baseline


def main():
    p = argparse.ArgumentParser(description="Cyphox Tamper Verification CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("target"); b.add_argument("--id"); b.add_argument("--max-files", type=int, default=10000)
    v = sub.add_parser("verify")
    v.add_argument("baseline_id"); v.add_argument("--target"); v.add_argument("--max-files", type=int)
    a = p.parse_args()
    data = ROOT / "data"
    bs = JsonStore(data / "baselines"); vs = JsonStore(data / "verifications")
    if a.cmd == "baseline":
        bid = a.id or new_id("BASELINE")
        rec = create_baseline(target_path=a.target,user_id="LOCAL-USER",device_id="LOCAL-DEVICE",session_id="LOCAL-SESSION",baseline_id=bid,job_id=new_id("CLIJOB"),max_files=a.max_files,check_metadata=True)
        path = bs.save(bid, rec)
        print(json.dumps({"baselineId":bid,"path":str(path),"summary":rec["summary"],"integrity":rec["baselineIntegritySha256"]}, indent=2))
    else:
        baseline = bs.load(a.baseline_id)
        vid = new_id("VERIFY")
        rec = verify_target_against_baseline(baseline=baseline,target_path=a.target,verification_id=vid,job_id=new_id("CLIJOB"),user_id="LOCAL-USER",device_id="LOCAL-DEVICE",session_id="LOCAL-SESSION",max_files=a.max_files,check_metadata=None)
        path = vs.save(vid, rec)
        print(json.dumps({"verificationId":vid,"path":str(path),"tamperStatus":rec["tamperStatus"],"verificationState":rec["verificationState"],"summary":rec["summary"]}, indent=2))

if __name__ == "__main__": main()
