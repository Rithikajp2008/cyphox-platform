from __future__ import annotations
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from app.engine import verify_report
if len(sys.argv) != 2:
    raise SystemExit("Usage: python scripts/verify_report.py <report.json>")
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps(verify_report(report), indent=2))
