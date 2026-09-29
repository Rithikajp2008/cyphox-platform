from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tamper_app.certificate_service import CertificateService

p=argparse.ArgumentParser(); p.add_argument("certificate_json"); a=p.parse_args()
path=Path(a.certificate_json)
cert=json.loads(path.read_text(encoding="utf-8"))
svc=CertificateService(ROOT/"data"/"certificates", ROOT/"data"/"keys")
print(json.dumps(svc.verify(cert), indent=2))
