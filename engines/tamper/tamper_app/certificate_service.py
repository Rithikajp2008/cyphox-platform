from __future__ import annotations
import base64
import hashlib
import hmac
import html
import io
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
import qrcode
from .tamper_engine import canonical_hash, new_id, verify_verification_integrity


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CertificateService:
    def __init__(self, certificates_dir: Path, keys_dir: Path):
        self.certificates_dir = certificates_dir
        self.keys_dir = keys_dir
        self.certificates_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.keys_dir / "certificate_hmac.key"
        self.key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            raw = self.key_path.read_bytes()
            if len(raw) >= 32:
                return raw
        key = secrets.token_bytes(32)
        self.key_path.write_bytes(key)
        return key

    def _sign(self, certificate_without_signature: dict[str, Any]) -> str:
        payload = json.dumps(certificate_without_signature, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def _base_url(self) -> str:
        return os.environ.get("CYPHOX_PUBLIC_BASE_URL", "http://127.0.0.1:8004").rstrip("/")

    def create(self, verification: dict[str, Any], *, certificate_id: str | None, user_id: str,
               session_id: str, title: str) -> dict[str, Any]:
        vcheck = verify_verification_integrity(verification)
        if not vcheck["valid"]:
            raise ValueError("Verification record integrity is invalid")

        cid = certificate_id or new_id("CERT")
        if (self.certificates_dir / f"{cid}.json").exists():
            raise ValueError(f"certificateId already exists: {cid}")

        digest = verification["verificationIntegritySha256"]
        verify_url = f"{self._base_url()}/api/v1/certificates/{quote(cid)}/verify?digest={digest}"
        cert = {
            "schemaVersion": "1.0",
            "recordType": "CYPHOX_CERTIFICATE",
            "certificateType": "TAMPER_VERIFICATION",
            "certificateId": cid,
            "title": title,
            "issuedAtUtc": _now(),
            "issuer": "Cyphox Local Verification Service",
            "identifiers": {
                "userId": user_id,
                "sessionId": session_id,
                "deviceId": verification["identifiers"].get("deviceId"),
                "baselineId": verification["identifiers"]["baselineId"],
                "verificationId": verification["identifiers"]["verificationId"],
            },
            "target": verification["target"],
            "verification": {
                "verificationState": verification["verificationState"],
                "tamperStatus": verification["tamperStatus"],
                "summary": verification["summary"],
                "verificationIntegritySha256": digest,
            },
            "verifyUrl": verify_url,
        }
        cert["certificateDigestSha256"] = canonical_hash(cert)
        to_sign = dict(cert)
        cert["signature"] = {
            "algorithm": "HMAC-SHA256",
            "value": self._sign(to_sign),
            "keyScope": "LOCAL_CYPHOX_SERVICE",
        }
        paths = self._write_artifacts(cert)
        cert["artifactPaths"] = paths
        # Save final JSON again with artifact paths. Signature intentionally covers the core certificate,
        # not local filesystem paths which may change when moved to another machine.
        (self.certificates_dir / f"{cid}.json").write_text(json.dumps(cert, indent=2, ensure_ascii=False), encoding="utf-8")
        return cert

    def _write_artifacts(self, cert: dict[str, Any]) -> dict[str, str]:
        cid = cert["certificateId"]
        qr_path = self.certificates_dir / f"{cid}-QR.png"
        html_path = self.certificates_dir / f"{cid}.html"
        json_path = self.certificates_dir / f"{cid}.json"

        qr = qrcode.QRCode(version=None, box_size=8, border=4)
        qr.add_data(cert["verifyUrl"])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_path)

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        v = cert["verification"]
        s = v["summary"]
        html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(cert['title'])}</title>
<style>body{{font-family:Arial,sans-serif;background:#f5f7fb;color:#111;padding:32px}}.c{{max-width:820px;margin:auto;background:white;border:1px solid #dfe5ee;border-radius:14px;padding:32px}}h1{{margin-top:0}}.status{{font-size:28px;font-weight:700}}table{{border-collapse:collapse;width:100%;margin-top:18px}}td{{padding:9px;border-bottom:1px solid #eee}}.qr{{text-align:center;margin-top:28px}}code{{word-break:break-all}}</style></head><body><div class="c">
<h1>{html.escape(cert['title'])}</h1><div class="status">{html.escape(v['tamperStatus'])}</div>
<table><tr><td>Certificate ID</td><td>{html.escape(cid)}</td></tr><tr><td>Verification ID</td><td>{html.escape(cert['identifiers']['verificationId'])}</td></tr><tr><td>Baseline ID</td><td>{html.escape(cert['identifiers']['baselineId'])}</td></tr><tr><td>Target</td><td>{html.escape(cert['target']['path'])}</td></tr><tr><td>Issued UTC</td><td>{html.escape(cert['issuedAtUtc'])}</td></tr><tr><td>Added</td><td>{s['added']}</td></tr><tr><td>Deleted</td><td>{s['deleted']}</td></tr><tr><td>Modified</td><td>{s['modified']}</td></tr><tr><td>Renamed</td><td>{s['renamed']}</td></tr><tr><td>Metadata changed</td><td>{s['metadataChanged']}</td></tr></table>
<div class="qr"><img alt="Verification QR" src="data:image/png;base64,{qr_b64}" width="220"><p>Scan to verify this certificate.</p><code>{html.escape(cert['verifyUrl'])}</code></div>
</div></body></html>"""
        html_path.write_text(html_doc, encoding="utf-8")
        json_path.write_text(json.dumps(cert, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"json": str(json_path), "html": str(html_path), "qrPng": str(qr_path)}

    def load(self, certificate_id: str) -> dict[str, Any]:
        path = self.certificates_dir / f"{certificate_id}.json"
        if not path.exists():
            raise FileNotFoundError(certificate_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def verify(self, cert: dict[str, Any], digest: str | None = None) -> dict[str, Any]:
        sig = cert.get("signature", {})
        core = {k: v for k, v in cert.items() if k not in {"signature", "artifactPaths"}}
        expected_sig = sig.get("value")
        actual_sig = self._sign(core)
        signature_valid = bool(expected_sig) and hmac.compare_digest(expected_sig, actual_sig)

        stored_digest = cert.get("certificateDigestSha256")
        digest_core = {k: v for k, v in core.items() if k != "certificateDigestSha256"}
        actual_digest = canonical_hash(digest_core)
        certificate_digest_valid = bool(stored_digest) and stored_digest == actual_digest
        requested_digest_valid = True if digest is None else digest == cert.get("verification", {}).get("verificationIntegritySha256")

        return {
            "certificateId": cert.get("certificateId"),
            "valid": signature_valid and certificate_digest_valid and requested_digest_valid,
            "signatureValid": signature_valid,
            "certificateDigestValid": certificate_digest_valid,
            "requestedVerificationDigestValid": requested_digest_valid,
            "tamperStatus": cert.get("verification", {}).get("tamperStatus"),
            "verificationState": cert.get("verification", {}).get("verificationState"),
        }
