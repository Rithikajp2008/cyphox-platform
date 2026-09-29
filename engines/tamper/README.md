# CYPHOX Tamper Verification + Certificate/QR Service

> **Important:** This package uses the unique Python module `tamper_app` to avoid collision with other Cyphox services. Run `tamper_app.main:app` on port **8004**. If Swagger shows unrelated module endpoints, the wrong project is running.



## Architecture

- **Tamper Engine**: baseline + re-scan + compare + `INTACT` / `TAMPERED` / `INDETERMINATE`.
- **Certificate Service**: consumes a completed tamper verification record, signs the certificate using a persistent local HMAC key, generates JSON + HTML + QR PNG, and exposes a QR verification endpoint.
- **QR is not a separate engine**. It is an output of the Certificate Service.

## What counts as tampering

- Same path, different SHA-256: `modified`
- New path: `added`
- Missing path: `deleted`
- Unique same-content move: `renamed`
- Same content but changed modification metadata (when enabled): `metadataChanged`

If scanning is incomplete or contains scan errors, the result becomes `INDETERMINATE` / `NOT_VERIFIED` rather than falsely claiming integrity.

## Windows / VS Code setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python -m pytest -q
python -m uvicorn tamper_app.main:app --host 127.0.0.1 --port 8004 --reload
```

Swagger: `http://127.0.0.1:8004/docs`

## Recommended independent test

1. Create a disposable folder, e.g. `D:\Cyphox_Tamper_Test`.
2. Put 2-3 files inside.
3. `POST /api/v1/tamper/baselines`.
4. Poll `GET /api/v1/tamper/jobs/{jobId}` until `SUCCESS`.
5. Run a verification without changing files: expect `INTACT`.
6. Modify/add/delete/rename files.
7. Run another verification: expect `TAMPERED` with categorized changes.
8. `POST /api/v1/certificates` using the verification ID.
9. Open the returned HTML certificate and QR PNG.
10. `GET /api/v1/certificates/{certificateId}/verify` must return `valid: true`.

## QR notes

The QR stores a verification URL, not raw evidence/file contents. By default the URL points to `127.0.0.1:8004`, which works on the same PC. To scan with a phone, set `CYPHOX_PUBLIC_BASE_URL` to the PC's LAN-accessible URL or a deployed HTTPS domain before issuing the certificate.

## Security note

The service creates a persistent local HMAC signing key at `data/keys/certificate_hmac.key`. Do not commit or share this key. For production, replace local key storage with a protected secret store/KMS and put authentication/authorization in front of this API.
