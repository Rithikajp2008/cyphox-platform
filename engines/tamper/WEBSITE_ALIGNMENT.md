# Website alignment

The current Cyphox frontend already has separate **Verification** and **Certificates** pages. Keep that separation.

Recommended service layout:

- Main Node/Express + SQL Server: `http://localhost:5000/api` — login, users, database/history.
- Tamper + certificate service: `http://127.0.0.1:8004/api/v1` — baseline verification and certificate/QR.

## Verification page mapping

1. Create/select baseline.
2. Start verification.
3. Poll job status.
4. Display `verificationState`: `VERIFIED`, `NOT_VERIFIED`, or API/job failure.
5. Display `tamperStatus`: `INTACT`, `TAMPERED`, `INDETERMINATE`.
6. Show counts and detailed `changes` arrays.

## Certificates page mapping

After a verification record exists, call `POST /api/v1/certificates`. Display:

- certificate ID
- verification ID / baseline ID
- target
- issued time
- tamper status
- signed-certificate validity
- QR image from `/api/v1/certificates/{id}/qr`
- HTML certificate from `/api/v1/certificates/{id}/html`

The certificate module is generic enough to be extended later for erasure certificates without moving QR generation into the tamper engine.
