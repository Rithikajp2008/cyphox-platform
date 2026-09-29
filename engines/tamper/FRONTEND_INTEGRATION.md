# Frontend integration contract

Do not replace the existing `API_BASE_URL = "http://localhost:5000/api"`. Add a second base URL for verification/certificates:

```js
const TAMPER_SERVICE_URL = "http://127.0.0.1:8004/api/v1";
```

Use `frontend/tamper_adapter.js` as the browser adapter.

## Typical UI flow

### A. Baseline

`POST /tamper/baselines`

```json
{
  "userId":"LOCAL-USER",
  "deviceId":"DRIVE-D",
  "sessionId":"SESSION-TAMPER-001",
  "targetPath":"D:\\Cyphox_Tamper_Test",
  "maxFiles":1000,
  "checkMetadata":true
}
```

Poll `/tamper/jobs/{jobId}` until `SUCCESS`. Save the returned `baselineId` in the main backend/database later.

### B. Verification

`POST /tamper/verifications`

```json
{
  "userId":"LOCAL-USER",
  "deviceId":"DRIVE-D",
  "sessionId":"SESSION-TAMPER-002",
  "baselineId":"BASELINE-...",
  "targetPath":"D:\\Cyphox_Tamper_Test"
}
```

Poll the job. When complete, the result has `tamperStatus`, `verificationState`, `summary`, and `changes`.

### C. Certificate + QR

`POST /certificates`

```json
{
  "userId":"LOCAL-USER",
  "sessionId":"SESSION-TAMPER-002",
  "verificationId":"VERIFY-..."
}
```

Use the returned certificate ID for JSON, HTML, QR, and public verification routes.
