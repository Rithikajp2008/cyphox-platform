# Website ↔ Forensic Service Alignment

## What the supplied website currently has
- A Forensics navigation page with the presentation concepts **findings, artifacts, residual-data analysis**.
- The page is currently a placeholder and says results will appear after the forensic API is connected.
- Existing authentication/database calls use the Node/Express backend through `http://localhost:5000/api`.

## What this forensic service provides to that page
| Website concept | API/result field |
|---|---|
| Forensic findings | `result.findings` and `GET /jobs/{jobId}/findings` |
| Artifacts | `result.artifacts` |
| Residual-data analysis | `result.residualDataAnalysis` (allocated-file indicators only) |
| Device/USB selection | `GET /devices` |
| Scan progress | async job status: `PENDING → RUNNING → SUCCESS/FAILED` |
| Evidence/report | `GET /jobs/{jobId}/report` |
| Integrity verification | `POST /verify` |
| Correlation with final system | `userId`, `deviceId`, `sessionId`, `jobId` |

## Recommended integration architecture
Do **not** replace the existing auth/database backend.

```text
index.html
  ├─ http://localhost:5000/api        -> Node/Express auth + database
  └─ http://127.0.0.1:8003/api/v1/forensics -> local forensic service
```

When all modules move behind a master backend later, the Node backend may proxy forensic routes if the team wants a single public base URL.
