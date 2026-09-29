# Cyphox Website Integration Contract

The supplied `index1.html` currently uses the Node/Express auth/database backend at `http://localhost:5000/api`. Keep that unchanged. The forensic service should be a second local API.

Recommended frontend configuration:
```js
const API_BASE_URL = "http://localhost:5000/api";       // existing auth/database backend
const FORENSICS_API_URL = "http://127.0.0.1:8003/api/v1/forensics";
```

## Forensics page flow
1. `GET /devices` – show local drives / USB devices.
2. User chooses a file, folder, or drive path.
3. `POST /jobs` – starts the read-only forensic scan and returns a `jobId`.
4. Poll `GET /jobs/{jobId}` until `SUCCESS` or `FAILED`.
5. `GET /jobs/{jobId}/findings` – populate the website's findings/artifacts/residual-analysis cards.
6. `GET /jobs/{jobId}/report` – get the complete evidence manifest and report paths.
7. `POST /verify` – independently verify the JSON report integrity hash.

### Create job example
```json
{
  "userId": "USER-001",
  "deviceId": "DRIVE-E",
  "sessionId": "SESSION-001",
  "targetPath": "E:\\Evidence",
  "includeHashes": true,
  "includeMd5": false,
  "includeSha1": false,
  "maxFiles": 10000,
  "saveReport": true,
  "reportFormats": ["json", "csv", "txt", "html"],
  "keywords": ["confidential"]
}
```

### Job response shape
```json
{
  "userId": "USER-001",
  "deviceId": "DRIVE-E",
  "sessionId": "SESSION-001",
  "jobId": "FORENSICS-ABC123",
  "status": "PENDING",
  "timestamp": "...",
  "result": null,
  "error": null
}
```

On success, `result` contains `summary`, `findings`, `artifacts`, `residualDataAnalysis`, `reportIntegritySha256`, `reportPaths`, and the full `report`.

## Important scope note
The website says “residual-data analysis”. This forensic service reports residual indicators that are visible in allocated files (zero-byte files, hidden/system files, signature/extension mismatches, duplicates, keyword matches). It deliberately does not carve deleted/unallocated space; that remains Recovery Engine scope.
