/* Cyphox Forensics adapter for the supplied index.html.
   Keep API_BASE_URL (Node/Express auth/database) unchanged.
   Add this second service URL for forensic operations. */

const FORENSICS_API_URL = "http://127.0.0.1:8003/api/v1/forensics";

async function forensicRequest(endpoint, options = {}) {
  const token = localStorage.getItem("cyberwipe_token");
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${FORENSICS_API_URL}${endpoint}`, {
    ...options,
    headers
  });

  let data = {};
  try { data = await response.json(); } catch (_) {}
  if (!response.ok) {
    const message = data.detail || data.error || `Forensics API failed (${response.status})`;
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }
  return data;
}

async function listForensicDevices() {
  return forensicRequest("/devices");
}

async function startForensicJob({userId, deviceId, sessionId, targetPath, keywords = []}) {
  return forensicRequest("/jobs", {
    method: "POST",
    body: JSON.stringify({
      userId, deviceId, sessionId, targetPath,
      includeHashes: true,
      maxFiles: 10000,
      saveReport: true,
      reportFormats: ["json", "csv", "txt", "html"],
      keywords
    })
  });
}

async function getForensicJob(jobId) {
  return forensicRequest(`/jobs/${encodeURIComponent(jobId)}`);
}

async function waitForForensicJob(jobId, {intervalMs = 800, timeoutMs = 120000} = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const job = await getForensicJob(jobId);
    if (["SUCCESS", "FAILED", "CANCELLED"].includes(job.status)) return job;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error("Forensic job timed out in the browser.");
}

async function getForensicFindings(jobId) {
  return forensicRequest(`/jobs/${encodeURIComponent(jobId)}/findings`);
}

async function getForensicReport(jobId) {
  return forensicRequest(`/jobs/${encodeURIComponent(jobId)}/report`);
}

async function verifyForensicReport(report) {
  return forensicRequest("/verify", {
    method: "POST",
    body: JSON.stringify({report})
  });
}
