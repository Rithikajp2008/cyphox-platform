const TAMPER_SERVICE_URL = "http://127.0.0.1:8004/api/v1";

function tamperAuthHeaders(){
  const token = localStorage.getItem("cyberwipe_token");
  return {
    "Content-Type":"application/json",
    ...(token ? {Authorization:`Bearer ${token}`} : {})
  };
}

async function tamperRequest(path, options={}){
  const response = await fetch(`${TAMPER_SERVICE_URL}${path}`, {
    ...options,
    headers:{...tamperAuthHeaders(), ...(options.headers||{})}
  });
  let data={};
  try{ data=await response.json(); }catch(_){ }
  if(!response.ok) throw new Error(data.detail || `Tamper API failed (${response.status})`);
  return data;
}

async function createTamperBaseline({userId="LOCAL-USER",deviceId="LOCAL-DEVICE",sessionId="LOCAL-SESSION",targetPath,maxFiles=10000,checkMetadata=true}){
  return tamperRequest("/tamper/baselines", {method:"POST",body:JSON.stringify({userId,deviceId,sessionId,targetPath,maxFiles,checkMetadata})});
}

async function getTamperJob(jobId){ return tamperRequest(`/tamper/jobs/${encodeURIComponent(jobId)}`); }
async function getTamperBaseline(baselineId){ return tamperRequest(`/tamper/baselines/${encodeURIComponent(baselineId)}`); }

async function startTamperVerification({userId="LOCAL-USER",deviceId="LOCAL-DEVICE",sessionId="LOCAL-SESSION",baselineId,targetPath=null}){
  return tamperRequest("/tamper/verifications", {method:"POST",body:JSON.stringify({userId,deviceId,sessionId,baselineId,targetPath})});
}

async function getTamperVerification(verificationId){ return tamperRequest(`/tamper/verifications/${encodeURIComponent(verificationId)}`); }

async function issueTamperCertificate({verificationId,userId="LOCAL-USER",sessionId="LOCAL-SESSION"}){
  return tamperRequest("/certificates", {method:"POST",body:JSON.stringify({verificationId,userId,sessionId})});
}

async function getCertificate(certificateId){ return tamperRequest(`/certificates/${encodeURIComponent(certificateId)}`); }
function certificateQrUrl(certificateId){ return `${TAMPER_SERVICE_URL}/certificates/${encodeURIComponent(certificateId)}/qr`; }
function certificateHtmlUrl(certificateId){ return `${TAMPER_SERVICE_URL}/certificates/${encodeURIComponent(certificateId)}/html`; }
