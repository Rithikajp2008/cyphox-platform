import time
from fastapi.testclient import TestClient
from app.main import app

c=TestClient(app)

def wait_job(jid):
    for _ in range(100):
        data=c.get(f'/api/v1/forensics/jobs/{jid}').json()
        if data['status'] in ('SUCCESS','FAILED'): return data
        time.sleep(.02)
    raise AssertionError('job timeout')


def test_health():
    assert c.get('/health').json()['status']=='OK'
    assert c.get('/').json()['mode']=='READ_ONLY'


def test_devices():
    x=c.get('/api/v1/forensics/devices')
    assert x.status_code==200 and x.json()['status']=='SUCCESS'
    assert isinstance(x.json()['devices'],list)


def test_job_flow(tmp_path):
    (tmp_path/'x.txt').write_text('hello')
    payload={'userId':'U','deviceId':'D','sessionId':'S','targetPath':str(tmp_path),'saveReport':False}
    x=c.post('/api/v1/forensics/jobs',json=payload)
    assert x.status_code==202
    jid=x.json()['jobId']
    done=wait_job(jid)
    assert done['status']=='SUCCESS'
    assert done['result']['operation']=='DIGITAL_FORENSICS'
    assert done['result']['readOnly'] is True
    f=c.get(f'/api/v1/forensics/jobs/{jid}/findings')
    assert f.status_code==200 and 'residualDataAnalysis' in f.json()
    r=c.get(f'/api/v1/forensics/jobs/{jid}/report')
    assert r.status_code==200 and r.json()['report']['identifiers']['jobId']==jid


def test_verify_endpoint(tmp_path):
    (tmp_path/'x.txt').write_text('hello')
    x=c.post('/api/v1/forensics/scan',json={'target':str(tmp_path),'save_report':False})
    assert x.status_code==200 and x.json()['status']=='SUCCESS'
    report=x.json()['report']
    v=c.post('/api/v1/forensics/verify',json={'report':report})
    assert v.json()['valid'] is True


def test_legacy_scan_missing():
    x=c.post('/api/v1/forensics/scan',json={'target':'/__cyphox_missing__'})
    assert x.status_code==404
