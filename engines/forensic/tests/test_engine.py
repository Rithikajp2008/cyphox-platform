from pathlib import Path
from app.engine import ForensicEngine, verify_report


def test_basic_scan_and_integrity(tmp_path):
    (tmp_path/'a.txt').write_text('hello CYBER_TEST', encoding='utf-8')
    (tmp_path/'b.txt').write_text('hello CYBER_TEST', encoding='utf-8')
    (tmp_path/'empty.txt').write_bytes(b'')
    r = ForensicEngine(keywords=['CYBER_TEST'], job_id='J1', session_id='S1', device_id='D1').analyze(tmp_path)
    assert r['summary']['file_count'] == 3
    assert len(r['duplicates']) == 1
    assert any(f['type']=='ZERO_BYTE_FILES' for f in r['findings'])
    assert any(f['type']=='KEYWORD_HITS' for f in r['findings'])
    assert all(x['evidence_id'].startswith('EVID-') for x in r['evidence_manifest'])
    assert verify_report(r)['valid'] is True


def test_signature_mismatch(tmp_path):
    p=tmp_path/'fake.jpg'; p.write_bytes(b'MZ'+b'X'*20)
    r=ForensicEngine().analyze(tmp_path)
    assert any(f['type']=='CONTENT_EXTENSION_MISMATCH' for f in r['findings'])


def test_tamper_detection(tmp_path):
    p=tmp_path/'a.txt'; p.write_text('hello')
    r=ForensicEngine().analyze(tmp_path)
    assert verify_report(r)['valid']
    r['summary']['file_count']=999
    assert verify_report(r)['valid'] is False


def test_missing_target():
    import pytest
    with pytest.raises(FileNotFoundError): ForensicEngine().analyze('/__cyphox_missing_target__')


def test_hash_failure_keeps_evidence_and_marks_warning(tmp_path, monkeypatch):
    from app import engine as E
    p = tmp_path/'large.mkv'
    p.write_bytes(b'x' * 1024)
    def boom(path, algorithm, chunk_size=1024*1024):
        raise OSError(22, 'Invalid argument')
    monkeypatch.setattr(E, 'hash_file', boom)
    r = E.ForensicEngine(job_id='JHASH').analyze(tmp_path)
    assert r['summary']['file_count'] == 1
    assert r['evidence_manifest'][0]['name'] == 'large.mkv'
    assert r['evidence_manifest'][0]['sha256'] is None
    assert r['summary']['scan_error_count'] == 1
    assert r['summary']['complete'] is False
    assert r['summary']['completedWithWarnings'] is True
    assert r['scan_errors'][0]['stage'] == 'SHA256'
    assert E.verify_report(r)['valid'] is True


def test_device_fallback_uses_requested_id(tmp_path, monkeypatch):
    from app import engine as E
    (tmp_path/'a.txt').write_text('x')
    monkeypatch.setattr(E, 'device_for_path', lambda path: None)
    monkeypatch.setattr(E, 'list_devices', lambda: [{"deviceId":"DRIVE-D","mountPoint":"D:\\\\","driveType":"REMOVABLE"}])
    r = E.ForensicEngine(device_id='DRIVE-D').analyze(tmp_path)
    assert r['device']['deviceId'] == 'DRIVE-D'
