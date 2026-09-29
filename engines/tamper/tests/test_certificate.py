import json
from tamper_app.tamper_engine import create_baseline, verify_target_against_baseline
from tamper_app.certificate_service import CertificateService


def make_verification(tmp_path):
    target=tmp_path/"target"; target.mkdir(); (target/"a.txt").write_text("hello",encoding="utf-8")
    b=create_baseline(target_path=str(target),user_id="u",device_id="d",session_id="s",baseline_id="B1",job_id="J1",max_files=10,check_metadata=False)
    return verify_target_against_baseline(baseline=b,target_path=str(target),verification_id="V1",job_id="J2",user_id="u",device_id="d",session_id="s",max_files=10,check_metadata=False)


def test_certificate_and_qr(tmp_path):
    v=make_verification(tmp_path); svc=CertificateService(tmp_path/"certs",tmp_path/"keys")
    cert=svc.create(v,certificate_id="C1",user_id="u",session_id="s",title="Test")
    assert svc.verify(cert)["valid"] is True
    assert (tmp_path/"certs"/"C1-QR.png").exists()
    assert (tmp_path/"certs"/"C1.html").exists()


def test_certificate_tamper_detected(tmp_path):
    v=make_verification(tmp_path); svc=CertificateService(tmp_path/"certs",tmp_path/"keys")
    cert=svc.create(v,certificate_id="C1",user_id="u",session_id="s",title="Test")
    cert["verification"]["tamperStatus"]="TAMPERED"
    assert svc.verify(cert)["valid"] is False
