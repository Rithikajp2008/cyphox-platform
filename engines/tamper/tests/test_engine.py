from pathlib import Path
from tamper_app.tamper_engine import create_baseline, verify_target_against_baseline, verify_baseline_integrity


def base(tmp_path):
    (tmp_path/"a.txt").write_text("hello", encoding="utf-8")
    (tmp_path/"b.txt").write_text("world", encoding="utf-8")
    return create_baseline(target_path=str(tmp_path),user_id="u",device_id="d",session_id="s",baseline_id="B1",job_id="J1",max_files=100,check_metadata=False)


def verify(b, tmp_path):
    return verify_target_against_baseline(baseline=b,target_path=str(tmp_path),verification_id="V1",job_id="J2",user_id="u",device_id="d",session_id="s",max_files=100,check_metadata=False)


def test_baseline_integrity(tmp_path):
    b=base(tmp_path); assert verify_baseline_integrity(b)["valid"] is True


def test_intact(tmp_path):
    b=base(tmp_path); r=verify(b,tmp_path); assert r["tamperStatus"]=="INTACT"; assert r["summary"]["changeCount"]==0


def test_modified(tmp_path):
    b=base(tmp_path); (tmp_path/"a.txt").write_text("changed",encoding="utf-8"); r=verify(b,tmp_path)
    assert r["tamperStatus"]=="TAMPERED"; assert r["summary"]["modified"]==1


def test_added_deleted(tmp_path):
    b=base(tmp_path); (tmp_path/"a.txt").unlink(); (tmp_path/"c.txt").write_text("new",encoding="utf-8"); r=verify(b,tmp_path)
    assert r["summary"]["added"]==1; assert r["summary"]["deleted"]==1


def test_rename_detection(tmp_path):
    b=base(tmp_path); (tmp_path/"a.txt").rename(tmp_path/"renamed.txt"); r=verify(b,tmp_path)
    assert r["summary"]["renamed"]==1; assert r["summary"]["added"]==0; assert r["summary"]["deleted"]==0
