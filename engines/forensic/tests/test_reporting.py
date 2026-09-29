from app.engine import ForensicEngine
from app.reporting import write_reports


def test_all_report_formats(tmp_path):
    source=tmp_path/'src'; source.mkdir(); (source/'a.txt').write_text('abc')
    report=ForensicEngine(job_id='J').analyze(source)
    paths=write_reports(report,tmp_path/'out'/'report',['json','csv','txt','html'])
    assert set(paths)=={'json','csv','txt','html'}
    for p in paths.values():
        from pathlib import Path
        assert Path(p).exists() and Path(p).stat().st_size>0
