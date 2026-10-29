"""Custom executor identifiers never authorize ambient Mission cancellation."""
from pathlib import Path

import pytest

from unrest_harness import run_control,run_worker


@pytest.mark.parametrize('built_in',(False,True))
def test_cancelled_worker_keeps_executor_project_scope(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,built_in: bool) -> None:
    reference='unrest_harness.runtime_executor:execute' if built_in else 'custom:execute'
    snapshots=[]
    def execute(operation,arguments,context):
        raise run_worker.WorkerCancelled()
    monkeypatch.setattr(run_control,'load_executor',lambda ref:execute)
    monkeypatch.setattr(run_worker,'load_executor',lambda ref:execute)
    monkeypatch.setattr(run_control.RunControl,'_spawn',lambda *args:None)
    monkeypatch.setattr(run_worker.signal,'signal',lambda *args:None)
    def forbidden_discovery(*args,**kwargs):
        pytest.fail('custom executor crossed into ambient Mission configuration')
    monkeypatch.setattr(run_worker.HarnessConfig,'discover',forbidden_discovery)
    if built_in:
        monkeypatch.setattr(run_worker,'_terminalize_cancelled_attempts',lambda arguments:snapshots.append(dict(arguments)))
    control=run_control.RunControl(tmp_path,executor_ref=reference,recover=False)
    arguments={'project_id':'executor-owned-project'}
    queued=control.submit_run('advance_project',arguments,'idem:cancel-scope')
    status=run_worker.main(['--project-root',str(tmp_path),'--run-id',queued.run_id,
        '--executor',reference,'--custody-root-id','local:unrest-run-control','--generation','1'])
    assert status==2
    assert control.inspect_run(queued.run_id).state=='cancelled'
    assert snapshots==([arguments] if built_in else [])
