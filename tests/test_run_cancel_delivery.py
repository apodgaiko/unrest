"""Cancellation notifies the retained owner without killing its cleanup chain."""
from pathlib import Path
import os
import signal
import time

import pytest

import unrest_harness.run_control as runs


@pytest.mark.parametrize('mismatch',[None,'generation','session'])
def test_cancel_targets_only_matching_worker_and_keeps_durable_replay(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,mismatch: str | None) -> None:
    control=runs.RunControl(tmp_path,executor_ref='unrest_harness.runtime_executor:execute',recover=False)
    monkeypatch.setattr(control,'_spawn',lambda request:None)
    run=control.submit_run('advance_project',{'project_id':'project','max_steps':1},'admit')
    pid=12345
    assert control.worker_start(run.run_id,pid=pid,pgid=pid,generation=1)
    cursor=control._load_worker_cursor(run.run_id)
    assert cursor is not None
    if mismatch=='generation':
        cursor={**cursor,'generation':2}
    monkeypatch.setattr(control,'_load_worker_cursor',lambda run_id:cursor)
    monkeypatch.setattr(runs.os,'getpgid',lambda candidate:pid)
    monkeypatch.setattr(runs.os,'getsid',lambda candidate:pid+int(mismatch=='session'))
    monkeypatch.setattr(runs,'_pid_live',lambda candidate:True)
    calls=[]
    monkeypatch.setattr(runs.os,'kill',lambda candidate,sig:calls.append((candidate,sig)))
    monkeypatch.setattr(runs.os,'killpg',lambda *args:pytest.fail('managed children must drain through their owner'))
    first=control.cancel_run(run.run_id,'stop','cancel-once')
    assert first.state==('cancel_requested' if mismatch is None else 'cancelled')
    assert calls==([(pid,signal.SIGTERM)] if mismatch is None else [])
    assert control.cancel_run(run.run_id,'stop','cancel-once')==first
    assert calls==([(pid,signal.SIGTERM)] if mismatch is None else [])


def test_cancel_registered_child_drains_before_unlock(tmp_path: Path) -> None:
    checkout=Path(__file__).resolve().parents[1]
    control=runs.RunControl(tmp_path,executor_ref='tests.fixtures.cancel_registered_executor:execute',
        worker_environment={'PYTHONPATH':str(checkout)+os.pathsep+str(checkout/'src')})
    run=control.submit_run('advance_project',{'project_id':'project','max_steps':1},'registered-child')

    def wait_for(name: str) -> None:
        until=time.monotonic()+5
        while not (tmp_path/name).exists():
            assert time.monotonic()<until, name
            time.sleep(0.01)

    try:
        wait_for('child-ready')
        control.cancel_run(run.run_id,'stop','cancel-registered')
        wait_for('child-cleanup-started')
        assert control.inspect_run(run.run_id).state not in runs.TERMINAL_RUN_STATES
        with pytest.raises(runs.RunControlError) as busy:
            control.submit_run('advance_project',{'project_id':'project','max_steps':1},'competing-run')
        assert busy.value.code=='busy'
        (tmp_path/'allow-child-exit').write_text('finish')
        assert control.attach_run(run.run_id,timeout_seconds=5).state=='cancelled'
    finally:
        (tmp_path/'allow-child-exit').write_text('finish')
        control.attach_run(run.run_id,timeout_seconds=5)
