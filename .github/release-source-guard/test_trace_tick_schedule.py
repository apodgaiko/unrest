"""Deterministic callback ordering plus the real finite Linux exec seam."""
from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

import trace_tick_schedule as scheduling


def test_empty_spins_do_not_reacquire_and_every_kernel_event_forces_fresh_service(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    owner = object()
    calls = []
    service = scheduling.TickSchedule(calls.append, owner)
    service.service()
    for _ in range(1000):
        service.service()
    assert calls == [owner]
    for _ in range(5):
        service.service(kernel_event=True)
    assert calls == [owner] * 6
    now[0] += 0.009
    service.service()
    assert len(calls) == 6
    now[0] += 0.002
    service.service()
    assert len(calls) == 7


def test_idle_interval_starts_after_complete_callback_not_before_acquisition(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    calls = []
    def acquire(owner):
        calls.append(owner)
        now[0] += 1.0
    service = scheduling.TickSchedule(acquire, 'owner')
    service.service()
    service.service()
    assert calls == ['owner'] and service.last == 101.0
    service.service(kernel_event=True)
    assert calls == ['owner', 'owner'] and service.last == 102.0


def test_callback_failure_and_clock_reversal_cannot_be_ignored(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    cause = RuntimeError('fresh acquisition refused')
    def refuse(owner):
        raise cause
    service = scheduling.TickSchedule(refuse, 'owner')
    with pytest.raises(RuntimeError) as caught:
        service.service(kernel_event=True)
    assert caught.value is cause and service.last is None
    service = scheduling.TickSchedule(lambda owner: None, 'owner')
    service.service()
    now[0] -= 1
    with pytest.raises(RuntimeError, match='clock_reversed'):
        service.service(kernel_event=True)


def test_absent_callback_retains_plain_trace_behavior():
    service = scheduling.TickSchedule(None, 'owner')
    service.service()
    service.service(kernel_event=True)
    assert service.last is None


@pytest.mark.skipif(sys.platform != 'linux' or os.uname().machine != 'x86_64',
                    reason='actual Linux ptrace and exec custody')
@pytest.mark.parametrize('accepted', [False, True])
def test_every_actual_exec_stop_is_serviced_before_permission_and_resume(monkeypatch, accepted):
    import linux_trace as trace
    import hashlib
    argv = [sys.executable, '-I', '-S', '-c', 'import os; os._exit(0)']
    child = os.fork()
    if child == 0:
        try:
            trace.install_observation_filter()
            trace.trace_me()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    fresh = [False]
    calls = []
    real_ptrace = trace.ptrace
    def ptrace(request, *args, **kwargs):
        if request in (7, 24):
            fresh[0] = False
        return real_ptrace(request, *args, **kwargs)
    def callback(owner):
        fresh[0] = True
        calls.append(len(owner.records))
    attempts = []
    def resolve(pid, path, vector, environment, cwd):
        assert fresh[0]
        assert pid == child and vector == argv and environment == {} and cwd == os.getcwd()
        assert path == sys.executable
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest()
        attempts.append(pid)
        return accepted
    monkeypatch.setattr(trace, 'ptrace', ptrace)
    result = trace.OwnedTrace(child, [], timeout=10, selective=True,
                              on_tick=callback, resolve_exec=resolve).run()
    assert attempts == [child] and calls
    assert bool(result['poison']) is (not accepted)
    assert result['root_parent_wait_raw'] == (0 if accepted else 127 << 8)
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)
