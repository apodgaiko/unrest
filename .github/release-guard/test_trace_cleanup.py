"""Synthetic control-flow tests; real waits are covered in test_kernel_trace."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import signal

import pytest

spec = importlib.util.spec_from_file_location("cleanup_trace", Path(__file__).with_name("linux_trace.py"))
assert spec is not None and spec.loader is not None
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def owned():
    value = object.__new__(trace.OwnedTrace)
    value.child = 11
    value.active = {11, 12}
    value.pidfds = {11: 101, 12: 102}
    value.records, value.poison = [], []
    value.cleanup_seconds = .05
    value.root_parent_wait = None
    value.foreign = set()
    value.start_write = None
    value.attached = {11, 12}
    value.stopped = {}
    value.harvested = set()
    value.vforks = {}
    value.identities = {}
    value.acquired_root = {"pid": 11, "tgid": 11, "ppid": trace.os.getpid(),
                           "start_ticks": 4, "boot_id": "boot"}
    return value


def test_cleanup_waits_only_exact_owned_pids(monkeypatch):
    value = owned()
    waited, signals = [], []
    monkeypatch.setattr(trace, "ptrace", lambda op, pid: signals.append((op, pid)))

    def wait(pid, flags):
        waited.append(pid)
        assert pid in {11, 12}
        return pid, 0 if pid == 11 else signal.SIGKILL

    monkeypatch.setattr(trace.os, "waitpid", wait)
    assert value._cleanup() == []
    assert waited == [11, 12] and signals == [(0x4207, 11), (0x4207, 12)]
    assert not value.active and value.root_parent_wait == 0
    assert all(row["kind"] == "failure_cleanup_tracer_wait" for row in value.records)


def test_cleanup_deadline_never_infers_missing_wait(monkeypatch):
    value = owned()
    ticks = iter((0, .01, 1, 1))
    monkeypatch.setattr(trace.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(trace.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(trace, "ptrace", lambda *args: None)
    monkeypatch.setattr(trace.os, "waitpid", lambda *args: (0, 0))
    errors = value._cleanup()
    assert isinstance(errors[-1], TimeoutError)
    assert value.active == {11, 12} and value.root_parent_wait is None
    assert value.poison == ["cleanup_freeze_incomplete", "owned_cleanup_incomplete"]
    assert value.records == [{"kind": "cleanup_incomplete", "pids": [11, 12],
                              "numeric_waits_unverified": True}]


def test_one_cleanup_error_does_not_prevent_other_owned_waits(monkeypatch):
    value = owned()
    original = ChildProcessError("numeric wait missing")
    monkeypatch.setattr(trace, "ptrace", lambda *args: None)

    def wait(pid, flags):
        if pid == 11:
            raise original
        return pid, signal.SIGKILL

    monkeypatch.setattr(trace.os, "waitpid", wait)
    errors = value._cleanup()
    assert errors[0] is original and isinstance(errors[-1], TimeoutError)
    assert value.active == {11} and value.root_parent_wait is None
    assert value.records[0]["pid"] == 12


def test_initial_wait_has_same_deadline_and_is_nonblocking(monkeypatch):
    value = owned()
    value.deadline = .05
    ticks = iter((0, 1))
    calls = []
    monkeypatch.setattr(trace.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(trace.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(trace.os, "waitpid", lambda pid, flags: calls.append((pid, flags)) or (0, 0))
    with pytest.raises(TimeoutError, match="initial stop"):
        value._initial_wait(0x40000000)
    assert calls == [(11, trace.os.WNOHANG | 0x40000000)]


@pytest.mark.parametrize("where", ["attached", "tick"])
def test_setup_and_tick_errors_keep_original_and_cleanup_failures(monkeypatch, where):
    value = owned()
    value.active = {11}
    value.pidfds = {}
    value.attached = set()
    value.start_write = 99
    value.selective = False
    value.deadline = float("inf")
    value.identities = {}
    value.on_tick = None
    value.on_attached = None
    original, cleanup = RuntimeError("initiating"), RuntimeError("cleanup")
    calls = []

    def fail(*args):
        raise original

    value.on_attached = fail if where == "attached" else None
    value.on_tick = fail if where == "tick" else None
    value._pin = lambda pid: {"pid": pid}
    raw = (128 << 16) | (signal.SIGTRAP << 8) | 0x7f
    value._initial_wait = lambda options: (11, raw)
    value._cleanup = lambda: calls.append("cleanup") or [cleanup]
    monkeypatch.setattr(trace, "ptrace", lambda *args, **kwargs: 0)
    monkeypatch.setattr(trace.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(trace.os, "close", lambda fd: None)
    with pytest.raises(BaseExceptionGroup) as result:
        value.run()
    assert result.value.exceptions == (original, cleanup)
    assert calls == ["cleanup"]


def test_pidfd_acquisition_birth_race_closes_acquired_fd(monkeypatch):
    value = owned()
    first = dict(value.acquired_root)
    values = iter((first, {**first, "start_ticks": 5}))
    closed = []
    monkeypatch.setattr(trace._observation, "process_identity", lambda pid: next(values))
    monkeypatch.setattr(trace.os, "pidfd_open", lambda *args: 111, raising=False)
    monkeypatch.setattr(trace.os, "close", closed.append)
    with pytest.raises(RuntimeError, match="birth changed"):
        value._pin(11)
    assert closed == [111]


def test_constructor_run_root_substitution_never_acquires_or_signals_foreign_pid(monkeypatch):
    value = owned()
    value.active = {11}
    value.pidfds = {}
    signals, waits = [], []
    monkeypatch.setattr(trace._observation, "process_identity",
                        lambda pid: {**value.acquired_root, "start_ticks": 99})
    monkeypatch.setattr(trace.os, "pidfd_open", lambda *args: pytest.fail("foreign pidfd acquired"),
                        raising=False)
    monkeypatch.setattr(trace, "ptrace", lambda *args: signals.append(args))
    monkeypatch.setattr(trace.os, "waitpid", lambda *args: waits.append(args) or (0, 0))
    with pytest.raises(RuntimeError, match="original root birth changed"):
        value._pin(11)
    errors = value._cleanup()
    assert errors and not signals and not waits and value.foreign == {11}


def test_pending_birth_is_frozen_before_any_kill(monkeypatch):
    value = owned()
    value.active = value.attached = {11}
    value.newborn = set()
    value.stopped = {11: (1 << 16) | (signal.SIGTRAP << 8) | 0x7f}
    value._pin = lambda pid: {'pid': pid}
    calls = []
    terminal = set()

    def operation(op, pid, address=0, data=0):
        calls.append((op, pid))
        if op == 0x4201:
            data._obj.value = 12
        elif op == 8:
            assert value.active == {11, 12}
            assert set(value.stopped) == {11, 12}
            terminal.add(pid)

    def wait(pid, flags):
        if pid in terminal:
            return pid, signal.SIGKILL
        assert pid == 12
        return pid, (128 << 16) | (signal.SIGTRAP << 8) | 0x7f

    monkeypatch.setattr(trace, 'ptrace', operation)
    monkeypatch.setattr(trace.os, 'waitpid', wait)
    assert value._cleanup() == []
    assert calls.index((0x4201, 11)) < calls.index((8, 11))
    assert not value.active and value.root_parent_wait == signal.SIGKILL
    assert [row['pid'] for row in value.records if row['kind'] == 'failure_cleanup_tracer_wait'] == [11, 12]


def test_failed_kill_never_resumes_owned_body(monkeypatch):
    value = owned()
    value.active = value.attached = {11}
    value.stopped = {11: (128 << 16) | (signal.SIGTRAP << 8) | 0x7f}
    calls = []

    def operation(op, pid):
        calls.append((op, pid))
        assert op != 7, 'body resumed after failed kill'
        raise PermissionError('controlled refused kill')

    monkeypatch.setattr(trace, 'ptrace', operation)
    errors = value._cleanup()
    assert isinstance(errors[0], PermissionError) and isinstance(errors[-1], TimeoutError)
    assert calls == [(8, 11)] and value.active == {11}


def test_cleanup_interrupt_still_closes_all_descriptors(monkeypatch):
    value = owned()
    value._pin = lambda pid: (_ for _ in ()).throw(RuntimeError('setup'))
    value._cleanup = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
    closed = []
    monkeypatch.setattr(trace.os, 'close', closed.append)
    with pytest.raises(BaseExceptionGroup) as result:
        value.run()
    assert isinstance(result.value.exceptions[1], KeyboardInterrupt)
    assert closed == [101, 102] and not value.pidfds
    assert value.records[-1]['numeric_waits_unverified']


def test_post_kill_resume_disappearance_still_requires_actual_wait(monkeypatch):
    value = owned()
    value.active = value.attached = {11}
    value.stopped = {11: (128 << 16) | (signal.SIGTRAP << 8) | 0x7f}
    waits = []

    def operation(op, pid):
        if op == 7:
            raise ProcessLookupError('kill already advanced stop')
        assert op == 8

    monkeypatch.setattr(trace, 'ptrace', operation)
    monkeypatch.setattr(trace.os, 'waitpid',
                        lambda pid, flags: waits.append(pid) or (pid, signal.SIGKILL))
    assert value._cleanup() == []
    assert waits == [11] and value.root_parent_wait == signal.SIGKILL and not value.active


def test_vfork_child_stop_settles_before_suspended_parent(monkeypatch):
    value = owned()
    value.vforks = {11: 12}
    value.stopped = {12: (7 << 16) | (signal.SIGTRAP << 8) | 0x7f}
    killed = set()
    parent_stopped = False

    def operation(op, pid, *args):
        if op == 8:
            assert pid == 12 or 12 not in value.active
            killed.add(pid)

    def wait(pid, flags):
        nonlocal parent_stopped
        if pid in killed:
            return pid, signal.SIGKILL
        if pid == 11 and 12 not in value.active and not parent_stopped:
            parent_stopped = True
            return pid, (128 << 16) | (signal.SIGTRAP << 8) | 0x7f
        return 0, 0

    monkeypatch.setattr(trace, 'ptrace', operation)
    monkeypatch.setattr(trace.os, 'waitpid', wait)
    assert value._cleanup() == []
    assert killed == {11, 12} and not value.active and not value.poison
    assert value.root_parent_wait == signal.SIGKILL
