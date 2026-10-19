"""New controlled proofs of actual original-parent multiprocessing cleanup."""
from __future__ import annotations

import asyncio
import multiprocessing
from multiprocessing import resource_tracker, util
import os

import pytest

from tests.multiprocess_lifetime import SpawnResources


def _publish(queue, gate, value):
    assert gate.wait(10)
    queue.put((os.getpid(), value.value))


def _exit_with_status(status):
    raise SystemExit(status)


def _wait(gate):
    assert gate.wait(10)


def test_joined_spawn_queue_event_and_value_close_before_summary():
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context('spawn'))
        queue = context.Queue()
        gate = context.Event()
        value = context.Value('i', 37)
        process = context.Process(target=_publish, args=(queue, gate, value))
        process.start()
        pid = process.pid
        gate.set()
        assert queue.get(timeout=10) == (pid, 37)
        process.join(10)
        assert process.exitcode == 0
        tracker_pid = owner.pid
        owned_finalizers = tuple(owner.finalizers)
    assert owner.closed
    assert resource_tracker._resource_tracker._pid is None
    assert resource_tracker._resource_tracker._fd is None
    assert resource_tracker._resource_tracker._exitcode == 0
    assert process._closed and queue._closed
    assert queue._reader.closed and queue._writer.closed
    assert all(not finalizer.still_active() for finalizer in owned_finalizers)
    with pytest.raises(ChildProcessError):
        os.waitpid(tracker_pid, os.WNOHANG)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_parent_feeder_and_both_pipe_endpoints_are_settled():
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context('spawn'))
        queue = context.Queue()
        parent, child = context.Pipe()
        queue.put('owned')
        assert queue.get(timeout=5) == 'owned'
        parent.send('pipe')
        assert child.recv() == 'pipe'
        feeder = queue._thread
    assert not feeder.is_alive()
    assert queue._reader.closed and queue._writer.closed
    assert parent.closed and child.closed


@pytest.mark.parametrize('error', [ValueError('original test error'), asyncio.CancelledError()])
def test_original_failure_or_cancellation_survives_clean_teardown(error):
    owner = SpawnResources()
    with pytest.raises(type(error)) as caught:
        with owner:
            owner.context(multiprocessing.get_context('spawn')).Queue()
            raise error
    assert caught.value is error
    assert owner.closed and resource_tracker._resource_tracker._pid is None


def test_live_child_refusal_preserves_original_error_and_does_not_kill():
    owner = SpawnResources()
    original = ValueError('causal assertion failure')
    try:
        with pytest.raises(ExceptionGroup) as caught:
            with owner:
                context = owner.context(multiprocessing.get_context('spawn'))
                gate = context.Event()
                process = context.Process(target=_wait, args=(gate,))
                process.start()
                raise original
        assert caught.value.exceptions[0] is original
        assert 'has not been joined' in str(caught.value.exceptions[1])
        assert process.is_alive()
        assert owner.tracker._pid == owner.pid
    finally:
        gate.set()
        process.join(10)
        assert process.exitcode == 0
        owner.close()


@pytest.mark.parametrize('status', [0, 17])
def test_original_child_status_is_preserved(status):
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context('spawn'))
        process = context.Process(target=_exit_with_status, args=(status,))
        process.start()
        process.join(10)
        assert process.exitcode == status


def test_preexisting_tracker_is_refused_and_left_owned_by_its_parent():
    tracker = resource_tracker._resource_tracker
    with SpawnResources() as original:
        original.context(multiprocessing.get_context('spawn'))
        identity = tracker._pid, tracker._fd, os.fstat(tracker._fd)
        with pytest.raises(RuntimeError, match='preexisting'):
            with SpawnResources() as owner:
                owner.context(multiprocessing.get_context('spawn'))
        assert (tracker._pid, tracker._fd, os.fstat(tracker._fd)) == identity
    assert tracker._exitcode == 0


def test_reused_descriptor_number_has_no_pipe_authority():
    owner = SpawnResources()
    owner.context(multiprocessing.get_context('spawn'))
    foreign = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(foreign, owner.fd, inheritable=False)
        with pytest.raises(RuntimeError, match='generation changed'):
            owner.close()
        assert not owner.closed
    finally:
        os.dup2(owner.custody, owner.fd, inheritable=False)
        os.close(foreign)
        owner.close()


def test_case_drift_refuses_without_releasing_owned_resources(monkeypatch):
    owner = SpawnResources()
    owner.context(multiprocessing.get_context('spawn'))
    before = os.environ.get('PYTEST_CURRENT_TEST')
    monkeypatch.setenv('PYTEST_CURRENT_TEST', 'foreign-case (call)')
    with pytest.raises(RuntimeError, match='case/parent'):
        owner.close()
    if before is None:
        monkeypatch.delenv('PYTEST_CURRENT_TEST')
    else:
        monkeypatch.setenv('PYTEST_CURRENT_TEST', before)
    owner.close()


def test_unrelated_finalizer_is_not_consumed():
    calls = []
    unrelated = util.Finalize(None, calls.append, ('unrelated',), exitpriority=0)
    try:
        with SpawnResources() as owner:
            owner.context(multiprocessing.get_context('spawn')).Event()
        assert unrelated.still_active() and calls == []
    finally:
        unrelated()
    assert calls == ['unrelated']


def test_altered_stdlib_stop_is_refused_before_launch(monkeypatch):
    tracker = resource_tracker._resource_tracker
    with monkeypatch.context() as patch:
        patch.setattr(type(tracker), '_stop', lambda self: None)
        with pytest.raises(RuntimeError, match='differs from stdlib'):
            with SpawnResources() as owner:
                owner.context(multiprocessing.get_context('spawn'))
        assert tracker._pid is None and tracker._fd is None
