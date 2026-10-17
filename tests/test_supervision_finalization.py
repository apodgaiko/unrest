"""Finalization fences, using real processes and controlled dispatcher barriers."""
from __future__ import annotations

import fcntl
import multiprocessing
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from unrest_harness import supervision as s
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher
from unrest_harness.models import ActiveAttemptSnapshot, TerminalReviewHandoff, ValidateHandoff, WorkHandoff
from unrest_harness.project_lock import project_access_guard
from unrest_harness.storage import ProjectStore
from tests.test_supervision import STEERING_TARGETS, _config, _prepare_role_checkpoint, _request


def _publisher(home, payload, ordering, pipe):
    store = ProjectStore(_config(Path(home)))
    snapshot = ActiveAttemptSnapshot.model_validate(payload)
    # Same admission read as a role call, deliberately before ownership.
    current = s.load_snapshot(store, snapshot.project_id, snapshot.mission_id, snapshot.attempt_id)
    assert current.checkpoint_sequence == 0
    seen = False

    def trace(frame, event, arg):
        nonlocal seen
        if (ordering == 'publication_first' and event == 'line'
                and frame.f_code is s.save_snapshot.__code__
                and 'current' in frame.f_locals and not seen):
            seen = True
            pipe.send('snapshot_owned')
            assert pipe.poll(15)
            pipe.recv()
        return trace

    try:
        if ordering == 'finalization_first':
            pipe.send('admission_read')
            assert pipe.poll(15)
            pipe.recv()
        sys.settrace(trace)
        try:
            binding = s.report_supervision_checkpoint(store, snapshot,
                assigned_target_ids=STEERING_TARGETS, project_guard=False)
            pipe.send(('accepted', binding.checkpoint_sequence))
        except s.SupervisionSnapshotError:
            pipe.send(('refused', None))
    finally:
        sys.settrace(None)
        pipe.close()


def _prepare(tmp_path, role):
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, role)
    # Setup only: no processes or owners exist yet.
    for path in s.supervision_runtime_dir(store, binding.project_id, binding.mission_id).iterdir():
        path.unlink()
    state = store.load_task_state(binding.project_id, binding.mission_id)
    for task in store.load_task_list(binding.project_id, binding.mission_id).tasks:
        state.set_status(task.id, 'cleared' if role == 'terminal_reviewer' else 'pending')
    if role == 'validator':
        state.set_status('work-1', 'cleared')
    store.save_task_state(binding.project_id, binding.mission_id, state)
    return store, controller, binding


@pytest.mark.parametrize('role', ['worker', 'validator', 'terminal_reviewer'])
@pytest.mark.parametrize('ordering', ['publication_first', 'finalization_first'])
@pytest.mark.parametrize('success', [True, False])
def test_process_orderings_preserve_carrier_and_terminal_fence(tmp_path, role, ordering, success):
    store, controller, binding = _prepare(tmp_path, role)
    owned = {}
    contended = threading.Event()
    released = threading.Event()

    def effect(attempt):
        zero = s.load_snapshot(store, binding.project_id, binding.mission_id, attempt)
        checkpoint = zero.model_copy(update={'checkpoint_sequence': 1,
            'phase': 'waiting_at_checkpoint', 'supervision_status': 'waiting'})
        ctx = multiprocessing.get_context('spawn')
        pipe, child = ctx.Pipe()
        proc = ctx.Process(target=_publisher, args=(str(store.config.harness_home),
            checkpoint.model_dump(), ordering, child))
        proc.start()
        child.close()
        owned.update(proc=proc, pipe=pipe, snapshot=checkpoint)
        assert pipe.poll(10)
        assert pipe.recv() == ('snapshot_owned' if ordering == 'publication_first' else 'admission_read')
        lock = s.snapshot_path(store, binding.project_id, binding.mission_id, attempt).with_suffix('.lock')
        owned.update(lock=lock, inode=lock.stat().st_ino)
        if ordering == 'publication_first':
            fd = os.open(lock, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        if role == 'terminal_reviewer':
            if not success:
                raise RuntimeError('controlled reviewer crash')
            return TerminalReviewHandoff(done=True, report='controlled review')
        if role == 'validator':
            return ValidateHandoff(node_id='validate-1', done=success, report='controlled validation',
                passed=success, items=[{'item_id': t, 'passed': success} for t in STEERING_TARGETS])
        return WorkHandoff(node_id='work-1', done=success, report='controlled work')

    class Reviewer:
        def review(self, project_id, mission_id, attempt):
            return effect(attempt)

    coordinator = MissionCoordinator(store, binding.project_id,
        MockDispatcher(lambda request: effect(request.spawn_ts)), Reviewer())

    def trace(frame, event, arg):
        if (event == 'exception' and frame.f_code is s._supervision_transaction.__wrapped__.__code__
                and arg[0] is BlockingIOError):
            contended.set()
        return trace

    # Independent controller releases the owner only after real flock contention.
    def release():
        if contended.wait(10) and 'pipe' in owned:
            owned['pipe'].send('release')
            released.set()

    thread = threading.Thread(target=release) if ordering == 'publication_first' else None
    try:
        if thread:
            thread.start()
        sys.settrace(trace)
        with project_access_guard(store, binding.project_id):
            result = (coordinator.close_mission(binding.mission_id)
                if role == 'terminal_reviewer' else coordinator.step())
        sys.settrace(None)
        if thread:
            thread.join(12)
            assert not thread.is_alive() and released.is_set() and contended.is_set()
        else:
            owned['pipe'].send('release')
        assert owned['pipe'].poll(10)
        response = owned['pipe'].recv()
        assert response == (('accepted', 1) if ordering == 'publication_first' else ('refused', None))
        owned['proc'].join(10)
        assert owned['proc'].exitcode == 0
        assert owned['lock'].stat().st_ino == owned['inode']
        snapshot = owned['snapshot']
        fresh = ProjectStore(store.config)
        terminal = s.load_snapshot(fresh, binding.project_id, binding.mission_id, snapshot.attempt_id)
        assert terminal.phase == terminal.supervision_status == 'terminal'
        assert terminal.checkpoint_sequence == (1 if ordering == 'publication_first' else 0)
        assert s.load_project_active_attempts(fresh, binding.project_id, binding.mission_id,
            fresh.load_task_list(binding.project_id, binding.mission_id)) == []
        assert coordinator._unique_attempt_id(binding.mission_id, snapshot.attempt_id) == snapshot.attempt_id + '-0001'
        before = s.snapshot_path(fresh, binding.project_id, binding.mission_id, snapshot.attempt_id).read_bytes()
        with pytest.raises(s.SupervisionSnapshotError):
            s.save_snapshot(fresh, snapshot, assigned_target_ids=STEERING_TARGETS)
        assert s.snapshot_path(fresh, binding.project_id, binding.mission_id, snapshot.attempt_id).read_bytes() == before
        if role == 'terminal_reviewer':
            assert result.detail == ('done' if success else 'terminal_review_crash')
        else:
            assert fresh.load_task_state(binding.project_id, binding.mission_id).status_of(binding.node_id) == ('cleared' if success else 'failed')
    finally:
        sys.settrace(None)
        contended.set()
        if thread:
            thread.join(12)
        if 'proc' in owned:
            if owned['proc'].is_alive():
                owned['proc'].kill()
            owned['proc'].join(10)
            assert not owned['proc'].is_alive()
            owned['pipe'].close()


@pytest.mark.parametrize('role', ['worker', 'validator', 'terminal_reviewer'])
@pytest.mark.parametrize('crash', [False, True])
def test_stop_receipt_recovery_precedes_success_or_crash(tmp_path, role, crash):
    store, controller, binding = _prepare(tmp_path, role)
    captured = []

    def effect(attempt):
        zero = s.load_snapshot(store, binding.project_id, binding.mission_id, attempt)
        checkpoint = zero.model_copy(update={'checkpoint_sequence': 1,
            'phase': 'waiting_at_checkpoint', 'supervision_status': 'waiting'})
        bound = s.report_supervision_checkpoint(store, checkpoint,
            assigned_target_ids=STEERING_TARGETS, project_guard=False)
        captured.append(bound)

        def fault(label):
            if label == 'after_receipt_fsync:stop_requested':
                raise RuntimeError('receipt-first crash')
        with pytest.raises(RuntimeError, match='receipt-first crash'):
            s.steer_attempt(store, _request(bound, 'stop_for_attention'), project_guard=False, fault=fault)
        if crash:
            raise RuntimeError('controlled role crash')
        if role == 'terminal_reviewer':
            return TerminalReviewHandoff(done=True, report='controlled')
        if role == 'validator':
            return ValidateHandoff(node_id='validate-1', done=True, report='controlled',
                passed=True, items=[{'item_id': t, 'passed': True} for t in STEERING_TARGETS])
        return WorkHandoff(node_id='work-1', done=True, report='controlled')

    class Reviewer:
        def review(self, project_id, mission_id, attempt):
            return effect(attempt)

    co = MissionCoordinator(store, binding.project_id, MockDispatcher(lambda req: effect(req.spawn_ts)), Reviewer())
    with project_access_guard(store, binding.project_id):
        result = co.close_mission(binding.mission_id) if role == 'terminal_reviewer' else co.step()
    assert result.kind == 'attention_needed'
    assert store.load_attention(binding.project_id)[0].kind == ('terminal_review' if role == 'terminal_reviewer' else 'node_attention')
    assert 'stopped cooperatively' in store.load_attention(binding.project_id)[0].report
    final = s.load_snapshot(store, binding.project_id, binding.mission_id, captured[0].attempt_id)
    assert final.phase == 'terminal'
    if role != 'terminal_reviewer':
        assert store.load_task_state(binding.project_id, binding.mission_id).status_of(binding.node_id) == 'failed'


def _hold_snapshot(home, payload, pipe):
    store = ProjectStore(_config(Path(home)))
    snap = ActiveAttemptSnapshot.model_validate(payload)
    path = s.snapshot_path(store, snap.project_id, snap.mission_id, snap.attempt_id)
    with s._snapshot_lock(path, root=store.bucket_root(snap.project_id)):
        pipe.send('owned')
        assert pipe.poll(15)
        pipe.recv()


def test_finalization_real_snapshot_contention_is_bounded(tmp_path):
    store, _, snap, binding = _prepare_role_checkpoint(tmp_path, 'worker')
    ctx = multiprocessing.get_context('spawn')
    pipe, child = ctx.Pipe()
    proc = ctx.Process(target=_hold_snapshot, args=(str(store.config.harness_home), snap.model_dump(), child))
    proc.start()
    child.close()
    try:
        assert pipe.poll(10) and pipe.recv() == 'owned'
        start = time.monotonic()
        with pytest.raises(s.SupervisionSteeringError) as error:
            s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
                binding.attempt_id, assigned_target_ids=STEERING_TARGETS)
        elapsed = time.monotonic() - start
        assert error.value.code == 'project_busy'
        assert 4.9 <= elapsed < 7
        assert proc.is_alive()
        with s._supervision_transaction(store, binding.project_id, binding.mission_id):
            pass
        assert s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id) == snap
        pipe.send('release')
        proc.join(10)
        assert proc.exitcode == 0
        assert s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
            binding.attempt_id, assigned_target_ids=STEERING_TARGETS) == (snap, False)
    finally:
        if proc.is_alive():
            proc.kill()
        proc.join(10)
        pipe.close()


@pytest.mark.parametrize('role', ['worker', 'validator', 'terminal_reviewer'])
def test_actual_role_mcp_delayed_admission_refuses_terminal_snapshot(tmp_path, role):
    from concurrent.futures import ThreadPoolExecutor
    from tests.test_server import _call_process_mcp, _http_server_process, _process_group_inventory

    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, role)
    if role == 'terminal_reviewer':
        snapshot = snapshot.model_copy(update={'attempt_id': snapshot.terminal_review_id})
        s.report_supervision_checkpoint(store, snapshot, assigned_target_ids=STEERING_TARGETS)
        binding = s.binding_from_snapshot(snapshot)
    barrier = tmp_path / 'barrier'
    barrier.mkdir()
    environment = {'UNREST_PROJECT_ID': binding.project_id, 'UNREST_MISSION_ID': binding.mission_id,
        'SUPERVISION_TEST_BARRIER': str(barrier)}
    if binding.node_id:
        environment.update(UNREST_NODE_ID=binding.node_id, UNREST_HANDOFF_PATH=str(store.attempt_path(
            binding.project_id, binding.mission_id, binding.attempt_id, binding.node_id)))
    else:
        environment.update(UNREST_TERMINAL_REVIEW_ID=binding.terminal_review_id,
            UNREST_TERMINAL_REVIEW_PATH=str(store.terminal_review_path(
                binding.project_id, binding.mission_id, binding.terminal_review_id)))
    script = Path(__file__).parent / 'fixtures/supervision_finalization_role.py'
    checkpoint = snapshot.model_copy(update={'checkpoint_sequence': 2, 'elapsed_nanoseconds': 0,
        'checkpoint_requests': 0})
    with _http_server_process(store.config, tmp_path / 'workspace', mode=role.replace('_', '-'),
            role_environment=environment,
            entrypoint=f"import runpy; runpy.run_path({str(script)!r}, run_name='__main__')") as (process, url), ThreadPoolExecutor() as pool:
        future = pool.submit(_call_process_mcp, url, 'report_supervision_checkpoint',
            {'snapshot': checkpoint.model_dump(mode='json')})
        try:
            cutoff = time.monotonic() + 10
            while not (barrier / 'admitted').exists():
                assert time.monotonic() < cutoff
                time.sleep(.005)
            assert not future.done()
            with project_access_guard(store, binding.project_id):
                s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
                    binding.attempt_id, assigned_target_ids=STEERING_TARGETS, project_guard=False)
            (barrier / 'release').touch()
            result = future.result(10)
            assert result['error']['code'] == 'invalid_checkpoint'
            assert s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id).phase == 'terminal'
        finally:
            (barrier / 'release').touch()
    assert process.poll() is not None
    assert _process_group_inventory(process.pid) == []


@pytest.mark.parametrize('role', ['worker', 'validator'])
def test_restart_after_terminal_publication_preserves_stop_and_denial(tmp_path, role):
    from unrest_harness.provider_review import ProviderReviewBlock, ReviewIdentity

    store, controller, snap, binding = _prepare_role_checkpoint(tmp_path, role)
    s.steer_attempt(store, _request(binding, 'stop_for_attention'), project_guard=False)
    s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
        binding.attempt_id, assigned_target_ids=STEERING_TARGETS)
    store = ProjectStore(store.config)
    task = next(t for t in store.load_task_list(binding.project_id, binding.mission_id).tasks if t.id == binding.node_id)
    handoff = (WorkHandoff(node_id=task.id, done=True, report='controlled') if role == 'worker'
        else ValidateHandoff(node_id=task.id, done=True, report='controlled', passed=True,
            items=[{'item_id': t, 'passed': True} for t in STEERING_TARGETS]))
    co = MissionCoordinator(store, binding.project_id, controller.dispatcher, controller.terminal_reviewer)
    with project_access_guard(store, binding.project_id):
        assert co._apply_handoff(binding.mission_id, task, handoff, binding.attempt_id).kind == 'attention_needed'
    assert store.load_task_state(binding.project_id, binding.mission_id).status_of(task.id) == 'failed'
    assert 'stopped cooperatively' in store.load_attention(binding.project_id)[0].report
    # A separate denied generation must never inherit the passing handoff outcome.
    denied = 'denied-generation'
    co._begin_supervision_attempt(binding.mission_id, attempt_id=denied, role=role,
        assigned_target_ids=STEERING_TARGETS, node_id=task.id)
    store.begin_provider_review(binding.project_id, binding.mission_id, denied, task.id, 'thread-1')
    store.save_provider_review(binding.project_id, binding.mission_id, denied, task.id, 'thread-1',
        ProviderReviewBlock('denied', ReviewIdentity('thread-1', 'turn-1', 'review-1')))
    with project_access_guard(store, binding.project_id):
        assert co._apply_handoff(binding.mission_id, task, handoff, denied).kind == 'attention_needed'
    assert store.load_task_state(binding.project_id, binding.mission_id).status_of(task.id) == 'failed'
    assert s.load_snapshot(store, binding.project_id, binding.mission_id, denied).phase == 'terminal'
    assert ProjectStore(store.config).read_provider_review(binding.project_id, binding.mission_id, denied, task.id).reason == 'denied'


def test_finalization_cancellation_preserves_first_error_and_releases_ownership(tmp_path, monkeypatch):
    import asyncio

    store, _, snap, binding = _prepare_role_checkpoint(tmp_path, 'worker')
    cancellation = asyncio.CancelledError()
    close = os.close

    def fail_write(*args, **kwargs):
        raise cancellation

    def close_then_fail(fd):
        close(fd)
        raise OSError('supplemental cleanup fault')

    with monkeypatch.context() as patch:
        patch.setattr(s, 'atomic_write_json', fail_write)
        patch.setattr(s.os, 'close', close_then_fail)
        with pytest.raises(asyncio.CancelledError) as caught:
            s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
                binding.attempt_id, assigned_target_ids=STEERING_TARGETS, project_guard=False)
        assert caught.value is cancellation
    assert s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id) == snap
    assert s.finalize_supervision_attempt(store, binding.project_id, binding.mission_id,
        binding.attempt_id, assigned_target_ids=STEERING_TARGETS) == (snap, False)
