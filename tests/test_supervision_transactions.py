"""Real ownership, crash and role regressions for the shared receipt tail."""
from __future__ import annotations

import asyncio
import fcntl
import multiprocessing
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tests.multiprocess_lifetime import SpawnResources

from unrest_harness import supervision as s
from unrest_harness.models import SteeringBinding
from unrest_harness.project_lock import project_access_guard
from unrest_harness.storage import ProjectStore
from tests.test_server import (
    _call_process_mcp,
    _http_server_process,
    _process_group_inventory,
)
from tests.test_supervision import (
    STEERING_TARGETS,
    _config,
    _prepare_role_checkpoint,
    _request,
)


def _body(store):
    path = store.config.harness_home / ".test-canary"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(32))
        path.chmod(0o600)
    return path.read_text()


def _body_equal(actual, store):
    return actual == _body(store)


def _child(home, binding_payload, operation, cut, connection):
    store = ProjectStore(_config(Path(home)))
    binding = SteeringBinding.model_validate(binding_payload)

    def fault(label):
        if label == cut:
            connection.send(label)
            if not connection.poll(10):
                raise RuntimeError("barrier expired")
            connection.recv()

    try:
        if operation == "race":
            connection.send("ready")
            if not connection.poll(10):
                raise RuntimeError("barrier expired")
            connection.recv()
            try:
                if cut == "timeout":
                    result = s.wait_for_steering_action(
                        store, binding, timeout_seconds=0, project_guard=False,
                    )
                    connection.send((result.code, _body_equal(result.body, store)))
                else:
                    result = s.steer_attempt(
                        store, _request(binding, cut, body=_body(store) if cut == "nudge" else None),
                        project_guard=False,
                    )
                    connection.send((result.code, False))
            except s.SupervisionSteeringError as exc:
                connection.send((exc.code, False))
        elif operation == "hold":
            with s._supervision_transaction(store, binding.project_id, binding.mission_id):
                connection.send("owned")
                if not connection.poll(10):
                    raise RuntimeError("barrier expired")
                connection.recv()
        elif operation == "admission":
            with project_access_guard(store, binding.project_id):
                connection.send("owned")
                if not connection.poll(10):
                    raise RuntimeError("barrier expired")
                connection.recv()
        elif operation == "steer":
            s.steer_attempt(store, _request(binding, "nudge", body=_body(store)),
                            fault=fault, project_guard=False)
        elif operation == "wait":
            s.wait_for_steering_action(store, binding, fault=fault, project_guard=False)
        connection.send("finished")
    finally:
        connection.close()


@pytest.fixture
def child_owner():
    with SpawnResources() as ownership:
        owned = []

        def start(store, binding, operation, cut=None):
            _body(store)
            context = ownership.context(multiprocessing.get_context("spawn"))
            parent, child = context.Pipe()
            process = context.Process(target=_child, args=(
                str(store.config.harness_home), binding.model_dump(), operation, cut, child,
            ))
            process.start()
            child.close()
            owned.append((process, parent))
            assert parent.poll(10)
            assert parent.recv() == ("ready" if operation == "race" else cut or "owned")
            return process, parent

        yield start
        for process, connection in owned:
            if process.is_alive():
                process.kill()
            process.join(5)
            assert not process.is_alive() and process.exitcode is not None
            connection.close()
            process.close()


def _carrier(store, binding):
    return s.supervision_runtime_dir(store, binding.project_id, binding.mission_id) / ".transaction"


def _rows(store):
    return s.load_supervision_receipts(store, "project-1", "mission-001")


def _cancelled_mcp_call(url, arguments, cancel):
    from fastmcp import Client

    async def call():
        async with Client(url) as client:
            request = asyncio.create_task(client.call_tool("report_supervision_checkpoint", arguments))
            cutoff = time.monotonic() + 10
            while not cancel.is_set():
                assert time.monotonic() < cutoff
                await asyncio.sleep(.005)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
        return {"cancelled": True}

    return asyncio.run(call())


@pytest.mark.parametrize("role", ["worker", "validator", "terminal_reviewer"])
@pytest.mark.parametrize("schedule", ["held-inbox", "held-recovery", "cancelled-client"])
def test_actual_role_excludes_both_diagnostic_interleavings(tmp_path, child_owner, role, schedule):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, role)
    if role == "terminal_reviewer":
        snapshot = snapshot.model_copy(update={"attempt_id": snapshot.terminal_review_id})
        s.report_supervision_checkpoint(store, snapshot, assigned_target_ids=STEERING_TARGETS)
        binding = s.binding_from_snapshot(snapshot)
    admission, admission_pipe = child_owner(store, binding, "admission")
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    environment = {
        "UNREST_PROJECT_ID": binding.project_id,
        "UNREST_MISSION_ID": binding.mission_id,
        "SUPERVISION_TEST_BARRIER": str(barrier),
    }
    if binding.node_id:
        environment["UNREST_NODE_ID"] = binding.node_id
        environment["UNREST_HANDOFF_PATH"] = str(store.attempt_path(
            binding.project_id, binding.mission_id, binding.attempt_id, binding.node_id,
        ))
    else:
        environment["UNREST_TERMINAL_REVIEW_ID"] = binding.terminal_review_id
        environment["UNREST_TERMINAL_REVIEW_PATH"] = str(store.terminal_review_path(
            binding.project_id, binding.mission_id, binding.terminal_review_id,
        ))
    child_snapshot = snapshot.model_copy(update={
        "checkpoint_sequence": 2, "elapsed_nanoseconds": 0, "checkpoint_requests": 0,
    })
    binding = s.binding_from_snapshot(child_snapshot)
    script = Path(__file__).parent / "fixtures/supervision_role_process.py"
    entrypoint = f"import runpy; runpy.run_path({str(script)!r}, run_name='__main__')"
    entered, release, cancel = threading.Event(), threading.Event(), threading.Event()

    def hold(label):
        if label == "after_pending_inbox_fsync":
            entered.set()
            assert release.wait(10)

    with _http_server_process(
        store.config, tmp_path / "workspace", mode=role.replace("_", "-"),
        role_environment=environment, entrypoint=entrypoint,
    ) as (process, url), ThreadPoolExecutor(max_workers=2) as pool:
        arguments = {"snapshot": child_snapshot.model_dump(mode="json")}
        if schedule == "cancelled-client":
            waiter = pool.submit(_cancelled_mcp_call, url, arguments, cancel)
        else:
            waiter = pool.submit(_call_process_mcp, url, "report_supervision_checkpoint", arguments)
        try:
            cutoff = time.monotonic() + 10
            while s.load_snapshot(store, binding.project_id, binding.mission_id,
                                  binding.attempt_id).checkpoint_sequence != 2:
                assert time.monotonic() < cutoff
                time.sleep(.005)
            writer = pool.submit(s.steer_attempt, store,
                                 _request(binding, "nudge", body=_body(store)),
                                 fault=hold, project_guard=False)
            assert entered.wait(10)
            while not (barrier / "contended").exists():
                assert time.monotonic() < cutoff
                time.sleep(.005)
            # Positive contention witness excludes both original schedules.
            assert not (barrier / "missing-pending").exists()
            assert not waiter.done() and not writer.done()
            assert _rows(store) == []
            assert s.inbox_path(store, binding).is_file()
            if schedule == "cancelled-client":
                cancel.set()
                assert waiter.result(5) == {"cancelled": True}
            release.set()
            assert writer.result(10).code == "nudge_pending"
            if schedule == "cancelled-client":
                cutoff = time.monotonic() + 10
                while s.load_snapshot(store, binding.project_id, binding.mission_id,
                                      binding.attempt_id).phase != "active":
                    assert time.monotonic() < cutoff
                    time.sleep(.005)
            else:
                outcome = waiter.result(10)
                assert outcome["action"] == "nudge"
                assert _body_equal(outcome["body"], store)
                assert outcome["code"] == "nudge_consumed"
            assert not (barrier / "missing-pending").exists()
            rows = _rows(store)
            assert [(r.receipt_sequence, r.delivery_status) for r in rows] == [
                (1, "pending"), (2, "delivered"), (3, "consumed"),
            ]
            assert all(s._binding_key(r) == s._binding_key(binding) for r in rows)
            assert _body(store) not in s.receipts_path(
                store, binding.project_id, binding.mission_id,
            ).read_text()
            assert not s.inbox_path(store, binding).exists()
            current = s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id)
            assert (current.phase, current.supervision_status, current.checkpoint_sequence) == (
                "active", "running", 2,
            )
            with pytest.raises(s.SupervisionSteeringError):
                s.wait_for_steering_action(store, binding, timeout_seconds=0, project_guard=False)
        finally:
            cancel.set()
            release.set()
            admission_pipe.send("release")
            admission.join(5)
            assert admission.exitcode == 0
    assert not _process_group_inventory(process.pid)
    for log in (tmp_path / "workspace").glob("*.log"):
        assert _body(store) not in log.read_text()


@pytest.mark.parametrize("cut,operation,delivers", [
    ("after_pending_inbox_fsync", "steer", True),
    ("before_consumed_inbox_fsync", "wait", True),
    ("after_consumed_inbox_fsync", "wait", False),
    ("after_receipt_fsync:nudge_consumed", "wait", False),
])
def test_process_death_releases_stable_carrier_and_recovery_never_replays(
    tmp_path, child_owner, cut, operation, delivers,
):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    if operation == "wait":
        s.steer_attempt(store, _request(binding, "nudge", body=_body(store)))
    carrier = _carrier(store, binding)
    inode = carrier.stat().st_ino
    process, _ = child_owner(store, binding, operation, cut)
    with pytest.raises(s.SupervisionSteeringError, match="project_busy"):
        s.wait_for_steering_action(store, binding, timeout_seconds=0, project_guard=False)
    process.kill()
    process.join(5)
    assert process.exitcode != 0
    restarted = ProjectStore(store.config)
    s.recover_supervision(restarted, binding.project_id, binding.mission_id, project_guard=False)
    outcome = s.wait_for_steering_action(restarted, binding, timeout_seconds=0, project_guard=False)
    assert _body_equal(outcome.body, store) is delivers
    assert [r.delivery_status for r in _rows(restarted)] == ["pending", "delivered", "consumed"]
    assert carrier.stat().st_ino == inode
    assert not s.inbox_path(restarted, binding).exists()


@pytest.mark.parametrize("timeout", [0, .06, .15])
def test_real_contended_wait_uses_original_deadline_without_false_timeout(tmp_path, child_owner, timeout):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    process, connection = child_owner(store, binding, "hold")
    inode = _carrier(store, binding).stat().st_ino
    witnessed = []
    started = time.monotonic()
    with pytest.raises(s.SupervisionSteeringError, match="project_busy"):
        s.wait_for_steering_action(store, binding, timeout_seconds=timeout,
                                  project_guard=False, fault=witnessed.append)
    elapsed = time.monotonic() - started
    assert timeout <= elapsed < timeout + 1
    assert "supervision_transaction_contended" in witnessed
    assert _rows(store) == []
    connection.send("release")
    process.join(5)
    assert process.exitcode == 0
    outcome = s.wait_for_steering_action(store, binding, timeout_seconds=0, project_guard=False)
    assert outcome.code == "timeout_continue"
    assert _carrier(store, binding).stat().st_ino == inode


def test_shared_tail_and_same_attempt_competitors(tmp_path):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    other = snapshot.model_copy(update={"attempt_id": "attempt-other"})
    s.report_supervision_checkpoint(store, other, assigned_target_ids=STEERING_TARGETS)
    second = s.binding_from_snapshot(other)
    _body(store)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(s.steer_attempt, store, _request(b, "nudge", body=_body(store)),
                               project_guard=False) for b in (binding, second)]
        for future in futures:
            assert future.result(5).code == "nudge_pending"
        outcomes = [pool.submit(s.wait_for_steering_action, store, b, project_guard=False)
                    for b in (binding, second)]
        assert all(_body_equal(f.result(5).body, store) for f in outcomes)
    rows = _rows(store)
    assert [r.receipt_sequence for r in rows] == list(range(1, 7))
    for b in (binding, second):
        assert [r.delivery_status for r in rows if s._binding_key(r) == s._binding_key(b)] == [
            "pending", "delivered", "consumed",
        ]
    # A fresh checkpoint receives exactly one of stop, nudge or timeout.
    snapshot = snapshot.model_copy(update={"attempt_id": "competing-attempt", "checkpoint_sequence": 1})
    s.report_supervision_checkpoint(store, snapshot, assigned_target_ids=STEERING_TARGETS)
    binding = s.binding_from_snapshot(snapshot)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(s.steer_attempt, store, _request(binding, "stop_for_attention"), project_guard=False),
                   pool.submit(s.steer_attempt, store, _request(binding, "nudge", body=_body(store)), project_guard=False),
                   pool.submit(s.wait_for_steering_action, store, binding, timeout_seconds=0, project_guard=False)]
        for future in futures:
            try:
                future.result(5)
            except s.SupervisionSteeringError as exc:
                assert exc.code in {"steering_action_replayed", "not_at_semantic_checkpoint", "nudge_limit_exceeded", "project_busy"}
    rows = s._binding_receipts(_rows(store), binding)
    assert rows[0].action in {"continue", "stop_for_attention", "nudge"}
    if rows[0].action == "nudge":
        assert [r.delivery_status for r in rows] in [["pending"], ["pending", "delivered", "consumed"]]
    else:
        assert len(rows) == 1


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "mode", "hardlink"])
def test_unsafe_transaction_carrier_refuses_without_outside_changes(tmp_path, kind):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    path = _carrier(store, binding)
    path.unlink()  # No owner exists; this fixture creates an invalid carrier.
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    before = outside.stat()
    if kind == "symlink":
        path.symlink_to(outside)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "mode":
        path.touch(mode=0o644)
    else:
        os.link(outside, path)
    with pytest.raises(s.SupervisionSteeringError) as error:
        s.recover_supervision(store, binding.project_id, binding.mission_id, project_guard=False)
    assert error.value.code in {"project_lock_error", "supervision_storage_integrity_error"}
    assert outside.read_text() == "unchanged"
    assert outside.stat().st_mode == before.st_mode
    assert _rows(store) == []


def test_poll_sleep_releases_transaction_and_cancellation_preserves_first_error(tmp_path, monkeypatch):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    observed = []

    def sleep(seconds):
        with s._supervision_transaction(store, binding.project_id, binding.mission_id):
            observed.append("free")
        s.steer_attempt(store, _request(binding, "continue"), project_guard=False)

    assert s.wait_for_steering_action(store, binding, sleep=sleep, project_guard=False).code == "continued"
    assert observed == ["free"]
    close = os.close

    def close_then_fail(fd):
        close(fd)
        raise OSError("cleanup")

    with pytest.raises(asyncio.CancelledError):
        with s._supervision_transaction(store, binding.project_id, binding.mission_id):
            monkeypatch.setattr(s.os, "close", close_then_fail)
            raise asyncio.CancelledError()
    monkeypatch.undo()
    with s._supervision_transaction(store, binding.project_id, binding.mission_id):
        pass
    fd = os.open(_carrier(store, binding), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_distinct_processes_share_tail_and_compete_for_one_action(tmp_path, child_owner):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    second_snapshot = snapshot.model_copy(update={"attempt_id": "second-process"})
    s.report_supervision_checkpoint(store, second_snapshot, assigned_target_ids=STEERING_TARGETS)
    second = s.binding_from_snapshot(second_snapshot)
    pairs = [child_owner(store, b, "race", "nudge") for b in (binding, second)]
    for _, connection in pairs:
        connection.send("go")
    for process, connection in pairs:
        assert connection.poll(5)
        assert connection.recv() == ("nudge_pending", False)
        process.join(5)
        assert process.exitcode == 0
    assert [r.receipt_sequence for r in _rows(store)] == [1, 2]
    for b in (binding, second):
        assert _body_equal(s.wait_for_steering_action(store, b, timeout_seconds=0).body, store)
    snapshot = snapshot.model_copy(update={"attempt_id": "competing-process"})
    s.report_supervision_checkpoint(store, snapshot, assigned_target_ids=STEERING_TARGETS)
    binding = s.binding_from_snapshot(snapshot)
    pairs = [child_owner(store, binding, "race", action)
             for action in ("nudge", "stop_for_attention", "timeout")]
    for _, connection in pairs:
        connection.send("go")
    results = []
    for process, connection in pairs:
        assert connection.poll(5)
        results.append(connection.recv())
        process.join(5)
        assert process.exitcode == 0
    assert sum(result[1] for result in results) <= 1
    rows = s._binding_receipts(_rows(store), binding)
    assert rows
    if rows[0].action == "nudge":
        assert [r.delivery_status for r in rows] in [["pending"], ["pending", "delivered", "consumed"]]
    else:
        assert len(rows) == 1
    stale = binding.model_copy(update={"checkpoint_sequence": 0})
    with pytest.raises(s.SupervisionSteeringError, match="stale_checkpoint_binding"):
        s.steer_attempt(store, _request(stale, "continue"), project_guard=False)


def test_nonwaiter_contention_is_finite_and_checkpoint_cannot_publish(tmp_path, child_owner):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    process, connection = child_owner(store, binding, "hold")
    inode = _carrier(store, binding).stat().st_ino
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:
        recovery = pool.submit(s.recover_supervision, store, binding.project_id,
                               binding.mission_id, project_guard=False)
        checkpoint = pool.submit(s.report_supervision_checkpoint, store,
                                 snapshot.model_copy(update={"checkpoint_sequence": 2}),
                                 assigned_target_ids=STEERING_TARGETS, project_guard=False)
        for future in (recovery, checkpoint):
            with pytest.raises(s.SupervisionSteeringError, match="project_busy"):
                future.result(7)
    assert 5 <= time.monotonic() - started < 7
    assert _rows(store) == []
    assert s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id) == snapshot
    connection.send("go")
    process.join(5)
    assert process.exitcode == 0
    s.recover_supervision(store, binding.project_id, binding.mission_id)
    assert _carrier(store, binding).stat().st_ino == inode


def test_contended_owner_release_before_original_cutoff_succeeds(tmp_path, child_owner):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"))
    process, connection = child_owner(store, binding, "hold")
    witnessed = []

    def fault(label):
        if label == "supervision_transaction_contended" and not witnessed:
            witnessed.append(label)
            connection.send("release")

    started = time.monotonic()
    outcome = s.wait_for_steering_action(store, binding, timeout_seconds=1,
                                       project_guard=False, fault=fault)
    assert witnessed and outcome.code == "continued"
    assert time.monotonic() - started < 1
    process.join(5)
    assert process.exitcode == 0


@pytest.mark.parametrize("at", [1.0, 1.001])
def test_exact_and_after_deadline_do_not_retry_ownership(tmp_path, child_owner, at):
    """Boundary supplement; actual-process timing cases above use real clocks."""
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    process, connection = child_owner(store, binding, "hold")
    now = [0.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        connection.send("release")
        process.join(5)
        assert process.exitcode == 0
        now[0] = at

    with pytest.raises(s.SupervisionSteeringError, match="project_busy"):
        s.wait_for_steering_action(store, binding, timeout_seconds=1,
                                  monotonic=lambda: now[0], sleep=sleep, project_guard=False)
    assert slept == [s.TRANSACTION_POLL_SECONDS]
    assert _rows(store) == []


def test_symlinked_runtime_parent_is_rejected(tmp_path):
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    directory = _carrier(store, binding).parent
    saved = directory.with_name("saved-supervision")
    directory.rename(saved)
    directory.symlink_to(saved, target_is_directory=True)
    with pytest.raises(s.SupervisionSteeringError, match="supervision_storage_integrity_error"):
        s.recover_supervision(store, binding.project_id, binding.mission_id, project_guard=False)
    assert _rows(store) == []


def test_admission_cleanup_preserves_original_error(tmp_path, monkeypatch):
    from unrest_harness.project_lock import ProjectLockError, ProjectMutationLock

    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "validator")
    release = ProjectMutationLock.release

    def release_then_fail(lock):
        release(lock)
        raise ProjectLockError()

    monkeypatch.setattr(ProjectMutationLock, "release", release_then_fail)
    with pytest.raises(asyncio.CancelledError):
        with s._supervision_project_guard(store, binding.project_id):
            raise asyncio.CancelledError()
    with pytest.raises(s.SupervisionSteeringError, match="project_lock_error"):
        with s._supervision_project_guard(store, binding.project_id):
            pass
