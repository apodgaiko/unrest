"""Nested snapshot contention uses the owning transaction's original cutoff."""
from __future__ import annotations

import asyncio
import fcntl
import multiprocessing
import os
import time
from pathlib import Path

import pytest

from unrest_harness import supervision as s
from tests.test_supervision import STEERING_TARGETS, _prepare_role_checkpoint, _request


def _hold_snapshot(path, connection):
    with s._snapshot_lock(Path(path)):
        connection.send("owned")
        assert connection.poll(15)
        connection.recv()
    connection.close()


@pytest.fixture
def snapshot_owner():
    children = []

    def start(path):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=_hold_snapshot, args=(str(path), child))
        process.start()
        child.close()
        children.append((process, parent))
        assert parent.poll(5) and parent.recv() == "owned"
        return process, parent

    yield start
    for process, connection in children:
        if process.is_alive():
            process.kill()
        process.join(5)
        assert not process.is_alive()
        connection.close()
        process.close()


def _released(store, binding):
    carrier = s.supervision_runtime_dir(store, binding.project_id, binding.mission_id) / ".transaction"
    descriptor = os.open(carrier, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)
    assert s._snapshot_acquisition.get() is None


@pytest.mark.parametrize("operation", [
    "continue", "nudge", "timeout", "blocked", "checkpoint", "stop", "other-stop", "recovery", "other-checkpoint", "other-steer",
])
def test_real_held_snapshot_refuses_and_reconciles(tmp_path, snapshot_owner, operation):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    held = snapshot
    if operation in {"continue", "nudge", "blocked"}:
        action = "continue" if operation == "continue" else "nudge"
        s.steer_attempt(store, _request(binding, action, body="private-canary" if action == "nudge" else None),
                        delivery_supported=operation != "blocked", project_guard=False)
    if operation in {"other-stop", "recovery", "other-checkpoint", "other-steer"}:
        held = snapshot.model_copy(update={"attempt_id": "another-attempt"}, deep=True)
        s.save_snapshot(store, held, assigned_target_ids=STEERING_TARGETS)
        other = s.binding_from_snapshot(held)

        def interrupted(label):
            if label == "after_receipt_fsync:stop_requested":
                raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            s.steer_attempt(store, _request(other, "stop_for_attention"), fault=interrupted, project_guard=False)
    path = s.snapshot_path(store, held.project_id, held.mission_id, held.attempt_id)
    process, connection = snapshot_owner(path)
    before = time.monotonic()
    with pytest.raises(s.SupervisionSteeringError, match="^project_busy$"):
        if operation in {"checkpoint", "other-checkpoint"}:
            s.report_supervision_checkpoint(store, snapshot, assigned_target_ids=STEERING_TARGETS, project_guard=False)
        elif operation in {"stop", "other-steer"}:
            s.steer_attempt(store, _request(binding, "stop_for_attention"), project_guard=False)
        elif operation == "recovery":
            s.recover_supervision(store, binding.project_id, binding.mission_id, project_guard=False)
        else:
            s.wait_for_steering_action(store, binding, timeout_seconds=.06, project_guard=False)
    elapsed = time.monotonic() - before
    bound = 5 if operation in {"checkpoint", "stop", "recovery", "other-checkpoint", "other-steer"} else .06
    assert bound <= elapsed < bound + .5
    assert process.is_alive()  # Refusal happened while the actual inner owner still held.
    _released(store, binding)
    current = s.load_snapshot(store, held.project_id, held.mission_id, held.attempt_id)
    assert current.phase == "waiting_at_checkpoint"
    rows = s.load_supervision_receipts(store, binding.project_id, binding.mission_id)
    expected = {
        "continue": ["continued"], "nudge": ["nudge_pending", "nudge_delivered", "nudge_consumed"],
        "timeout": ["timeout_continue"], "blocked": ["delivery_blocked"], "checkpoint": [],
        "stop": ["stop_requested"], "other-stop": ["stop_requested"], "recovery": ["stop_requested"],
        "other-checkpoint": ["stop_requested"], "other-steer": ["stop_requested"],
    }[operation]
    assert [r.code for r in rows] == expected
    assert [r.receipt_sequence for r in rows] == list(range(1, len(rows) + 1))
    if rows:
        assert "private-canary" not in s.receipts_path(store, binding.project_id, binding.mission_id).read_text()
    connection.send("release")
    process.join(5)
    assert process.exitcode == 0
    s.recover_supervision(store, binding.project_id, binding.mission_id, project_guard=False)
    if operation in {"stop", "recovery"}:
        current = s.load_snapshot(store, held.project_id, held.mission_id, held.attempt_id)
        assert current.phase == "stopping"
    else:
        outcome = s.wait_for_steering_action(store, binding, timeout_seconds=0, project_guard=False)
        assert outcome.body is None  # Failed post-consumption response must never replay.
        assert outcome.code == ("nudge_already_consumed" if operation == "nudge" else
                                "delivery_blocked" if operation == "blocked" else
                                "continued" if operation == "continue" else "timeout_continue")
        assert s.load_snapshot(store, binding.project_id, binding.mission_id, binding.attempt_id).phase == "active"
    if operation in {"other-stop", "other-checkpoint", "other-steer"}:
        assert s.load_snapshot(store, held.project_id, held.mission_id, held.attempt_id).phase == "stopping"
    _released(store, binding)


@pytest.mark.parametrize("operation_error", [None, "acquisition", "body"])
@pytest.mark.parametrize("unlock_fails,close_fails", [(True, False), (False, True), (True, True)])
def test_first_snapshot_error_survives_all_cleanup(tmp_path, monkeypatch, operation_error, unlock_fails, close_fails):
    path = tmp_path / "supervision" / "attempt.json"
    original_flock, original_close = s.fcntl.flock, s.os.close
    cancellation = asyncio.CancelledError()
    unlock_error, close_error = OSError("unlock failure"), OSError("close failure")
    closed = []

    def flock(fd, flags):
        if flags == fcntl.LOCK_UN:
            if unlock_fails:
                raise unlock_error
        elif operation_error == "acquisition":
            raise cancellation
        return original_flock(fd, flags)

    def close(fd):
        original_close(fd)
        closed.append(fd)
        if close_fails:
            raise close_error

    with monkeypatch.context() as patch:
        patch.setattr(s.fcntl, "flock", flock)
        patch.setattr(s.os, "close", close)
        with pytest.raises(BaseException) as caught:
            with s._snapshot_lock(path):
                if operation_error == "body":
                    raise cancellation
        assert caught.value is (cancellation if operation_error else unlock_error if unlock_fails else close_error)
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])
    with s._snapshot_lock(path):
        pass


def test_supplemental_exact_cutoff_and_recovery_rows_share_context(tmp_path, snapshot_owner):
    """Injected clock equality supplements, rather than replaces, real-clock cases."""
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    second = snapshot.model_copy(update={"attempt_id": "second"}, deep=True)
    s.save_snapshot(store, second, assigned_target_ids=STEERING_TARGETS)
    process, connection = snapshot_owner(s.snapshot_path(store, second.project_id, second.mission_id, second.attempt_id))
    clock = [10.0]
    sleeps = []

    def sleep(duration):
        sleeps.append(duration)
        clock[0] += duration

    with s._supervision_transaction(store, binding.project_id, binding.mission_id,
                                   deadline=10.025, monotonic=lambda: clock[0], sleep=sleep):
        # First acquisition consumes elapsed time; the second must not renew it.
        s.save_snapshot(store, snapshot, assigned_target_ids=STEERING_TARGETS)
        clock[0] = 10.02
        with pytest.raises(s.SupervisionSteeringError, match="project_busy"):
            s.save_snapshot(store, second, assigned_target_ids=STEERING_TARGETS)
        assert clock[0] == 10.025
        assert sum(sleeps) == pytest.approx(.005)
        # Immediate uncontended acquisition remains possible at the exact cutoff.
        s.save_snapshot(store, snapshot, assigned_target_ids=STEERING_TARGETS)
    _released(store, binding)
    connection.send("release")
    process.join(5)
    assert process.exitcode == 0
    assert s.wait_for_steering_action(store, binding, timeout_seconds=0,
                                    monotonic=lambda: clock[0], sleep=sleep,
                                    project_guard=False).code == "timeout_continue"
