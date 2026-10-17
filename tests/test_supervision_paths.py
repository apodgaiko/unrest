"""Snapshot carrier safety through standalone saves and nested public waiters."""
from __future__ import annotations

import fcntl
import multiprocessing
import os
import socket
import stat
import tempfile
from pathlib import Path

import pytest

from unrest_harness import supervision as s
from tests.test_supervision import STEERING_TARGETS, _prepare_role_checkpoint, _request
from tests import test_supervision_nested as nested_tests

snapshot_owner = nested_tests.snapshot_owner
_released = nested_tests._released


def _call(store, snapshot, binding, nested):
    if nested:
        return s.wait_for_steering_action(store, binding, timeout_seconds=.05, project_guard=False)
    return s.save_snapshot(store, snapshot, assigned_target_ids=STEERING_TARGETS)


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "directory", "fifo", "socket", "mode"])
def test_static_carrier_refuses_without_outside_effects(tmp_path, nested, kind):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"), project_guard=False)
    path = s.snapshot_path(store, binding.project_id, binding.mission_id, binding.attempt_id)
    before = path.read_bytes()
    lock = path.with_suffix(".lock")
    lock.unlink()  # Disposable fixture, no live owner.
    outside = tmp_path / "outside"
    if kind != "dangling":
        outside.write_bytes(b"private-canary")
        outside.chmod(0o600 if kind == "hardlink" else 0o640)
    sock = None
    if kind in {"symlink", "dangling"}:
        lock.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, lock)
    elif kind == "directory":
        lock.mkdir(mode=0o700)
    elif kind == "fifo":
        os.mkfifo(lock, 0o600)
    elif kind == "socket":
        # Bind under a short disposable path for macOS's 104-byte limit.
        sock = socket.socket(socket.AF_UNIX)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as short:
            socket_path = Path(short) / "s"
            sock.bind(str(socket_path))
            socket_path.rename(lock)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o640)
    carrier_before = lock.lstat()
    outside_before = outside.stat() if outside.exists() else None
    try:
        with pytest.raises(s.SupervisionSnapshotError, match="unsafe snapshot lock"):
            _call(store, snapshot, binding, nested)
    finally:
        if sock is not None:
            sock.close()
    assert lock.lstat() == carrier_before
    assert path.read_bytes() == before
    if outside_before is None:
        assert not outside.exists()
    else:
        assert outside.stat() == outside_before
        assert outside.read_bytes() == b"private-canary"
    assert [(r.receipt_sequence, r.code) for r in s.load_supervision_receipts(store, binding.project_id, binding.mission_id)] == [(1, "continued")]
    _released(store, binding)


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("component", ["root", "intermediate", "final"])
@pytest.mark.parametrize("unsafe", ["symlink", "mode"])
def test_lexical_parent_refusal_before_mutation(tmp_path, nested, component, unsafe):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"), project_guard=False)
    root = store.bucket_root(binding.project_id)
    parent = s.supervision_runtime_dir(store, binding.project_id, binding.mission_id)
    selected = {"root": root, "intermediate": root / ".unrest-runtime", "final": parent}[component]
    outside = tmp_path / "redirected"
    if unsafe == "symlink":
        selected.rename(outside)
        selected.symlink_to(outside, target_is_directory=True)
        observed = outside
    else:
        selected.chmod(0o777)
        observed = selected
    before = observed.stat()
    try:
        with pytest.raises((s.SupervisionSnapshotError, s.SupervisionSteeringError),
                           match="unsafe snapshot directory|supervision_storage_integrity_error"):
            _call(store, snapshot, binding, nested)
        assert observed.stat() == before
    finally:
        if unsafe == "symlink":
            selected.unlink()
            outside.rename(selected)
        else:
            selected.chmod(0o700)
    _released(store, binding)
    assert [(r.receipt_sequence, r.code) for r in s.load_supervision_receipts(store, binding.project_id, binding.mission_id)] == [(1, "continued")]


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("change", ["replace", "remove", "symlink", "mode", "hardlink"])
def test_detectable_change_while_real_owner_holds(tmp_path, snapshot_owner, monkeypatch, nested, change):
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"), project_guard=False)
    path = s.snapshot_path(store, binding.project_id, binding.mission_id, binding.attempt_id)
    lock = path.with_suffix(".lock")
    process, connection = snapshot_owner(path)
    original = s.fcntl.flock
    changed = False

    def flock(fd, flags):
        nonlocal changed
        if not changed and flags != fcntl.LOCK_UN and os.fstat(fd).st_ino == lock.stat().st_ino:
            # Positive ownership witness; change the actual path while this
            # descriptor waits, then release the real child. No outcome is mocked.
            with pytest.raises(BlockingIOError):
                original(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            changed = True
            if change in {"replace", "remove", "symlink"}:
                lock.rename(lock.with_suffix(".held"))
                if change == "replace":
                    lock.touch(mode=0o600)
                elif change == "symlink":
                    lock.symlink_to(lock.with_suffix(".held"))
            elif change == "mode":
                lock.chmod(0o640)
            else:
                os.link(lock, lock.with_suffix(".linked"))
            connection.send("release")
            process.join(5)
            assert process.exitcode == 0
        return original(fd, flags)

    monkeypatch.setattr(s.fcntl, "flock", flock)
    with pytest.raises(s.SupervisionSnapshotError, match="snapshot lock"):
        _call(store, snapshot, binding, nested)
    assert changed
    _released(store, binding)
    assert [(r.receipt_sequence, r.code) for r in s.load_supervision_receipts(store, binding.project_id, binding.mission_id)] == [(1, "continued")]


def _first_save(store, snapshot, gate, connection):
    try:
        assert gate.wait(5)
        s.save_snapshot(store, snapshot, assigned_target_ids=STEERING_TARGETS)
        lock = s.snapshot_path(store, snapshot.project_id, snapshot.mission_id, snapshot.attempt_id).with_suffix(".lock")
        connection.send((lock.stat().st_dev, lock.stat().st_ino))
    finally:
        connection.close()


def test_competing_first_use_and_restart_share_carrier(tmp_path):
    store, _, snapshot, _ = _prepare_role_checkpoint(tmp_path, "validator")
    snapshot = snapshot.model_copy(update={"attempt_id": "fresh", "mission_id": "fresh-mission"})
    ctx = multiprocessing.get_context("spawn")
    gate = ctx.Event()
    children = []
    try:
        for _ in range(2):
            parent, child = ctx.Pipe()
            proc = ctx.Process(target=_first_save, args=(store, snapshot, gate, child))
            proc.start()
            child.close()
            children.append((proc, parent))
        gate.set()
        identities = []
        for proc, parent in children:
            assert parent.poll(10)
            identities.append(parent.recv())
            proc.join(5)
            assert proc.exitcode == 0
        assert identities[0] == identities[1]
        s.save_snapshot(store, snapshot, assigned_target_ids=STEERING_TARGETS)
        lock = s.snapshot_path(store, snapshot.project_id, snapshot.mission_id, snapshot.attempt_id).with_suffix(".lock")
        assert (lock.stat().st_dev, lock.stat().st_ino) == identities[0]
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    finally:
        for proc, parent in children:
            if proc.is_alive():
                proc.kill()
            proc.join(5)
            assert not proc.is_alive()
            parent.close()
            proc.close()


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("target", ["carrier", "root"])
def test_supplemental_wrong_owner_stat_refusal(tmp_path, monkeypatch, nested, target):
    """Stat fault only: no authority to manufacture a foreign-owned 0600 file."""
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"), project_guard=False)
    lock = s.snapshot_path(store, binding.project_id, binding.mission_id, binding.attempt_id).with_suffix(".lock")
    selected = lock if target == "carrier" else store.bucket_root(binding.project_id)
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == selected:
            fields = list(info)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises((s.SupervisionSnapshotError, s.SupervisionSteeringError),
                       match="unsafe snapshot|supervision_storage_integrity_error"):
        _call(store, snapshot, binding, nested)
    _released(store, binding)


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("fault", ["owner", "mode", "links"])
def test_supplemental_descriptor_validation_before_body(tmp_path, monkeypatch, nested, fault):
    """Descriptor stat substitution supplements actual path/process cases."""
    store, _, snapshot, binding = _prepare_role_checkpoint(tmp_path, "validator")
    s.steer_attempt(store, _request(binding, "continue"), project_guard=False)
    path = s.snapshot_path(store, binding.project_id, binding.mission_id, binding.attempt_id)
    before = path.read_bytes()
    identity = path.with_suffix(".lock").stat().st_ino
    original = os.fstat
    descriptors = set()

    def fstat(fd):
        info = original(fd)
        if info.st_ino == identity:
            descriptors.add(fd)
            fields = list(info)
            index, value = {"owner": (4, os.geteuid() + 1), "mode": (0, stat.S_IFREG | 0o640), "links": (3, 2)}[fault]
            fields[index] = value
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(s.os, "fstat", fstat)
    with pytest.raises(s.SupervisionSnapshotError, match="unsafe snapshot lock"):
        _call(store, snapshot, binding, nested)
    assert descriptors
    for fd in descriptors:
        with pytest.raises(OSError):
            original(fd)
    assert path.read_bytes() == before
    _released(store, binding)
