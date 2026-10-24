"""Connected acquisition discards vanished entries, never positive kernel evidence."""

import os
from pathlib import Path
import socket
import sys

import pytest

import linux_sockets as observation


@pytest.fixture
def census(tmp_path, monkeypatch):
    root = tmp_path / "proc"
    descriptors = root / "123/fd"
    descriptors.mkdir(parents=True)
    for name in ("5", "6", "7"):
        (descriptors / name).touch()
    original_path = Path
    monkeypatch.setattr(
        observation, "Path", lambda value: root if str(value) == "/proc" else original_path(value)
    )
    monkeypatch.setattr(observation, "identity", lambda pid: {"pid": pid, "start_ticks": 10})
    values = {"5": None, "6": "socket:[21]", "7": "socket:[22]"}
    calls = []

    def readlink(path):
        calls.append(path.name)
        value = values[path.name]
        if isinstance(value, BaseException):
            raise value
        if value is None:
            raise FileNotFoundError()
        return value

    monkeypatch.setattr(observation.os, "readlink", readlink)
    rows = {
        21: {
            "inode": 21,
            "socket_cookie": 31,
            "socket_uid": 20000,
            "state": 10,
            "local_host": "127.0.0.1",
            "local_port": 12345,
            "remote_host": "0.0.0.0",
            "remote_port": 0,
        },
        22: {
            "inode": 22,
            "socket_cookie": 32,
            "socket_uid": 20000,
            "state": 1,
            "local_host": "127.0.0.1",
            "local_port": 12345,
            "remote_host": "127.0.0.1",
            "remote_port": 40000,
        },
    }
    monkeypatch.setattr(observation, "tcp_table", lambda: rows)
    return values, rows, calls


def test_disappeared_unrelated_descriptor_does_not_change_any_live_tcp_row(census):
    _, rows, calls = census
    with pytest.raises(RuntimeError, match="owned descriptor observation raced"):
        observation.sockets(123)
    expected = [{"pid": 123, "fd": fd, **rows[inode]} for fd, inode in ((6, 21), (7, 22))]
    assert observation.connected_sockets(123) == expected
    assert calls.count("5") >= 2
    # Generic and Unix acquisition retain their existing refusal behavior.
    with pytest.raises(RuntimeError, match="owned descriptor observation raced"):
        observation.unix_pair(123, [6, 7])


@pytest.mark.parametrize("missing", ["6", "7"])
def test_missing_requested_listener_or_peer_never_supplies_a_row(census, missing):
    values, rows, _ = census
    saved = dict(rows[21 if missing == "6" else 22])
    values[missing] = None
    observed = observation.connected_sockets(123)
    assert not any(row["fd"] == int(missing) for row in observed)
    assert saved not in observed
    assert len(observed) == 1


def test_reused_descriptor_cannot_supply_old_inode_or_cookie(census, monkeypatch):
    values, rows, _ = census

    def table():
        values["6"] = "socket:[99]"
        return rows

    monkeypatch.setattr(observation, "tcp_table", table)
    with pytest.raises(RuntimeError, match="owned descriptor binding changed"):
        observation._connected_socket_snapshot(123)
    # Reacquisition gets no guessed row when the new inode is not in the table.
    assert not any(row["fd"] == 6 for row in observation.connected_sockets(123))


@pytest.mark.parametrize(
    "failure",
    [PermissionError(), RuntimeError("malformed diagnostic"), ValueError("malformed inode")],
)
def test_permission_or_malformed_input_is_not_retried(census, failure):
    values, _, calls = census
    values["6"] = failure
    with pytest.raises(type(failure)):
        observation.connected_sockets(123)
    assert calls.count("6") == 1


@pytest.mark.parametrize("failures", [1, 2, 3])
def test_same_three_attempt_bound_discards_all_raced_rows(monkeypatch, failures):
    births, attempts = [], []

    def identity(pid):
        births.append(pid)
        return {"pid": pid, "start_ticks": 10}

    def snapshot(pid):
        attempts.append(pid)
        if len(attempts) <= failures:
            raise RuntimeError("owned descriptor binding changed during socket observation")
        return [{"pid": pid, "fd": 6, "inode": 22, "socket_cookie": 32}]

    monkeypatch.setattr(observation, "identity", identity)
    monkeypatch.setattr(observation, "_connected_socket_snapshot", snapshot)
    if failures == 3:
        with pytest.raises(RuntimeError, match="owned descriptor binding changed"):
            observation.connected_sockets(123)
    else:
        assert observation.connected_sockets(123) == [
            {"pid": 123, "fd": 6, "inode": 22, "socket_cookie": 32}
        ]
    assert len(attempts) == min(failures + 1, 3)
    assert len(births) == 1 + len(attempts) + (failures < 3)


@pytest.mark.parametrize("replace_at", [2, 3])
def test_pid_birth_replacement_before_or_after_snapshot_refuses(monkeypatch, replace_at):
    calls = []

    def identity(pid):
        calls.append(pid)
        return {"pid": pid, "start_ticks": 10 if len(calls) < replace_at else 11}

    monkeypatch.setattr(observation, "identity", identity)
    monkeypatch.setattr(
        observation, "_connected_socket_snapshot", lambda pid: [{"fd": 6, "inode": 21}]
    )
    with pytest.raises(RuntimeError, match="stale_or_reused_ownership"):
        observation.connected_sockets(123)
    assert len(calls) == replace_at


@pytest.mark.skipif(sys.platform != "linux", reason="actual /proc and SOCK_DIAG require Linux")
def test_actual_connected_acquisition_retains_live_cookie_and_rejects_closed_target():
    pid = os.getpid()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        descriptor = listener.fileno()
        row = next(row for row in observation.connected_sockets(pid) if row["fd"] == descriptor)
        assert row["inode"] == os.fstat(descriptor).st_ino
        assert row["socket_cookie"] > 0 and row["socket_uid"] == os.getuid()
        assert row["state"] == 10 and row["local_port"] == listener.getsockname()[1]
    assert not any(
        item["fd"] == descriptor and item["inode"] == row["inode"]
        for item in observation.connected_sockets(pid)
    )
