"""Synthetic inherited-member controls; native original cases prove real custody."""

import os
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from process_ledger import Birth
from endpoint_policy import Owner
from unix_endpoints import Member, Pair, UnixPairs
import multiprocess_pipe as pipe


def birth(pid, start=100):
    return Birth.read(
        {
            "pid": pid,
            "tgid": pid,
            "ppid": 1 if pid == 100 else 100,
            "start_ticks": start,
            "boot_id": "boot",
            "uids": [20000] * 4,
        }
    )


def bindings():
    root, child = birth(100), birth(101)
    owner = Owner(root, "root-token", 1)
    pair = Pair(
        1,
        owner,
        "case",
        (Member(root, 11, 50, 900, 20000, 60, 1), Member(root, 12, 60, 901, 20000, 50, 1)),
    )
    pairs = object.__new__(UnixPairs)
    pairs.pairs = {1: pair}
    pairs.poison = []
    pairs.endpoints = SimpleNamespace(owner=lambda *args, **kwargs: None)
    return root, child, owner, pair, pairs


@pytest.mark.parametrize(
    "mutation", [None, "missing", "case", "owner", "replaced", "direction", "nonstream"]
)
def test_parent_inheritance_requires_current_original_pair(tmp_path, monkeypatch, mutation):
    root, _, owner, pair, pairs = bindings()
    actor = {"birth": root}
    host = SimpleNamespace(
        case="case", descriptors={(root, 11): pair}, owner=lambda actor: owner, pairs=pairs
    )
    if mutation == "missing":
        host.descriptors.clear()
    elif mutation == "case":
        host.case = "other"
    elif mutation == "owner":
        host.owner = lambda actor: Owner(root, "foreign", 1)
    observed = pair.members[0]
    if mutation == "replaced":
        observed = Member(root, 11, 50, 999, 20000, 60, 1)
    monkeypatch.setattr(pipe, "acquire_unix_member", lambda *args: observed)
    info = os.stat_result(
        (
            (stat.S_IFREG if mutation == "nonstream" else stat.S_IFSOCK) | 0o777,
            50,
            1,
            1,
            20000,
            20000,
            0,
            0,
            0,
            0,
        )
    )
    monkeypatch.setattr(Path, "stat", lambda path: info)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path: "flags:\t" + ("00" if mutation == "direction" else "02") + "\n",
    )
    if mutation is None:
        assert pipe.parent_record(host, actor, 11) == [11, 1, 50, os.O_RDWR, 900, 60, 1]
    else:
        with pytest.raises(Refused):
            pipe.parent_record(host, actor, 11)


@pytest.mark.parametrize(
    "mutation", [None, "inode", "uid", "file", "flags", "cookie", "domain", "type", "race"]
)
def test_child_queries_held_description_without_new_network_family(monkeypatch, mutation):
    saved = [11, 1, 50, os.O_RDWR, 900, 60, 1]
    reads = []

    def metadata(fd):
        reads.append(fd)
        inode = 51 if mutation == "inode" or mutation == "race" and len(reads) > 1 else 50
        mode = (stat.S_IFREG if mutation == "file" else stat.S_IFSOCK) | 0o777
        return os.stat_result(
            (mode, inode, 1, 1, 999 if mutation == "uid" else 20000, 20000, 0, 0, 0, 0)
        )

    monkeypatch.setattr(pipe.os, "fstat", metadata)
    monkeypatch.setattr(
        pipe.fcntl, "fcntl", lambda *args: os.O_RDWR | (os.O_NONBLOCK if mutation == "flags" else 0)
    )
    monkeypatch.setattr(pipe.os, "dup", lambda fd: 700)

    class Socket:
        def __init__(self, *, fileno):
            assert fileno == 700

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def getsockopt(self, level, option, *size):
            assert level == socket.SOL_SOCKET
            if option == 39:
                return socket.AF_INET if mutation == "domain" else socket.AF_UNIX
            if option == socket.SO_TYPE:
                return socket.SOCK_DGRAM if mutation == "type" else socket.SOCK_STREAM
            assert option == 57 and size == (8,)
            return struct.pack("=Q", 901 if mutation == "cookie" else 900)

    monkeypatch.setattr(pipe.socket, "socket", Socket)
    if mutation is None:
        assert pipe.local_record(saved) == saved and reads == [11, 11]
    else:
        with pytest.raises(Refused):
            pipe.local_record(saved)


@pytest.mark.parametrize(
    "mutation", [None, "case", "parent", "pair", "birth", "gone", "state", "core-eof", "body-eof"]
)
def test_observer_checks_child_epoch_and_saved_pair_after_parent_duplicate_closes(
    monkeypatch, mutation
):
    root, child, owner, pair, pairs = bindings()
    row = [11, 1, 50, os.O_RDWR, 900, 60, 1]
    actor = {"birth": child, "case": "case", "role": "mp-child"}
    process = SimpleNamespace(
        parent=birth(100, 99) if mutation == "parent" else root, exit=None, terminal=None
    )
    ready = []
    host = SimpleNamespace(
        case="other" if mutation == "case" else "case",
        pairs=pairs,
        owner=lambda actor: Owner(child, "child-token", 1),
        endpoints=SimpleNamespace(owner=lambda *args, **kwargs: ready.append(kwargs["body"])),
        ledger=SimpleNamespace(process=lambda value: process),
    )
    if mutation == "pair":
        pairs.pairs.clear()
    identity = {
        "pid": 101,
        "tgid": 101,
        "ppid": 100,
        "start_ticks": 99 if mutation == "birth" else 100,
        "boot_id": "boot",
        "uids": [20000] * 4,
    }
    monkeypatch.setattr(pipe, "process_identity", lambda pid: identity)
    observed = (
        None
        if mutation == "gone"
        else {
            "state": 2 if mutation == "state" else 1,
            "peer_inode": 0 if mutation in ("core-eof", "body-eof") else 60,
        }
    )
    seen = []

    def retained(pid, fd, records):
        seen.append((pid, fd, records))
        return observed

    monkeypatch.setattr(pipe, "retained_unix_member", retained)
    body = mutation != "core-eof"
    if mutation in (None, "body-eof"):
        pipe.retained(host, actor, row, body=body)
        assert seen == [
            (
                101,
                11,
                [
                    {
                        "fd": 11,
                        "inode": 50,
                        "socket_cookie": 900,
                        "socket_uid": 20000,
                        "peer_inode": 60,
                    }
                ],
            )
        ]
        assert ready == [body] and process.exit is None and process.terminal is None
    else:
        with pytest.raises(Refused):
            pipe.retained(host, actor, row, body=body)


def test_actual_core_ready_dispatch_precedes_independent_member_recensus(monkeypatch):
    from source_observer import Observer

    child = birth(101)
    stage = []
    actor = {"birth": child, "pins": (), "role": "mp-child"}
    host = SimpleNamespace(
        mp_pipes={(child, 11): [11, 1, 50, 2, 900, 60, 1]},
        ledger=SimpleNamespace(ready=lambda *args: stage.append("core-ready")),
    )

    def retained(host, actor, row, *, body):
        assert stage == ["core-ready"] and body is False
        stage.append("independent-recensus")

    monkeypatch.setattr(pipe, "retained", retained)
    assert Observer.dispatch(host, actor, {"kind": "core-ready", "payload": {"pins": []}}) == {
        "ok": True
    }
    assert stage == ["core-ready", "independent-recensus"]
