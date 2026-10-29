"""Inherited-description custody and current owner checks; no fabricated peers."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from process_ledger import Birth
import multiprocess_pipe as pipe


def bindings(*, child=False):
    root = Birth(100, 100, 1, 10, "boot", 20000)
    birth = Birth(101, 101, 100, 11, "boot", 20000) if child else root
    actor = {
        "birth": birth,
        "token": "token",
        "case": "case",
        "role": "mp-child" if child else "root",
    }
    process = SimpleNamespace(
        token="token",
        registered_generation=1,
        generation=1,
        case="case",
        exit=None,
        terminal=None,
        stage="registered" if child else "body-ready",
        parent=root if child else None,
    )
    host = SimpleNamespace(
        case="case", ledger=SimpleNamespace(poison=[], process=lambda birth: process)
    )
    return host, actor, process


@pytest.mark.parametrize(
    "mutation", [None, "case", "token", "generation", "exit", "terminal", "stage"]
)
def test_parent_record_requires_live_current_authenticated_owner(monkeypatch, mutation):
    host, actor, process = bindings()
    monkeypatch.setattr(pipe, "acquire", lambda birth, fd: [fd, 1, 50, 2, 900])
    if mutation == "case":
        host.case = "foreign"
    elif mutation == "token":
        actor["token"] = "foreign"
    elif mutation == "generation":
        process.generation = 2
    elif mutation == "exit":
        process.exit = (1, 0)
    elif mutation == "terminal":
        process.terminal = (1, 0, 0)
    elif mutation == "stage":
        process.stage = "core-ready"
    if mutation is None:
        assert pipe.parent_record(host, actor, 11) == [11, 1, 50, 2, 900, 100, 10]
    else:
        with pytest.raises(Refused):
            pipe.parent_record(host, actor, 11)


@pytest.mark.parametrize("mutation", [None, "device", "inode", "access", "cookie"])
def test_local_inherited_record_compares_actual_file_description(monkeypatch, mutation):
    observed = [1, 50, 2, 900]
    if mutation is not None:
        observed[("device", "inode", "access", "cookie").index(mutation)] += 1
    monkeypatch.setattr(pipe, "descriptor", lambda fd, uid: observed)
    saved = [11, 1, 50, 2, 900, 100, 10]
    if mutation is None:
        assert pipe.local_record(saved) == saved
    else:
        with pytest.raises(Refused, match="file description changed"):
            pipe.local_record(saved)


@pytest.mark.parametrize("mutation", [None, "parent", "ticks", "role", "cookie", "fd", "already_ready"])
def test_observer_reacquires_child_before_body_ready(monkeypatch, mutation):
    host, actor, process = bindings(child=True)
    saved = [11, 1, 50, 2, 900, 100, 10]
    observed = saved[:5]
    if mutation == "parent":
        saved[5] += 1
    elif mutation == "ticks":
        saved[6] += 1
    elif mutation == "role":
        actor["role"] = "fixed-inline"
    elif mutation == "cookie":
        observed[4] += 1
    elif mutation == "fd":
        observed[0] += 1
    elif mutation == "already_ready":
        process.stage = "body-ready"
    monkeypatch.setattr(pipe, "acquire", lambda birth, fd: observed)
    if mutation is None:
        pipe.retained(host, actor, saved, body=False)
    else:
        with pytest.raises(Refused):
            pipe.retained(host, actor, saved, body=False)


def test_actual_body_ready_follows_independent_recensus(monkeypatch):
    from source_observer import Observer

    host, actor, _ = bindings(child=True)
    stages = []
    host.ledger.ready = lambda *args: stages.append("body-ready")
    host.mp_pipes = {(actor["birth"], 11): [11, 1, 50, 2, 900, 100, 10]}

    def retained(host, actor, row, *, body):
        assert stages == [] and body is False
        stages.append("independent-recensus")

    monkeypatch.setattr(pipe, "retained", retained)
    assert Observer.dispatch(host, actor, {"kind": "body-ready", "payload": {}}) == {
        "ok": True
    }
    assert stages == ["independent-recensus", "body-ready"] and actor["body_ready"] is True
