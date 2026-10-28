"""Owned-signal mutation controls at the independent observer boundary."""

from dataclasses import replace

import pytest

from content_manifest import Refused
from controlled_cases import WARNING_REFUSALS
from source_observer import Observer
import source_observer
from test_process_ledger import setup, identity


def signal_model(monkeypatch, case):
    ledger, root, child = setup()
    for birth in (root, child):
        ledger.process(birth).case = case
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.ledger, observer.root_birth, observer.finished, observer.case = (
        ledger,
        root,
        False,
        case,
    )
    parent = {"role": "root", "case": case, "birth": root, "token": "root-token"}
    backend = {
        "role": "backend",
        "case": case,
        "birth": child,
        "token": "child-token",
        "signals": set(),
    }
    observer.actors = {root.pid: parent, child.pid: backend}
    monkeypatch.setattr(
        source_observer, "process_identity", lambda pid: identity(child.pid, root.pid)
    )
    payload = {"pid": child.pid, "child_token": "child-token", "signal": 10, "group": False}
    return observer, parent, backend, payload


@pytest.mark.parametrize(
    "mutation", [None, "group", "pid", "generation", "token", "parent", "case", "signal", "boolean"]
)
def test_original_teardown_signal_requires_its_exact_owned_backend(monkeypatch, mutation):
    case = "tests/test_experimental_bridge_shutdown.py::test_owned_teardown_completes_after_native_drain_failure"
    observer, parent, backend, payload = signal_model(monkeypatch, case)
    if mutation == "group":
        payload["group"] = True
    elif mutation == "pid":
        payload["pid"] += 1
    elif mutation == "generation":
        monkeypatch.setattr(
            source_observer,
            "process_identity",
            lambda pid: {**identity(101, 100), "start_ticks": 99999},
        )
    elif mutation == "token":
        payload["child_token"] = "foreign"
    elif mutation == "parent":
        observer.ledger.process(backend["birth"]).parent = replace(parent["birth"], ticks=99999)
    elif mutation == "case":
        backend["case"] = "foreign"
    elif mutation == "signal":
        payload["signal"] = 12
    elif mutation == "boolean":
        payload["signal"] = True
    if mutation == "generation":
        assert observer.dispatch(parent, {"kind": "custody_signal", "payload": payload}) == {
            "ok": True,
            "live": False,
        }
    elif mutation is None:
        assert observer.dispatch(parent, {"kind": "custody_signal", "payload": payload}) == {
            "ok": True,
            "live": True,
        }
        assert backend["signals"] == {10}
    else:
        with pytest.raises(Refused):
            observer.dispatch(parent, {"kind": "custody_signal", "payload": payload})
        assert not backend["signals"]


@pytest.mark.parametrize("case", WARNING_REFUSALS)
def test_warning_signal_is_case_bound_and_cannot_be_replayed(monkeypatch, case):
    observer, parent, backend, payload = signal_model(monkeypatch, case)
    assert observer.dispatch(parent, {"kind": "custody_signal", "payload": payload}) == {
        "ok": True,
        "live": True,
    }
    with pytest.raises(Refused, match="replay"):
        observer.dispatch(parent, {"kind": "custody_signal", "payload": payload})
