"""Actual collection is deferred; persisted numeric evidence is never rewritten."""

from __future__ import annotations

import copy
import os
from types import SimpleNamespace

import pytest

import approval_wait_order as order


def example(monkeypatch):
    child = {
        "pid": 54,
        "ppid": 53,
        "uid": 20000,
        "start_ticks": 123,
        "boot_id": "boot",
        "clock_ticks_per_second": 100,
    }
    parent = {**child, "pid": 53, "ppid": 51, "start_ticks": 122}
    case = next(c for c in order.CASES if c.endswith("[cancel]"))
    registration = {
        "kind": "registered",
        "pid": 54,
        "owner_pid": 53,
        "case": case,
        "class": "source-approval-python-backend",
        "token": "child",
    }
    parent_registration = {
        **registration,
        "pid": 53,
        "owner_pid": 51,
        "class": "source-approval-relay",
        "token": "parent",
    }
    events = [
        registration,
        parent_registration,
        {
            "kind": "ready",
            "owner_pid": 54,
            "token": "child",
            "case": case,
            "class": registration["class"],
            "parent_pid": 53,
        },
        {
            "kind": "ready",
            "owner_pid": 53,
            "token": "parent",
            "case": case,
            "class": parent_registration["class"],
            "parent_pid": 51,
        },
    ]
    supervisor = SimpleNamespace(
        events=lambda: events,
        registered={
            54: {"identity": child, "token": "child"},
            53: {"identity": parent, "token": "parent"},
        },
    )
    trace = SimpleNamespace(
        active={53, 54, 55},
        identities={53: parent},
        records=[
            {"kind": "kernel_child", "parent": 53, "child": 54, "identity": child},
            {"kind": "kernel_exit", "pid": 54, "raw": 15},
            {"kind": "kernel_exit", "pid": 53, "raw": 15},
        ],
    )
    authority = SimpleNamespace(
        _approval_exited={53, 54}, bound={54: {"registration": registration}}, supervisor=supervisor
    )
    current = {**child, "ppid": os.getpid(), "uids": [20000] * 4}
    monkeypatch.setattr(order, "snapshot", lambda pid: dict(current))
    monkeypatch.setattr(order, "PINS", {})
    return authority, trace, events, current


@pytest.mark.parametrize(
    "change",
    [
        None,
        "running-parent",
        "already-collected-parent",
        "duplicate-child-exit",
        "duplicate-birth",
        "wrong-birth",
        "foreign-case",
        "no-ready",
        "foreign-token",
        "wrong-identity",
        "wrong-uids",
        "not-adopted",
        "wrong-signal",
        "wrong-class",
        "wrong-parent-token",
        "ready-case",
        "ready-class",
        "ready-parent",
        "parent-ready-case",
        "parent-ready-class",
        "parent-ready-parent",
    ],
)
def test_deferral_requires_exact_exited_adopted_child(monkeypatch, change):
    authority, trace, events, current = example(monkeypatch)
    if change == "running-parent":
        trace.records.pop()
    elif change == "already-collected-parent":
        trace.records.append({"kind": "tracer_terminal_wait", "pid": 53})
    elif change == "duplicate-child-exit":
        trace.records.append(dict(trace.records[1]))
    elif change == "duplicate-birth":
        trace.records.append(dict(trace.records[0]))
    elif change == "wrong-birth":
        trace.records[0]["identity"] = {**trace.records[0]["identity"], "start_ticks": 1}
    elif change == "foreign-case":
        events[0]["case"] = "foreign"
    elif change == "no-ready":
        events.pop(2)
    elif change == "foreign-token":
        events[2]["token"] = "foreign"
    elif change == "wrong-identity":
        current["start_ticks"] = 1
    elif change == "wrong-uids":
        current["uids"] = [0] * 4
    elif change == "not-adopted":
        current["ppid"] = 53
    elif change == "wrong-signal":
        trace.records[-1]["raw"] = 0
    elif change == "wrong-class":
        events[0]["class"] = "foreign"
    elif change == "wrong-parent-token":
        events[-1]["token"] = "foreign"
    elif change and change.startswith("ready-"):
        events[2][
            {"ready-case": "case", "ready-class": "class", "ready-parent": "parent_pid"}[change]
        ] = "foreign"
    elif change and change.startswith("parent-ready-"):
        events[3][
            {
                "parent-ready-case": "case",
                "parent-ready-class": "class",
                "parent-ready-parent": "parent_pid",
            }[change]
        ] = "foreign"
    before = copy.deepcopy(trace.records)
    assert order.defer(authority, trace, 54) is (change is None)
    assert trace.records == before
    assert not order.defer(authority, trace, 55)


def test_round_robin_collects_actual_parent_first_and_reacquires(monkeypatch):
    authority, trace, _, current = example(monkeypatch)
    recorded = []
    # A delayed parent does not prevent servicing an unrelated runnable task.
    for available in ({55}, {53}, {54}):
        for candidate in (54, 53, 55):
            if order.defer(authority, trace, candidate):
                continue
            if candidate in available:
                recorded.append(candidate)
                trace.records.append({"kind": "tracer_terminal_wait", "pid": candidate})
                break
    assert recorded == [55, 53, 54]
    # Identity uncertainty never creates deferral authority or a wait result.
    current["start_ticks"] += 1
    assert not order.defer(authority, trace, 54)
