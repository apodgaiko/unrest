"""Exact composed RunControl orphan evidence; no child status is inferred."""

import os
from typing import Any

CASES = frozenset(
    "tests/test_server.py::test_composed_all_role_parity_restart_and_cooperative_stop[" + role + "]"
    for role in ("worker", "validator", "terminal_reviewer")
)


def record(
    state: dict[str, Any], events: list[dict[str, Any]], child: dict[str, Any]
) -> dict[str, Any] | None:
    if child["class"] != "source-run-worker" or child.get("case") not in CASES:
        return None
    token = child["token"]
    owner = child["owner_pid"]
    pid = child["pid"]
    parent = next(
        (
            e
            for e in events
            if e["kind"] == "registered"
            and e["pid"] == owner
            and e["class"] == "composed-http-role:orchestrator"
            and e.get("case") == child["case"]
        ),
        None,
    )
    ready = next((e for e in events if e["kind"] == "ready" and e["token"] == token), None)
    admitted = next((e for e in events if e["kind"] == "admitted" and e["token"] == token), None)
    binding = next(
        (e for e in events if e["kind"] == "actual_launch_binding" and e["token"] == token), None
    )
    options = next(
        (e for e in events if e["kind"] == "launch_lifecycle_binding" and e["token"] == token), None
    )
    parent_wait = next(
        (
            e
            for e in events
            if e["kind"] == "actual_waitpid"
            and parent
            and e["owner_pid"] == parent["owner_pid"]
            and e["pid"] == owner
            and e["numeric_returncode"] == -15
        ),
        None,
    )
    before = next(
        (
            e
            for e in events
            if e["kind"] == "original_group_inventory"
            and e["case"] == child["case"]
            and any(r == [pid, owner, pid] for r in e["members"])
        ),
        None,
    )
    orphan = next(
        (
            e
            for e in events
            if e["kind"] == "original_group_inventory"
            and e["case"] == child["case"]
            and any(r == [pid, 1, pid] for r in e["members"])
        ),
        None,
    )
    passed = any(
        e["kind"] == "test_outcome"
        and e.get("nodeid") == child["case"]
        and e["phase"] == "call"
        and e["outcome"] == "passed"
        for e in events
    )
    finished = any(
        e["kind"] == "finished" and e["owner_pid"] == pid and e["token"] == token for e in events
    )
    if not all(
        (parent, ready, admitted, binding, options, parent_wait, before, orphan, passed, finished)
    ):
        return None
    assert ready is not None and admitted is not None and options is not None
    if (
        ready["parent_pid"] != owner
        or ready["sid"] != pid
        or ready["pgid"] != pid
        or not options["start_new_session"]
        or options["executable_sha256"] != state["runtime"]["sha256"]
        or admitted["source_binding"]["path"]
        != state["checkout"] + "/src/unrest_harness/run_control.py"
        or admitted["source_binding"]["sha256"]
        != state["product_pins"]["src/unrest_harness/run_control.py"]
    ):
        return None
    try:
        os.kill(pid, 0)
        return None
    except ProcessLookupError:
        pass
    try:
        os.killpg(pid, 0)
        return None
    except ProcessLookupError:
        pass
    return {
        "wait_status": "exact_approved_live_orphan",
        "actual_wait_observed": False,
        "numeric_returncode": None,
        "final_child_timing": "UNVERIFIED",
        "physical_absence_observed": True,
        "process_group_absence_observed": True,
        "parent_numeric_wait": parent_wait,
        "before_inventory": before,
        "orphan_inventory": orphan,
        "original_oracle_passed": True,
        "finished_marker": True,
        "ready": ready,
        "admitted": admitted,
        "launch_binding": binding,
        "lifecycle_binding": options,
        "source_oracle_sha256": state["http_source_sha256"],
        "limits": "sole original composed RunControl live-orphan route; no child wait or exit cause inferred",
    }
