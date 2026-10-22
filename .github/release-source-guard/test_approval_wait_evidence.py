"""A dead original parent is never invented; adopted waits require kernel proof."""

import copy

import pytest

from approval_wait_evidence import (
    adopted_waits,
    digest,
    original_missing,
    summary_closed,
    unresolved,
)
from approval_orphan_custody import DURABLE_PREFIX


def fixture(second=False):
    case = DURABLE_PREFIX + "[cancel]"

    def identity(pid, ppid):
        return dict(
            pid=pid,
            ppid=ppid,
            pgid=9,
            sid=9,
            uid=20000,
            start_ticks=pid * 100,
            boot_id="controlled-boot",
            clock_ticks_per_second=100,
        )

    def birth(pid, parent):
        value = identity(pid, parent)
        return dict(
            kind="kernel_child", child=pid, identity={**value, "tgid": pid, "uids": [20000] * 4}
        )

    p, c = identity(10, 5), identity(20, 10)
    rows = [
        birth(10, 5),
        birth(20, 10),
        dict(kind="kernel_exit", pid=10, raw=15),
        dict(
            kind="tracer_terminal_wait",
            pid=10,
            raw=15,
            normalized=-15,
            identity={**p, "uids": [20000] * 4},
        ),
        dict(kind="kernel_exit", pid=20, raw=15),
        dict(kind="tracer_terminal_wait", pid=20, raw=15, normalized=-15, identity=c),
        dict(kind="original_parent_wait4", child=10, parent_tgid=5, raw=15),
    ]
    events = [
        dict(kind="registered", pid=10, owner_pid=5, case=case, **{"class": "source-run-worker"}),
        dict(
            kind="registered",
            pid=20,
            owner_pid=10,
            case=case,
            token="controlled-token",
            **{"class": "source-approval-relay"},
        ),
        dict(
            kind="ready",
            owner_pid=20,
            parent_pid=10,
            case=case,
            token="controlled-token",
            **{"class": "source-approval-relay"},
        ),
        dict(
            kind="endpoint_install_complete",
            owner_pid=20,
            case=case,
            token="controlled-token",
            identity=c,
        ),
    ]
    events += [
        dict(kind="test_outcome", nodeid=case, phase=phase, outcome="passed")
        for phase in ("setup", "call", "teardown")
    ]
    current = {**c, "ppid": 1}
    if second:
        pipes = [
            dict(
                kind="actual_adoptive_parent_wait4",
                pid=20,
                observer_pid=1,
                observer_uid=20001,
                raw=15,
                normalized=-15,
                current_identity=current,
                original_birth=c,
                parent_death=dict(parent_terminal=rows[3], parent_kernel_exit=rows[2], case=case),
                tracer_wait_index=5,
                tracer_wait_sha256=digest(rows[5]),
                trace_record_count_at_actual_wait=len(rows),
                process_absent_after_actual_wait=True,
            )
        ]
    else:
        pipes = [
            dict(
                kind="approval_exit_observation",
                pid=20,
                observer_pid=1,
                observer_uid=20001,
                phase=phase,
                trace_index=i,
                trace_row_sha256=digest(rows[i]),
                raw=15,
                case=case,
                numeric_wait_observed=phase == "tracer_terminal_wait",
                current_identity={**current, "uids": [20000] * 4},
                process_absent_after_actual_wait=True,
                **{"class": "source-approval-relay"},
            )
            for i, phase in [(4, "kernel_exit"), (5, "tracer_terminal_wait")]
        ]
    k = dict(
        records=rows, source_events=events, source_pipe_records=pipes, missing_parent_waits=[20]
    )
    s = dict(
        ready=False,
        original_pytest_exit_code=0,
        failures=[dict(kind="missing_wait", owner_pid=10, pid=20)],
    )
    return k, s


@pytest.mark.parametrize("second", [False, True])
def test_numeric_adoptive_wait_retains_original_gap(second):
    k, s = fixture(second)
    before = copy.deepcopy(k)
    assert original_missing(k) == [20]
    assert list(adopted_waits(k)) == [20] and unresolved(k) == [] and summary_closed(s, k)
    assert k == before and k["missing_parent_waits"] == [20]


@pytest.mark.parametrize("second", [False, True])
@pytest.mark.parametrize(
    "drift",
    [
        "no_wait",
        "residue",
        "wrong_parent",
        "reused_birth",
        "wrong_status",
        "duplicate_wait",
        "wrong_token",
        "wrong_case",
        "foreign_class",
        "failed_teardown",
        "parent_not_dead",
        "raw_inventory",
        "false_ready",
        "wrong_trace_hash",
        "wrong_uid",
        "numeric_bool",
        "summary_other_failure",
    ],
)
def test_absence_claim_or_contradiction_never_closes_wait(second, drift):
    k, s = fixture(second)
    p = k["source_pipe_records"][-1]
    if drift == "no_wait":
        k["source_pipe_records"] = []
    elif drift == "residue":
        p["process_absent_after_actual_wait"] = False
    elif drift == "wrong_parent":
        k["source_pipe_records"][0]["current_identity"]["ppid"] = 999
    elif drift == "reused_birth":
        k["source_pipe_records"][0]["current_identity"]["start_ticks"] += 1
    elif drift == "wrong_status":
        p["raw"] = 0
    elif drift == "duplicate_wait":
        k["records"] += [dict(kind="original_parent_wait4", child=20, parent_tgid=10, raw=15)] * 2
    elif drift == "wrong_token":
        k["source_events"][2]["token"] = "foreign"
    elif drift == "wrong_case":
        k["source_events"][1]["case"] = "unapproved"
    elif drift == "foreign_class":
        k["source_events"][1]["class"] = "native-provider"
    elif drift == "failed_teardown":
        k["source_events"][-1]["outcome"] = "failed"
    elif drift == "parent_not_dead":
        k["records"][3]["raw"] = 0
    elif drift == "raw_inventory":
        k["missing_parent_waits"] = []
    elif drift == "false_ready":
        s.update(ready=True, failures=[])
        k["source_pipe_records"] = []
    elif drift == "wrong_trace_hash":
        p["tracer_wait_sha256" if second else "trace_row_sha256"] = "0" * 64
    elif drift == "wrong_uid":
        p["observer_uid"] = 20000
    elif drift == "numeric_bool":
        p["raw"] = True
    else:
        s["failures"].append(dict(kind="poison", pid=20, owner_pid=10))
    assert not summary_closed(s, k)


@pytest.mark.parametrize("second", [False, True])
def test_trace_causality_cannot_be_reordered(second):
    k, s = fixture(second)
    k["records"][2], k["records"][3] = k["records"][3], k["records"][2]
    assert unresolved(k) == [20] and not summary_closed(s, k)


def test_explicit_wait_cannot_precede_parent_death():
    k, s = fixture(True)
    k["source_pipe_records"][0]["trace_record_count_at_actual_wait"] = 3
    assert unresolved(k) == [20] and not summary_closed(s, k)


def test_missing_raw_inventory_is_not_reconstructed():
    k, s = fixture()
    del k["missing_parent_waits"]
    assert unresolved(k) == [-1] and not summary_closed(s, k)


@pytest.mark.parametrize("drift", [None, "omitted", "duplicate", "status_type"])
def test_receipt_retains_original_gaps_with_separate_numeric_waits(drift):
    from test_checkpoint_receipt import fixture as receipt_fixture, seal, receipt

    expected, run, jobs, data, cipher = receipt_fixture()
    data["source"]["missing_original_parent_waits"] = [20]
    data["source"]["actual_adoptive_parent_waits"] = [
        dict(pid=20, method="actual_adoptive_parent_wait4", raw=15)
    ]
    if drift == "omitted":
        data["source"]["actual_adoptive_parent_waits"] = []
    elif drift == "duplicate":
        data["source"]["actual_adoptive_parent_waits"] *= 2
    elif drift == "status_type":
        data["source"]["actual_adoptive_parent_waits"][0]["raw"] = True
    body, artifact = seal(data, cipher)
    if drift is None:
        assert (
            receipt.validate(body, artifact, run, jobs, expected)["execution_kind"]
            == "verified-same-commit-reuse"
        )
    else:
        with pytest.raises(RuntimeError):
            receipt.validate(body, artifact, run, jobs, expected)


def test_host_reducer_has_no_runtime_guard_imports():
    import ast
    from pathlib import Path
    from approval_orphan_custody import CASES, CLASSES
    import approval_wait_evidence as rule

    assert rule.CASES == CASES and rule.CLASSES == CLASSES
    tree = ast.parse(Path(rule.__file__).read_bytes())
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imported.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert imported == {"__future__", "hashlib", "json", "os"}


@pytest.mark.parametrize("second", [False, True])
def test_live_terminal_connection_uses_actual_adoptive_wait_before_teardown(second):
    from types import SimpleNamespace
    from approval_terminal_peer import settled

    k, s = fixture(second)
    k["source_events"] = [r for r in k["source_events"] if r["kind"] != "test_outcome"]
    saved = next(
        r["identity"] for r in k["source_events"] if r["kind"] == "endpoint_install_complete"
    )
    host = SimpleNamespace(
        owned_trace=SimpleNamespace(records=k["records"]),
        approval_pipe_records=k["source_pipe_records"],
        events=lambda: k["source_events"],
    )
    result = settled(host, saved)
    assert result["original_parent_wait"] is None
    assert result["actual_adoptive_parent_wait"]["raw"] == 15
    assert not summary_closed(s, k)  # Final certification still requires original teardown.


def test_live_terminal_connection_never_treats_absence_as_adoption():
    from types import SimpleNamespace
    from approval_terminal_peer import settled
    from linux_supervisor import AwaitOwnedPeer

    k, _ = fixture()
    saved = next(
        r["identity"] for r in k["source_events"] if r["kind"] == "endpoint_install_complete"
    )
    host = SimpleNamespace(
        owned_trace=SimpleNamespace(records=k["records"]),
        approval_pipe_records=[],
        events=lambda: k["source_events"],
    )
    with pytest.raises(AwaitOwnedPeer):
        settled(host, saved)
