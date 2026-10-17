"""Exact topology owner requests actual-parent waits after its original assertions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any

CASE = "tests/test_server.py::test_composed_hermetic_acp_topology_uses_public_attached_control"
REFUSAL_CASES = tuple(
    "tests/test_server.py::test_composed_completion_refusal_matrix_uses_original_generation[second-invalid-live-"
    + role
    + "]"
    for role in ("worker", "validator")
)
DEFECT_CASE = (
    "tests/test_server.py::test_composed_defective_work_reaches_independent_validator_dissent"
)
NUDGE_CASE = (
    "tests/test_server.py::test_composed_undeliverable_nudge_continues_without_body_persistence"
)
EXACT_CASES = (CASE, *REFUSAL_CASES, DEFECT_CASE, NUDGE_CASE)
SECONDS = 8.0


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".pending")
    if path.exists() or temporary.exists():
        raise RuntimeError("topology teardown publication collision")
    temporary.write_text(json.dumps(data, sort_keys=True) + "\n")
    temporary.replace(path)


def install(state: dict[str, Any], append: Any, refuse: Any, query: Any) -> dict[str, Any]:
    retained: list[dict[str, Any]] = []
    selected = state.get("case") in EXACT_CASES
    case = state.get("case")
    directory = Path(state["events"])
    source = Path(state["http_source"])
    pin = state["http_source_sha256"]

    def retain(handle: Any, registration: dict[str, Any], token: str) -> None:
        if (
            selected
            and state["class"] == "composed-http-role:orchestrator"
            and registration["class"] == "source-run-worker"
        ):
            observed = query(handle.pid)
            if observed["native_ppid"] != os.getpid():
                refuse("topology_retained_parent_drift")
            retained.append({"handle": handle, "identity": observed, "token": token})
            append(
                {
                    "kind": "topology_retained_child_identity",
                    "pid": handle.pid,
                    "token": token,
                    "identity": observed,
                }
            )

    def drain() -> None:
        request = directory / ("topology-teardown-" + str(os.getpid()) + ".json")
        while not request.exists():
            time.sleep(0.02)
        data = json.loads(request.read_bytes())
        if (
            data
            != {
                "owner_pid": os.getpid(),
                "token": state["token"],
                "case": case,
                "source_sha256": pin,
                "seconds": SECONDS,
            }
            or sha(source) != pin
        ):
            refuse("topology_teardown_request_drift")
        deadline = time.monotonic() + SECONDS
        for row in retained:
            handle = row["handle"]
            if handle.returncode is not None:
                continue
            identity = query(handle.pid)
            if any(
                identity[k] != row["identity"][k]
                for k in ("native_pid", "native_ppid", "native_start_ticks", "native_boot_id")
            ):
                refuse("topology_teardown_child_identity_drift")
            journal = directory / (str(handle.pid) + ".jsonl")
            ready = [
                json.loads(line)
                for line in journal.read_bytes().splitlines()
                if json.loads(line)["kind"] == "ready"
            ]
            if (
                len(ready) != 1
                or ready[0]["token"] != row["token"]
                or ready[0]["parent_pid"] != os.getpid()
                or ready[0]["manifest_sha256"] != state["pin"]
            ):
                refuse("topology_teardown_READY_drift")
            code = handle.wait(timeout=max(0.001, deadline - time.monotonic()))
            append(
                {
                    "kind": "topology_actual_parent_teardown_wait",
                    "pid": handle.pid,
                    "token": row["token"],
                    "numeric_returncode": code,
                    "identity": identity,
                    "original_assertions_before_request": True,
                    "seconds": SECONDS,
                }
            )
        ack = request.with_suffix(".ack")
        publish(ack, data)
        append(
            {
                "kind": "topology_actual_parent_teardown_ack",
                "retained_children": len(retained),
                "seconds": SECONDS,
            }
        )

    if selected and state["class"] == "composed-http-role:orchestrator":
        threading.Thread(target=drain, daemon=True, name="exact-topology-teardown").start()

    def before_signal(frame: Any, pgid: int, sig: int) -> None:
        case = state.get("case")
        if case not in EXACT_CASES or state["token"] != "root" or sig != 15:
            return
        helper = frame
        owner = frame
        name = case.split("::")[1].split("[")[0]
        while owner is not None and owner.f_code.co_name != name:
            owner = owner.f_back
        if (
            owner is None
            or helper.f_code.co_filename != str(source)
            or helper.f_code.co_name != "_http_server_process"
        ):
            return
        local = owner.f_locals
        process = helper.f_locals.get("process")
        if sha(source) != pin or process is None or process.pid != pgid:
            return
        if case == CASE:
            completed = (
                local.get("closed", {}).get("result", {}).get("state", {}).get("state") == "done"
                and local.get("close_steer", {}).get("code") == "continued"
                and local.get("orchestrator") is process
            )
        elif case in REFUSAL_CASES:
            completed = (
                local.get("restart") is False
                and local.get("repair") is False
                and local.get("finished", {}).get("result", {}).get("state", {}).get("state")
                == "attention_needed"
                and local.get("first_server") is process
            )
        elif case == NUDGE_CASE:
            completed = (
                local.get("completed", {}).get("result", {}).get("state", {}).get("state")
                == "mission_running"
                and local.get("blocked", {}).get("code") == "delivery_blocked"
                and local.get("_") is process
            )
        else:
            validator = local.get("validator")
            worker = local.get("worker")
            completed = (
                local.get("completed", {}).get("result", {}).get("state", {}).get("state")
                == "attention_needed"
                and worker is not None
                and worker.done is True
                and validator is not None
                and validator.done is True
                and validator.passed is False
                and local.get("_") is process
            )
        if not completed:
            return
        expected = state["isolated_source_code"](source)
        if helper.f_code != state["isolated_named"](
            expected, "_http_server_process"
        ) or owner.f_code != state["isolated_named"](expected, name):
            refuse("topology_teardown_source_code_drift")
        import sys

        if (
            sys.modules[owner.f_globals["__name__"]].__dict__ is not owner.f_globals
            or helper.f_globals is not owner.f_globals
        ):
            refuse("topology_teardown_globals_drift")
        records = [
            json.loads(line)
            for line in (directory / (str(pgid) + ".jsonl")).read_bytes().splitlines()
        ]
        ready = [
            r
            for r in records
            if r["kind"] == "ready" and r["class"] == "composed-http-role:orchestrator"
        ]
        if (
            len(ready) != 1
            or ready[0]["parent_pid"] != os.getpid()
            or ready[0]["manifest_sha256"] != state["pin"]
        ):
            refuse("topology_teardown_owner_READY_drift")
        identity = query(pgid)
        append(
            {
                "kind": "topology_teardown_original_assertions_completed",
                "pid": pgid,
                "identity": identity,
                "source_sha256": pin,
            }
        )
        data = {
            "owner_pid": pgid,
            "token": ready[0]["token"],
            "case": case,
            "source_sha256": pin,
            "seconds": SECONDS,
        }
        request = directory / ("topology-teardown-" + str(pgid) + ".json")
        publish(request, data)
        deadline = time.monotonic() + SECONDS + 1
        while not request.with_suffix(".ack").exists():
            if time.monotonic() >= deadline:
                refuse("topology_teardown_ack_missing")
            time.sleep(0.01)
        if json.loads(request.with_suffix(".ack").read_bytes()) != data:
            refuse("topology_teardown_ack_drift")
        current = query(pgid)
        if any(
            current[k] != identity[k]
            for k in ("native_pid", "native_ppid", "native_start_ticks", "native_boot_id")
        ):
            refuse("topology_teardown_owner_identity_drift")

    return {"retain": retain, "before_signal": before_signal}
