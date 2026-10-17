"""Exact selected run_worker failure return: actual parent retains and reaps."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

CASE = "tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct"
CLASSES = {"source-owned-role:worker", "source-owned-role:validator",
           "source-owned-role:terminal-reviewer", "source-composed-adapter"}


def install(guard, endpoint):
    state = guard._STATE
    if state.get("case") != CASE or state["class"] != "source-run-worker":
        return
    source = Path(state["checkout"]) / "src/unrest_harness/run_worker.py"
    pin = state["product_pins"]["src/unrest_harness/run_worker.py"]
    expected = state["isolated_named"](state["isolated_source_code"](source), "main")
    previous = sys.getprofile()
    original_initialize = subprocess.Popen.__init__
    handles = {}
    closing = [False]
    lock = threading.RLock()

    def initialize(handle, *args, **kwargs):
        with lock:
            if closing[0]:
                endpoint.refuse("preexit_late_child")
            original_initialize(handle, *args, **kwargs)
            records = [
                json.loads(line)
                for line in (Path(state["events"]) / (str(os.getpid()) + ".jsonl"))
                .read_bytes()
                .splitlines()
            ]
            registered = next(
                e
                for e in reversed(records)
                if e["kind"] == "registered"
                and e["pid"] == handle.pid
                and e["owner_pid"] == os.getpid()
            )
            if registered["class"] not in CLASSES or len(handles) >= 16:
                endpoint.refuse("preexit_unbound_child")
            handles[handle.pid] = (handle, registered)

    def observe(frame, event, value):
        if previous:
            previous(frame, event, value)
        if (
            frame.f_code.co_filename != str(source)
            or frame.f_code.co_name != "main"
            or event != "return"
        ):
            return
        poisoned = (
            endpoint.STATE["poison"]
            or (Path(endpoint.STATE["spec"]["responses"]) / "POISON.json").exists()
        )
        if value not in (1, 2) and not poisoned:
            return
        function = frame.f_globals.get("main")
        if (
            hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or frame.f_code != expected
            or function is None
            or function.__code__ is not frame.f_code
            or function.__globals__ is not frame.f_globals
            or frame.f_globals is not sys.modules["__main__"].__dict__
        ):
            endpoint.refuse("preexit_source_code_globals_drift")
        with lock:
            closing[0] = True
            owned = list(handles.values())
        if state.get("integration_mode") == "NONCANONICAL-drain-controls":
            first = owned[0][1]
            controls = [
                ("stale", "drain_child", {"child": first["pid"], "child_token": "0" * 32}),
                ("foreign", "drain_child", {"child": os.getppid(), "child_token": first["token"]}),
                (
                    "late",
                    "drain_inventory",
                    {"children": sorted(handles) + [os.getpid()], "source_sha256": pin},
                ),
                (
                    "source",
                    "drain_inventory",
                    {"children": sorted(handles), "source_sha256": "0" * 64},
                ),
                (
                    "identity",
                    "drain_child",
                    {
                        "child": first["pid"],
                        "child_token": first["token"],
                        "identity": {**endpoint.STATE["identity"], "start_ticks": -1},
                    },
                ),
            ]
            for name, kind, fields in controls:
                try:
                    endpoint.request(kind, **fields)
                except endpoint.EndpointRefusal as error:
                    guard.append(
                        {
                            "kind": "preexit_adversarial_refusal",
                            "control": name,
                            "reason": str(error),
                        }
                    )
                else:
                    endpoint.refuse("preexit_control_unexpected_acceptance")
                try:
                    endpoint.check()
                except endpoint.EndpointRefusal:
                    guard.append({"kind": "preexit_caught_refusal_poison", "control": name})
                else:
                    endpoint.refuse("preexit_poison_lost")
        endpoint.request("drain_inventory", children=sorted(handles), source_sha256=pin)
        deadline = time.monotonic() + 8
        for handle, registration in owned:
            answer = endpoint.request(
                "drain_child", child=handle.pid, child_token=registration["token"]
            )
            if not answer["wait_recorded"]:
                handle.terminate()
                handle.wait(timeout=max(0.001, deadline - time.monotonic()))
        completed = endpoint.request("drain_complete", children=sorted(handles))
        guard.append(
            {
                "kind": "actual_parent_preexit_drain",
                "children": sorted(handles),
                "numeric_returncodes": completed["actual_waits"],
                "observed_handle_returncodes": {
                    str(pid): h.returncode for pid, (h, _) in handles.items()
                },
                "original_return": value,
                "source_sha256": pin,
                "poison_preserved": (endpoint.STATE["poison"] or
                                     (Path(endpoint.STATE["spec"]["responses"]) / "POISON.json").exists()),
            }
        )

    subprocess.Popen.__init__ = initialize
    sys.setprofile(observe)
    threading.setprofile(observe)
