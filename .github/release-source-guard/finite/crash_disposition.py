"""Exact approved anchor76 evidence disposition. Numeric child exits stay unknown."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import time

OWNER = "tests/test_experimental_cohort.py::test_actual_controller_crash_has_no_resume_authority"
BOUNDARIES = ("prompt_sent", "backend_received", "provider_completed")
CLASSES = ("canonical-backend", "controlled-acp")
CONTROLLER = "source-crash-controller"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def kernel(pid):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "linux_identity", Path(__file__).with_name("linux_identity.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.identity(pid)
    except FileNotFoundError:
        return None


def family(case):
    return case in [OWNER + "[" + b + "]" for b in (*BOUNDARIES, "reservation")]


def before_launch(state, registration, argv, options, token, append, refuse):
    if not family(state.get("case")):
        return
    kind = registration["class"]
    if kind not in (*CLASSES, CONTROLLER):
        return
    if kind == CONTROLLER and (
        options.get("cwd") is not None
        or options.get("env") is not None
        or options.get("start_new_session", False)
    ):
        refuse("crash_controller_options_drift")
    if kind in CLASSES and (
        state["class"] != CONTROLLER or options.get("start_new_session") is not True
    ):
        refuse("crash_child_parent_or_group_drift")
    spec = state["exact_crash_disposition"]
    if (
        tuple(spec["boundaries"]) != BOUNDARIES
        or spec["observation_seconds"] != 20
        or spec["closeout_seconds"] != 30
        or spec["outer_seconds"] != 300
    ):
        refuse("crash_disposition_policy_drift")
    if any(sha(p) != pin for p, pin in spec["files"].items()):
        refuse("crash_child_bytes_drift")
    if kind == "canonical-backend":
        fixture = str(Path(state["checkout"]) / "tests/fixtures/experimental_session_app_server.py")
        launcher = Path(argv[1])
        if (
            len(argv) != 3
            or argv[-1] != "app-server"
            or launcher.name != "fake-app-server"
            or not launcher.resolve().is_relative_to(Path(state["owned_root"]))
            or sha(launcher) != spec["files"][fixture]
        ):
            refuse("crash_backend_exact_vector_drift")
    if kind == "controlled-acp":
        fixture = str(Path(state["checkout"]) / "tests/fixtures/controlled_python_acp.py")
        if argv != [state["runtime"]["realpath"], fixture, "--controlled-local-acp-v1"]:
            refuse("crash_adapter_exact_vector_drift")
    append(
        {
            "kind": "exact_crash_launch_provenance",
            "token": token,
            "class": kind,
            "controller_token": state["token"] if kind in CLASSES else None,
            "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            "environment_sha256": hashlib.sha256(
                json.dumps(
                    dict(os.environ if options.get("env") is None else options["env"]),
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            "cwd": str(Path(options.get("cwd") or os.getcwd()).resolve()),
            "runtime_sha256": state["runtime"]["sha256"],
            "source_binding": registration["source_binding"],
            "backend_adapter_transport_sha256": spec["files"],
            "manifest_sha256": sha(state["manifest_path"]),
        }
    )


def snapshot(state, registration, pid, token, append, refuse):
    if not family(state.get("case")) or registration["class"] not in (*CLASSES, CONTROLLER):
        return
    value = kernel(pid)
    if value is None or value["ppid"] != os.getpid() or value["uid"] != os.getuid():
        refuse("crash_live_parent_identity_unobserved")
    if registration["class"] in CLASSES and value["pgid"] != pid:
        refuse("crash_live_group_identity_drift")
    append(
        {
            "kind": "exact_crash_live_kernel_identity",
            "token": token,
            "class": registration["class"],
            "pid": pid,
            "kernel": value,
            "manifest_sha256": sha(state["manifest_path"]),
        }
    )


def one(events, kind, **fields):
    selected = [
        e for e in events if e["kind"] == kind and all(e.get(k) == v for k, v in fields.items())
    ]
    if len(selected) != 1:
        raise RuntimeError("crash_receipt_count:" + kind)
    return selected[0]


def validate(state, events, case):
    spec = state["exact_crash_disposition"]
    if case not in [OWNER + "[" + b + "]" for b in BOUNDARIES]:
        raise RuntimeError("crash_parameter_outside_disposition")
    if (
        tuple(spec["boundaries"]) != BOUNDARIES
        or spec["observation_seconds"] != 20
        or spec["closeout_seconds"] != 30
        or spec["outer_seconds"] != 300
        or sha(spec["source"]) != spec["source_sha256"]
        or sha(spec["adapter_global"]) != spec["adapter_global_sha256"]
        or any(sha(p) != pin for p, pin in spec["files"].items())
        or sha(state["runtime"]["realpath"]) != state["runtime"]["sha256"]
    ):
        raise RuntimeError("crash_disposition_binding_drift")
    import ast

    node = next(
        n
        for n in ast.parse(Path(spec["source"]).read_bytes()).body
        if isinstance(n, ast.FunctionDef) and n.name == OWNER.split("::")[1]
    )
    if (
        hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
        != spec["owner_ast_sha256"]
    ):
        raise RuntimeError("crash_owner_ast_drift")
    if any(e["kind"] == "forbidden" for e in events):
        raise RuntimeError("crash_poisoned_run")
    one(events, "test_outcome", nodeid=case, phase="call", outcome="passed")
    if any(e["kind"] == "test_outcome" and e.get("outcome") not in ("passed",) for e in events):
        raise RuntimeError("crash_original_oracle_failed")
    controller = one(events, "registered", case=case, **{"class": CONTROLLER})
    controller_pid = controller["pid"]
    pin = sha(state["manifest_path"])
    owner_binding = one(
        events, "exact_crash_owner_registration", case=case, owner_pid=controller["owner_pid"]
    )
    if (
        owner_binding["boundary"] != case.removeprefix(OWNER + "[").removesuffix("]")
        or owner_binding["owner_ast_sha256"] != spec["owner_ast_sha256"]
        or owner_binding["source_binding"]["sha256"] != spec["source_sha256"]
        or owner_binding["callable_code_globals_identity_verified"] is not True
    ):
        raise RuntimeError("crash_callable_parameter_binding_drift")
    body = next(
        n.value.value
        for n in node.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "source" for t in n.targets)
    )
    boundary = owner_binding["boundary"]
    root = owner_binding["root"]
    fixture = str(Path(state["checkout"]) / "tests/fixtures/experimental_session_app_server.py")
    script = (
        "BOUNDARY="
        + repr(boundary)
        + "\nfrom pathlib import Path\nROOT=Path("
        + repr(root)
        + ")\nADAPTER=Path("
        + repr(spec["adapter_global"])
        + ")\nFIXTURE=Path("
        + repr(fixture)
        + ")\n"
        + body
    )
    allowed_argv = [
        hashlib.sha256(json.dumps([runtime, "-c", script]).encode()).hexdigest()
        for runtime in state["runtime"]["paths"]
    ]
    if (
        owner_binding["script_sha256"] != hashlib.sha256(script.encode()).hexdigest()
        or owner_binding["argv_sha256"] not in allowed_argv
        or not Path(root).is_relative_to(Path(state["owned_root"]))
    ):
        raise RuntimeError("crash_generated_script_drift")
    children = [
        e
        for e in events
        if e["kind"] == "registered" and e["owner_pid"] == controller_pid and e["python"]
    ]
    if len(children) != 2 or sorted(e["class"] for e in children) != sorted(CLASSES):
        raise RuntimeError("crash_unexpected_children")
    # Only ordinary numerically waited setup Git leaves may accompany the pair.
    other = [
        e
        for e in events
        if e["kind"] == "registered" and e["owner_pid"] == controller_pid and not e["python"]
    ]
    from collections import Counter

    expected_native = {
        "source-crash-setup-git": 4,
        "source-candidate-object-git:-t": 21,
        "source-candidate-object-git:commit": 7,
        "source-candidate-object-git:tree": 7,
        "source-candidate-object-git:blob": 7,
    }
    if dict(Counter(c["class"] for c in other)) != expected_native:
        raise RuntimeError("crash_unrelated_child_or_count")
    registered = [e for e in events if e["kind"] == "registered"]
    if len({e["token"] for e in registered}) != len(registered) or len(
        {e["pid"] for e in registered}
    ) != len(registered):
        raise RuntimeError("crash_registration_identity_duplicate")
    for child in other:
        one(events, "actual_waitpid", owner_pid=controller_pid, pid=child["pid"])
    one(
        events,
        "actual_waitpid",
        owner_pid=controller["owner_pid"],
        pid=controller_pid,
        numeric_returncode=73,
    )
    one(
        events,
        "abrupt_exit",
        owner_pid=controller_pid,
        token=controller["token"],
        numeric_returncode=73,
        **{"class": CONTROLLER},
    )
    if any(
        e["kind"] == "abrupt_exit"
        and e["owner_pid"] == controller_pid
        and e.get("numeric_returncode") != 73
        for e in events
    ):
        raise RuntimeError("crash_wrong_exit")
    if kernel(controller_pid) is not None:
        raise RuntimeError("crash_controller_survives")
    receipts = []
    for child in [controller, *children]:
        token = child["token"]
        pid = child["pid"]
        ready = one(
            events,
            "ready",
            token=token,
            owner_pid=pid,
            parent_pid=child["owner_pid"],
            case=case,
            **{"class": child["class"]},
        )
        if any(
            ready[key] != value
            for key, value in {
                "manifest_sha256": pin,
                "runtime_sha256": state["runtime"]["sha256"],
                "guard_sha256": state["guard_sha256"],
                "registry_sha256": state["registry"]["sha256"],
                "support_sha256": hashlib.sha256(
                    json.dumps(state["direct_support"]["files"], sort_keys=True).encode()
                ).hexdigest(),
            }.items()
        ):
            raise RuntimeError("crash_READY_binding_drift")
        admitted = one(
            events,
            "admitted",
            token=token,
            owner_pid=child["owner_pid"],
            **{"class": child["class"]},
        )
        launch = one(events, "actual_launch_binding", token=token, owner_pid=child["owner_pid"])
        provenance = one(
            events, "exact_crash_launch_provenance", token=token, owner_pid=child["owner_pid"]
        )
        live = one(
            events,
            "exact_crash_live_kernel_identity",
            token=token,
            owner_pid=child["owner_pid"],
            pid=pid,
        )
        options = one(events, "launch_lifecycle_binding", token=token, owner_pid=child["owner_pid"])
        if (
            admitted["argv_sha256"] != provenance["argv_sha256"]
            or admitted["source_binding"] != provenance["source_binding"]
            or launch["environment_sha256"] != provenance["environment_sha256"]
            or launch["cwd"] != provenance["cwd"]
            or provenance["manifest_sha256"] != pin
            or live["manifest_sha256"] != pin
            or provenance["runtime_sha256"] != options["executable_sha256"]
            or provenance["runtime_sha256"] != state["runtime"]["sha256"]
            or provenance["backend_adapter_transport_sha256"] != spec["files"]
            or not launch["bootstrap_sha256"]
            or not launch["transformed_argv_sha256"]
            or live["kernel"]["ppid"] != child["owner_pid"]
            or live["kernel"]["uid"] != os.getuid()
            or ready["pgid"] != live["kernel"]["pgid"]
        ):
            raise RuntimeError("crash_launch_identity_drift")
        if child is controller:
            if (
                admitted["argv_sha256"] != owner_binding["argv_sha256"]
                or launch["environment_sha256"] != owner_binding["environment_sha256"]
                or launch["cwd"] != state["checkout"]
                or options["start_new_session"] is not False
            ):
                raise RuntimeError("crash_controller_binding_drift")
        else:
            if (
                ready["sid"] != pid
                or ready["pgid"] != pid
                or options["start_new_session"] is not True
                or provenance["controller_token"] != controller["token"]
                or not Path(launch["cwd"]).is_relative_to(Path(owner_binding["root"]))
            ):
                raise RuntimeError("crash_child_binding_drift")
            if child["class"] == "controlled-acp":
                adapter_path = str(
                    Path(state["checkout"]) / "tests/fixtures/controlled_python_acp.py"
                )
                if (
                    admitted["source_binding"]["path"] != adapter_path
                    or admitted["source_binding"]["sha256"] != spec["files"][adapter_path]
                ):
                    raise RuntimeError("crash_adapter_binding_drift")
            else:
                if (
                    admitted["source_binding"]["path"] != fixture
                    or admitted["source_binding"]["sha256"] != spec["files"][fixture]
                ):
                    raise RuntimeError("crash_backend_binding_drift")
                # This original owner uses the plain controlled backend vector.
                # Configured provider variants are outside this disposition.
                if any(
                    e["kind"] == "concrete_configured_backend_registration"
                    and e["owner_pid"] == controller_pid
                    for e in events
                ):
                    raise RuntimeError("crash_unexpected_configured_backend")
            one(
                events,
                "bounded_controlled_READY_handshake",
                token=token,
                pid=pid,
                owner_pid=controller_pid,
            )
            if any(e["kind"] == "actual_waitpid" and e["pid"] == pid for e in events):
                raise RuntimeError("crash_pair_has_unexpected_wait")
        receipts.append(
            {
                "registration": child,
                "ready": ready,
                "admitted": admitted,
                "launch": launch,
                "provenance": provenance,
                "live": live,
                "options": options,
            }
        )
    return {
        "case": case,
        "controller": controller,
        "children": children,
        "owner_binding": owner_binding,
        "receipts": receipts,
        "manifest_sha256": pin,
    }


def group_present(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def same_orphan(value, original):
    return (
        value["ppid"] == 1
        and value["uid"] == original["uid"]
        and all(value[k] == original[k] for k in ("pid", "pgid", "start_ticks", "boot_id"))
    )


def closeout(state, events, append):
    cases = sorted(
        {
            e["case"]
            for e in events
            if e["kind"] == "registered"
            and e["class"] == CONTROLLER
            and e["case"] in [OWNER + "[" + b + "]" for b in BOUNDARIES]
        }
    )
    for case in cases:
        started = time.monotonic()
        try:
            proof = validate(state, events, case)
            children = proof["children"]
            observation = started + 20
            deadline = started + 30
            while time.monotonic() < observation and any(
                kernel(c["pid"]) is not None for c in children
            ):
                time.sleep(0.01)
            rows = []
            for child in children:
                original = one(events, "exact_crash_live_kernel_identity", token=child["token"])[
                    "kernel"
                ]
                signals = []
                observations = []
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    value = kernel(child["pid"])
                    if value is None:
                        break
                    if not same_orphan(value, original):
                        raise RuntimeError("crash_closeout_identity_drift")
                    observations.append(value)
                    if time.monotonic() >= deadline:
                        raise RuntimeError("crash_closeout_deadline")
                    os.kill(child["pid"], sig)
                    signals.append(int(sig))
                    append(
                        {
                            "kind": "exact_crash_closeout_signal",
                            "pid": child["pid"],
                            "token": child["token"],
                            "signal": int(sig),
                            "kernel": value,
                            "numeric_wait_inferred": False,
                        }
                    )
                    signal_deadline = min(deadline, time.monotonic() + 5)
                    while time.monotonic() < signal_deadline and kernel(child["pid"]) is not None:
                        time.sleep(0.01)
                if kernel(child["pid"]) is not None or group_present(child["pid"]):
                    raise RuntimeError("crash_residual_child_or_group")
                rows.append(
                    {
                        "pid": child["pid"],
                        "token": child["token"],
                        "signals": signals,
                        "kernel_observations": observations,
                        "absent": True,
                        "numeric_child_exit": "UNVERIFIED",
                        "final_exit_timing": "UNVERIFIED",
                    }
                )
            registered = [e for e in events if e["kind"] == "registered"]
            if any(kernel(e["pid"]) is not None for e in registered):
                raise RuntimeError("crash_unrelated_process_residue")
            groups = sorted(
                {
                    e["pgid"]
                    for e in events
                    if e["kind"] == "ready"
                    and e["pgid"] == e["owner_pid"]
                    and e["owner_pid"] != os.getpid()
                }
            )
            if any(group_present(g) for g in groups):
                raise RuntimeError("crash_unrelated_group_residue")
            if time.monotonic() > deadline:
                raise RuntimeError("crash_closeout_deadline")
            append(
                {
                    "kind": "exact_crash_provenance_closeout",
                    "case": case,
                    "controller_pid": proof["controller"]["pid"],
                    "manifest_sha256": proof["manifest_sha256"],
                    "children": rows,
                    "registered_pids_absent": [e["pid"] for e in registered],
                    "groups_absent": groups,
                    "observation_bound_seconds": 20,
                    "closeout_bound_seconds": 30,
                    "elapsed_seconds": time.monotonic() - started,
                    "numeric_wait_inferred": False,
                }
            )
        except (RuntimeError, OSError, KeyError, StopIteration, ValueError) as error:
            append(
                {
                    "kind": "forbidden",
                    "reason": "exact_crash_disposition_refused",
                    "detail": str(error).split(":")[0],
                    "case": case,
                }
            )


def record(state, events, child):
    if child["class"] not in CLASSES or child["case"] not in [
        OWNER + "[" + b + "]" for b in BOUNDARIES
    ]:
        return None
    try:
        proof = validate(state, events, child["case"])
        if child not in proof["children"]:
            return None
        closed = one(
            events,
            "exact_crash_provenance_closeout",
            case=child["case"],
            controller_pid=child["owner_pid"],
            manifest_sha256=proof["manifest_sha256"],
        )
        rows = [
            r
            for r in closed["children"]
            if r["pid"] == child["pid"] and r["token"] == child["token"]
        ]
        if (
            len(rows) != 1
            or rows[0]["absent"] is not True
            or closed["numeric_wait_inferred"] is not False
        ):
            return None
        if kernel(child["pid"]) is not None or group_present(child["pid"]):
            return None
        return {
            "wait_status": "exact_approved_intentional_crash",
            "actual_wait_observed": False,
            "numeric_child_exit": "UNVERIFIED",
            "final_exit_timing": "UNVERIFIED",
            "numeric_wait_inferred": False,
            "controller_numeric_exit": 73,
            "binding": proof["owner_binding"],
            "READY": one(events, "ready", token=child["token"]),
            "closeout": rows[0],
            "release_acceptance": False,
        }
    except (RuntimeError, OSError, KeyError, StopIteration, ValueError):
        return None
