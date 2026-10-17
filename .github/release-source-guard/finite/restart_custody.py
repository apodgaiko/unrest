"""Finite test-method delegation: acknowledgements are never child handles."""

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CANONICAL = "tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct"
CONTROL = "NONCANONICAL::restart_custody"
OPTIONS = {"cwd", "env", "stdin", "stdout", "stderr", "start_new_session", "close_fds"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SpawnEvidence:
    """Authenticated spawn evidence only; deliberately has no wait/poll interface."""

    def __init__(self, evidence):
        self.evidence = evidence


def source_snapshot(guard, frame, argv, kwargs):
    state = guard._STATE
    source = Path(state["checkout"]) / "src/unrest_harness/run_control.py"
    from unrest_harness.run_control import RunControl, _Request

    function = RunControl._spawn
    expected = state["isolated_named"](state["isolated_source_code"](source), "_spawn")
    if (
        frame is None
        or frame.f_code is not function.__code__
        or frame.f_code != expected
        or frame.f_code.co_filename != str(source)
        or frame.f_lineno != 1147
        or frame.f_globals is not sys.modules[function.__module__].__dict__
        or function.__globals__ is not frame.f_globals
        or sha(source) != state["product_pins"]["src/unrest_harness/run_control.py"]
    ):
        guard.refuse("custody_wrong_source_code_globals")
    tree = ast.parse(source.read_bytes())
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == 1147)
    if ast.unparse(call.func) != "subprocess.Popen":
        guard.refuse("custody_source_AST_drift")
    control, request = frame.f_locals["self"], frame.f_locals["request"]
    if type(control) is not RunControl or type(request) is not _Request:
        guard.refuse("custody_owner_request_type_drift")
    expected_argv = [
        control.python_executable,
        "-m",
        "unrest_harness.run_worker",
        "--project-root",
        str(control.project_root),
        "--run-id",
        request.run_id,
        "--executor",
        control.executor_ref,
        "--custody-root-id",
        control.custody_root_id,
        "--generation",
        str(request.generation),
    ]
    environment = {
        "LANG": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONPATH": str(source.parent.parent),
        **control.worker_environment,
    }
    expected_options = {
        "cwd": control.project_root,
        "env": environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "start_new_session": True,
        "close_fds": True,
    }
    if list(argv) != expected_argv or kwargs != expected_options:
        guard.refuse("custody_argv_environment_cwd_options_drift")
    if control.executor_ref not in (
        "executor_fixture:execute",
        "unrest_harness.runtime_executor:execute",
    ):
        guard.refuse("custody_executor_drift")
    if (
        not guard.owned(str(control.project_root))
        or Path(control.project_root).resolve() != control.project_root
    ):
        guard.refuse("custody_root_drift")
    root = control.project_root
    request_path = root / ".unrest/runs" / request.run_id.removeprefix("run:") / "request.json"
    request_bytes = request_path.read_bytes()
    durable = json.loads(request_bytes)
    if durable["run_id"] != request.run_id or durable["generation"] != request.generation:
        guard.refuse("custody_request_generation_drift")
    return {
        "argv": expected_argv,
        "cwd": str(root),
        "env": environment,
        "owner_id": control.owner_id,
        "worker_environment": dict(control.worker_environment),
        "request": {"run_id": request.run_id, "generation": request.generation},
        "request_path": str(request_path),
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "source_sha256": sha(source),
        "AST_sha256": hashlib.sha256(ast.dump(call, include_attributes=False).encode()).hexdigest(),
        "executor": control.executor_ref,
        "custody_root_id": control.custody_root_id,
        "requesting_case": state["case"],
        "requesting_class": state["class"],
    }


def install(guard, endpoint):
    state = guard._STATE
    if state.get("case") not in (CANONICAL, CONTROL):
        return
    actual_class = subprocess.Popen
    pending = []
    retained = []
    state["custody_retained"] = retained
    state["custody_pending"] = pending

    class CustodyPopen(actual_class):
        def __new__(cls, args, *positional, **kwargs):
            vector = list(args) if isinstance(args, (tuple, list)) else []
            worker_route = len(vector) > 2 and vector[1:3] == ["-m", "unrest_harness.run_worker"]
            if worker_route:
                if positional:
                    guard.refuse("custody_positional_options")
                frame = inspect.currentframe().f_back
                try:
                    try:
                        snapshot = source_snapshot(guard, frame, vector, kwargs)
                    except guard.GuardRefusal:
                        raise
                    except (OSError, ValueError, KeyError, TypeError, AttributeError):
                        guard.refuse("custody_source_snapshot_error")
                finally:
                    del frame
                guard.require_ready(state["token"])
                # Original admission runs in both original and actual source frames.
                registration, admitted = guard.admit(vector, kwargs.get("cwd"), kwargs.get("env"))
                if registration["class"] != "source-run-worker" or admitted != vector:
                    guard.refuse("custody_original_admission_drift")
                if state["class"] == "restart-custodian":
                    if len(pending) != 1 or {
                        k: v for k, v in snapshot.items() if k != "requesting_class"
                    } != {
                        k: v for k, v in pending[0]["snapshot"].items() if k != "requesting_class"
                    }:
                        guard.refuse("custody_actual_owner_revalidation_drift")
                    return super().__new__(cls)
                if state["class"] not in (
                    "composed-http-role:orchestrator",
                    "restart-control-frontend",
                ):
                    guard.refuse("custody_wrong_requester_role")
                if state["case"] == CONTROL:
                    mode = state.get("custody_control", "positive")
                    if mode == "wrong-source":
                        snapshot["source_sha256"] = "0" * 64
                    elif mode in ("wrong-argv", "caught-refusal"):
                        snapshot["argv"][-1] = "99"
                    elif mode == "wrong-cwd":
                        snapshot["cwd"] = str(Path(snapshot["cwd"]).parent)
                    elif mode == "wrong-environment":
                        snapshot["env"]["PATH"] += ":/foreign"
                    elif mode == "stale":
                        snapshot["request"]["generation"] += 1
                    elif mode == "symlink":
                        path = Path(snapshot["request_path"])
                        target = path.with_suffix(".retained")
                        path.rename(target)
                        path.symlink_to(target)
                attestation = sys.modules["custody_ipc"].attest(snapshot)
                receipt = endpoint.request(
                    "custody_submit", snapshot=snapshot, attestation=attestation
                )
                guard.append(
                    {
                        "kind": "delegated_spawn_acknowledgement",
                        "requesting_pid": os.getpid(),
                        "actual_parent": receipt["custodian"],
                        "pid": receipt["child"],
                        "child_token": receipt["child_token"],
                        "terminal_wait": False,
                    }
                )
                return SpawnEvidence(receipt)
            return super().__new__(cls)

        def __init__(self, args, *positional, **kwargs):
            super().__init__(args, *positional, **kwargs)
            if state["class"] == "restart-custodian":
                if len(pending) != 1:
                    guard.refuse("custody_unbound_actual_launch")
                retained.append(self)

    subprocess.Popen = CustodyPopen


def start_custodian(work):
    with (Path(work) / "custodian.stderr").open("wb") as diagnostic:
        return subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("custody_process.py"))],
            cwd=work,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostic,
            close_fds=True,
            start_new_session=True,
        )


def serve():
    guard, endpoint = sys.modules["runtime_guard"], sys.modules["endpoint"]
    state = guard._STATE
    sys.path.insert(0, str(Path(state["checkout"]) / "src"))
    from unrest_harness.run_control import RunControl, _Request

    retained = state["custody_retained"]
    pending = state["custody_pending"]
    closing = False
    close_ipc = sys.modules["custody_ipc"].start()
    try:
        while not closing:
            for handle in retained:
                handle.poll()  # Actual parent waitpid(WNOHANG), never absence inference.
            answer = endpoint.request("custody_poll")
            job = answer.get("job")
            if job:
                snapshot = job["snapshot"]
                if sha(snapshot["request_path"]) != snapshot["request_sha256"]:
                    guard.refuse("custody_actual_request_bytes_drift")
                control = object.__new__(RunControl)
                control.project_root = Path(snapshot["cwd"])
                control.python_executable = snapshot["argv"][0]
                control.worker_environment = snapshot["worker_environment"]
                control.executor_ref = snapshot["executor"]
                control.custody_root_id = snapshot["custody_root_id"]
                control.owner_id = snapshot["owner_id"]
                durable = json.loads(Path(snapshot["request_path"]).read_bytes())
                request = _Request(**{k: v for k, v in durable.items() if k != "schema_version"})
                pending[:] = [job]
                before = len(retained)
                try:
                    RunControl._spawn(control, request)
                finally:
                    pending.clear()
                if len(retained) != before + 1:
                    guard.refuse("custody_exactly_one_child_required")
                child = retained[-1]
                endpoint.request("custody_spawned", job_id=job["id"], child=child.pid)
            closing = answer.get("closing", False)
            if not job:
                time.sleep(0.002)
    finally:
        close_ipc()
        # Source-success closes only after its complete unchanged test returns.
        # Failure/cancellation cleanup still belongs to each real parent.
        deadline = time.monotonic() + 8
        for child in retained:
            try:
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                endpoint.request("custody_signal", child=child.pid, signal=15)
                child.terminate()
                child.wait(timeout=5)
        guard.append(
            {
                "kind": "custodian_drained",
                "children": [h.pid for h in retained],
                "actual_returncodes": [h.returncode for h in retained],
            }
        )
