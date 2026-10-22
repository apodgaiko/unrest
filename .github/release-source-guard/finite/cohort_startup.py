"""Finish exact mock-agent guard setup before returning the original handle."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time

CASES = frozenset(
    "tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success["
    + provider
    + "]"
    for provider in ("claude", "codex")
)
CLASS = "source-cohort2:mock-agent"


class StartupFailure(RuntimeError):
    pass


def failed_setup(guard, endpoint, handle, identity, birth, reason):
    """Settle only the same proven child; uncertain custody remains a failure."""
    outcome = {
        "kind": "failed_cohort_endpoint_READY",
        "pid": handle.pid,
        "reason": reason,
        "cleanup_verified": False,
    }
    try:
        if (
            birth is not None
            and birth["ppid"] == os.getpid()
            and birth["uid"] == os.geteuid()
            and identity(handle.pid) == birth
        ):
            if handle.poll() is None:
                handle.kill()
            code = handle.wait(timeout=5)
            if type(code) is not int:
                raise RuntimeError("cohort_startup_numeric_wait_missing")
            outcome["observed_handle_returncode"] = code
            outcome["cleanup_verified"] = True
        else:
            outcome["custody"] = "UNVERIFIED; no signal or wait on an uncertain PID"
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        outcome["cleanup_error_type"] = type(error).__name__
    finally:
        try:
            guard.append(outcome)
        finally:
            endpoint.refuse(reason)


def wait_ready(guard, endpoint, handle, registration, identity):
    state = guard._STATE
    birth = None
    try:
        birth = identity(handle.pid)
        if birth["ppid"] != os.getpid() or birth["uid"] != os.geteuid():
            raise StartupFailure("cohort_startup_parent_identity")
        token = registration["token"]
        expected = dict(
            kind="ready",
            token=token,
            owner_pid=handle.pid,
            parent_pid=os.getpid(),
            **{"class": CLASS},
            manifest_sha256=state["pin"],
            guard_sha256=state["guard_sha256"],
            registry_sha256=state["registry"]["sha256"],
            runtime_sha256=state["runtime"]["sha256"],
        )
        complete = dict(
            kind="endpoint_install_complete",
            token=token,
            owner_pid=handle.pid,
            parent_pid=os.getpid(),
            identity=birth,
            nonce=endpoint.STATE["spec"]["nonce"],
            manifest_sha256=state["pin"],
            guard_sha256=state["guard_sha256"],
        )
        journal = Path(state["events"]) / (str(handle.pid) + ".jsonl")
        deadline = time.monotonic() + 5
        while True:
            try:
                records = [json.loads(line) for line in journal.read_bytes().splitlines()]
            except FileNotFoundError:
                records = []
            if any(all(row.get(k) == v for k, v in expected.items()) for row in records) and any(
                all(row.get(k) == v for k, v in complete.items()) for row in records
            ):
                if identity(handle.pid) != birth:
                    raise StartupFailure("cohort_startup_birth_drift")
                guard.append(
                    dict(
                        kind="bounded_cohort_endpoint_READY",
                        pid=handle.pid,
                        token=token,
                        identity=birth,
                        deadline_seconds=5,
                        original_rendezvous_seconds=1,
                        original_protocol_and_deadline_unchanged=True,
                    )
                )
                return
            if handle.poll() is not None or time.monotonic() >= deadline:
                raise StartupFailure("cohort_startup_endpoint_not_READY")
            time.sleep(0.001)
    except (OSError, ValueError, KeyError, RuntimeError, TypeError, AttributeError) as error:
        reason = (
            str(error) if isinstance(error, StartupFailure) else "cohort_startup_invalid_evidence"
        )
        failed_setup(guard, endpoint, handle, identity, birth, reason)


def install(guard, endpoint):
    state = guard._STATE
    if state["class"] != "pytest-root":
        return
    if "_cohort_startup_hook" in state:
        if subprocess.Popen.__init__ is not state["_cohort_startup_hook"]:
            endpoint.refuse("cohort_startup_hook_drift")
        return
    path = Path(state["guard"]).with_name("linux_identity.py")
    identity = guard.checked_source(path, state["direct_support"]["files"][str(path)])["identity"]
    original = subprocess.Popen.__init__
    validated_prefix = b""

    def initialize(handle, *args, **kwargs):
        nonlocal validated_prefix
        result = original(handle, *args, **kwargs)
        if state.get("case") not in CASES:
            return result
        vector = args[0] if args else kwargs.get("args")
        if (
            type(vector) not in (list, tuple)
            or len(vector) != 2
            or vector[0] not in state["runtime"]["paths"]
            or vector[1] != state["checkout"] + "/tests/mock_acp_agent.py"
        ):
            return result
        journal = Path(state["events"]) / (str(os.getpid()) + ".jsonl")
        try:
            registration, validated_prefix = endpoint.latest_wait_registration(
                journal.read_bytes(), os.getpid(), handle.pid, validated_prefix
            )
        except (OSError, ValueError, KeyError, TypeError):
            failed_setup(
                guard, endpoint, handle, identity, None, "cohort_startup_registration_invalid"
            )
        if registration is None:
            failed_setup(
                guard, endpoint, handle, identity, None, "cohort_startup_registration_missing"
            )
        if registration["class"] != CLASS:
            return result
        if registration.get("python") is not True or registration.get("case") != state["case"]:
            failed_setup(
                guard, endpoint, handle, identity, None, "cohort_startup_registration_drift"
            )
        wait_ready(guard, endpoint, handle, registration, identity)
        return result

    state["_cohort_startup_hook"] = initialize
    subprocess.Popen.__init__ = initialize
