"""Finite mock-agent and intentional invalid-format plans for original ACP owners."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

import inspect


def active_frames():
    result = []
    frame = inspect.currentframe().f_back
    while frame:
        result.append(frame)
        frame = frame.f_back
    import asyncio

    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    coroutine = task.get_coro() if task else None
    seen = set()
    while coroutine is not None and id(coroutine) not in seen:
        seen.add(id(coroutine))
        candidate = getattr(coroutine, "cr_frame", None) or getattr(coroutine, "gi_frame", None)
        if candidate is not None:
            result.append(candidate)
        coroutine = getattr(coroutine, "cr_await", None) or getattr(coroutine, "gi_yieldfrom", None)
    return result


OWNERS = {
    "test_run_node_with_mock_agent",
    "test_full_jobs_and_handoffs_preserve_complete_format_templates",
    "test_full_jobs_do_not_infer_credentials_inside_format_fields",
    "test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success",
    "test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling",
    "test_owned_node_launch_uses_one_identical_plan",
    "test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol",
    "test_terminal_real_startup_failure_is_safe_and_starts_no_protocol",
}


def bound_code(state: dict[str, Any], source: Path) -> Any:
    pin = hashlib.sha256(source.read_bytes()).hexdigest()
    relative = str(source.relative_to(state["checkout"]))
    if pin != state["product_pins"][relative]:
        raise RuntimeError("cohort expected source drift")
    cache = state.setdefault("cohort_expected_codes", {})
    key = (str(source), pin, "_pytest.assertion.rewrite" in sys.modules)
    if key not in cache:
        cache[key] = state["isolated_source_code"](source)
    return cache[key]


def select(
    argv: list[str], cwd: Any, env: Any, state: dict[str, Any], append: Any, refuse: Any
) -> Any:
    source = Path(state["checkout"]) / "tests/test_acp_runner.py"
    prefix = "tests/test_acp_runner.py::"
    case = state.get("case", "")
    if state.get("class", "").startswith("reference:"):
        resolver_path = Path(state["guard"]).with_name("execution_owner.py")
        case = sys.modules["runtime_guard"].checked_source(
            resolver_path, state["direct_support"]["files"][str(resolver_path)]
        )["current"](state, refuse)
    if not case.startswith(prefix) or case[len(prefix) :].split("[")[0] not in OWNERS:
        return None
    frames = active_frames()
    try:
        product = Path(state["checkout"]) / "src/unrest_harness/acp_runner.py"
        frame = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(product) and f.f_code.co_name == "spawn_launch"
            ),
            None,
        )
        if frame is None:
            return None
        for p in (product, source):
            if (
                hashlib.sha256(p.read_bytes()).hexdigest()
                != state["product_pins"][str(p.relative_to(state["checkout"]))]
            ):
                refuse("cohort_plan_source_drift")
        fn = frame.f_globals["spawn_launch"]
        original_code = state["isolated_named"](bound_code(state, product), "spawn_launch")
        if (
            frame.f_code != original_code
            or sys.modules[frame.f_globals["__name__"]].__dict__ is not frame.f_globals
        ):
            refuse("cohort_plan_callable_drift")
        if fn.__code__ is not frame.f_code:
            wrapper = state["isolated_named"](bound_code(state, source), "recording_spawn")
            if (
                "test_owned_node_launch_uses_one_identical_plan[" not in case
                or fn.__code__ != wrapper
                or fn.__globals__ is not sys.modules["tests.test_acp_runner"].__dict__
            ):
                refuse("cohort_plan_wrapper_drift")
        plan = frame.f_locals["plan"]
        root = Path(state["owned_root"]).resolve()
        directory = Path(cwd).resolve()
        if (
            not directory.is_relative_to(root)
            or directory.name != "workspace"
            or os.getcwd() != state["checkout"]
        ):
            refuse("cohort_plan_root_drift")
        if tuple(argv) != plan.argv or str(cwd) != plan.cwd or env != plan.environment:
            refuse("cohort_plan_vector_drift")
        mock = source.with_name("mock_acp_agent.py")
        invalid = "real_startup_failure" in case
        if invalid:
            name = (
                "invalid-format-reviewer"
                if "terminal_real" in case
                else "invalid-format-" + case.split("[")[1].removesuffix("]")
            )
            launcher = directory / name
            if (
                argv != ["./" + name]
                or launcher.read_bytes() != b"mode executable, intentionally invalid format\n"
                or launcher.stat().st_mode & 0o777 != 0o700
            ):
                refuse("cohort_invalid_format_drift")
        else:
            if (
                argv != [sys.executable, str(mock)]
                or hashlib.sha256(mock.read_bytes()).hexdigest()
                != state["product_pins"]["tests/mock_acp_agent.py"]
            ):
                refuse("cohort_mock_fixture_drift")
        if env.get("UNREST_HOME") is not None and not Path(
            env["UNREST_HOME"]
        ).resolve().is_relative_to(root):
            refuse("cohort_plan_environment_root_drift")
        binding = {
            "path": str(product),
            "line": 409,
            "sha256": state["product_pins"]["src/unrest_harness/acp_runner.py"],
            "function": "spawn_launch",
        }
        append(
            {
                "kind": "concrete_cohort_plan_registration",
                "source_binding": binding,
                "original_owner_source_sha256": state["product_pins"]["tests/test_acp_runner.py"],
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "cwd": str(directory),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(env), sort_keys=True).encode()
                ).hexdigest(),
                "expected_startup": "original ENOEXEC; no successful exec or protocol"
                if invalid
                else "exact controlled mock agent",
            }
        )
        return (
            {
                "class": "source-cohort2:invalid-format"
                if invalid
                else "source-cohort2:mock-agent",
                "python": not invalid,
                "source_binding": binding,
            },
            argv,
        )
    finally:
        frames.clear()
