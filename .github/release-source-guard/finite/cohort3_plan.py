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


OWNERS = {"test_actual_runner_matching_id_order_and_owned_cleanup"}


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
    source = Path(state["checkout"]) / "tests/test_provider_review_frames.py"
    prefix = "tests/test_provider_review_frames.py::"
    case = state.get("case", "")
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
        if case not in state["cohort3_full_cases"]:
            refuse("cohort3_review_parameter_drift")
        owner = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(source) and f.f_code.co_name == "record"
            ),
            None,
        )
        owner_module = sys.modules.get("tests.test_provider_review_frames")
        expected = bound_code(state, source)
        owner_fn = getattr(
            owner_module, "test_actual_runner_matching_id_order_and_owned_cleanup", None
        )
        nested = state["isolated_named"](expected, "record")
        if (
            owner is None
            or owner_fn is None
            or owner_module.__dict__ is not owner.f_globals
            or owner.f_code != nested
            or owner_fn.__globals__ is not owner.f_globals
            or owner_fn.__code__
            != state["isolated_named"](
                expected, "test_actual_runner_matching_id_order_and_owned_cleanup"
            )
        ):
            refuse("cohort3_review_owner_drift")
        assert owner is not None and owner_fn is not None
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
        mock = source.parent / "fixtures/approval_acp_process.py"
        scenario = directory.parent / "scenario.json"
        if not scenario.is_file() or not scenario.resolve().is_relative_to(root):
            refuse("cohort3_review_scenario_root")
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
                argv != [sys.executable, str(mock), str(scenario)]
                or hashlib.sha256(mock.read_bytes()).hexdigest()
                != state["product_pins"]["tests/fixtures/approval_acp_process.py"]
            ):
                refuse("cohort_mock_fixture_drift")
        ordering = case.split("[")[1].removesuffix("]")
        if ordering not in ("before", "after", "batch_before", "batch_after", "eof"):
            refuse("cohort3_review_ordering_drift")
        malformed = owner.f_globals["malformed"]
        if malformed.__globals__ is not owner.f_globals or malformed.__code__ != state[
            "isolated_named"
        ](expected, "malformed"):
            refuse("cohort3_review_frame_callable_drift")
        event = owner.f_globals["event"]
        event_source = source.with_name("test_provider_review.py")
        event_module = sys.modules.get(event.__module__)
        if (
            event_module is None
            or event.__globals__ is not event_module.__dict__
            or event.__code__ != state["isolated_named"](bound_code(state, event_source), "event")
        ):
            refuse("cohort3_review_event_callable_drift")
        frame_data = malformed("result", {})
        frame_data["id"] = "$prompt_id"
        runner_frame = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(product) and f.f_code.co_name == "run_node"
            ),
            None,
        )
        if runner_frame is None:
            refuse("cohort3_review_runner_frame_missing")
        assert runner_frame is not None
        expected_data = {
            "events": [],
            "frames": [frame_data],
            "ordering": ordering,
            "handoff": str(runner_frame.f_locals["handoff_path"]),
            "mcp_receipt": str(scenario.parent / "mcp-receipt"),
        }
        if scenario.read_text() != json.dumps(expected_data):
            refuse("cohort3_review_scenario_bytes_drift")
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
                "original_owner_source_sha256": state["product_pins"][
                    "tests/test_provider_review_frames.py"
                ],
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "cwd": str(directory),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(env), sort_keys=True).encode()
                ).hexdigest(),
                "expected_startup": "original ENOEXEC; no child created"
                if invalid
                else "exact controlled mock agent",
            }
        )
        return (
            {
                "class": "source-cohort3:invalid-format"
                if invalid
                else "source-cohort3:mock-agent",
                "python": not invalid,
                "source_binding": binding,
            },
            argv,
        )
    finally:
        frames.clear()
