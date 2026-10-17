"""Two exact vectors for the unchanged source session-group timeout owner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

CASE = "tests/test_provider_sessions.py::test_timeout_kills_adapter_process_group"


def admit(argv, cwd, env, state, append, refuse):
    fallback = Path(state["guard"]).with_name("fallback_binding.py")
    if (
        hashlib.sha256(fallback.read_bytes()).hexdigest()
        != state["direct_support"]["files"][str(fallback)]
    ):
        refuse("timeout_frame_support_drift")
    namespace = {"__file__": str(fallback)}
    exec(compile(fallback.read_bytes(), str(fallback), "exec"), namespace)
    active_frames = namespace["active_frames"]

    root = Path(state["checkout"])
    fixture = root / "tests/mock_provider_session_acp.py"
    source = root / "src/unrest_harness/provider_sessions.py"
    if state.get("case") != CASE:
        return None
    for path in (fixture, source, root / "tests/test_provider_sessions.py"):
        pin = state["product_pins"][str(path.relative_to(root))]
        if hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            refuse("timeout_source_drift")
    frames = active_frames()
    try:
        if state["class"] == "source-session-helper:timeout":
            parent = state["original_argv"]
            if (
                len(parent) != 7
                or parent[0] != str(fixture)
                or parent[1:4] != ["--sleep", "30", "--child-pid-path"]
                or parent[5] != "--child-stop-path"
            ):
                refuse("timeout_parent_vector_drift")
            directory = Path(parent[4]).parent / "workspace"
            expected = [sys.executable, str(fixture), "--child", parent[6]]
            selected = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(fixture)
                    and f.f_code.co_name == "main"
                    and f.f_lineno == 50
                ),
                None,
            )
            if selected is None:
                return None
            module = sys.modules.get("__main__")
            if (
                module is None
                or vars(module) is not selected.f_globals
                or selected.f_code
                != state["isolated_named"](state["isolated_source_code"](fixture), "main")
                or argv != expected
                or cwd is not None
                or env is not None
                or Path.cwd() != directory
                or Path(parent[6]) != directory.parent / "child.stopped"
            ):
                refuse("timeout_child_context_drift")
            binding = {
                "path": str(fixture),
                "line": 50,
                "sha256": state["product_pins"]["tests/mock_provider_session_acp.py"],
            }
            append(
                {
                    "kind": "exact_timeout_child_registration",
                    "source_binding": binding,
                    "wait_claim": "required: actual numeric owned child wait",
                }
            )
            return {"class": "source-session-child", "python": True, "source_binding": binding}
        selected = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(source)
                and f.f_code.co_name == "_spawn_provider_launch"
            ),
            None,
        )
        if selected is None:
            return None
        plan = selected.f_locals["plan"]
        directory = Path(plan.cwd)
        owned = Path(state["owned_root"])
        expected = [
            sys.executable,
            str(fixture),
            "--sleep",
            "30",
            "--child-pid-path",
            str(directory.parent / "child.pid"),
            "--child-stop-path",
            str(directory.parent / "child.stopped"),
        ]
        function = selected.f_globals["_spawn_provider_launch"]
        if (
            function.__globals__ is not selected.f_globals
            or function.__code__ is not selected.f_code
            or selected.f_code
            != state["isolated_named"](
                state["isolated_source_code"](source), "_spawn_provider_launch"
            )
            or not directory.resolve().is_relative_to(owned)
            or directory.name != "workspace"
            or argv != expected
            or list(plan.argv) != expected
            or cwd != plan.cwd
            or env != plan.environment
            or os.getcwd() != state["checkout"]
        ):
            refuse("timeout_original_plan_drift")
        binding = {
            "path": str(source),
            "line": 75,
            "sha256": state["product_pins"]["src/unrest_harness/provider_sessions.py"],
        }
        append(
            {
                "kind": "exact_timeout_owner_registration",
                "source_binding": binding,
                "original_timeout_seconds": 0.3,
                "native_adapter": False,
            }
        )
        return {"class": "source-session-helper:timeout", "python": True, "source_binding": binding}
    finally:
        frames.clear()
