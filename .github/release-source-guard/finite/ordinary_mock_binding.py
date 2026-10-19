"""The one observed reference mock route through the real production dispatcher."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

CASE = "tests/test_acp_runner.py::test_missing_end_node_diagnostics_survive_production_dispatch_and_attention"
OUTER = "tests/contracts/test_lean_evidence_crosswalk.py::test_crosswalk_is_complete_and_every_mapped_node_passes"
OWNER = CASE.split("::")[1]


def matches(argv, cwd, environment, state, frames):
    if state.get("case") not in (CASE, OUTER):
        return False
    if state.get("case") == OUTER:
        if state.get('registered_payload') is None:
            return False
        guard = sys.modules['runtime_guard']
        path = Path(state['guard']).with_name('execution_owner.py')
        selected = guard.checked_source(path, state['direct_support']['files'][str(path)])['resolve'](
            state, guard.refuse, frames)
        if selected != CASE:
            return False
    root = Path(state["checkout"])
    product = root / "src/unrest_harness/acp_runner.py"
    source = root / "tests/test_acp_runner.py"
    fixture = root / "tests/mock_acp_agent.py"
    if argv != [sys.executable, str(fixture), "--missing-handoff-session-error"]:
        return False
    for path in (product, source, fixture):
        if (
            hashlib.sha256(path.read_bytes()).hexdigest()
            != state["product_pins"][str(path.relative_to(root))]
        ):
            return False
    module = sys.modules.get("unrest_harness.acp_runner")
    test_module = sys.modules.get("tests.test_acp_runner")
    if module is None or test_module is None:
        return False
    product_code = state["isolated_source_code"](product)
    test_code = state["isolated_named"](state["isolated_source_code"](source), OWNER)
    selected = {}
    points = [
        ("spawn_launch", 409),
        ("run_node", 1556),
        ("_run_coro_blocking", 2541),
        ("dispatch", 2573),
    ]
    functions = [
        module.spawn_launch,
        module.ACPNodeRunner.run_node,
        module._run_coro_blocking,
        module.ACPNodeDispatcher.dispatch,
    ]
    for (name, line), function in zip(points, functions, strict=True):
        found = [
            f
            for f in frames
            if f.f_code.co_filename == str(product)
            and f.f_code.co_name == name
            and f.f_lineno == line
            and f.f_code == state["isolated_named"](product_code, name)
            and f.f_code is function.__code__
            and f.f_globals is vars(module)
            and function.__globals__ is f.f_globals
        ]
        if not found:
            return False
        selected[name] = found[0]
    found = [
        f
        for f in frames
        if f.f_code.co_filename == str(source)
        and f.f_code.co_name == "dispatch"
        and f.f_lineno == 720
        and f.f_code == state["isolated_named"](test_code, "dispatch")
        and f.f_globals is vars(test_module)
    ]
    if len(found) != 1:
        return False
    dispatch = found[0]
    dispatcher = dispatch.f_locals["self"]
    function = type(dispatcher).__dict__.get("dispatch")
    if (
        type(dispatcher).__qualname__ != OWNER + ".<locals>.RecordingACPNodeDispatcher"
        or function is None
        or function.__code__ is not dispatch.f_code
        or function.__globals__ is not dispatch.f_globals
        or selected["dispatch"].f_locals["self"] is not dispatcher
        or selected["run_node"].f_locals["self"] is not dispatcher.runner
    ):
        return False
    local = selected["spawn_launch"].f_locals
    plan = local["plan"]
    directory = Path(cwd).resolve()
    return (
        type(plan) is module.LaunchPlan
        and tuple(argv) == plan.argv
        and cwd == plan.cwd
        and environment is plan.environment
        and directory.is_relative_to(Path(state["owned_root"]).resolve())
        and directory.name == "workspace"
        and os.getcwd() == str(root)
        and all(local.get(k) == subprocess.PIPE for k in ("stdin", "stdout", "stderr"))
        and local.get("limit") == module.SUBPROCESS_STREAM_LIMIT == 8 * 1024 * 1024
    )
