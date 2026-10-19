"""Finite original caller identity controls; no original case or child executes."""

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import types

import pytest

from unrest_harness import acp_runner
from tests import test_acp_runner as original

ROOT = Path(__file__).resolve().parents[2]
PATH = Path(__file__).with_name("finite") / "ordinary_mock_binding.py"
SPEC = importlib.util.spec_from_file_location("ordinary_mock_binding_control", PATH)
METHOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METHOD)


def named(code, name):
    if code.co_name == name:
        return code
    for child in code.co_consts:
        if isinstance(child, types.CodeType):
            result = named(child, name)
            if result is not None:
                return result
    return None


@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "outer",
        "flag",
        "cwd",
        "environment",
        "source",
        "plan-class",
        "stream",
        "limit",
        "missing-launch",
        "missing-owner",
        "code",
        "globals",
        "dispatcher",
        "runner",
    ],
)
def test_exact_original_chain_required(tmp_path, monkeypatch, change):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    vector = [
        sys.executable,
        str(ROOT / "tests/mock_acp_agent.py"),
        "--missing-handoff-session-error",
    ]
    plan = acp_runner.LaunchPlan(tuple(vector), str(workspace), {"PATH": "/bin"}, "/bin")
    test_code = original.test_missing_end_node_diagnostics_survive_production_dispatch_and_attention.__code__
    owner_code = named(test_code, "dispatch")

    # Recreate only the nested class identity; never execute the original test.
    def cell(value):
        return (lambda: value).__closure__[0]

    cls = type("RecordingACPNodeDispatcher", (acp_runner.ACPNodeDispatcher,), {})
    cls.__qualname__ = METHOD.OWNER + ".<locals>.RecordingACPNodeDispatcher"
    function = types.FunctionType(
        owner_code, vars(original), closure=tuple(cell(cls) for _ in owner_code.co_freevars)
    )
    cls.dispatch = function
    dispatcher = object.__new__(cls)
    dispatcher.runner = object.__new__(acp_runner.ACPNodeRunner)
    frames = []
    for fn, line, local in [
        (
            acp_runner.spawn_launch,
            409,
            {
                "plan": plan,
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "limit": 8 * 1024 * 1024,
            },
        ),
        (acp_runner.ACPNodeRunner.run_node, 1556, {"self": dispatcher.runner}),
        (acp_runner._run_coro_blocking, 2541, {}),
        (acp_runner.ACPNodeDispatcher.dispatch, 2573, {"self": dispatcher}),
        (function, 720, {"self": dispatcher}),
    ]:
        frames.append(
            types.SimpleNamespace(
                f_code=fn.__code__, f_globals=fn.__globals__, f_lineno=line, f_locals=local
            )
        )

    def code(path):
        if path.name == "test_acp_runner.py":
            # Actual imported pytest rewrite code, as required at runtime.
            return types.SimpleNamespace(test=test_code)
        return compile(path.read_bytes(), str(path), "exec", dont_inherit=True)

    def select(c, name):
        if isinstance(c, types.SimpleNamespace):
            return c.test if name == METHOD.OWNER else None
        return named(c, name)

    state = {
        "case": METHOD.OUTER if change == "outer" else METHOD.CASE,
        "checkout": str(ROOT),
        "owned_root": str(tmp_path),
        "product_pins": {
            p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
            for p in [
                "src/unrest_harness/acp_runner.py",
                "tests/test_acp_runner.py",
                "tests/mock_acp_agent.py",
            ]
        },
        "isolated_source_code": code,
        "isolated_named": select,
    }
    cwd, env = str(workspace), plan.environment
    if change == "case":
        state["case"] += "-foreign"
    elif change == "flag":
        vector[-1] = "--foreign"
    elif change == "cwd":
        cwd = str(tmp_path)
    elif change == "environment":
        env = dict(env)
    elif change == "source":
        state["product_pins"]["tests/mock_acp_agent.py"] = "0" * 64
    elif change == "plan-class":
        frames[0].f_locals["plan"] = types.SimpleNamespace(
            argv=plan.argv, cwd=plan.cwd, environment=plan.environment
        )
    elif change == "stream":
        frames[0].f_locals["stdin"] = subprocess.DEVNULL
    elif change == "limit":
        frames[0].f_locals["limit"] += 1
    elif change == "missing-launch":
        frames.pop(0)
    elif change == "missing-owner":
        frames.pop()
    elif change == "code":
        frames[0].f_code = frames[0].f_code.replace(co_name="foreign")
    elif change == "globals":
        frames[0].f_globals = dict(frames[0].f_globals)
    elif change == "dispatcher":
        frames[-1].f_locals["self"] = object()
    elif change == "runner":
        frames[1].f_locals["self"] = object()
    monkeypatch.chdir(ROOT)
    assert METHOD.matches(vector, cwd, env, state, frames) is (change is None)
