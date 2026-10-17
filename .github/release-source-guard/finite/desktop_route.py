"""Finite local stdio source-fixture admission, without desktop activation."""

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


CASE = "tests/test_v046_desktop_fixture.py::test_actual_stdio_response_binds_fixture_process_and_candidate"
TOOL = "tools/v046_desktop_fixture.py"
OWNER = "tests/test_v046_desktop_fixture.py"


def select(
    argv: list[str], cwd: Any, env: Any, state: dict[str, Any], append: Any, refuse: Any
) -> Any:
    if state.get("case") != CASE:
        return targetless(argv, cwd, env, state, append, refuse)
    frames = active_frames()
    try:
        checkout = Path(state["checkout"])
        source = checkout / TOOL
        owner_source = checkout / OWNER
        for relative in (TOOL, OWNER):
            if (
                hashlib.sha256((checkout / relative).read_bytes()).hexdigest()
                != state["product_pins"][relative]
            ):
                refuse("desktop_source_drift")
        if (
            str(Path(sys.executable).resolve()) != state["runtime"]["realpath"]
            or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            != state["runtime"]["sha256"]
        ):
            refuse("desktop_runtime_identity_drift")
        owned = Path(state["owned_root"]).resolve()
        if state["class"] == "pytest-root":
            owner = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(owner_source)
                    and f.f_code.co_name == CASE.split("::")[1]
                ),
                None,
            )
            if owner is None:
                return None
            module = sys.modules.get("tests.test_v046_desktop_fixture")
            function = getattr(module, CASE.split("::")[1], None)
            expected = state["isolated_named"](bound_code(state, owner_source), CASE.split("::")[1])
            if (
                module is None
                or function is None
                or module.__dict__ is not owner.f_globals
                or function.__globals__ is not owner.f_globals
                or function.__code__ != expected
                or owner.f_code != expected
            ):
                refuse("desktop_original_owner_drift")
            assert module is not None and function is not None
            root, setup = owner.f_locals["prepared"]
            root = root.resolve()
            if not root.is_relative_to(owned) or Path.cwd() != root or root.name != "desktop":
                refuse("desktop_owned_root_drift")
            if json.loads((root / "setup.json").read_bytes()) != setup:
                refuse("desktop_setup_drift")
            registration = setup["registration"]
            exact = {
                "command": sys.executable,
                "args": ["-I", str(source), "serve", "--root", str(root)],
            }
            if registration != exact or json.loads((root / "registration.json").read_bytes()) != {
                "mcpServers": {setup["registration_name"]: exact}
            }:
                refuse("desktop_registration_drift")
            from mcp.client.stdio import get_default_environment

            if (
                argv != [exact["command"], *exact["args"]]
                or cwd is not None
                or env != get_default_environment()
            ):
                refuse("desktop_stdio_vector_environment_drift")
            fixture = module.fixture
            for name in ("prepare", "isolate", "package_identity"):
                fn = getattr(fixture, name)
                if fn.__globals__ is not fixture.__dict__ or fn.__code__ != state["isolated_named"](
                    compile(source.read_bytes(), str(source), "exec", dont_inherit=True), name
                ):
                    refuse("desktop_setup_callable_drift")
            binding = {
                "path": str(owner_source),
                "line": 84,
                "sha256": state["product_pins"][OWNER],
                "function": function.__name__,
            }
            python = True
            command_class = "source-cohort4:desktop-stdio"
        elif state["class"] == "source-cohort4:desktop-stdio":
            frame = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(source) and f.f_code.co_name == "serve"
                ),
                None,
            )
            if frame is None:
                return None
            plain = compile(source.read_bytes(), str(source), "exec", dont_inherit=True)
            module = sys.modules.get(frame.f_globals.get("__name__", ""))
            fn = frame.f_globals.get("serve")
            if (
                module is None
                or module.__dict__ is not frame.f_globals
                or fn.__globals__ is not frame.f_globals
                or fn.__code__ != frame.f_code
                or frame.f_code != state["isolated_named"](plain, "serve")
            ):
                refuse("desktop_serve_identity_drift")
            root = frame.f_locals["root"].resolve()
            if (
                not root.is_relative_to(owned)
                or Path.cwd() != root
                or state["registered_payload"]["orig_argv"]
                != [sys.executable, "-I", str(source), "serve", "--root", str(root)]
            ):
                refuse("desktop_child_root_drift")
            if (
                argv != ["/bin/ps", "-p", str(os.getpid()), "-o", "lstart="]
                or cwd is not None
                or env is not None
            ):
                refuse("desktop_ps_vector_environment_drift")
            if (
                hashlib.sha256(Path("/bin/ps").read_bytes()).hexdigest()
                != state["cohort_native_pins"]["/bin/ps"]
            ):
                refuse("desktop_native_bytes_drift")
            binding = {
                "path": str(source),
                "line": 184,
                "sha256": state["product_pins"][TOOL],
                "function": "serve",
            }
            python = False
            command_class = "source-cohort4:desktop-ps"
        else:
            return None
        append(
            {
                "kind": "concrete_desktop_source_registration",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ) if env is None else env, sort_keys=True).encode()
                ).hexdigest(),
                "cwd": str(root),
                "genuine_desktop_acceptance": False,
            }
        )
        return ({"class": command_class, "python": python, "source_binding": binding}, argv)
    finally:
        frames.clear()


def targetless(argv, cwd, env, state, append, refuse):
    case = state.get("case", "")
    prefix = "tests/test_server.py::test_real_targetless_dispatch_consumption["
    if case not in (prefix + "False]", prefix + "True]") or state.get("class") not in (
        "source-run-worker",
        "composed-http-role:orchestrator",
    ):
        return None
    source = Path(state["checkout"]) / "tests/test_server.py"
    product = Path(state["checkout"]) / "src/unrest_harness/acp_runner.py"
    frames = active_frames()
    try:
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
        for p in (source, product):
            if (
                hashlib.sha256(p.read_bytes()).hexdigest()
                != state["product_pins"][str(p.relative_to(state["checkout"]))]
            ):
                refuse("targetless_source_drift")
        expected = state["isolated_named"](bound_code(state, product), "spawn_launch")
        module = sys.modules.get(frame.f_globals["__name__"])
        if (
            frame.f_code != expected
            or module.__dict__ is not frame.f_globals
            or frame.f_globals["spawn_launch"].__code__ != expected
        ):
            refuse("targetless_launch_owner_drift")
        import ast

        tree = ast.parse(source.read_bytes())
        helper = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "_write_composed_acp_adapter"
        )
        original = next(
            n.args[0].value
            for n in ast.walk(helper)
            if isinstance(n, ast.Call) and ast.unparse(n.func) == "adapter.write_text"
        )
        owner = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "test_real_targetless_dispatch_consumption"
        )
        expression = next(
            n.value
            for n in owner.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "source" for t in n.targets)
            and isinstance(n.value, ast.BinOp)
        )
        begin = original.index("    snapshot = {")
        end = original.index("\ndef response(", begin)
        program = eval(
            compile(ast.Expression(expression), str(source), "eval", dont_inherit=True),
            {},
            {"source": original, "begin": begin, "end": end, "attention": case == prefix + "True]"},
        )
        plan = frame.f_locals["plan"]
        directory = Path(cwd).resolve()
        script = directory / ".hermetic-acp-adapter.py"
        trace = directory / ".hermetic-acp-trace.jsonl"
        if (
            not directory.is_relative_to(Path(state["owned_root"]))
            or argv != [sys.executable, str(script), str(trace)]
            or script.read_bytes() != program.encode()
            or tuple(argv) != plan.argv
            or str(cwd) != plan.cwd
            or env != plan.environment
            or Path.cwd() != directory
        ):
            refuse("targetless_exact_adapter_plan_drift")
        binding = {
            "path": str(source),
            "line": helper.lineno,
            "sha256": state["product_pins"]["tests/test_server.py"],
            "function": helper.name,
        }
        append(
            {
                "kind": "targetless_original_adapter_registration",
                "source_binding": binding,
                "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
                "cwd": str(directory),
                "case": case,
            }
        )
        return (
            {"class": "source-composed-adapter", "python": True, "source_binding": binding},
            argv,
        )
    finally:
        frames.clear()
