"""Exact original call expressions for the fixed second canonical cohort."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import sys
import types
from typing import Any

SITES = {
    "tests/test_launch_preflight.py": {293},
    "src/unrest_harness/server.py": {266},
    "tests/test_acp_runner.py": {70, 214, 413, 465, 544, 632, 1080, 1383, 1843, 2209, 2268},
    "tests/test_completion_setup.py": {131, 132},
    "tests/test_completion_ownership.py": {33, 34, 99, 108, 134, 135},
    "tests/test_coordinator.py": {214, 1046, 1047, 1448},
    "tests/test_experimental_session.py": {347, 381, 490},
    "tests/test_lean_provider_security_runtime.py": {388},
}


def codes(code: types.CodeType) -> list[types.CodeType]:
    return [
        code,
        *(c for value in code.co_consts if isinstance(value, types.CodeType) for c in codes(value)),
    ]


def evaluate(node: ast.expr, frame: types.FrameType, source: Path) -> Any:
    return eval(
        compile(ast.Expression(node), str(source), "eval", dont_inherit=True),
        frame.f_globals,
        frame.f_locals,
    )


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
    route = Path(state["guard"]).with_name("launch_preflight_routes.py")
    selected = sys.modules["runtime_guard"].checked_source(
        route, state["direct_support"]["files"][str(route)]
    )["select"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    frame = inspect.currentframe()
    try:
        while frame:
            relative = os.path.relpath(frame.f_code.co_filename, state["checkout"])
            if relative in SITES and frame.f_lineno in SITES[relative]:
                break
            frame = frame.f_back
        if frame is None:
            return None
        case = state.get("case", "")
        resolver_path = Path(state["guard"]).with_name("execution_owner.py")
        resolver = sys.modules["runtime_guard"].checked_source(
            resolver_path, state["direct_support"]["files"][str(resolver_path)])
        case = resolver["current"](state, refuse)
        if (relative, frame.f_lineno) in {
            ("src/unrest_harness/server.py", 266), ("tools/release_binding.py", 36)
        }:
            if resolver["shared_family"](state, case, relative, frame.f_lineno, refuse) != 2:
                return None
        source = Path(state["checkout"]) / relative
        pin = hashlib.sha256(source.read_bytes()).hexdigest()
        if pin != state["product_pins"][relative]:
            refuse("cohort_source_drift")
        module = sys.modules.get(frame.f_globals.get("__name__", ""))
        if module is None or module.__dict__ is not frame.f_globals:
            refuse("cohort_globals_drift")
        expected_codes = codes(bound_code(state, source))
        expected = next(
            (c for c in expected_codes if c.co_qualname == frame.f_code.co_qualname), None
        )
        if frame.f_code != expected:
            refuse("cohort_code_drift")
        owner = frame
        while owner.f_back and owner.f_back.f_globals is frame.f_globals:
            owner = owner.f_back
        if owner.f_code.co_qualname != "<module>":
            top = owner.f_code.co_qualname.split(".<locals>")[0]
            obj: Any = module
            for part in top.split("."):
                obj = getattr(obj, part, None)
            if (
                not isinstance(obj, types.FunctionType)
                or obj.__globals__ is not frame.f_globals
                or obj.__code__ != next((c for c in expected_codes if c.co_qualname == top), None)
            ):
                refuse("cohort_callable_drift")
        trees = state.setdefault("cohort_original_call_ASTs", {})
        tree_key = (str(source), pin)
        if tree_key not in trees:
            tree = ast.parse(source.read_bytes())
            trees[tree_key] = (
                tree,
                {
                    n.lineno: n
                    for n in ast.walk(tree)
                    if isinstance(n, ast.Call)
                    and ast.unparse(n.func) in ("asyncio.create_subprocess_exec", "subprocess.run")
                },
            )
        if relative.startswith("tests/"):
            case_owner = top.replace(".", "::")
            case_prefix = relative + "::" + case_owner
            if case != case_prefix and not case.startswith(
                case_prefix + "["
            ):
                refuse("cohort_selected_owner_drift")
        tree, calls = trees[tree_key]
        call = calls[frame.f_lineno]
        # Reconstruct literal programs from the unchanged assignments, rather than
        # accepting a caller-supplied program merely because the vector matches it.
        scopes = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == frame.f_code.co_name
            and n.lineno <= call.lineno <= n.end_lineno
        ]
        scope = min(scopes, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
        for name in ("script", "retry", "code", "secret"):
            if name not in frame.f_locals:
                continue
            assignments = [
                n.value
                for n in ast.walk(scope)
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
                and n.lineno < call.lineno
            ]
            values = []
            for value in assignments:
                try:
                    values.append(evaluate(value, frame, source))
                except (KeyError, NameError, AttributeError):
                    continue
            if frame.f_locals[name] not in values:
                refuse("cohort_program_drift")
        if relative == "tests/test_acp_runner.py" and call.lineno == 70:
            modes = {
                "ready": "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); print(s.getsockname()[1],flush=True); time.sleep(30)",
                "early_exit": "import sys; print('private-prompt-credential',file=sys.stderr); sys.exit(23)",
                "never_ready": "import time; print('started',flush=True); time.sleep(30)",
                "cancel": "import time; print('started',flush=True); time.sleep(30)",
            }
            if (
                frame.f_locals.get("mode") not in modes
                or frame.f_locals["body"] != modes[frame.f_locals["mode"]]
                or case
                != relative
                + "::test_readiness_attributes_local_child_and_drains["
                + frame.f_locals["mode"]
                + "]"
            ):
                refuse("cohort_parameter_or_body_drift")
        if relative == "tests/test_acp_runner.py" and call.lineno == 214:
            if frame.f_locals["git_args"] not in (
                ("init", "--quiet", "--initial-branch=main"),
                ("commit", "--allow-empty", "--quiet", "-m", "base"),
            ):
                refuse("cohort_git_parameter_drift")
        expected_argv: list[Any] = []
        for arg in call.args:
            value = evaluate(arg.value if isinstance(arg, ast.Starred) else arg, frame, source)
            expected_argv.extend(value if isinstance(arg, ast.Starred) else [value])
        if ast.unparse(call.func) == "subprocess.run":
            expected_argv = expected_argv[0]
        expected_argv = [os.fspath(a) for a in expected_argv]
        keywords = {
            k.arg: evaluate(k.value, frame, source)
            for k in call.keywords
            if k.arg in ("cwd", "env")
        }
        if argv != expected_argv or cwd != keywords.get("cwd") or env != keywords.get("env"):
            refuse("cohort_vector_or_environment_drift")
        if os.getcwd() != state["checkout"] and not (
            relative == "src/unrest_harness/server.py"
            and state["class"]
            in (
                "source-owned-role:worker",
                "composed-http-role:worker",
                "source-cohort2:ownership-stdio",
                "source-completion-helper:test_real_roles_first_use",
            )
            and Path(os.getcwd()).resolve().is_relative_to(Path(state["owned_root"]))
        ):
            refuse("cohort_parent_cwd_drift")
        root = Path(state["owned_root"]).resolve()
        directory = Path(cwd or os.getcwd()).resolve()
        if directory != Path(state["checkout"]) and not directory.is_relative_to(root):
            refuse("cohort_owned_cwd_drift")
        for name in ("tmp_path", "workspace", "path"):
            owned_value = frame.f_locals.get(name)
            if isinstance(owned_value, Path) and not owned_value.resolve().is_relative_to(root):
                refuse("cohort_owned_root_drift")
        config = frame.f_locals.get("config")
        if config is not None and any(
            not Path(getattr(config, attr)).resolve().is_relative_to(root)
            for attr in ("harness_home", "projects_dir")
        ):
            refuse("cohort_configuration_root_drift")
        session = frame.f_locals.get("session")
        if session is not None and not Path(session.root).resolve().is_relative_to(root):
            refuse("cohort_session_root_drift")
        python = argv[0] == sys.executable
        if not python:
            resolved = shutil.which(argv[0], path=(env or os.environ).get("PATH"))
            known = "/usr/bin/git" if argv[0] == "git" else "/usr/bin/sleep"
            aliases = {known, known.replace('/usr/bin/', '/bin/', 1)}
            if (resolved not in aliases or Path(resolved).resolve() != Path(known).resolve()
                    or argv[1:] != expected_argv[1:]):
                refuse("cohort_native_identity_drift")
            # The manifest pins native executable bytes independently of PATH.
            if (
                hashlib.sha256(Path(known).read_bytes()).hexdigest()
                != state["cohort_native_pins"][known]
            ):
                refuse("cohort_native_bytes_drift")
        elif str(Path(argv[0]).resolve()) != state["runtime"]["realpath"]:
            refuse("cohort_runtime_drift")
        if python and len(argv) > 1 and argv[1] not in ("-c", "-m"):
            script = Path(argv[1]).resolve()
            if not script.is_relative_to(Path(state["checkout"])):
                refuse("cohort_script_root_drift")
            script_pin = state["product_pins"].get(str(script.relative_to(state["checkout"])))
            if script_pin is None or hashlib.sha256(script.read_bytes()).hexdigest() != script_pin:
                refuse("cohort_script_bytes_drift")
        if (relative == 'tests/test_acp_runner.py' and call.lineno == 214
                and argv == ['git', 'commit', '--allow-empty', '--quiet', '-m', 'base']):
            support = Path(state['guard']).with_name('owned_git_fixture.py')
            sys.modules['runtime_guard'].checked_source(
                support, state['direct_support']['files'][str(support)])['configure'](
                    frame, argv, directory, env, state, append, refuse)
        binding = {
            "path": str(source),
            "line": call.lineno,
            "sha256": pin,
            "function": frame.f_code.co_qualname,
        }
        append(
            {
                "kind": "concrete_cohort_source_registration",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ) if env is None else env, sort_keys=True).encode()
                ).hexdigest(),
                "cwd": str(directory),
            }
        )
        return (
            {
                "class": "source-cohort2:" + relative + ":" + str(call.lineno),
                "python": python,
                "source_binding": binding,
            },
            argv,
        )
    finally:
        del frame
