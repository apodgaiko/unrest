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
    "src/unrest_harness/server.py": {266},
    "tools/release_binding.py": {36},
    "tests/test_provider_review.py": {55},
    "tests/test_provider_review_frames.py": {69, 70},
    "tests/test_release_binding.py": {144, 130, 119},
    "tests/test_repository_contract.py": {82, 67, 70, 87},
    "tests/test_runtime_observability.py": {527},
    "tests/test_server.py": {
        5403,
        5404,
        2335,
        2336,
        2337,
        2465,
        2466,
        1968,
        1969,
        5041,
        5042,
        1847,
        1848,
        1208,
        5436,
        4285,
        4286,
        5437,
        2373,
        4937,
        3786,
        3787,
        4554,
        4555,
        4938,
        1745,
        1746,
        3284,
        4821,
        4820,
        5465,
        5466,
        2144,
        2145,
        3565,
        110,
        3566,
    },
}


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
    frame = inspect.currentframe()
    try:
        while frame:
            relative = os.path.relpath(frame.f_code.co_filename, state["checkout"])
            if relative in SITES and frame.f_lineno in SITES[relative]:
                break
            frame = frame.f_back
        if frame is None:
            return None
        if (
            relative == "src/unrest_harness/server.py"
            and state.get("case", "").split("[")[0] not in state["cohort3_cases"]
        ):
            return None
        source = Path(state["checkout"]) / relative
        pin = hashlib.sha256(source.read_bytes()).hexdigest()
        if pin != state["product_pins"][relative]:
            refuse("cohort_source_drift")
        module = sys.modules.get(frame.f_globals.get("__name__", ""))
        if relative == "tools/release_binding.py":
            module = sys.modules["tests.test_release_binding"].release_binding
        if module is None or module.__dict__ is not frame.f_globals:
            refuse("cohort_globals_drift")
        code_cache = state.setdefault("cohort3_code_indexes", {})
        code_key = (str(source), pin, "_pytest.assertion.rewrite" in sys.modules)
        if code_key not in code_cache:
            code_cache[code_key] = codes(bound_code(state, source))
        expected_codes = code_cache[code_key]
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
                    and ast.unparse(n.func)
                    in (
                        "asyncio.create_subprocess_exec",
                        "subprocess.run",
                        "subprocess.check_output",
                        "subprocess.Popen",
                    )
                },
            )
        case = state.get("case", "")
        selected = case.split("[")[0]
        if selected not in state["cohort3_cases"] or case not in state["cohort3_full_cases"]:
            refuse("cohort3_selected_owner_drift")
        case_source, *parts = selected.split("::")
        case_path = Path(state["checkout"]) / case_source
        case_module = sys.modules.get("tests." + case_path.stem)
        case_obj: Any = case_module
        for part in parts:
            case_obj = getattr(case_obj, part, None)
        case_pin = state["product_pins"][case_source]
        authenticated_child = (
            relative == "src/unrest_harness/server.py"
            and state.get("registered_payload") is not None
            and state["class"]
            in (
                "source-cohort3:tests/test_server.py:2373",
                "source-recovery-role",
                "composed-http-role:worker",
                "source-owned-role:worker",
            )
        )
        if hashlib.sha256(case_path.read_bytes()).hexdigest() != case_pin:
            refuse("cohort3_original_owner_source_drift")
        if not authenticated_child and (
            not isinstance(case_obj, types.FunctionType)
            or case_obj.__globals__ is not case_module.__dict__
            or case_obj.__code__
            != next(
                (
                    c
                    for c in codes(bound_code(state, case_path))
                    if c.co_qualname == ".".join(parts)
                ),
                None,
            )
        ):
            refuse("cohort3_original_owner_drift")

        active = active_frames()
        try:
            for caller in active:
                if caller.f_code.co_filename == str(
                    case_path
                ) and caller.f_code.co_qualname == ".".join(parts):
                    if (
                        caller.f_globals is not case_module.__dict__
                        or caller.f_code != case_obj.__code__
                    ):
                        refuse("cohort3_active_owner_namespace_drift")
        finally:
            active.clear()
        tree, calls = trees[tree_key]
        call = calls[frame.f_lineno]
        # Reconstruct literal programs from the unchanged assignments, rather than
        # accepting a caller-supplied program merely because the vector matches it.
        scope_cache = state.setdefault("cohort3_scope_indexes", {})
        if tree_key not in scope_cache:
            nodes = [
                n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            scope_cache[tree_key] = {
                line: min(
                    [n for n in nodes if n.lineno <= line <= (n.end_lineno or n.lineno)],
                    key=lambda n: (n.end_lineno or n.lineno) - n.lineno,
                )
                for line in calls
            }
        scope = scope_cache[tree_key][call.lineno]
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
            if not assignments:
                outer = next(
                    (
                        n
                        for n in tree.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == top
                    ),
                    None,
                )
                if outer is not None:
                    assignments = [
                        n.value
                        for n in ast.walk(outer)
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
                or state["case"]
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
        if ast.unparse(call.func) != "asyncio.create_subprocess_exec":
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
                "source-cohort3:ownership-stdio",
                "source-completion-helper:test_real_roles_first_use",
                "source-cohort3:tests/test_server.py:2373",
                "source-recovery-role",
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
        if relative == "tests/test_provider_review.py":
            scenario = frame.f_locals["scenario"]
            if not scenario.resolve().is_relative_to(root) or scenario.read_text() != json.dumps(
                {k: frame.f_locals[k] for k in ("events", "delay", "raw_frame")}
            ):
                refuse("cohort3_scenario_drift")
            fixture = Path(state["checkout"]) / "tests/fixtures/approval_acp_process.py"
            if frame.f_globals["FIXTURE"] != fixture:
                refuse("cohort3_fixture_global_drift")
        if relative == "tests/test_server.py" and frame.f_code.co_name == "git":
            arguments = frame.f_locals["arguments"]
            parent_scope = next(
                n
                for n in tree.body
                if isinstance(n, ast.AsyncFunctionDef)
                and n.name == "test_real_run_inquiry_workspace_and_campaign_results_cross_validator"
            )
            vectors = [
                tuple(ast.literal_eval(a) for a in n.args)
                for n in ast.walk(parent_scope)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "git"
            ]
            if arguments not in vectors:
                refuse("cohort3_git_parameter_drift")
        if relative == "tests/test_runtime_observability.py":
            allowed = [
                (["--help"], True),
                (["list-projects"], True),
                (["observe-project", "--help"], False),
            ]
            if (frame.f_locals["args"], frame.f_locals["trap"]) not in allowed:
                refuse("cohort3_probe_parameter_drift")
        if relative == "tests/test_server.py" and call.lineno == 2373:
            environment = frame.f_locals["environment"]
            update = next(
                n.args[0]
                for n in ast.walk(scope)
                if isinstance(n, ast.Call) and ast.unparse(n.func) == "environment.update"
            )
            if environment != {**dict(os.environ), **evaluate(update, frame, source)}:
                refuse("cohort3_dispatch_environment_drift")
        if relative == "tests/test_release_binding.py":
            constant = "PUBLISHED_V045_COMMIT"
            assigned = next(
                n.value
                for n in tree.body
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == constant for t in n.targets)
            )
            if frame.f_globals[constant] != ast.literal_eval(assigned) or frame.f_globals[
                "ROOT"
            ] != Path(state["checkout"]):
                refuse("cohort3_historical_global_drift")
            for name in ("V045_PROSE_CARRIERS", "V045_MANIFEST"):
                value = next(
                    n.value
                    for n in tree.body
                    if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
                )
                if frame.f_globals[name] != evaluate(value, frame, source):
                    refuse("cohort3_historical_inventory_drift")
        if relative == "tools/release_binding.py" and (
            argv != ["git", "ls-tree", "-r", "-z", "5a3d568aa881c746432b7034597bbb8a1ffe025f"]
            or cwd != Path(state["checkout"])
            or env is not None
        ):
            refuse("cohort3_published_inventory_drift")
        if relative == "tests/test_repository_contract.py" and call.lineno == 70:
            return None  # Exact copied-console translation owns this admission.
        python = argv[0] == sys.executable
        if not python:
            resolved = shutil.which(argv[0], path=(env or os.environ).get("PATH"))
            known = (
                "/usr/bin/git"
                if argv[0] == "git"
                else "/usr/bin/ps"
                if relative == "tests/test_server.py" and call.lineno == 3284 and argv[0] == "ps"
                else "/usr/bin/sleep"
            )
            if (
                relative == "src/unrest_harness/server.py"
                and authenticated_child
                and state["class"] in ("composed-http-role:worker", "source-owned-role:worker")
                and argv[0] == "git"
            ):
                known = (
                    "/usr/bin/git"
                    if case.startswith(
                        (
                            "tests/test_provider_review_frames.py::test_actual_runner_matching_id_order_and_owned_cleanup[",
                            "tests/test_server.py::test_real_completion_target_binding[",
                            "tests/test_server.py::test_real_orchestrator_restart_preserves_completion_refusal_attempt[",
                            "tests/test_server.py::test_real_targetless_work_completion[",
                            "tests/test_server.py::test_real_targetless_dispatch_consumption[",
                        )
                    )
                    else "/usr/bin/git"
                )
            if resolved != known or argv[1:] != expected_argv[1:]:
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
                "class": "source-cohort3:" + relative + ":" + str(call.lineno),
                "python": python,
                "source_binding": binding,
            },
            argv,
        )
    finally:
        del frame
