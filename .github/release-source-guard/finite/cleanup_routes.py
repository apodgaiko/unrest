"""Finite unchanged cleanup owner vectors and exact scenario-backed adapter."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys

CASE = "tests/test_acp_cleanup.py::test_recorded_transport_failures"
FAULT_CASE = "tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation"
PARAMETERS = {
    'test_recorded_transport_failures': ('case', ('deep_json', 'array_id', 'object_id', 'success')),
    'test_cleanup_faults_and_repeated_cancellation': ('fault', ('reader', 'client', 'progress', 'cancel', 'primary')),
}


def current_task():
    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


def task_frames():
    try:
        tasks = asyncio.all_tasks()
    except RuntimeError:
        return []
    result = {}
    for task in tasks:
        coroutine, seen = task.get_coro(), set()
        while coroutine is not None and id(coroutine) not in seen:
            seen.add(id(coroutine))
            frame = getattr(coroutine, 'cr_frame', None) or getattr(coroutine, 'gi_frame', None)
            if frame is not None:
                result[id(frame)] = frame
            coroutine = getattr(coroutine, 'cr_await', None) or getattr(coroutine, 'gi_yieldfrom', None)
    return list(result.values())


def scenario_value(owner, parameter, role, temporary):
    if owner not in PARAMETERS or role not in ('work', 'validate', 'terminal_reviewer'):
        raise ValueError('cleanup_parameter_drift')
    if parameter not in PARAMETERS[owner][1]:
        raise ValueError('cleanup_parameter_drift')
    if owner == 'test_cleanup_faults_and_repeated_cancellation':
        return {'role': role, 'no_handoff': True}
    raw = (None if parameter == 'success' else '[' * 10000 + '0' + ']' * 10000
           if parameter == 'deep_json' else json.dumps({
               'jsonrpc': '2.0', 'id': [] if parameter == 'array_id' else {}, 'result': {}}))
    return {'raw': raw, 'role': role, 'receipt': str(temporary / 'receipt')}



def admit(argv, cwd, env, state, append, refuse):
    selected_case = state.get('case') or ''
    owner = next((name for name in PARAMETERS
                  if selected_case.startswith('tests/test_acp_cleanup.py::' + name + '[')), None)
    if owner is None:
        return None
    root = Path(state["checkout"])
    source = root / "tests/test_acp_cleanup.py"
    fallback = Path(state["guard"]).with_name("fallback_binding.py")
    if (
        hashlib.sha256(fallback.read_bytes()).hexdigest()
        != state["direct_support"]["files"][str(fallback)]
    ):
        refuse("cleanup_support_drift")
    namespace = {}
    exec(compile(fallback.read_bytes(), str(fallback), "exec"), namespace)
    frames = namespace["active_frames"]()
    if owner == 'test_cleanup_faults_and_repeated_cancellation':
        frames = list({id(f): f for f in [*frames, *task_frames()]}.values())
    try:
        server = root / "src/unrest_harness/server.py"
        completion = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(server) and f.f_code.co_name == "_completion_context"
            ),
            None,
        )
        if (owner == "test_recorded_transport_failures" and completion is not None
                and state["class"] == "source-owned-role:worker"):
            function = completion.f_globals["_completion_context"]
            module = sys.modules.get(function.__module__)
            pin = state["product_pins"]["src/unrest_harness/server.py"]
            workspace = completion.f_locals["workspace"]
            if (
                hashlib.sha256(server.read_bytes()).hexdigest() != pin
                or module is None
                or vars(module) is not completion.f_globals
                or function.__globals__ is not completion.f_globals
                or function.__code__ is not completion.f_code
                or completion.f_code
                != state["isolated_named"](
                    state["isolated_source_code"](server), "_completion_context"
                )
                or completion.f_lineno != 266
                or argv != ["git", "rev-parse", "HEAD"]
                or cwd != workspace
                or env is not None
                or not workspace.resolve().is_relative_to(Path(state["owned_root"]))
            ):
                refuse("cleanup_completion_git_drift")
            binding = {
                "path": str(server),
                "line": 266,
                "sha256": pin,
                "owner": "_completion_context",
            }
            append({"kind": "exact_cleanup_completion_git_registration", "source_binding": binding})
            return {
                "class": "source-cleanup-completion-git",
                "python": False,
                "source_binding": binding,
            }
        frame = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(source)
                and f.f_code.co_name == owner
            ),
            None,
        )
        if frame is None:
            return None
        pin = state["product_pins"][str(source.relative_to(root))]
        function = frame.f_globals[frame.f_code.co_name]
        module = sys.modules.get(function.__module__)
        if (
            hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or module is None
            or vars(module) is not frame.f_globals
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or frame.f_code
            != state["isolated_named"](state["isolated_source_code"](source), frame.f_code.co_name)
        ):
            refuse("cleanup_owner_drift")
        local = frame.f_locals
        role, case = local['role'], local[PARAMETERS[owner][0]]
        temporary = local['tmp_path']
        try:
            expected_scenario = scenario_value(owner, case, role, temporary)
        except ValueError:
            refuse('cleanup_parameter_drift')
            return None
        if selected_case != 'tests/test_acp_cleanup.py::' + owner + '[' + case + '-' + role + ']':
            refuse('cleanup_case_binding')
        if owner == 'test_cleanup_faults_and_repeated_cancellation':
            task = current_task()
            if task is None or local.get('task') is not task:
                refuse('cleanup_task_owner_drift')
            ws = temporary / 'workspace'
        else:
            ws = local['ws']
        if (
            not temporary.resolve().is_relative_to(Path(state["owned_root"]))
            or not ws.resolve().is_relative_to(Path(state["owned_root"]))
            or os.getcwd() != state["checkout"]
        ):
            refuse("cleanup_root_drift")
        if argv[0] in ("git", "/usr/bin/git"):
            if owner != 'test_recorded_transport_failures':
                return None
            expected = {
                123: ["git", "init", "-q", str(ws)],
                124: [
                    "git",
                    "-c",
                    "user.name=Controlled",
                    "-c",
                    "user.email=controlled@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "Controlled",
                ],
            }
            if frame.f_lineno not in expected:
                return None
            if (
                argv != expected[frame.f_lineno]
                or env is not None
                or cwd != (ws if frame.f_lineno == 124 else None)
            ):
                refuse("cleanup_git_vector_drift")
            kind, python, line = "source-cleanup-git:" + str(frame.f_lineno), False, frame.f_lineno
        else:
            fixture = root / "tests/fixtures/cleanup_acp_process.py"
            if argv[:2] != [sys.executable, str(fixture)]:
                return None
            if (
                hashlib.sha256(fixture.read_bytes()).hexdigest()
                != state["product_pins"][str(fixture.relative_to(root))]
            ):
                refuse("cleanup_fixture_drift")
            scenario = temporary / "scenario.json"
            if (scenario.resolve() != scenario or not scenario.is_file()
                    or json.loads(scenario.read_bytes()) != expected_scenario):
                refuse("cleanup_scenario_drift")
            launch = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(root / "src/unrest_harness/acp_runner.py")
                    and f.f_code.co_name == "spawn_launch"
                ),
                None,
            )
            if launch is None:
                return None
            plan = launch.f_locals["plan"]
            if (
                argv != [sys.executable, str(fixture), str(scenario)]
                or tuple(argv) != plan.argv
                or cwd != plan.cwd
                or Path(cwd) != ws
                or env != plan.environment
            ):
                refuse("cleanup_launch_plan_drift")
            kind, python, line = "source-cleanup-adapter", True, 409
            source = root / "src/unrest_harness/acp_runner.py"
            pin = state["product_pins"][str(source.relative_to(root))]
        binding = {
            "path": str(source),
            "line": line,
            "sha256": pin,
            "owner": owner,
        }
        append(
            {
                "kind": "exact_cleanup_registration",
                "source_binding": binding,
                "class": kind,
                "role": role,
                "scenario": case,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            }
        )
        return {"class": kind, "python": python, "source_binding": binding}
    finally:
        frames.clear()
