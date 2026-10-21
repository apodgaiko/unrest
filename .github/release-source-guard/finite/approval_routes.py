"""Finite controlled approval owner, relay and Python backend registrations."""

import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import stat

CASE = "tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[success]"
PREFIX = 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup'
MODES = ('success', 'delayed_interrupt', 'drop_ack', 're_denied', 'multiple',
         'failed_interrupt', 'outstanding', 'late_ack', 'crash_after_send')


DURABLE_PREFIX = 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives'
DURABLE_MODES = {'success': 'success', 'cancel': 'success', 'crash': 'success',
                 'cancel_after_send': 'drop_ack', 'crash_after_send': 'drop_ack',
                 'cancel_after_continue': 'continuation_hold', 'crash_after_continue': 'continuation_hold'}


def selected_mode(case):
    if type(case) is not str:
        return None
    ordinary = next((mode for mode in MODES if case == PREFIX + '[' + mode + ']'), None)
    return ordinary or next((mode for boundary, mode in DURABLE_MODES.items()
                             if case == DURABLE_PREFIX + '[' + boundary + ']'), None)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def select(argv, cwd, env, state, append, refuse):
    mode = selected_mode(state.get('case'))
    if mode is None:
        return None
    root = Path(state["checkout"])
    out = Path(state["guard"]).parent
    namespace = {}
    exec(
        compile(
            (out / "fallback_binding.py").read_bytes(), str(out / "fallback_binding.py"), "exec"
        ),
        namespace,
    )
    frames = namespace["active_frames"]()
    try:
        owned = Path(state["owned_root"])

        def pinned(relative):
            path = root / relative
            if sha(path) != state["product_pins"][relative]:
                refuse("approval_source_drift")
            return path

        def checked(frame, function, source, name):
            if (
                function.__globals__ is not frame.f_globals
                or function.__code__ is not frame.f_code
                or frame.f_code != state["isolated_named"](
                    state["isolated_source_code"](source) if source == root / 'tests/test_approval_recovery.py'
                    else compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), name)
                or sys.modules.get(function.__module__) is None
                or vars(sys.modules[function.__module__]) is not frame.f_globals
            ):
                refuse("approval_callable_drift")

        def registration(kind, source, line, translated, **custody):
            binding = {"path": str(source), "line": line, "sha256": sha(source)}
            append(
                {
                    "kind": "exact_controlled_approval_registration",
                    "class": kind,
                    "source_binding": binding,
                    "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                    "environment_sha256": hashlib.sha256(
                        json.dumps(
                            dict(os.environ if env is None else env), sort_keys=True
                        ).encode()
                    ).hexdigest(),
                    "native_provider": False,
                    **custody,
                }
            )
            return {"class": kind, "python": True, "source_binding": binding}, translated

        acp = pinned("src/unrest_harness/acp_runner.py")
        mcp = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(acp)
                and f.f_code.co_name == "_start_worker_mcp_server"
            ),
            None,
        )
        if mcp is not None:
            checked(
                mcp,
                mcp.f_globals["ACPNodeRunner"]._start_worker_mcp_server,
                acp,
                "_start_worker_mcp_server",
            )
            local = mcp.f_locals
            info = os.fstat(local["read_fd"])
            if (
                not stat.S_ISFIFO(info.st_mode)
                or info.st_uid != os.getuid()
                or fcntl.fcntl(local["read_fd"], fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            ):
                refuse("approval_mcp_pipe_drift")
            expected = [
                sys.executable,
                "-c",
                "from unrest_harness.approval_recovery import run_owned_mcp; "
                + f"run_owned_mcp({os.getpid()})",
                "--mode",
                "worker",
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                str(local["mcp_port"]),
                "--sensitive-inventory-fd",
                str(local["read_fd"]),
            ]
            if (
                argv != expected
                or cwd != local["workspace_dir"]
                or env != local["child_environment"]
                or local["task"].type != "work"
                or not Path(cwd).resolve().is_relative_to(owned)
            ):
                refuse("approval_mcp_vector_drift")
            return registration("source-approval-mcp", acp, 2191, argv,
                                pipe_device=info.st_dev, pipe_inode=info.st_ino)
        spawn = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(acp) and f.f_code.co_name == "spawn_launch"
            ),
            None,
        )
        fixture = pinned("tests/fixtures/approval_recovery_acp.py")
        if spawn is not None and len(argv) == 3 and argv[:2] == [sys.executable, str(fixture)]:
            checked(spawn, spawn.f_globals["spawn_launch"], acp, "spawn_launch")
            owner_path = pinned("tests/test_approval_recovery.py")
            durable = state['case'].startswith(DURABLE_PREFIX + '[')
            module = sys.modules.get('tests.fixtures.approval_run_executor' if durable else 'tests.test_approval_recovery')
            if module is None:
                return None
            if durable:
                owner_path = pinned('tests/fixtures/approval_run_executor.py')
                function = module.execute
                expected_owner = compile(owner_path.read_bytes(), str(owner_path), 'exec', dont_inherit=True)
            else:
                function = module.test_actual_acp_owner_native_subprocess_order_and_cleanup
                expected_owner = state['isolated_source_code'](owner_path)
            if (function.__globals__ is not vars(module)
                    or function.__code__ != state['isolated_named'](expected_owner, function.__name__)
                    or not durable and module.FIXTURES != root / 'tests/fixtures'
                    or durable and state['class'] != 'source-run-worker'):
                refuse('approval_original_owner_drift')
            scenario = Path(argv[2])
            plan = spawn.f_locals["plan"]
            scenario_body = json.loads(scenario.read_bytes())
            expected_prefix = {'mode': mode, 'trace': str(scenario.parent / ('run-methods.jsonl' if durable else 'trace.jsonl'))}
            handoff = Path(scenario_body.get("handoff", ""))
            if (
                scenario.name != ('run-scenario.json' if durable else 'scenario.json')
                or not scenario.resolve().is_relative_to(owned)
                or set(scenario_body) != {"mode", "trace", "handoff"}
                or any(scenario_body[k] != v for k, v in expected_prefix.items())
                or not handoff.resolve().is_relative_to(owned)
                or handoff.name != "attempt-1__w1.json"
                or tuple(argv) != plan.argv
                or cwd != plan.cwd
                or env != plan.environment
                or not Path(cwd).resolve().is_relative_to(owned)
            ):
                refuse("approval_adapter_scenario_drift")
            return registration("source-approval-adapter", acp, 409, argv)
        child = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(fixture) and f.f_code.co_name == "main"
            ),
            None,
        )
        if child is not None and state["class"] == "source-approval-adapter":
            checked(child, child.f_globals["main"], fixture, "main")
            scenario = child.f_locals["scenario"]
            launcher = Path(child.f_locals["environment"]["CODEX_PATH"])
            if (
                argv != [str(launcher), "app-server"]
                or cwd is not None
                or env != child.f_locals["environment"]
                or not launcher.resolve().is_relative_to(owned)
                or launcher.resolve() != launcher
                or launcher.name != "backend"
                or not launcher.parent.name.startswith("unrest-approval-")
            ):
                refuse("approval_relay_vector_drift")
            tree = ast.parse(launcher.read_bytes())
            call = tree.body[-1].value
            try:
                socket, token, backend, digest = [ast.literal_eval(n) for n in call.args]
            except (ValueError, AttributeError):
                refuse("approval_relay_body_drift")
            native = pinned("tests/fixtures/approval_native_backend.py")
            backend_path = Path(backend)
            backend_body = f"#!{sys.executable}\n".encode() + native.read_bytes()
            expected = (
                f"#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(root / 'src')!r})\n"
                "from unrest_harness.approval_relay import main\n"
                f"main({socket!r}, {token!r}, {backend!r}, {digest!r})\n"
            )
            if (
                launcher.read_text() != expected
                or Path(socket) != launcher.parent / "control"
                or re.fullmatch("[0-9a-f]{64}", token) is None
                or not backend_path.resolve().is_relative_to(owned)
                or backend_path.resolve() != backend_path
                or backend_path.name != "controlled-backend"
                or backend_path.read_bytes() != backend_body
                or sha(backend_path) != digest
                or scenario["mode"] != mode
                or env["CONTROLLED_APPROVAL_TRACE"] != scenario["trace"]
            ):
                refuse("approval_relay_identity_drift")
            return registration(
                "source-approval-relay", fixture, 17, [sys.executable, str(launcher), "app-server"]
            )
        relay = pinned("src/unrest_harness/approval_relay.py")
        frame = next(
            (f for f in frames if f.f_code.co_filename == str(relay) and f.f_code.co_name == "run"),
            None,
        )
        if frame is not None and state["class"] == "source-approval-relay":
            checked(frame, frame.f_globals["run"], relay, "run")
            local = frame.f_locals
            backend = Path(local["backend_path"])
            native = pinned("tests/fixtures/approval_native_backend.py")
            body = f"#!{sys.executable}\n".encode() + native.read_bytes()
            if (
                argv != [str(backend), "app-server"]
                or local["argv"] != ["app-server"]
                or cwd is not None
                or env != local["environment"]
                or not backend.resolve().is_relative_to(owned)
                or backend.resolve() != backend
                or backend.read_bytes() != body
                or sha(backend) != local["backend_digest"]
                or env["CONTROLLED_APPROVAL_MODE"] != mode
            ):
                refuse("approval_backend_identity_drift")
            return registration(
                "source-approval-python-backend",
                relay,
                131,
                [sys.executable, str(backend), "app-server"],
            )
        return None
    finally:
        frames.clear()
