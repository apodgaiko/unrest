"""Source-owned ordinary MCP roles; pipe and selected argv identity are required."""

import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys


def admit(argv, cwd, environment, state, append, refuse):
    source = Path(state["checkout"]) / "src/unrest_harness/acp_runner.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if Path(frame.f_code.co_filename).resolve() == source and frame.f_code.co_name in (
                "_start_worker_mcp_server",
                "_start_terminal_reviewer_mcp",
            ):
                break
            frame = frame.f_back
        if frame is None:
            return None
        pin = state["product_pins"]["src/unrest_harness/acp_runner.py"]
        if hashlib.sha256(source.read_bytes()).hexdigest() != pin:
            refuse("owned_role_source_drift")
        local = frame.f_locals
        role = (
            "terminal-reviewer"
            if frame.f_code.co_name == "_start_terminal_reviewer_mcp"
            else ("validator" if local["task"].type == "validate" else "worker")
        )
        if frame.f_code.co_name == "_start_worker_mcp_server" and local["task"].type not in (
            "work",
            "validate",
        ):
            refuse("owned_role_task_type")
        fd = local["read_fd"]
        info = os.fstat(fd)
        port = local["mcp_port"]
        expected = [
            argv[0],
            "-m",
            "unrest_harness",
            "--mode",
            role,
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--sensitive-inventory-fd",
            str(fd),
        ]
        substitute = None
        if argv != expected and state.get('case') in {
                'tests/test_acp_runner.py::test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained[worker]',
                'tests/test_acp_runner.py::test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained[terminal-reviewer]'}:
            support = Path(state['guard']).with_name('chatty_role.py')
            guard = sys.modules['runtime_guard']
            substitute = guard.checked_source(
                support, state['direct_support']['files'][str(support)])['bind'](
                    argv, cwd, environment, state, role, frame, fd, expected, refuse)
        directory = Path(cwd).resolve()
        expected_env = local.get("child_environment", local["environment"])
        if (
            (argv != expected and substitute is None)
            or not isinstance(port, int)
            or not 0 < port < 65536
            or directory != Path(local["workspace_dir"]).resolve()
            or not directory.is_relative_to(Path(state["owned_root"]))
            or environment != expected_env
            or not stat.S_ISFIFO(info.st_mode)
            or info.st_uid != os.getuid()
            or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        ):
            refuse("owned_role_identity")
        binding = substitute or {"path": str(source), "line": frame.f_code.co_firstlineno, "sha256": pin}
        append(
            {
                "kind": "concrete_owned_role_registration",
                "role": role,
                "source_binding": binding,
                "pipe_device": info.st_dev,
                "pipe_inode": info.st_ino,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            }
        )
        return {"class": "source-owned-role:" + role, "python": True, "source_binding": binding}
    finally:
        del frame
