"""Exact source-frame and executable bindings for two original CLI launchers."""

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def translate(argv, cwd, env, state, append, refuse):
    directory = Path(cwd or os.getcwd()).resolve()
    environment = dict(os.environ if env is None else env)
    checkout = Path(state["checkout"])
    frame = inspect.currentframe()
    try:
        while frame:
            source = Path(frame.f_code.co_filename).resolve()
            if (
                source == checkout / "tests/test_repository_contract.py"
                and frame.f_code.co_name == "_run_repository_cli"
            ):
                if argv != [str(Path(sys.executable).with_name("unrest")), "check-repository"]:
                    return None
                if sha(source) != state["product_pins"]["tests/test_repository_contract.py"]:
                    refuse("copied_cli_source_drift")
                local = frame.f_locals
                root = local["root"].resolve()
                if (
                    directory != root
                    or not root.is_relative_to(Path(state["owned_root"]))
                    or environment != local["environment"]
                    or environment != {**os.environ, "PYTHONPATH": str(root / "src")}
                ):
                    refuse("copied_cli_environment_or_cwd")
                copied = sorted(p for p in (root / "src/unrest_harness").rglob("*") if p.is_file())
                expected = {
                    k: pin
                    for k, pin in state["product_pins"].items()
                    if k.startswith("src/unrest_harness/")
                }
                actual = {str(p.relative_to(root)): sha(p) for p in copied}
                if actual != expected:
                    refuse("copied_cli_module_bytes")
                executable = Path(argv[0])
                if sha(executable) != state["copied_console_pins"]["unrest"]:
                    refuse("copied_cli_console_bytes")
                if (
                    executable.read_bytes().splitlines()[0]
                    != ("#!" + sys.executable).encode()
                ):
                    refuse("copied_cli_console_interpreter")
                binding = {
                    "path": str(source),
                    "line": 70,
                    "sha256": sha(source),
                    "function": "_run_repository_cli",
                }
                append(
                    {
                        "kind": "concrete_copied_cli_registration",
                        "source_binding": binding,
                        "cwd": str(root),
                        "environment_sha256": hashlib.sha256(
                            json.dumps(environment, sort_keys=True).encode()
                        ).hexdigest(),
                        "copied_source_sha256": hashlib.sha256(
                            json.dumps(actual, sort_keys=True).encode()
                        ).hexdigest(),
                        "console_sha256": sha(executable),
                        "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                    }
                )
                return {
                    "class": "source-copied-repository-cli",
                    "python": True,
                    "source_binding": binding,
                }, [sys.executable, str(executable), *argv[1:]]
            if (
                source == checkout / "tests/test_cli.py"
                and frame.f_code.co_name
                == "test_registered_command_launches_from_another_workspace"
            ):
                local = frame.f_locals
                server = local["server"]
                if argv != [server["command"], *server["args"], "--help"]:
                    return None
                if (
                    sha(source) != state["product_pins"]["tests/test_cli.py"]
                    or directory != local["unrelated"].resolve()
                    or not directory.is_relative_to(Path(state["owned_root"]))
                    or environment != {**os.environ, **server["env"]}
                    or server["command"] != "unrest-server"
                    or server["args"] != ["--mode", "orchestrator"]
                ):
                    refuse("registered_workspace_cli_binding")
                binding = {
                    "path": str(source),
                    "line": 1184,
                    "sha256": sha(source),
                    "function": frame.f_code.co_name,
                }
                append(
                    {
                        "kind": "concrete_copied_cli_registration",
                        "source_binding": binding,
                        "cwd": str(directory),
                        "environment_sha256": hashlib.sha256(
                            json.dumps(environment, sort_keys=True).encode()
                        ).hexdigest(),
                        "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                    }
                )
                console = next(r for r in state["console_routes"] if r["name"] == "unrest-server")
                import shutil

                executable = shutil.which("unrest-server", path=environment.get("PATH"))
                if (
                    executable != console["path"]
                    or sha(executable) != console["sha256"]
                    or Path(executable).read_bytes().splitlines()[0]
                    != ("#!" + console["python"]).encode()
                ):
                    refuse("registered_workspace_console_identity")
                return {
                    "class": "source-registered-workspace-cli",
                    "python": True,
                    "source_binding": binding,
                }, [console["python"], executable, *argv[1:]]
            frame = frame.f_back
        return None
    finally:
        del frame
