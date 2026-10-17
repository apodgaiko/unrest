"""Bind the exact installed-lifecycle owner before inherited operation admission."""

import hashlib
import inspect
from pathlib import Path
import sys


def check(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/contracts/test_lean_package.py"
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename == str(source)
            and frame.f_code.co_name == "_run_installed_lifecycle"
        ):
            frame = frame.f_back
        if frame is None:
            return
        pin = state["product_pins"]["tests/contracts/test_lean_package.py"]
        function = frame.f_globals["_run_installed_lifecycle"]
        module = sys.modules.get(function.__module__)
        expected = state["isolated_named"](
            state["isolated_source_code"](source), "_run_installed_lifecycle"
        )
        plain = state["isolated_named"](
            compile(source.read_bytes(), str(source), "exec", dont_inherit=True),
            "_run_installed_lifecycle",
        )
        if (
            hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or module is None
            or vars(module) is not frame.f_globals
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or frame.f_code not in (plain, expected)
            or frame.f_lineno != 173
        ):
            refuse("installed_lifecycle_owner_identity_drift")
        local = frame.f_locals
        built = local["built_distribution"]
        expected_argv = [
            str(built.installed_python),
            "-S",
            "-c",
            local["script"],
            str(local["probe_root"]),
            str(local["repository_root"]),
            str(built.installed_site),
            str(built.dependency_site),
        ]
        if (
            argv != expected_argv
            or cwd != built.directory
            or env != local["child_env"]
            or not built.directory.resolve().is_relative_to(Path(state["owned_root"]))
        ):
            refuse("installed_lifecycle_owner_vector_drift")
        append(
            {
                "kind": "exact_installed_lifecycle_owner_binding",
                "path": str(source),
                "line": 173,
                "source_sha256": pin,
                "module_globals_identity": True,
                "source_code_identity": True,
                "source_code_variant": "plain"
                if frame.f_code == plain
                else "pytest-original-assertion-rewrite",
            }
        )
    finally:
        del frame
