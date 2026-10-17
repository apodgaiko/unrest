"""Exact seeded-environment source helper; original oracle remains unchanged."""

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import types

NAME = "test_seeded_pytest_run_is_hermetic_and_restores_parent_environment"


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/test_environment_isolation.py"
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename == str(source) and frame.f_code.co_name == NAME
        ):
            frame = frame.f_back
        if frame is None:
            return None
        body = source.read_bytes()
        pin = hashlib.sha256(body).hexdigest()
        if pin != state["product_pins"]["tests/test_environment_isolation.py"]:
            refuse("environment_helper_source_drift")
        code = state["isolated_source_code"](source)
        for name, current in ((NAME, frame.f_code), ("_adversarial_environment", None)):
            fn = frame.f_globals.get(name)
            if (
                not isinstance(fn, types.FunctionType)
                or fn.__globals__ is not frame.f_globals
                or fn.__code__ != state["isolated_named"](code, name)
                or current is not None
                and fn.__code__ is not current
            ):
                refuse("environment_helper_callable_drift")
        program = next(
            n.value.value
            for n in ast.parse(body).body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_PYTEST_RESTORE_PROBE" for t in n.targets)
        )
        expected = [
            sys.executable,
            "-c",
            program,
            "-q",
            str(source) + "::test_autouse_fixture_scrubs_complete_authoritative_inventory",
            str(source) + "::test_autouse_fixture_preserves_unrelated_environment",
            "tests/test_config.py::test_discover_defaults_to_four_parallel_nodes",
        ]
        local = frame.f_locals
        expected_env = {
            **dict(os.environ),
            **frame.f_globals["_adversarial_environment"](),
            "UNREST_TEST_ISOLATION_UNRELATED_SENTINEL": "outer-unrelated-value",
        }
        if (
            frame.f_lineno != 130
            or frame.f_globals["_PYTEST_RESTORE_PROBE"] != program
            or argv != expected
            or cwd != source.parent.parent
            or os.getcwd() != state["checkout"]
            or env != expected_env
            or local["parent_before"] != dict(os.environ)
        ):
            refuse("environment_helper_vector_or_context_drift")
        binding = {"path": str(source), "line": 130, "sha256": pin, "function": NAME}
        append(
            {
                "kind": "concrete_literal_source_registration",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(expected_env, sort_keys=True).encode()
                ).hexdigest(),
                "cwd": state["checkout"],
                "lifecycle": "original synchronous run/communicate/wait",
            }
        )
        return {
            "class": "source-seeded-environment-helper",
            "python": True,
            "source_binding": binding,
        }
    finally:
        del frame
