"""Exact unchanged publication-crash StdioTransport source owner."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
from typing import Any


def select(
    argv: list[str], cwd: Any, env: Any, state: dict[str, Any], append: Any, refuse: Any
) -> Any:
    if (
        len(argv) < 3
        or argv[0] != sys.executable
        or argv[1] != "-c"
        or argv[2] == "from unrest_harness.server import main; main()"
    ):
        return None
    source = Path(state["checkout"]) / "tests/test_completion_ownership.py"
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename == str(source)
            and frame.f_code.co_name == "test_role_interrupted_publication"
        ):
            frame = frame.f_back
        if frame is None:
            return None
        pin = hashlib.sha256(source.read_bytes()).hexdigest()
        function = frame.f_globals["test_role_interrupted_publication"]
        if (
            pin != state["product_pins"]["tests/test_completion_ownership.py"]
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or function.__code__
            != state["isolated_named"](
                state["isolated_source_code"](source), "test_role_interrupted_publication"
            )
        ):
            refuse("cohort_stdio_owner_drift")
        local = frame.f_locals
        role, phase = local["role"], local["phase"]
        if (
            role not in ("work", "validate")
            or phase not in ("before", "after")
            or state["case"]
            != "tests/test_completion_ownership.py::test_role_interrupted_publication["
            + role
            + "-"
            + phase
            + "]"
        ):
            refuse("cohort_stdio_parameter_drift")
        node = next(
            n
            for n in ast.parse(source.read_bytes()).body
            if isinstance(n, ast.FunctionDef) and n.name == function.__name__
        )
        assignment = next(
            n.value
            for n in node.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "script" for t in n.targets)
        )
        program = eval(
            compile(ast.Expression(assignment), str(source), "eval"), frame.f_globals, local
        )
        directory = local["workspace"].resolve()
        if (
            argv != [sys.executable, "-c", program, "--mode", local["mode"]]
            or local["script"] != program
            or str(cwd) != str(directory)
            or dict(env) != local["env"]
            or os.getcwd() != state["checkout"]
            or not directory.is_relative_to(Path(state["owned_root"]))
            or not local["path"].resolve().is_relative_to(Path(state["owned_root"]))
        ):
            append(
                {
                    "kind": "cohort_stdio_context_difference",
                    "vector_matches": argv
                    == [sys.executable, "-c", program, "--mode", local["mode"]],
                    "program_matches": local["script"] == program,
                    "cwd_matches": str(cwd) == str(directory),
                    "env_matches": dict(env) == local["env"],
                    "parent_cwd_matches": os.getcwd() == state["checkout"],
                    "environment_differing_keys": sorted(
                        k for k in set(env) | set(local["env"]) if env.get(k) != local["env"].get(k)
                    ),
                }
            )
            refuse("cohort_stdio_vector_environment_root_drift")
        binding = {"path": str(source), "line": 173, "sha256": pin, "function": function.__name__}
        append(
            {
                "kind": "concrete_cohort_stdio_registration",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(env), sort_keys=True).encode()
                ).hexdigest(),
                "cwd": str(directory),
            }
        )
        return (
            {"class": "source-cohort2:ownership-stdio", "python": True, "source_binding": binding},
            argv,
        )
    finally:
        del frame
