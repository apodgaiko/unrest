"""Exact finite original historical carrier read vectors, with source custody."""

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import types

OWNERS = {
    "test_v02_carriers_are_byte_identical_to_the_v020_tag": (84, "v0.2.0", "HISTORICAL_CARRIERS"),
    "test_v030_carriers_are_byte_identical_to_the_v030_tag": (96, "v0.3.0", "V030_CARRIERS"),
    "test_v031_carriers_are_byte_identical_to_the_v031_tag": (108, "v0.3.1", "V031_CARRIERS"),
}


def admit(argv, cwd, env, state, append, refuse):
    root = Path(state["checkout"])
    source = root / "tests/test_release_binding.py"
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename == str(source) and frame.f_code.co_name in OWNERS
        ):
            frame = frame.f_back
        if frame is None:
            return None
        line, tag, inventory = OWNERS[frame.f_code.co_name]
        body = source.read_bytes()
        pin = state["product_pins"]["tests/test_release_binding.py"]
        if hashlib.sha256(body).hexdigest() != pin:
            refuse("historical_git_source_drift")
        code = state["isolated_source_code"](source)
        function = frame.f_globals.get(frame.f_code.co_name)
        if (
            not isinstance(function, types.FunctionType)
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or function.__code__ != state["isolated_named"](code, frame.f_code.co_name)
        ):
            refuse("historical_git_callable_drift")
        tree = ast.parse(body)
        expression = next(
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == inventory for t in n.targets)
        )
        carriers = eval(compile(ast.Expression(expression), str(source), "eval"), {"ROOT": root})
        vectors = [
            ["git", "show", tag + ":" + carrier.relative_to(root).as_posix()]
            for carrier in carriers
        ]
        if (
            frame.f_lineno != line
            or argv not in vectors
            or cwd != root
            or env is not None
            or os.getcwd() != str(root)
            or frame.f_globals["ROOT"] != root
            or frame.f_globals[inventory] != carriers
            or argv != ["git", "show", tag + ":" + frame.f_locals["relative"]]
        ):
            refuse("historical_git_vector_context_drift")
        binding = {
            "path": str(source),
            "line": line,
            "sha256": pin,
            "function": frame.f_code.co_name,
        }
        append(
            {
                "kind": "concrete_historical_git_registration",
                "source_binding": binding,
                "argv": argv,
                "cwd": str(root),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
                "finite_vectors_sha256": hashlib.sha256(json.dumps(vectors).encode()).hexdigest(),
            }
        )
        return {
            "class": "source-historical-carrier-git:" + tag,
            "python": False,
            "source_binding": binding,
        }
    finally:
        del frame
