"""Only the unchanged module fixture's five provider-free local CLI runs."""

import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import types

ENV = {"LANG": "C", "LC_ALL": "C", "PYTHONUTF8": "1", "TZ": "UTC"}


def admit(argv, cwd, env, state, append, refuse):
    root = Path(state["checkout"])
    source = root / "tests/test_v04_speed_runner.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if (
                frame.f_code.co_filename == str(source)
                and frame.f_code.co_name == "_collect_speed_runs"
            ):
                break
            frame = frame.f_back
        if frame is None:
            return None
        for name in (
            "tests/test_v04_speed_runner.py",
            "tools/v04_speed_runner.py",
            "tests/fixtures/v04_speed_workloads.v2.json",
            "src/unrest_harness/schemas/v04-speed-result.v2.schema.json",
        ):
            if (
                hashlib.sha256((root / name).read_bytes()).hexdigest()
                != state["product_pins"][name]
            ):
                refuse("benchmark_source_drift")
        owner = frame.f_back
        if (
            owner is None
            or owner.f_code.co_name != "speed_runs"
            or owner.f_code.co_filename != str(source)
            or owner.f_lineno != 47
        ):
            refuse("benchmark_fixture_owner_drift")
        compiled = compile(ast.parse(source.read_bytes()), str(source), "exec", dont_inherit=True)
        codes = {
            item.co_name: item for item in compiled.co_consts if isinstance(item, types.CodeType)
        }
        function = frame.f_globals.get("_collect_speed_runs")
        fixture = frame.f_globals.get("speed_runs")
        wrapped = getattr(fixture, "__wrapped__", None)
        if (
            not isinstance(function, types.FunctionType)
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or frame.f_code != codes["_collect_speed_runs"]
            or wrapped is None
            or wrapped.__code__ is not owner.f_code
            or owner.f_code != codes["speed_runs"]
            or owner.f_globals is not frame.f_globals
        ):
            refuse("benchmark_code_identity_drift")
        local = frame.f_locals
        parent = local["parent"]
        roots = tuple(parent / f"run-{i}" for i in range(5))
        index = len(local["observations"])
        if index not in range(5):
            refuse("benchmark_count_drift")
        selected = roots[index]
        expected = [
            sys.executable,
            str(root / "tools/v04_speed_runner.py"),
            "--fixture",
            str(root / "tests/fixtures/v04_speed_workloads.v2.json"),
            "--schema",
            str(root / "src/unrest_harness/schemas/v04-speed-result.v2.schema.json"),
            "--result-root",
            str(selected / "artifacts"),
            "--output",
            str(selected / "speed-result.json"),
            "--candidate-head",
            "c90a98626d7d595b40a3ac0d1ac954f24e1e12ad",
            "--candidate-tree",
            "d05eec79be56cfa8a9011bfa8859e0a65bfc05ad",
        ]
        if (
            frame.f_lineno != 60
            or argv != expected
            or Path(cwd) != root
            or env != ENV
            or local["roots"] != roots
            or local["root"] != selected
            or not parent.resolve().is_relative_to(Path(state["owned_root"]))
            or not selected.is_dir()
            or list(selected.iterdir())
        ):
            refuse("benchmark_vector_or_custody_drift")
        binding = {
            "path": str(source),
            "line": 60,
            "sha256": state["product_pins"]["tests/test_v04_speed_runner.py"],
            "function": "_collect_speed_runs",
        }
        append(
            {
                "kind": "concrete_benchmark_registration",
                "classification": "CONTROLLED_REGISTERED",
                "source_binding": binding,
                "run_index": index,
                "requested_runs": 5,
                "argv": expected,
                "environment": ENV,
                "cwd": str(root),
                "deadline_seconds": 300,
                "deadline_scope": "outer source pytest; run_focused.py subprocess.run timeout",
                "provider_model_network_allowed": False,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            }
        )
        return {"class": "source-benchmark-five-run", "python": True, "source_binding": binding}
    finally:
        del frame
