"""Exact unchanged crash owner; registration grants no orphan wait exception."""

import ast
import hashlib
import inspect
import json
import marshal
import os
from pathlib import Path
import sys

BOUNDARIES = ("reservation", "prompt_sent", "backend_received", "provider_completed")
OWNER = "test_actual_controller_crash_has_no_resume_authority"


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/test_experimental_cohort.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if frame.f_code.co_filename == str(source) and frame.f_code.co_name == OWNER:
                break
            frame = frame.f_back
        if frame is None:
            return None
        pin = state["product_pins"]["tests/test_experimental_cohort.py"]
        if hashlib.sha256(source.read_bytes()).hexdigest() != pin:
            refuse("crash_source_drift")
        module = sys.modules.get(frame.f_globals["__name__"])
        function = frame.f_globals[OWNER]
        if (
            module is None
            or vars(module) is not frame.f_globals
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or frame.f_code != state["isolated_named"](state["isolated_source_code"](source), OWNER)
        ):
            refuse("crash_owner_identity_drift")
        local = frame.f_locals
        boundary = local["boundary"]
        root = local["tmp_path"] / "crashed"
        node = next(
            n
            for n in ast.parse(source.read_bytes()).body
            if isinstance(n, ast.FunctionDef) and n.name == OWNER
        )
        body = next(
            n.value.value
            for n in node.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "source" for t in n.targets)
        )
        adapter = frame.f_globals["ADAPTER"]
        fixture = frame.f_globals["FIXTURE"].resolve()
        script = (
            "BOUNDARY="
            + repr(boundary)
            + "\nfrom pathlib import Path\nROOT=Path("
            + repr(str(root))
            + ")\nADAPTER=Path("
            + repr(str(adapter))
            + ")\nFIXTURE=Path("
            + repr(str(fixture))
            + ")\n"
            + body
        )
        if (
            boundary not in BOUNDARIES
            or state.get("case")
            != str(source.relative_to(state["checkout"])) + "::" + OWNER + "[" + boundary + "]"
            or not root.resolve().is_relative_to(Path(state["owned_root"]))
            or local["root"] != root
            or local["script"] != script
            or argv != [sys.executable, "-c", script]
            or cwd is not None
            or env is not None
            or Path.cwd() != Path(state["checkout"])
            or os.environ.get("TMPDIR") != state["owned_root"]
        ):
            refuse("crash_vector_environment_root_drift")
        spec = state.get("exact_crash_disposition")
        owner_ast = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
        if spec is not None:
            if (
                str(source) != spec["source"]
                or pin != spec["source_sha256"]
                or owner_ast != spec["owner_ast_sha256"]
                or str(adapter) != spec["adapter_global"]
                or hashlib.sha256(adapter.read_bytes()).hexdigest() != spec["adapter_global_sha256"]
                or str(fixture) not in spec["files"]
                or Path(sys.executable).resolve() != Path(state["runtime"]["realpath"])
                or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
                != state["runtime"]["sha256"]
                or any(
                    hashlib.sha256(Path(p).read_bytes()).hexdigest() != h
                    for p, h in spec["files"].items()
                )
            ):
                refuse("crash_disposition_input_drift")
        binding = {"path": str(source), "line": 497, "sha256": pin}
        append(
            {
                "kind": "exact_crash_owner_registration",
                "boundary": boundary,
                "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
                "source_binding": binding,
                "crash_exit": 73,
                "wait_exception": False,
                "owner_ast_sha256": owner_ast,
                "owner_code_sha256": hashlib.sha256(marshal.dumps(frame.f_code)).hexdigest(),
                "callable_code_globals_identity_verified": True,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
                "cwd": str(Path.cwd()),
                "root": str(root),
            }
        )
        return {"class": "source-crash-controller", "python": True, "source_binding": binding}
    finally:
        del frame


def native(argv, cwd, env, state, append, refuse):
    case = state.get("case", "")
    if case not in [
        "tests/test_experimental_cohort.py::" + OWNER + "[" + b + "]" for b in BOUNDARIES
    ]:
        return None
    source = Path(state["checkout"]) / "src/unrest_harness/experimental_cohort.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if frame.f_code.co_filename == str(source) and frame.f_code.co_name == "campaign":
                break
            frame = frame.f_back
        if frame is None or frame.f_lineno not in (567, 570, 571, 572):
            return None
        pin = state["product_pins"]["src/unrest_harness/experimental_cohort.py"]
        function = frame.f_globals["campaign"]
        if (
            hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or frame.f_code
            != state["isolated_named"](state["isolated_source_code"](source), "campaign")
        ):
            refuse("crash_campaign_identity_drift")
        vectors = {
            567: ["init", "--initial-branch=main", "--object-format=sha1"],
            570: ["add", "."],
            571: ["commit", "-m", "base"],
            572: ["rev-parse", "HEAD"],
        }
        directory = frame.f_locals["original"]
        custody = Path(state["checkout"]) / "src/unrest_harness/experimental_custody.py"
        tree = ast.parse(custody.read_bytes())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "git")
        expected_env = next(
            n.value for n in ast.walk(fn) if isinstance(n, ast.keyword) and n.arg == "env"
        )
        if (
            argv != ["/usr/bin/git", "--no-replace-objects", *vectors[frame.f_lineno]]
            or cwd != directory
            or not directory.resolve().is_relative_to(Path(state["owned_root"]))
            or env != ast.literal_eval(expected_env)
            or hashlib.sha256(custody.read_bytes()).hexdigest()
            != state["product_pins"]["src/unrest_harness/experimental_custody.py"]
        ):
            refuse("crash_setup_git_vector_drift")
        binding = {"path": str(source), "line": frame.f_lineno, "sha256": pin}
        append({"kind": "exact_crash_setup_git", "source_binding": binding})
        return {"class": "source-crash-setup-git", "python": False, "source_binding": binding}
    finally:
        del frame
