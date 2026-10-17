"""Identity checks for the three byte-proven inactive source-checkpoint helpers."""

import ast
import hashlib
import inspect
from pathlib import Path
import sys

POINTS = (
    ("src/unrest_harness/acp_runner.py", 126, "_run_cmd", None),
    ("src/unrest_harness/coordinator.py", 901, "_validate_integration_tree", "MissionCoordinator"),
    ("tests/contracts/conftest.py", 85, "run_candidate_process", None),
)


def check(state, append, refuse):
    root = Path(state["checkout"])
    frame = inspect.currentframe()
    try:
        while frame:
            for relative, line, name, owner in POINTS:
                source = root / relative
                if frame.f_code.co_filename != str(source) or frame.f_code.co_name != name:
                    continue
                call = next(
                    n
                    for n in ast.walk(ast.parse(source.read_bytes()))
                    if isinstance(n, ast.Call) and n.lineno == line
                )
                if not line <= frame.f_lineno <= call.end_lineno:
                    continue
                function = getattr(frame.f_globals[owner], name) if owner else frame.f_globals[name]
                module = sys.modules.get(function.__module__)
                plain = state["isolated_named"](
                    compile(source.read_bytes(), str(source), "exec", dont_inherit=True), name
                )
                rewritten = state["isolated_named"](state["isolated_source_code"](source), name)
                if (
                    hashlib.sha256(source.read_bytes()).hexdigest()
                    != state["product_pins"][relative]
                    or module is None
                    or vars(module) is not frame.f_globals
                    or function.__globals__ is not frame.f_globals
                    or function.__code__ is not frame.f_code
                    or frame.f_code not in (plain, rewritten)
                ):
                    refuse("inactive_source_owner_identity_drift")
                append(
                    {
                        "kind": "inactive_source_owner_identity_checked",
                        "path": relative,
                        "line": line,
                        "source_sha256": state["product_pins"][relative],
                        "new_launch_authority": False,
                    }
                )
            frame = frame.f_back
    finally:
        del frame
