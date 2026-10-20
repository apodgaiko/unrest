"""Pure guard control: actual constructor frame, no original test or OS launch."""

import ast
import inspect
import importlib
import json
from pathlib import Path
import sys
import weakref
import pytest

SUPPORT = Path(__file__).resolve().parent
sys.path.insert(0, str(SUPPORT))
sys.path.insert(0, str(SUPPORT / "finite"))
composition = importlib.import_module("test_source_activation_composition")


@pytest.mark.parametrize("mutation", ["none", "wrong-offset", "late-token"])
def test_genuine_admission_phase_defers_without_consuming_custody(tmp_path, monkeypatch, mutation):
    h = composition.setup(tmp_path, monkeypatch)
    integration = ast.parse((SUPPORT / "finite/source_integration_activation.py").read_bytes())
    shared = next(
        n for n in ast.walk(integration) if isinstance(n, ast.FunctionDef) and n.name == "shared"
    )

    class Base:
        def shared(self):
            pass

    cls = ast.ClassDef(
        name="SourceIntegrationActivation",
        bases=[ast.Name(id="original", ctx=ast.Load())],
        keywords=[],
        body=[shared],
        decorator_list=[],
    )
    ns = {"original": Base}
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
            str(SUPPORT / "finite/source_integration_activation.py"),
            "exec",
        ),
        ns,
    )
    activation = ns["SourceIntegrationActivation"]()
    activation.python_consumed = set()
    code = next(
        n
        for n in ast.walk(ast.parse((SUPPORT / "finite/child_relative.py").read_bytes()))
        if isinstance(n, ast.FunctionDef) and n.name == "capture"
    )
    check = next(
        n
        for n in ast.walk(ast.parse((SUPPORT / "finite/child_relative.py").read_bytes()))
        if isinstance(n, ast.FunctionDef) and n.name == "frame_check"
    )
    core = h.owner.subprocess.Popen.__init__.__code__

    def refuse(reason):
        raise RuntimeError(reason)

    context = {
        "inspect": inspect,
        "json": json,
        "weakref": weakref,
        "activation": activation,
        "shared": activation.shared.__func__,
        "shared_code": activation.shared.__func__.__code__,
        "shared_globals": activation.shared.__func__.__globals__,
        "captured_cells": {"initialize": core},
        "core": core,
        "guard": h.guard,
        "state": h.state,
        "refuse": refuse,
        "used": set(),
        "contexts": {},
        "observe": lambda: {},
    }
    from child_relative import admission_offsets

    context["admission"] = admission_offsets(core) if mutation != "wrong-offset" else frozenset()
    exec(
        compile(
            ast.Module(body=[check, code], type_ignores=[]),
            str(SUPPORT / "finite/child_relative.py"),
            "exec",
        ),
        context,
    )
    activation.capture_child_relative = context["capture"]
    observed = []

    def admission(*args):
        frame = inspect.currentframe().f_back
        if mutation == "late-token":
            frame.f_locals["launch_token"] = "not-an-admission-phase"
        observed.append(
            {
                "function": frame.f_code.co_name,
                "registration_assigned": "registration" in frame.f_locals,
            }
        )
        activation.shared()
        raise composition.Consumed

    monkeypatch.setattr(h.guard, "admit", admission)
    expected_error = composition.Consumed if mutation == "none" else RuntimeError
    with pytest.raises(expected_error) as caught:
        h.owner.launch(h.vector, h.tmp, {"FINITE": "original"})
    if mutation != "none":
        assert str(caught.value) == "child_relative_capture_phase"
    assert observed == [{"function": "initialize_inner", "registration_assigned": False}]
    assert not context["contexts"] and not context["used"]
