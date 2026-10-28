"""Finite bound-alias parameters preserve the original isolated programs."""

import ast
from pathlib import Path

import pytest

from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import METHODS, METHOD_CASES, METHOD_NAME, RELOAD_TEST, script, expected
from test_fixed_reload import fixture

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


def test_method_axis_is_exact_original_product_tuple():
    tree = ast.parse((ROOT / "tools/v04_speed_runner.py").read_bytes())
    value = next(
        n.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_SOCKET_METHOD_GUARDS" for t in n.targets)
    )
    assert ast.literal_eval(value) == METHODS


@pytest.mark.parametrize("case,method", zip(METHOD_CASES, METHODS, strict=True))
def test_full_original_program_and_one_real_child_declaration(case, method):
    tree = ast.parse((ROOT / RELOAD_TEST).read_bytes())
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == METHOD_NAME
    )
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_isolated_python"
    )
    # Evaluate only the pinned original string expression, never its program.
    original = eval(
        compile(ast.Expression(call.args[0]), "<original-template>", "eval"), {"method": method}
    )
    assert script(ROOT, method) == original
    host, calls, value, raw = fixture(case)
    assert value.argv == ("/native/python", "-c", original)
    assert proposal(host, {"role": "root"}, raw)["ok"] is True
    assert len(calls) == 1 and calls[0][-1]["maximum"] == 1
    with pytest.raises(Refused):
        expected(case, "reload", "/native/python", "a" * 64, ROOT, {})
    with pytest.raises(Refused):
        expected(case, method, "/native/python", "a" * 64, ROOT, {}, query=True)


@pytest.mark.parametrize("method", ("__class__", "close", "recv;import os", "shutdown-foreign"))
def test_unlisted_methods_never_select_a_program(method):
    case = RELOAD_TEST + "::" + METHOD_NAME + "[" + method + "]"
    with pytest.raises(Refused):
        expected(case, method, "/native/python", "a" * 64, ROOT, {})


def test_network_preflight_templates_preserve_exact_family_and_detachment():
    from fixed_inline import NETWORK, NETWORK_NAME

    tree = ast.parse((ROOT / RELOAD_TEST).read_bytes())
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == NETWORK_NAME
    )
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_isolated_python"
    )
    for case, (family, detached) in NETWORK.items():
        original = eval(
            compile(ast.Expression(call.args[0]), "<original-template>", "eval"),
            {"family": family, "detached": detached},
        )
        host, calls, value, raw = fixture(case)
        assert value.argv == ("/native/python", "-c", original)
        assert script(ROOT, case) == original
        assert proposal(host, {"role": "root"}, raw)["ok"] is True
        assert len(calls) == 1
