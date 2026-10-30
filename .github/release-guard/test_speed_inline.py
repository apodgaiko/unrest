"""Original formatted bodies use observed fixture metadata, never raw code slots."""

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import RELOAD_TEST, expected, script, translated
from speed_inline import CASES, NAMES, PRELUDE, directory, fixture
import speed_inline

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


@pytest.mark.parametrize("case", CASES)
def test_complete_original_string_matches_before_guard_prelude(case, tmp_path):
    tree = ast.parse((ROOT / RELOAD_TEST).read_bytes())
    function = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == NAMES[CASES.index(case)]
    )
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_isolated_python"
    )
    constants = {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and isinstance(n.value, ast.Constant)
        and type(n.value.value) is str
    }
    variables = {
        **constants,
        "tmp_path": tmp_path,
        "marker_system": tmp_path / "system-marker",
        "marker_run": tmp_path / "run-marker",
        "FIXTURE": ROOT / "tests/fixtures/v04_speed_workloads.v2.json",
    }
    original = eval(compile(ast.Expression(call.args[0]), "<original-template>", "eval"), variables)
    value = expected(case, case, "/native/python", "a" * 64, ROOT, {}, root=tmp_path)
    assert value.argv == ("/native/python", "-c", original)
    assert script(ROOT, case, tmp_path) == original
    assert translated(value) == ("/native/python", "-I", "-S", "-c", PRELUDE + original)
    with pytest.raises(Refused):
        expected(case, case, "/native/python", "a" * 64, ROOT, {})


def test_fixture_directory_is_owned_canonical_and_generation_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(speed_inline, "OWNER", os.getuid())
    base = tmp_path / "pytest"
    base.mkdir()
    path = base / (NAMES[0][:30] + "0")
    path.mkdir()
    acquired = directory(str(path), tmp_path, CASES[0])
    host = SimpleNamespace(
        case=CASES[0], meta={"owned": str(tmp_path)}, fixture_roots={CASES[0]: acquired}
    )
    assert fixture(host) == path
    path.rename(base / "retained")
    path.mkdir()
    assert fixture(host)==path
    alias = base / "alias"
    alias.symlink_to(path, target_is_directory=True)
    with pytest.raises(Refused):
        directory(str(alias), tmp_path, CASES[0])
    with pytest.raises(Refused):
        directory(str(tmp_path), tmp_path, CASES[0])
    with pytest.raises(Refused):
        directory(path, tmp_path, CASES[0])
    monkeypatch.setattr(speed_inline, "OWNER", os.getuid() + 1)
    with pytest.raises(Refused):
        directory(str(path), tmp_path, CASES[0])


@pytest.mark.parametrize(
    "expression", ("str(tmp_path.parent)", '__import__("os")', "marker_run.upper()")
)
def test_template_has_no_general_expression_evaluator(tmp_path, expression):
    tree = ast.parse((ROOT / RELOAD_TEST).read_bytes())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == NAMES[0])
    field = next(n for n in ast.walk(function) if isinstance(n, ast.FormattedValue))
    field.value = ast.parse(expression, mode="eval").body
    with pytest.raises(Refused, match="substitution"):
        speed_inline.body(tree, CASES[0], tmp_path, ROOT)


def test_fixture_metadata_is_root_only_exact_case_and_single_use(tmp_path, monkeypatch):
    from test_source_integration import backend_request

    observer, actor, _ = backend_request(tmp_path)
    monkeypatch.setattr(speed_inline, "OWNER", os.getuid())
    path = tmp_path / "pytest" / (NAMES[0][:30] + "0")
    path.mkdir(parents=True)
    observer.case = CASES[0]
    observer.fixture_roots = {}
    request = {"kind": "fixture-root", "payload": {"path": str(path)}}
    assert observer.dispatch(actor, request) == {"ok": True}
    assert fixture(observer) == path
    with pytest.raises(Refused):
        observer.dispatch(actor, request)
    observer.fixture_roots = {}
    with pytest.raises(Refused):
        observer.dispatch({**actor, "role": "fixed-inline"}, request)
    observer.case = "unknown"
    with pytest.raises(Refused):
        observer.dispatch(actor, request)


@pytest.mark.parametrize("suffix", ("0'", '0"', "0\\", "0\n", "", "foreign0"))
def test_unsafe_fixture_spelling_cannot_become_executable_source(tmp_path, monkeypatch, suffix):
    from test_source_integration import backend_request

    monkeypatch.setattr(speed_inline, "OWNER", os.getuid())
    observer, actor, _ = backend_request(tmp_path)
    observer.case = CASES[0]
    observer.fixture_roots = {}
    path = tmp_path / "pytest" / (NAMES[0][:30] + suffix)
    path.mkdir(parents=True)
    request={"kind": "fixture-root", "payload": {"path": str(path)}}
    if suffix in ("", "foreign0"):
        assert observer.dispatch(actor,request)=={"ok":True}
        assert fixture(observer)==path and not observer.intents
    else:
        with pytest.raises(Refused):
            observer.dispatch(actor,request)
        assert not observer.fixture_roots and not observer.intents
