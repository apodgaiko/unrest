"""Original inline catalogue parity, without starting any process."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from effect_proposals import proposal
from content_manifest import Refused
from cleanup_inline import (
    CASES,
    STARTUP,
    CLIENT,
    INFLIGHT,
    NO_LAUNCH,
    SLEEP,
    EXIT,
    body,
    child_count,
)
from cleanup_launch import TEST


def test_inline_bodies_and_effect_lines_are_original_source():
    file = (
        next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()) / TEST
    )
    tree = ast.parse(file.read_bytes())
    calls = {node.lineno: node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for line in (61, 269, 299, 429):
        assert line in calls
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) is str
    }
    assert SLEEP in constants and EXIT in constants
    assert len(CASES) == 21 and len(set(CASES)) == 21
    assert (len(STARTUP), len(CLIENT), len(INFLIGHT), len(NO_LAUNCH)) == (9, 3, 2, 7)


@pytest.mark.parametrize("case", CASES)
def test_inline_parameters_keep_original_effect_counts(case):
    if case in NO_LAUNCH:
        assert child_count(case) == 0
        with pytest.raises(Refused):
            body(case)
    else:
        assert body(case) == (EXIT if case in STARTUP and STARTUP[case][1] == "exit" else SLEEP)
        assert child_count(case) == (
            1 if case in STARTUP or CLIENT.get(case, (None, None))[1] == "reader" else 3
        )
    if case not in INFLIGHT:
        from cleanup_inline import expected
        with pytest.raises(Refused):
            expected(case, '/native', 'a'*64, Path('/source'), {},
                     base=Path('/owned/pytest/case'), terminal=True)


@pytest.mark.parametrize(
    "case", [True, "", "tests/test_acp_cleanup.py::foreign", CASES[0] + "-foreign"]
)
def test_no_generic_inline_selection(case):
    with pytest.raises(Refused):
        body(case)


def test_inline_options_and_vectors_are_closed():
    from cleanup_inline import expected

    root = {"HOME": "/owned/home", "TMPDIR": "/owned/tmp", "PATH": "/usr/bin:/bin"}
    for case in CASES:
        if case in NO_LAUNCH:
            with pytest.raises(Refused):
                expected(case, "/native", "a" * 64, Path("/source"), root)
            continue
        result = expected(case, "/native", "a" * 64, Path("/source"), root)
        assert result.argv == ("/native", "-c", body(case)) and result.cwd == "/source"
        assert dict(result.environment) == {
            **root,
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": case + " (call)",
        }
    case = next(iter(INFLIGHT))
    result = expected(
        case,
        "/native",
        "a" * 64,
        Path("/source"),
        root,
        base=Path("/owned/pytest/case"),
        terminal=True,
    )
    assert result.cwd == "/owned/pytest/case" and result.environment == ()


@pytest.mark.parametrize("case", NO_LAUNCH)
def test_numeric_cases_cannot_mint_a_child_intent(tmp_path, case):
    from test_source_integration import backend_request

    observer, actor, request = backend_request(tmp_path)
    observer.case = request["case"] = case
    with pytest.raises(Refused):
        proposal(observer, actor, request)
    assert observer.intents == {}


@pytest.mark.parametrize("case", tuple(STARTUP))
def test_preflight_only_command_never_matches_a_child_rule(case):
    from cleanup_inline import expected

    root = {"HOME": "/owned/home", "TMPDIR": "/owned/tmp", "PATH": "/usr/bin:/bin"}
    result = expected(case, "/native", "a" * 64, Path("/source"), root)
    assert result.argv != ("/native", "-c", "pass")
