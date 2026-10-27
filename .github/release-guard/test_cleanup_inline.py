"""Original inline catalogue parity, without starting any process."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from content_manifest import Refused
from cleanup_inline import CASES, STARTUP, CLIENT, INFLIGHT, NO_LAUNCH, SLEEP, EXIT, body, child_count, source_site, scheduling_site
from cleanup_launch import TEST


def test_inline_bodies_and_effect_lines_are_original_source():
    file = Path(__file__).resolve().parents[2] / TEST
    tree = ast.parse(file.read_bytes())
    calls = {node.lineno: node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for line in (53, 261, 291, 421):
        assert line in calls
    constants = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is str}
    assert SLEEP in constants and EXIT in constants
    assert len(CASES) == 21 and len(set(CASES)) == 21
    assert (len(STARTUP), len(CLIENT), len(INFLIGHT), len(NO_LAUNCH)) == (9, 3, 2, 7)


@pytest.mark.parametrize('case', CASES)
def test_inline_parameters_keep_original_effect_counts_and_source_sites(case):
    if case in NO_LAUNCH:
        assert child_count(case) == 0 and scheduling_site(case) is None
        with pytest.raises(Refused):
            body(case)
        with pytest.raises(Refused):
            source_site(case)
    else:
        assert body(case) == (EXIT if case in STARTUP and STARTUP[case][1] == 'exit' else SLEEP)
        assert child_count(case) == (1 if case in STARTUP or CLIENT.get(case, (None, None))[1] == 'reader' else 3)
        assert source_site(case) in (53, 261, 291, 421)
    if case in INFLIGHT:
        assert source_site(case, terminal=True) == 1034 and scheduling_site(case) == 470
    else:
        with pytest.raises(Refused):
            source_site(case, terminal=True)


@pytest.mark.parametrize('case', [True, '', 'tests/test_acp_cleanup.py::foreign', CASES[0] + '-foreign'])
def test_no_generic_inline_selection(case):
    with pytest.raises(Refused):
        body(case)


def test_inline_options_and_vectors_are_closed():
    from cleanup_inline import expected, options
    root = {'HOME': '/owned/home', 'TMPDIR': '/owned/tmp', 'PATH': '/usr/bin:/bin'}
    for case in CASES:
        if case in NO_LAUNCH:
            with pytest.raises(Refused):
                expected(case, '/native', 'a' * 64, Path('/source'), root)
            continue
        startup = case in STARTUP
        local = {'kwds': {}, 'stdin': None if startup else -1, 'stdout': -1,
                 'stderr': -1 if startup else None, 'limit': 65536}
        options(case, local)
        result, site = expected(case, '/native', 'a' * 64, Path('/source'), root)
        assert result.argv == ('/native', '-c', body(case)) and result.cwd == '/source'
        assert dict(result.environment) == {**root, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
        assert site == source_site(case)
        for changed in ({**local, 'limit': 8388608}, {**local, 'kwds': {'start_new_session': True}},
                        {**local, 'stdout': True}):
            with pytest.raises(Refused):
                options(case, changed)
    case = next(iter(INFLIGHT))
    terminal = {'kwds': {'cwd': '/owned/pytest/case', 'env': {}}, 'stdin': None,
                'stdout': -1, 'stderr': -2, 'limit': 8388608}
    options(case, terminal, terminal=True)
    result, site = expected(case, '/native', 'a' * 64, Path('/source'), root,
                            base=Path('/owned/pytest/case'), terminal=True)
    assert result.cwd == '/owned/pytest/case' and result.environment == () and site == 1034
    with pytest.raises(Refused):
        options(case, {**terminal, 'kwds': {'cwd': '/owned/pytest/case', 'env': {'FOREIGN': '1'}}}, terminal=True)


@pytest.mark.parametrize('case', NO_LAUNCH)
def test_numeric_cases_cannot_enter_a_child_profile_or_mint_an_intent(tmp_path, case):
    from source_profile import FIELDS, validate
    from test_source_integration import backend_request
    profile = dict.fromkeys(FIELDS)
    profile.update(schema='unrest.bootstrap-source.v1', role='cleanup-acp', case=case, cases=list(NO_LAUNCH))
    with pytest.raises(Refused, match='closed profile'):
        validate(profile, 'cpython.run_file', ('foreign.py',))
    observer, actor, request = backend_request(tmp_path)
    observer.case = request['case'] = case
    with pytest.raises(Refused, match='declared launch case'):
        observer.launch(actor, request)
    assert observer.intents == {}
