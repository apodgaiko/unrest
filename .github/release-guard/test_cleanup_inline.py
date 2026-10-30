"""Original inline catalogue parity, without starting any process."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from effect_proposals import proposal
from content_manifest import Refused
from inline_leaves import (
    DECLARATIONS,
    STARTUP,
    CLIENT,
    INFLIGHT,
    SLEEP,
    EXIT,
    body,
    child_count,
)
from cleanup_launch import TEST
from types import SimpleNamespace
from test_cleanup_scenario_oracle import inline_input as expected


NO_LAUNCH = tuple(TEST + f'::test_response_correlation_keeps_numeric_identity[{variant}]'
                  for variant in ('1_0', '1_1', 'None', 'True', '1.0', 'rid5', 'rid6'))
CASES = (*DECLARATIONS, *NO_LAUNCH)

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
        with pytest.raises(Refused):
            child_count(case)
        with pytest.raises(Refused):
            body(case)
    else:
        assert body(case) == (EXIT if case in STARTUP and STARTUP[case][1] == "exit" else SLEEP)
        assert child_count(case) == (
            1 if case in STARTUP or CLIENT.get(case, (None, None))[1] == "reader" else 3
        )
    if case not in INFLIGHT:
        value=expected(case,'/native','a'*64,Path('/source'),{},base=Path('/owned/pytest/case'),terminal=True)
        with pytest.raises(Refused):
            invoke(value,{},prior=2)



@pytest.mark.parametrize(
    "case", [True, "", "tests/test_acp_cleanup.py::foreign", CASES[0] + "-foreign"]
)
def test_no_generic_inline_selection(case):
    with pytest.raises(Refused):
        body(case)


def invoke(value,ambient,*,prior=0):
    from inline_leaves import proposal as leaf
    host=SimpleNamespace(case=value.case,meta={'checkout':'/source','owned':'/owned'},
        binding={'entry':{'path':'/native','sha256':'a'*64}},seen=[],
        root_only=lambda actor:None,meta_environment=lambda:ambient,
        intents={index:{'case':value.case,'consumed':True} for index in range(prior)},
        executed=lambda row:row['consumed'])
    def admit(actor,expected,role,vector,pin,**options):
        host.seen.append((expected,role,pin,options))
        return {'ticket':prior+1,'token':'bound'}
    host.admit_launch=admit
    raw={'case':value.case,'executable':value.executable,'argv':list(value.argv),
        'environment':dict(value.environment),'cwd':value.cwd,'stdin':None}
    leaf(host,{'role':'root'},raw)
    assert len(host.seen)==1
    return host.seen[0]


def test_inline_options_and_vectors_are_closed(monkeypatch):
    root={'HOME':'/owned/home','TMPDIR':'/owned/tmp','PATH':'/usr/bin:/bin'}
    for case in CASES:
        value=expected(case,'/native','a'*64,Path('/source'),root)
        if case in NO_LAUNCH:
            with pytest.raises(Refused):
                invoke(value,root)
            continue
        result,role,pin,options=invoke(value,root)
        assert result==value and role=='cleanup-inline' and pin==value.payload_sha256
        assert result.argv==('/native','-c',body(case)) and result.cwd=='/source'
        assert dict(result.environment)=={**root,'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
        assert options['maximum']==child_count(case)
    import inline_leaves
    observed=[]
    def owned(path,root):
        observed.append((path,root))
        return Path(path)
    monkeypatch.setattr(inline_leaves,'base_path',owned)
    case=next(iter(INFLIGHT))
    value=expected(case,'/native','a'*64,Path('/source'),root,base=Path('/owned/pytest/case'),terminal=True)
    result,role,_,_=invoke(value,root,prior=2)
    assert result.cwd=='/owned/pytest/case' and result.environment==() and role=='cleanup-inline'
    assert observed==[('/owned/pytest/case',Path('/owned'))]


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

    root = {"HOME": "/owned/home", "TMPDIR": "/owned/tmp", "PATH": "/usr/bin:/bin"}
    result = expected(case, "/native", "a" * 64, Path("/source"), root)
    assert result.argv != ("/native", "-c", "pass")
