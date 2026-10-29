"""Cohort source selection and closed launch operand regressions."""
from pathlib import Path

import pytest

from cohort_cases import CAMPAIGNS, CASES, EXTRA, GIT_ONLY, TEST
from content_manifest import Refused
from controlled_cases import CASES as CONTROLLED, STANDARD
from controlled_pairs import before_spawn
from custody_git import PREFIX, command


def test_cohort_declarations_match_original_collected_cases(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collector:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q','-o','addopts=','-p','pytest_asyncio.plugin','-p','pytest_mock',TEST],plugins=[Collector()])==0
    assert len(nodes)==77 and len(CAMPAIGNS)==35 and len(GIT_ONLY)==24
    assert set(CASES)<=set(nodes) and len(set(nodes)-set(CASES))==18
    assert all(CONTROLLED[case]==STANDARD for case in CAMPAIGNS)
    assert all(case not in CONTROLLED for case in GIT_ONLY)


@pytest.mark.parametrize('case,args',[(case,args) for case,rows in EXTRA.items() for args in rows])
def test_exceptional_git_literals_do_not_spread_to_other_cases(case,args):
    assert command(case,(*PREFIX,*args),'/owned/pytest/case/candidate',Path('/owned'))[0].argv==(*PREFIX,*args)
    other=TEST+'::test_actual_target_verdict_required[None]'
    with pytest.raises(Refused):
        command(other,(*PREFIX,*args),'/owned/pytest/case/candidate',Path('/owned'))


@pytest.mark.parametrize('boundary',['reservation','dispatch'])
def test_pre_send_stops_cannot_launch_a_backend(boundary):
    case=TEST+'::test_stop_boundaries_preserve_consumption_and_no_new_sends['+boundary+']'
    with pytest.raises(Refused,match='pair bound'):
        before_spawn(case,'/owned/pytest/case/worker','backend',[],lambda row:True)


def test_git_sequencing_is_per_repository_but_quota_remains_case_wide(monkeypatch):
    import custody_git
    from types import SimpleNamespace
    case=TEST+'::test_actual_four_arm_timing_and_model_conformance[equal-True-True]'
    cwd='/owned/pytest/case/other'
    prior={'case':case,'role':'git-custody','repository':'/owned/pytest/case/first','consumed':True,'birth':1,'token':'prior'}
    host=SimpleNamespace(case=case,meta={'owned':'/owned'},intents={1:prior},root_only=lambda actor:None,
        ledger=SimpleNamespace(reaped=lambda *args:False),admit_launch=lambda *args,**kwargs:None,
        git=SimpleNamespace(custody_roots={},commands={}))
    monkeypatch.setattr(custody_git,'repository',lambda *args,**kwargs:(((cwd,1,10,20000),),(1,20,20000)))
    selected=command(case,(*PREFIX,'rev-parse','HEAD'),cwd,Path('/owned'))
    assert custody_git.launch(host,None,*selected,None) is None
    prior['repository']=cwd
    with pytest.raises(Refused,match='actual wait'):
        custody_git.launch(host,None,*selected,None)
    prior['repository']='/owned/pytest/case/first'
    host.intents={i:prior for i in range(CASES[case][1])}
    with pytest.raises(Refused,match='command bound'):
        custody_git.launch(host,None,*selected,None)
