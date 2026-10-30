"""Cohort source selection and closed launch operand regressions."""
from pathlib import Path

import pytest

from cohort_cases import CAMPAIGNS, CASES, EXTRA, GIT_ONLY, TEST
from content_manifest import Refused
from test_controlled_catalogue import CASES as CONTROLLED, STANDARD
from controlled_pairs import before_spawn
from git_policy import CUSTODY_PREFIX as PREFIX, custody_command as command


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
def test_pre_send_stops_allow_one_owned_startup_pair_but_no_second(boundary):
    case=TEST+'::test_stop_boundaries_preserve_consumption_and_no_new_sends['+boundary+']'
    assert before_spawn(case,'/owned/pytest/case/worker','backend',[],lambda row:True)
    with pytest.raises(Refused,match='pair bound'):
        before_spawn(case,'/owned/pytest/case/other/worker','backend',
            [{'cwd':'/owned/pytest/case/worker','role':'backend'}],lambda row:True)


def test_git_quota_remains_case_wide_without_intermediate_wait_ordering(monkeypatch):
    import git_policy as custody_git
    import git_policy as git_observer
    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    from types import SimpleNamespace
    case=TEST+'::test_actual_four_arm_timing_and_model_conformance[equal-True-True]'
    cwd='/owned/pytest/case/other'
    prior={'case':case,'role':'git-custody','repository':'/owned/pytest/case/first','consumed':True,'birth':1,'token':'prior'}
    host=SimpleNamespace(case=case,meta={'owned':'/owned'},intents={1:prior},root_only=lambda actor:None,
        ledger=SimpleNamespace(reaped=lambda *args:False),admit_launch=lambda *args,**kwargs:None,
        git=SimpleNamespace(custody_roots={},commands={}))
    monkeypatch.setattr(custody_git,'custody_repository',lambda *args,**kwargs:(((cwd,1,10,20000),),(1,20,20000)))
    selected=command(case,(*PREFIX,'rev-parse','HEAD'),cwd,Path('/owned'))
    assert custody_git.custody_launch(host,None,*selected,{'executable':'/usr/bin/git','argv':list(selected[0].argv),
        'cwd':selected[0].cwd,'stdin':None,'environment':custody_git.CUSTODY_ENVIRONMENT}) is None
    prior['repository']=cwd
    assert custody_git.custody_launch(host,None,*selected,{'executable':'/usr/bin/git','argv':list(selected[0].argv),
        'cwd':selected[0].cwd,'stdin':None,'environment':custody_git.CUSTODY_ENVIRONMENT}) is None
    prior['repository']='/owned/pytest/case/first'
    host.intents={i:prior for i in range(CASES[case][1])}
    with pytest.raises(Refused,match='command bound'):
        custody_git.custody_launch(host,None,*selected,{'executable':'/usr/bin/git','argv':list(selected[0].argv),
        'cwd':selected[0].cwd,'stdin':None,'environment':custody_git.CUSTODY_ENVIRONMENT})
