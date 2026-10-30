"""The public projection admits only the original historical readonly queries."""
from pathlib import Path
import pytest
from content_manifest import Refused
from git_policy import HISTORY_BINDING as BINDING, HISTORY_V021 as V021, HISTORY_V045 as V045, HISTORY_CATALOG as CATALOG, HISTORY_CASES as CASES, history_commands as commands, history_proposal as proposal, HISTORY_CLI as CLI

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('case',CASES)
def test_exact_queries_are_readonly_and_bounded(case):
    rows=commands(ROOT,case)
    assert 1<=len(rows)<=128
    assert len(rows)==len(set(rows))
    assert {row[0] for row in rows}<={'ls-files','ls-tree','show','archive','merge-base','rev-parse','diff','status'}
    assert all(not any('\0' in part or '\n' in part for part in row) for row in rows)

def test_candidate_inventory_forms_and_historical_counts():
    assert commands(ROOT,BINDING+'::'+CATALOG[BINDING][0])==[
        ('ls-files','--stage','-z'),('ls-files','--others','--exclude-standard','-z')]
    assert len(commands(ROOT,BINDING+'::'+CATALOG[BINDING][3]))==5
    assert len(commands(ROOT,BINDING+'::'+CATALOG[BINDING][6]))==5
    assert len(commands(ROOT,V021+'::'+CATALOG[V021][1]))==2
    assert commands(ROOT,V045+'::'+CATALOG[V045][0])

def test_original_source_drift_refuses_before_any_query(tmp_path):
    target=tmp_path/BINDING
    target.parent.mkdir()
    target.write_text('raise RuntimeError("changed")')
    with pytest.raises(Refused,match='original source bytes'):
        commands(tmp_path,CASES[0])

@pytest.mark.parametrize('arguments', [('status',),('show','HEAD:USER'),('config','core.hooksPath','/tmp'),('archive','HEAD')])
def test_readonly_case_does_not_admit_other_git_commands(arguments):
    class Host:
        case=CASES[3]
        meta={'checkout':str(ROOT)}
        def root_only(self,actor):
            assert actor=='root'
    with pytest.raises(Refused,match='history exact readonly command'):
        proposal(Host(),'root',{'executable':'/usr/bin/git','stdin':None,'argv':['git',*arguments]})


def test_nested_cli_cannot_authorize_a_root_git_query():
    class Host:
        case=CLI
        meta={'checkout':str(ROOT)}
        binding={'entry':{'path':'/native/python'}}
    with pytest.raises(Refused,match='history original CLI parent'):
        proposal(Host(),{'role':'root'}, {'argv':['git','ls-files','--stage','-z']})


def test_canonical_git_resolution_does_not_change_the_requested_vector():
    from source_entry import direct_native
    args=(['git','ls-files','--stage','-z'],)
    assert direct_native(args,{},CLI,'fixed-inline')[1]=={'executable':'/usr/bin/git'}
    routed,options=direct_native(args,{},CASES[0],'fixed-inline')
    assert routed==args and options=={'executable':'/usr/bin/git'}
    assert direct_native(args,{},CLI,'session-child')==(args,{})
