"""Additional controlled fixture owners do not inherit unrelated capabilities."""
from pathlib import Path

import pytest

from content_manifest import Refused
import controlled_cases as live
import controlled_owners as owners
from controlled_pairs import before_spawn,limits
from controlled_startup import expected_entry


def test_original_session_and_retained_partition_preserves_native_and_no_child_negatives():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=[item.nodeid for item in session.items]
    collected=Collected()
    assert pytest.main(['--collect-only','-q',owners.SESSION,owners.RETAINED],plugins=[collected])==0
    assert len(collected.nodes)==86
    session=[case for case in collected.nodes if case.startswith(owners.SESSION+'::') and owners.selection(case) is not None]
    retained=[case for case in collected.nodes if case.startswith(owners.RETAINED+'::') and owners.selection(case) is not None]
    assert len(session)==49 and len(retained)==10
    assert sum(owners.selection(case).backend_only for case in session)==4
    assert all(not live.custody(case) for case in session+retained)
    excluded=('test_runtime_pin_rechecked_before_launch','test_genuine_adapter_beside_substituted_node_rejected',
        'test_ambient_env_not_imported_and_launcher_pin','test_fixture_substitution_is_rejected_before_root_creation')
    assert all(not live.eligible(owners.SESSION+'::'+name) for name in excluded)
    assert not live.eligible(owners.RETAINED+'::test_retained_expected_never_resnapshots[before-first]')


@pytest.mark.parametrize('case',owners.RESOURCE_NEGATIVES)
def test_resource_refusals_receive_git_setup_without_transport_authority(case):
    assert live.custody(case) and not live.eligible(case)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/case/worker','backend',[],{})


@pytest.mark.parametrize('node',owners.BACKEND_ONLY)
def test_registration_refusals_never_gain_acp_authority(node):
    case=owners.SESSION+'::'+node
    before_spawn(case,'/owned/pytest/case/worker','backend',[],{})
    rows=[{'role':'backend','cwd':'/owned/pytest/case/worker','consumed':True}]
    with pytest.raises(Refused,match='no ACP launch'):
        before_spawn(case,'/owned/pytest/case/worker','acp',rows,lambda row:True)


@pytest.mark.parametrize('case',(*owners.PRIORITIES,*owners.TTLS,*owners.DRIFTS,*owners.DRAINS,owners.STARTUP))
def test_additional_finite_transport_owners_keep_bound_and_separate_git_rights(case):
    selected=owners.selection(case)
    assert live.eligible(case) and 1<=limits(case)==selected.pairs<=20
    assert live.custody(case)==(case in owners.GIT_CASES)
    records=[{'cwd':f'/owned/pytest/root{index}/worker','role':'backend'} for index in range(selected.pairs)]
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/extra/worker','backend',records,{})


@pytest.mark.parametrize('case',[owners.SESSION+'::test_installed_adapter_two_prompts_and_http_completion',
    owners.RETAINED+'::test_retained_correction_rotation_then_one_shot',owners.STARTUP])
def test_new_owners_keep_standard_image_and_exact_original_configuration(tmp_path,monkeypatch,case):
    root=Path(__file__).resolve().parents[2]
    home=tmp_path/'probe/owner/worker'
    selected=owners.selection(case)
    monkeypatch.setattr(live,'read_regular',lambda *args,**kwargs:(None,None,live.STANDARD[0]))
    assert live.acquire_backend(case,home)==live.STANDARD[0]
    value,_,_=expected_entry(case,root,home,'/native','a'*64,backend=True,variant=selected.variant,backend_pin=live.STANDARD[0])
    raw={'argv':list(value.argv),'environment':dict(value.environment),'cwd':value.cwd}
    assert live.select_entry(case,root,home,'/native','a'*64,raw,backend=True,relay=None,records=[])[1]==selected.variant
    other,_,_=expected_entry(case,root,home,'/native','a'*64,backend=True,variant=(selected.variant+1)%4,backend_pin=live.STANDARD[0])
    with pytest.raises(Refused,match='original launch operands'):
        live.select_entry(case,root,home,'/native','a'*64,{'argv':list(other.argv),'environment':dict(other.environment),'cwd':other.cwd},backend=True,relay=None,records=[])
    monkeypatch.setattr(live,'read_regular',lambda *args,**kwargs:(None,None,next(pin for pin in live.BACKENDS if pin!=live.STANDARD[0])))
    with pytest.raises(Refused,match='unknown controlled backend'):
        live.acquire_backend(case,home)
