"""Finite proposal operands remain enforced after Python provenance retirement."""
from copy import deepcopy
from types import SimpleNamespace
import os

import pytest

from content_manifest import Refused
import plan_launch
from plan_launch import PYTHON,expected
from effect_proposals import proposal


@pytest.fixture
def prepared(tmp_path,monkeypatch):
    monkeypatch.setattr(plan_launch,'OWNER',os.getuid())
    cwd=tmp_path/'pytest/case'
    cwd.mkdir(parents=True)
    native=tmp_path/'python'
    native.write_bytes(b'synthetic native image')
    (cwd/'adapter').symlink_to(native)
    model=expected(PYTHON,str(cwd),tmp_path,str(native),'a'*64)
    requests=[]
    def launch(actor,declaration,*args,**kwargs):
        requests.append((declaration,args))
        host.intents={1:{}}
        return {'ok':True,'ticket':1,'token':'token'}
    host=SimpleNamespace(case=PYTHON,meta={'checkout':str(tmp_path/'source'),'owned':str(tmp_path)},
        binding={'entry':{'path':str(native),'sha256':'a'*64}},launch_owner=lambda actor:None,
        meta_environment=lambda:{'HOME':'/home','TMPDIR':'/tmp','PATH':'/usr/bin:/bin'},admit_launch=launch,root_only=lambda actor:None)
    raw={'case':PYTHON,'executable':'adapter','argv':list(model.expected.argv),'cwd':str(cwd),
         'environment':dict(model.expected.environment),'stdin':None}
    return host,raw,requests,model


def test_finite_exact_proposal_retains_guarded_vector_and_script_hash(prepared):
    host,raw,requests,model=prepared
    answer=proposal(host,{},raw)
    assert answer['translated']==list(model.vector)
    assert requests[0][0]==model.expected
    assert requests[0][1][-1]==model.expected.payload_sha256


@pytest.mark.parametrize('field,value',[('case','foreign'),('executable','foreign'),('argv',['foreign']),
    ('environment',{'PATH':'/foreign'}),('environment',{'PATH':'/usr/bin:/bin','PRIVATE':'foreign'}),
    ('cwd','/foreign')])
def test_changed_operands_never_reach_launch_admission(prepared,field,value):
    host,raw,requests,_=prepared
    changed=deepcopy(raw)
    changed[field]=value
    with pytest.raises((Refused,FileNotFoundError)):
        proposal(host,{},changed)
    assert not requests


def test_unknown_case_has_no_generic_python_route(prepared):
    host,raw,requests,_=prepared
    host.case=raw['case']='tests/foreign.py::test_unknown'
    with pytest.raises(Refused,match='no declaration'):
        proposal(host,{},raw)
    assert not requests


@pytest.mark.parametrize('role,family',(('approval-adapter','approval'),('approval-relay','approval'),
    ('archive-checker','archive'),('desktop','desktop'),('session-adapter','session'),('mcp','mcp')))
@pytest.mark.parametrize('mutation',(None,'case','finished','not-ready'))
def test_shared_owner_frontier_preserves_role_specific_readiness(role,family,mutation):
    import source_observer as observer
    case={'approval':observer.approval_launch.CASES[0],'archive':observer.package_cases.POSITIVE,
        'desktop':observer.desktop_launch.CASE,'session':observer.SESSION_TIMEOUT,'mcp':'local-case'}[family]
    host=SimpleNamespace(case=case,finished=mutation=='finished')
    actor={'role':role,'case':'foreign' if mutation=='case' else case,'body_ready':mutation!='not-ready'}
    refused=mutation in ('case','finished') or mutation=='not-ready' and family in ('approval','archive')
    if refused:
        with pytest.raises(Refused):
            observer.Observer.launch_owner(host,actor)
    else:
        observer.Observer.launch_owner(host,actor)


def test_fixed_owner_routing_keeps_composed_before_overlapping_role_family(monkeypatch):
    import source_observer as observer
    import composed_runtime
    from composed_cases import HERMETIC
    seen=[]
    monkeypatch.setattr(composed_runtime,'owner',lambda host,actor:seen.append('composed'))
    monkeypatch.setattr(observer,'actor_slot',lambda host,actor:pytest.fail('overlapping fallback'))
    host=SimpleNamespace(case=HERMETIC,finished=False)
    observer.Observer.launch_owner(host,{'role':'fixed-inline','case':HERMETIC})
    assert seen==['composed']
