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
    def launch(actor,payload,*args,**kwargs):
        requests.append(payload)
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
    assert requests[0]['original']==model.expected.wire()
    assert requests[0]['script_sha256']==model.expected.payload_sha256


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
