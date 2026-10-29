"""Readiness grants one exact local probe and never application payload."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import readiness_launch as readiness

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('case',readiness.CASES)
@pytest.mark.parametrize('mutation',[None,'body','env','cwd','descendant'])
def test_exact_original_readiness_program_and_operands(case,mutation):
    unit=source_unit(ROOT,readiness.TEST,readiness.PIN,(readiness.NAME,'exercise'))
    bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='body' for target in node.targets)]
    body=bodies[0 if case==readiness.READY else 1 if case==readiness.CASES[0] else 2]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},intents={})
    def root_only(actor):
        if actor['role']!='root':
            raise Refused('root only')
    host.root_only=root_only
    host.meta_environment=lambda:{'PATH':'/bin'}
    admitted=[]
    host.admit_launch=lambda *args,**kwargs:admitted.append(args) or {'ticket':1,'token':'bound'}
    raw={'case':case,'executable':'/native','argv':['/native','-c',body],
         'environment':{'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'},
         'cwd':str(ROOT),'stdin':None}
    if mutation=='body':
        raw['argv'][2]='print("different")'
    elif mutation=='env':
        raw['environment']['EXTRA']='not original'
    elif mutation=='cwd':
        raw['cwd']='/foreign'
    actor={'role':'child' if mutation=='descendant' else 'root'}
    if mutation is None:
        assert readiness.proposal(host,actor,raw)['translated']==['/native','-I','-S','-c',body]
        assert len(admitted)==1
    else:
        with pytest.raises(Refused):
            readiness.proposal(host,actor,raw)
        assert not admitted


@pytest.mark.parametrize('mutation',[None,'port','retained','unready','repeat','fresh'])
def test_probe_requires_actual_listener_and_cannot_grant_payload(monkeypatch,mutation):
    server={'birth':'server-birth','token':'server-token','role':'fixed-inline','case':readiness.READY}
    listener=SimpleNamespace(owner=SimpleNamespace(pid=2),fd=7,local=('127.0.0.1',12345))
    host=SimpleNamespace(case=readiness.READY,readiness_attempts={},actors={2:server},
        listeners={(readiness.READY,'readiness'):{'socket':listener}},
        intents={1:{**server,'consumed':mutation!='retained'}},
        ledger=SimpleNamespace(body_ready=lambda *args:mutation!='unready'),root_only=lambda actor:None)
    fresh=SimpleNamespace(state=7,local=('0.0.0.0',0),remote=None)
    monkeypatch.setattr(readiness,'acquire_tcp',lambda birth,fd:None if mutation=='fresh' else fresh if birth=='client' else listener)
    if mutation=='repeat':
        host.readiness_attempts[host.case]={}
    if mutation is None:
        assert readiness.connect(host,{'birth':'client','token':'root'},{'fd':4},12345)=={'ok':True,'probe':True,'readiness_only':True}
        record=host.readiness_attempts[host.case]
        assert record['payload_authority'] is False and record['accepted_peer_proven'] is False
    else:
        with pytest.raises(Refused):
            readiness.connect(host,{'birth':'client','token':'root'},{'fd':4},12346 if mutation=='port' else 12345)


@pytest.mark.parametrize('status,signals,expected',[(0,(),True),(-15,(15,),True),(-15,(),False),(23,(),False)])
def test_real_child_terminal_status_and_authorized_cleanup_required(status,signals,expected):
    actor={'case':readiness.READY,'body_ready':True,'signals':signals}
    assert readiness.completed(actor,(1,0,status)) is expected
    assert not readiness.completed(actor,None)
    assert not readiness.completed({**actor,'body_ready':False},(1,0,status))
