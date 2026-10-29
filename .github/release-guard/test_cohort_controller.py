"""Exact crash waiver controls; synthetic receipts never certify kernel waits."""
from types import SimpleNamespace
import json
import os
import time

import pytest

import cohort_controller as crash
from content_manifest import Refused
from process_ledger import Birth, canonical
from test_process_ledger import identity


def scenario(tmp_path,case):
    processes={}
    children=[]
    for pid,role in [(101,'fixed-inline'),*( (i,'git-custody') for i in range(102,106))]:
        birth=Birth.read(identity(pid,100 if pid==101 else 101))
        children.append({'birth':birth,'role':role,'case':case,'token':str(pid),'body_ready':True})
        processes[birth]=SimpleNamespace(parent=Birth.read(identity(101,100)),identity=identity(pid,101),terminal=(1,73<<8,73) if pid==101 else (1,0,0))
    if case!=crash.CASES[0]:
        for pid,role in [(106,'backend'),(107,'acp')]:
            birth=Birth.read(identity(pid,101))
            children.append({'birth':birth,'role':role,'case':case,'token':str(pid),'body_ready':True})
            processes[birth]=SimpleNamespace(parent=children[0]['birth'],identity=identity(pid,101),terminal=(1,0,0))
    children[0]['token']='a'*32
    row={'case':case,'role':'fixed-inline','cohort_controller':True,'birth':children[0]['birth'],
         'token':children[0]['token'],'closeout_started':time.monotonic()}
    host=SimpleNamespace(case=case,intents={1:row},directory=tmp_path,executed=lambda value:True,
        ledger=SimpleNamespace(process=lambda birth:processes[birth],reaped=lambda birth,token:birth.pid<106),
        git=SimpleNamespace(reaped=lambda actor:actor['birth'].pid<106),completed_child=lambda actor:True,
        cohort_observations=[])
    return host,children,processes


def test_reservation_retains_every_ordinary_wait_without_a_waiver(tmp_path):
    host,children,_=scenario(tmp_path,crash.CASES[0])
    assert crash.closeout(host,children)==set()
    assert not list(tmp_path.iterdir()) and not host.cohort_observations


@pytest.mark.parametrize('case',crash.WAIVED)
def test_approved_pair_receipt_stays_separate_from_original_parent_waits(tmp_path,monkeypatch,case):
    host,children,processes=scenario(tmp_path,case)
    assert crash.closeout(host,children) is None
    request=next(tmp_path.glob('*.json'))
    value=json.loads(request.read_bytes())
    crash.publish(request.with_suffix('.receipt'),{'case':case,'waits':[{**child,'raw':0} for child in value['children']]})
    original=crash.read_regular
    monkeypatch.setattr(crash,'read_regular',lambda path,*args,**kwargs:original(path,*args,**{**kwargs,'uid':os.getuid()}))
    assert crash.closeout(host,children)=={actor['birth'] for actor in children[-2:]}
    assert not any(host.ledger.reaped(actor['birth'],actor['token']) for actor in children[-2:])
    assert host.cohort_observations[-1]['original_parent_wait_proven'] is False
    assert host.cohort_observations[-1]['child_numeric_status_and_final_timing']=='UNVERIFIED'


@pytest.mark.parametrize('mutation',['controller-status','controller-wait','git-wait','extra-child','missing-ready','deadline','missing-epoch'])
def test_crash_exception_cannot_discharge_other_cleanup(tmp_path,mutation):
    host,children,processes=scenario(tmp_path,crash.WAIVED[0])
    if mutation=='controller-status':
        processes[children[0]['birth']].terminal=(1,0,0)
    elif mutation=='controller-wait':
        host.ledger.reaped=lambda *args:False
    elif mutation=='git-wait':
        host.git.reaped=lambda actor:False
    elif mutation=='extra-child':
        children.append(dict(children[-1]))
    elif mutation=='missing-ready':
        children[-1]['body_ready']=False
    elif mutation=='deadline':
        host.intents[1]['closeout_started']-=21
    else:
        host.intents[1].pop('closeout_started')
    with pytest.raises(Refused):
        crash.closeout(host,children)


def test_root_receipt_must_match_traced_terminal_status(tmp_path,monkeypatch):
    host,children,_=scenario(tmp_path,crash.WAIVED[0])
    assert crash.closeout(host,children) is None
    request=next(tmp_path.glob('*.json'))
    value=json.loads(request.read_bytes())
    crash.publish(request.with_suffix('.receipt'),{'case':host.case,'waits':[{**child,'raw':15} for child in value['children']]})
    original=crash.read_regular
    monkeypatch.setattr(crash,'read_regular',lambda path,*args,**kwargs:original(path,*args,**{**kwargs,'uid':os.getuid()}))
    with pytest.raises(Refused,match='terminal join'):
        crash.closeout(host,children)


def test_host_receipt_checks_adopted_parent_before_any_wait(tmp_path,monkeypatch):
    case=crash.WAIVED[0]
    request=tmp_path/('cohort-closeout-'+'a'*32+'.json')
    child={'identity':canonical(identity(106,101)),'token':'b'*32}
    crash.publish(request,{'case':case,'started':time.monotonic(),'children':[child,child]})
    original=crash.read_regular
    monkeypatch.setattr(crash,'read_regular',lambda path,*args,**kwargs:original(path,*args,**{**kwargs,'uid':os.getuid()}))
    monkeypatch.setattr(crash,'credential_identity',lambda pid:identity(pid,999))
    monkeypatch.setattr(crash.os,'waitpid',lambda *args:pytest.fail('foreign child cannot be waited'))
    with pytest.raises(Refused,match='adopted process identity'):
        crash.host_tick(tmp_path,{})


def test_crash_root_cannot_construct_controller_transport_children(tmp_path):
    host,children,_=scenario(tmp_path,crash.WAIVED[0])
    host.root_only=lambda actor:pytest.fail('crash children require actual controller')
    with pytest.raises(Refused,match='controller owner'):
        crash.parent(host,{'role':'root','case':host.case,'birth':children[0]['birth'],'token':'root'})


def test_atomic_publication_exposes_only_a_complete_single_link_file(tmp_path):
    target=tmp_path/'record.json'
    crash.publish(target,{'complete':True})
    assert target.stat().st_nlink==1 and target.stat().st_mode & 0o777==0o444
    assert json.loads(target.read_bytes())=={'complete':True}
    assert not list(tmp_path.glob('*.tmp'))
    with pytest.raises(Refused,match='duplicate closeout'):
        crash.publish(target,{'complete':False})
    assert json.loads(target.read_bytes())=={'complete':True}
