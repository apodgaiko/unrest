"""Follower adoption preserves original parent facts and requires actual waits."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from approval_launch import CRASH
from content_manifest import Refused
from process_ledger import Birth,Ledger,canonical
from test_process_ledger import PINS,identity,emit,terminal,wait4


def ready_follower():
    ledger=Ledger('nonce')
    root_identity,worker_identity=identity(100,99),identity(101,100)
    root,worker=Birth.read(root_identity),Birth.read(worker_identity)
    emit(ledger,'kernel_root',identity=root_identity)
    ledger.register(root,'root-token',PINS,case=CRASH[0],command_class='root')
    emit(ledger,'kernel_child',parent=root.pid,child=worker.pid,event=1,identity=worker_identity)
    emit(ledger,'kernel_exec',pid=worker.pid)
    ledger.register(worker,'child-token',PINS,case=CRASH[0],command_class='fixed-inline',new_session=True)
    process=ledger.process(worker)
    ledger.session(worker,{**process.identity,'pgid':worker.pid,'sid':worker.pid})
    ledger.ready(worker,'body-ready',{})
    observed={**identity(102,worker.pid),'pgid':worker.pid,'sid':worker.pid}
    birth=Birth.read(observed)
    emit(ledger,'kernel_child',parent=worker.pid,child=birth.pid,event=1,identity=observed)
    emit(ledger,'kernel_exec',pid=birth.pid)
    ledger.register(birth,'follower',(),case=CRASH[0],command_class='worker-mcp')
    ledger.ready(birth,'body-ready',{})
    emit(ledger,'kernel_exit',pid=worker.pid,raw=9)
    return ledger,root,worker,birth,{**observed,'ppid':1}


@pytest.mark.parametrize('mutation',[None,'parent-alive','parent-status','case','parent','pgid','sid','ppid','ticks','not-ready','epoch','repeat'])
def test_follower_has_no_session_leader_or_historical_wait_waiver(mutation):
    ledger,root,worker,child,observed=ready_follower()
    before=deepcopy(ledger.process(child))
    if mutation=='parent-alive':
        ledger.process(worker).exit=None
    elif mutation=='parent-status':
        ledger.process(worker).exit=(1,0)
    elif mutation=='case':
        ledger.process(child).case='foreign'
    elif mutation=='parent':
        worker=root
    elif mutation in ('pgid','sid','ppid'):
        observed[mutation]+=1
    elif mutation=='ticks':
        observed['start_ticks']+=1
    elif mutation=='not-ready':
        ledger.process(child).stage='registered'
    elif mutation=='epoch':
        ledger.process(child).generation+=1
    elif mutation=='repeat':
        ledger.adopt(child,observed,follower=worker)
    if mutation:
        with pytest.raises(Refused):
            ledger.adopt(child,observed,follower=worker)
    else:
        ledger.adopt(child,observed,follower=worker)
        current=ledger.process(child)
        assert not current.new_session and current.parent==worker and current.birth==before.birth
        assert current.identity==before.identity and current.parent_wait is None and current.init_wait is None
        assert ledger.peer_birth(child)==Birth.read(observed)
        assert current.adopted_identity==canonical(observed)


def test_follower_numeric_init_join_does_not_invent_original_parent_reap():
    ledger,root,worker,child,observed=ready_follower()
    ledger.adopt(child,observed,follower=worker)
    emit(ledger,'tracer_terminal_wait',pid=worker.pid,raw=9,normalized=-9,identity=ledger.process(worker).identity)
    wait4(ledger,root,worker,9)
    assert ledger.reaped(worker,'child-token')
    terminal(ledger,child,1<<8)
    ledger.retire_adopted(child,1<<8)
    assert ledger.process(child).init_wait==1<<8 and ledger.process(child).parent_wait is None
    assert not ledger.reaped(child,'follower')


def test_case_start_has_no_follower_rights_before_a_bound_worker_exists():
    from approval_adoption import followers,refresh
    root={'case':CRASH[0],'role':'root','birth':object(),'token':'root','intent':None}
    host=SimpleNamespace(case=CRASH[0],actors={1:root},intents={})
    assert followers(host)==(None,[])
    refresh(host)
    row={'ticket':1,'case':CRASH[0],'role':'fixed-inline','birth':object(),'token':'worker','consumed':True,'approval_worker':True}
    forged={key:row[key] for key in ('case','role','birth','token')}
    forged['intent']=dict(row)
    host.intents[1]=row
    host.actors[2]=forged
    assert followers(host)==(None,[])
