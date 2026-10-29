"""Adoption is a separate fact, never a rewritten parent or synthetic wait."""
from copy import deepcopy
from types import SimpleNamespace
import json
import os

import pytest

import composed_adoption as adoption
from composed_cases import PARITY
from content_manifest import Refused
from process_ledger import Birth,canonical
from test_process_ledger import setup,emit,terminal


def ready():
    ledger,parent,child=setup(new_session=True)
    observed={**ledger.process(child).identity,'pgid':child.pid,'sid':child.pid}
    ledger.session(child,observed)
    ledger.ready(child,'body-ready',{})
    emit(ledger,'kernel_exit',pid=parent.pid,raw=0)
    return ledger,parent,child,{**observed,'ppid':1}


@pytest.mark.parametrize('mutation',(None,'parent-alive','not-ready','uid','ticks','pgid','sid','ppid','repeat'))
def test_adoption_requires_live_exact_session_and_observed_parent_exit(mutation):
    ledger,parent,child,observed=ready()
    original=deepcopy(ledger.process(child))
    if mutation=='parent-alive':
        ledger.process(parent).exit=None
    elif mutation=='not-ready':
        ledger.process(child).stage='registered'
    elif mutation in ('pgid','sid','ppid'):
        observed[mutation]+=1
    elif mutation=='uid':
        observed['uids']=[0]*4
    elif mutation=='ticks':
        observed['start_ticks']+=1
    elif mutation=='repeat':
        ledger.adopt(child,observed)
    if mutation is not None:
        with pytest.raises(Refused):
            ledger.adopt(child,observed)
        return
    ledger.adopt(child,observed)
    assert ledger.peer_birth(child)==Birth.read(observed)
    current=ledger.process(child)
    assert (current.birth,current.parent,current.identity,current.parent_wait)==(original.birth,original.parent,original.identity,None)
    assert not ledger.reaped(child,'child-token')


@pytest.mark.parametrize('mutation',(None,'unadopted','no-exit','no-tracer','status','repeat'))
def test_namespace_wait_requires_its_independent_terminal_join(mutation):
    ledger,parent,child,observed=ready()
    if mutation!='unadopted':
        ledger.adopt(child,observed)
    terminal(ledger,child,15)
    if mutation=='no-exit':
        ledger.process(child).exit=None
    elif mutation=='no-tracer':
        ledger.process(child).terminal=None
    elif mutation=='repeat':
        ledger.retire_adopted(child,15)
    if mutation is not None:
        with pytest.raises(Refused):
            ledger.retire_adopted(child,0 if mutation=='status' else 15)
        return
    ledger.retire_adopted(child,15)
    assert ledger.process(child).init_wait==15
    assert ledger.process(child).parent_wait is None
    assert not ledger.reaped(child,'child-token')


def test_new_thread_after_adoption_keeps_ownership_and_current_kernel_parent():
    ledger,parent,child,observed=ready()
    ledger.adopt(child,observed)
    thread={**observed,'pid':102,'tgid':child.pid,'start_ticks':10200}
    emit(ledger,'kernel_child',parent=child.pid,child=102,event=3,identity=thread)
    assert ledger.process(Birth.read(thread)).parent==child
    assert ledger.process(child).parent==parent


@pytest.mark.parametrize('mutation',(None,'foreign-pid','uid','parent','status','expired'))
def test_pid1_wait_is_actual_exact_child_and_bounded(tmp_path,monkeypatch,mutation):
    ledger,_,child,observed=ready()
    value={'case':PARITY[0],'started':10.0,'identity':canonical(observed),'token':'a'*32}
    path=tmp_path/('composed-closeout-'+value['token']+'.json')
    adoption.publish(path,value)
    monkeypatch.setattr(adoption.os,'getpid',lambda:1)
    monkeypatch.setattr(adoption.os,'readlink',lambda path:'pid:[123]')
    monkeypatch.setattr(adoption.time,'monotonic',lambda:31.0 if mutation=='expired' else 11.0)
    read=adoption.read_regular
    monkeypatch.setattr(adoption,'read_regular',lambda file,*args,**kwargs:read(file,*args,**{**kwargs,'uid':os.getuid()}))
    actual=dict(observed)
    if mutation=='uid':
        actual['uids']=[0]*4
    elif mutation=='parent':
        actual['ppid']=2
    monkeypatch.setattr(adoption,'credential_identity',lambda pid:actual)
    seen=[]
    def wait(pid,options):
        seen.append((pid,options))
        return (pid+1 if mutation=='foreign-pid' else pid,0 if mutation=='status' else 15)
    monkeypatch.setattr(adoption.os,'waitpid',wait)
    if mutation in ('foreign-pid','uid','parent','expired'):
        with pytest.raises(Refused):
            adoption.host_tick(tmp_path)
        assert not path.with_suffix('.receipt').exists()
        return
    adoption.host_tick(tmp_path)
    assert seen==[(child.pid,os.WNOHANG)]
    receipt=json.loads(path.with_suffix('.receipt').read_text())
    assert receipt=={**value,'raw':0 if mutation=='status' else 15,'init_pid':1,'namespace':'pid:[123]','waited':11.0}
    assert ledger.process(child).init_wait is None


def test_no_adoption_work_is_inferred_for_unrelated_case():
    adoption.refresh(SimpleNamespace(case='foreign'))
    assert adoption.closeout(SimpleNamespace(case='foreign'),[]) is True


@pytest.mark.parametrize('mutation',(None,'status','namespace','token','deadline','late-finish'))
def test_passive_wait_precedes_case_finish_and_receipt_never_rewrites_parent_wait(tmp_path,monkeypatch,mutation):
    ledger,_,child,observed=ready()
    ledger.adopt(child,observed)
    row={'case':PARITY[0],'adoptable':True,'composed_worker':0}
    actor={'birth':child,'intent':row,'body_ready':True,'token':'a'*32}
    host=SimpleNamespace(case=PARITY[0],actors={child.pid:actor},ledger=ledger,executed=lambda row:True,
        meta={'pid_namespace':'pid:[123]'},directory=tmp_path,adoptions=[])
    read=adoption.read_regular
    monkeypatch.setattr(adoption,'read_regular',lambda file,*args,**kwargs:read(file,*args,**{**kwargs,'uid':os.getuid()}))
    monkeypatch.setattr(adoption.time,'monotonic',lambda:10.0)
    adoption.refresh(host)
    assert list(tmp_path.iterdir())==[]
    terminal(ledger,child,15)
    adoption.refresh(host)
    path=next(tmp_path.glob('*.json'))
    request=json.loads(path.read_text())
    assert request['started']==10.0
    assert adoption.closeout(host,[actor]) is False
    receipt={**request,'raw':0 if mutation=='status' else 15,'init_pid':1,'namespace':'pid:[123]','waited':11.0}
    monkeypatch.setattr(adoption.time,'monotonic',lambda:11.0)
    if mutation=='namespace':
        receipt['namespace']='foreign'
    elif mutation=='token':
        receipt['token']='b'*32
    elif mutation=='deadline':
        monkeypatch.setattr(adoption.time,'monotonic',lambda:30.001)
        receipt['waited']=30.001
    elif mutation=='late-finish':
        monkeypatch.setattr(adoption.time,'monotonic',lambda:100.0)
    adoption.publish(path.with_suffix('.receipt'),receipt)
    if mutation not in (None,'late-finish'):
        with pytest.raises(Refused):
            adoption.closeout(host,[actor])
        assert host.adoptions==[] and ledger.process(child).init_wait is None
        return
    assert adoption.closeout(host,[actor]) is True
    assert adoption.closeout(host,[actor]) is True
    assert len(host.adoptions)==1 and ledger.process(child).init_wait==15
    assert ledger.process(child).parent_wait is None


@pytest.mark.parametrize('transition',('before-death','adopted','foreign-parent','namespace','gone'))
def test_refresh_distinguishes_ptrace_exit_event_from_actual_reparenting(monkeypatch,transition):
    ledger,_,child,observed=ready()
    row={'case':PARITY[0],'adoptable':True,'composed_worker':0}
    actor={'birth':child,'intent':row,'body_ready':True}
    host=SimpleNamespace(case=PARITY[0],actors={child.pid:actor},ledger=ledger,executed=lambda row:True,
        meta={'pid_namespace':'pid:[123]'})
    actual={**observed,'namespaces':{'pid':'pid:[123]'}}
    if transition=='before-death':
        actual['ppid']=child.parent
    elif transition=='foreign-parent':
        actual['ppid']=2
    elif transition=='namespace':
        actual['namespaces']['pid']='foreign'
    def observe(pid):
        if transition=='gone':
            raise ProcessLookupError
        return actual
    monkeypatch.setattr(adoption,'process_identity',observe)
    if transition in ('foreign-parent','namespace'):
        with pytest.raises(Refused):
            adoption.refresh(host)
    else:
        adoption.refresh(host)
        assert (ledger.process(child).adopted_identity is not None)==(transition=='adopted')


@pytest.mark.parametrize('mutation',(None,'old-server','unknown-pid','control','cursor','generation','identity','namespace','sigkill','nongroup','group-probe'))
def test_resumed_signals_require_admission_and_exact_cursor_without_fake_popen(tmp_path,monkeypatch,mutation):
    import completion_roles
    import composed_runtime
    from unrest_harness.run_control import _safe_token
    ledger,_,child,observed=ready()
    ledger.adopt(child,observed)
    run='run:'+'a'*64
    row={'case':PARITY[0],'adoptable':True,'pid':child.pid,'run_id':run,'run_control':'control','run_project':'project'}
    cursor={'run_id':run,'generation':1,'control_identity_digest':'control','pid':child.pid,'pgid':child.pid}
    worker={'case':PARITY[0],'birth':child,'signals':set()}
    host=SimpleNamespace(case=PARITY[0],ledger=ledger,intents={1:row},actors={child.pid:worker},
        executed=lambda row:True,meta={'pid_namespace':'pid:[123]'})
    monkeypatch.setattr(completion_roles,'actor_slot',lambda host,actor:{'server_slot':0 if mutation=='old-server' else 1})
    monkeypatch.setattr(composed_runtime,'root',lambda host:tmp_path)
    def record(path):
        assert path==tmp_path/'.unrest/.unrest-runtime/runs'/(_safe_token(run)+'.worker.json')
        return cursor
    monkeypatch.setattr(composed_runtime,'record',record)
    actual={**observed,'namespaces':{'pid':'pid:[123]'}}
    monkeypatch.setattr(adoption,'process_identity',lambda pid:actual)
    payload={'pid':child.pid,'signal':15,'group':True}
    if mutation=='unknown-pid':
        payload['pid']+=1
    elif mutation=='control':
        cursor['control_identity_digest']='foreign'
    elif mutation=='cursor':
        cursor['pid']+=1
    elif mutation=='generation':
        cursor['generation']=2
    elif mutation=='identity':
        actual['start_ticks']+=1
    elif mutation=='namespace':
        actual['namespaces']['pid']='foreign'
    elif mutation=='sigkill':
        payload['signal']=9
    elif mutation=='nongroup':
        payload['group']=False
    elif mutation=='group-probe':
        payload['signal']=0
    if mutation is not None:
        with pytest.raises(Refused):
            adoption.signal(host,{},payload)
        assert worker['signals']==set()
        return
    assert adoption.signal(host,{},payload)=={'ok':True,'live':True}
    assert worker['signals']=={15}
    with pytest.raises(Refused):
        adoption.signal(host,{},payload)
    assert adoption.signal(host,{},dict(payload,signal=0,group=False))=={'ok':True,'live':True}


@pytest.mark.parametrize('mutation',(None,'birth','namespace'))
def test_group_signal_attributes_only_verified_members_and_keeps_other_sessions_alive(monkeypatch,mutation):
    from test_process_ledger import identity
    ledger,_,leader,observed=ready()
    ids={leader.pid:{**ledger.process(leader).registered_identity,'namespaces':{'pid':'pid:[123]'}}}
    actors={leader.pid:{'case':PARITY[0],'birth':leader,'signals':set()}}
    for pid,parent,group in ((102,leader.pid,leader.pid),(103,leader.pid,103),(104,100,leader.pid)):
        actual={**identity(pid,parent),'pgid':group,'sid':group}
        emit(ledger,'kernel_child',parent=parent,child=pid,event=1,identity=actual)
        birth=Birth.read(actual)
        ledger.register(birth,str(pid),(),case=PARITY[0],command_class='fixture')
        ids[pid]={**actual,'namespaces':{'pid':'pid:[123]'}}
        actors[pid]={'case':PARITY[0],'birth':birth,'signals':set()}
    if mutation=='birth':
        ids[102]['start_ticks']+=1
    elif mutation=='namespace':
        ids[102]['namespaces']['pid']='foreign'
    monkeypatch.setattr(adoption,'process_identity',ids.__getitem__)
    host=SimpleNamespace(case=PARITY[0],ledger=ledger,actors=actors,meta={'pid_namespace':'pid:[123]'})
    if mutation is not None:
        with pytest.raises(Refused):
            adoption.record_group(host,actors[leader.pid],15)
        assert not any(actor['signals'] for actor in actors.values())
    else:
        adoption.record_group(host,actors[leader.pid],15)
        assert {pid for pid,actor in actors.items() if actor['signals']}=={leader.pid,102}
