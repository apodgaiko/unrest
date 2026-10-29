"""Constructor reservations, concurrent slots and mandatory original cleanup."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import completion_server as server
import completion_roles as roles

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.fixture
def host(tmp_path,monkeypatch):
    case=next(case for case,row in roles.CASES.items() if row==('ownership','work','valid'))
    parent=tmp_path/'case'
    parent.mkdir()
    root=object()
    value=SimpleNamespace(case=case,fixture_roots={('completion-role',case):(str(parent),)},
        meta={'checkout':str(ROOT)},binding={'entry':{'path':'/native','sha256':'a'*64}},
        intents={},actors={},probe_ports={},retired=[],root_birth=root)
    value.meta_environment=lambda:{'HOME':'/owned/home','PATH':'/usr/bin:/bin'}
    value.root_only=lambda actor:None if actor['birth'] is root else pytest.fail('foreign parent')
    value.owner=lambda actor:actor['token']
    value.executed=lambda row:row['consumed'] and value.actors[row['pid']]['executed']
    value.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=None),reaped=lambda birth,token:value.actors[birth]['waited'])
    monkeypatch.setattr(server,'root',lambda host,cwd:parent)
    monkeypatch.setattr(server,'git_ready',lambda host,cwd:'1'*40)
    def admit(actor,expected,role,vector,pin,**kwargs):
        ticket=len(value.intents)+1
        value.intents[ticket]={'case':value.case,'role':role,'parent':actor['birth'],
            'consumed':False,'pid':None,'token':str(ticket)}
        return {'ticket':ticket,'token':str(ticket)}
    value.admit_launch=admit
    return value,{'birth':root},parent


def raw(host,parent,slot,port=12345):
    kind,_,_=roles.schedule(host.case)[slot]
    mode='validator' if roles.CASES[host.case][1]=='validate' else 'worker'
    env=roles.environment(ROOT,parent,host.case,slot,{**host.meta_environment(),
        'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'})
    argv=['/native','-c',roles.program(ROOT,parent,host.case,slot)]
    if kind=='http':
        argv+=['--mode',mode,'--transport','streamable-http','--host','127.0.0.1','--port',str(port)]
    else:
        argv+=([str(slot)] if roles.CASES[host.case][0]=='setup' else [])+['--mode',mode]
    return {'executable':'/native','argv':argv,'environment':env,'cwd':str(parent/'workspace'),'stdin':None}


def consumed(host,answer):
    row=host.intents[answer['ticket']]
    row.update(consumed=True,pid=answer['ticket'],birth=answer['ticket'])
    host.actors[row['pid']]={'executed':True,'waited':False,'birth':row['birth'],'token':row['token']}


def test_each_concurrent_http_constructor_consumes_one_exact_authored_slot(host):
    host,actor,parent=host
    for slot in (0,1):
        command=raw(host,parent,slot,12345+slot)
        changed={**command,'environment':{**command['environment'],'FOREIGN':'not admitted'}}
        with pytest.raises(Refused,match='original launch operands'):
            server.proposal(host,actor,changed)
        answer=server.proposal(host,actor,command)
        consumed(host,answer)
    # Application phase order belongs to the original tests; the slot stays exact.
    answer=server.proposal(host,actor,raw(host,parent,2))
    assert host.intents[answer['ticket']]['server_slot']==2
    assert not host.retired


def test_setup_slot_one_may_construct_first_but_neither_slot_may_repeat(host):
    host,actor,parent=host
    host.case=next(case for case,row in roles.CASES.items() if row==('setup','work','valid-valid'))
    host.fixture_roots={('completion-role',host.case):(str(parent),)}
    for slot in (1,0):
        answer=server.proposal(host,actor,raw(host,parent,slot))
        assert host.intents[answer['ticket']]['server_slot']==slot
        consumed(host,answer)
    with pytest.raises(Refused,match='original server sequence'):
        server.proposal(host,actor,raw(host,parent,1))
    assert not host.retired


def test_restart_inventory_is_native_bounded_and_requires_an_admitted_server(host,monkeypatch):
    import http_cases
    value,actor,parent=host
    value.case=next(iter(roles.RESTART))
    value.meta['owned']=str(parent)
    monkeypatch.setattr(http_cases,'image',lambda executable:'b'*64)
    environment={**value.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':value.case+' (call)'}
    request={'argv':['ps','-axo','pid=,ppid=,pgid='],'executable':'ps','cwd':str(ROOT),
        'environment':environment,'stdin':None}
    with pytest.raises(Refused,match='before original server wait'):
        server.proposal(value,actor,request)
    value.intents={1:{'case':value.case,'role':'mcp','consumed':False}}
    with pytest.raises(Refused):
        server.proposal(value,actor,request)
    value.intents[1]['consumed']=True
    seen=[]
    def admit(*args,**kwargs):
        seen.append((args,kwargs))
        return {'ticket':2,'token':'bound'}
    value.admit_launch=admit
    assert server.proposal(value,actor,request)['translated']==['/usr/bin/ps','-axo','pid=,ppid=,pgid=']
    assert seen[0][1]['maximum']==3
    request['environment']={**environment,'UNREST_WORKER_PROVIDER':'other'}
    with pytest.raises(Refused):
        server.proposal(value,actor,request)
    assert len(seen)==1


@pytest.mark.parametrize('role',('mcp','fixed-inline'))
@pytest.mark.parametrize('code,ready,accepted',((0,True,True),(1,True,False),(0,False,False)))
def test_each_role_server_keeps_terminal_status_at_the_shared_final_join(role,code,ready,accepted):
    from source_observer import Observer
    case=next(case for case,row in roles.CASES.items() if row==('ownership','work','valid'))
    birth=object()
    intent={'ticket':1,'case':case,'role':role,'birth':birth,'token':'server','consumed':True,'server_slot':0}
    actor={'case':case,'role':role,'birth':birth,'token':'server','intent':intent,'body_ready':ready,'signals':set()}
    host=SimpleNamespace(intents={1:intent},ledger=SimpleNamespace(process=lambda value:SimpleNamespace(terminal=(3,code<<8,code))))
    assert Observer.completed_child(host,actor) is accepted


@pytest.mark.parametrize('code,admitted,accepted',((0,True,True),(1,True,False),(0,False,False)))
def test_completion_git_head_keeps_success_at_shared_final_join(code,admitted,accepted):
    from source_observer import Observer
    birth=object()
    intent={'ticket':1,'case':'case','role':'git-command','birth':birth,'token':'git','consumed':True,'operation':'completion-head'}
    actor={'case':'case','role':'git-command','birth':birth,'token':'git','intent':intent,'kernel_admitted':admitted}
    host=SimpleNamespace(intents={1:intent},ledger=SimpleNamespace(process=lambda value:SimpleNamespace(terminal=(3,code<<8,code))))
    assert Observer.completed_child(host,actor) is accepted
