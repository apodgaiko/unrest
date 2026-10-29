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
    case=roles.GROUPS['roles2'][0]
    parent=tmp_path/'case'
    parent.mkdir()
    root=object()
    value=SimpleNamespace(case=case,fixture_roots={('completion-role',case):(str(parent),)},
        meta={'checkout':str(ROOT)},binding={'entry':{'path':'/native','sha256':'a'*64}},
        intents={},actors={},probe_ports={},retired=[],root_birth=root)
    value.meta_environment=lambda:{'HOME':'/owned/home','PATH':'/usr/bin:/bin'}
    value.root_only=lambda actor:None if actor['birth'] is root else pytest.fail('foreign parent')
    value.owner=lambda actor:actor['token']
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
    host.actors[row['pid']]={'returned':True,'waited':False,'birth':row['birth'],'token':row['token']}


def test_each_concurrent_http_constructor_consumes_one_exact_authored_slot(host):
    host,actor,parent=host
    for slot in (0,1):
        command=raw(host,parent,slot,12345+slot)
        changed={**command,'environment':{**command['environment'],'FOREIGN':'not admitted'}}
        with pytest.raises(Refused,match='original launch operands'):
            server.proposal(host,actor,changed)
        answer=server.proposal(host,actor,command)
        consumed(host,answer)
    # Both original servers are live; moving to the late-client phase must wait.
    with pytest.raises(Refused,match='actual server waits'):
        server.proposal(host,actor,raw(host,parent,2))
    assert not host.retired


def test_setup_slot_one_may_construct_first_but_neither_slot_may_repeat(host):
    host,actor,parent=host
    host.case=roles.GROUPS['setup2'][0]
    host.fixture_roots={('completion-role',host.case):(str(parent),)}
    for slot in (1,0):
        answer=server.proposal(host,actor,raw(host,parent,slot))
        assert host.intents[answer['ticket']]['server_slot']==slot
        consumed(host,answer)
    with pytest.raises(Refused,match='original server sequence'):
        server.proposal(host,actor,raw(host,parent,1))
    assert not host.retired


def test_child_exit_alone_cannot_satisfy_original_completion(host,monkeypatch):
    host,actor,parent=host
    monkeypatch.setattr(server,'status',lambda *args:True)
    row={'case':host.case,'role':'mcp','server_slot':0,'consumed':True,'pid':1}
    host.intents={1:row}
    host.actors={1:{'birth':1,'token':'server','waited':False}}
    assert not server.complete(host,row)
    host.actors[1]['waited']=True
    assert server.complete(host,row)
