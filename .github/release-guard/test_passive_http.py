"""Existing HTTP fixtures keep separate process, role and Git capabilities."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import completion_roles as roles
import completion_server as server
from git_policy import completion_fixture

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_no_git_http_family_parameter_ids_match_the_original_collection():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    collected=Collected()
    assert pytest.main(['--collect-only','-q',roles.FALLBACK,roles.SERVER_TEST+'::test_real_http_all_role_supervision_is_coordinator_causal'],plugins=[collected])==0
    assert collected.nodes==roles.NO_GIT


def original(case,parent,mode,ambient):
    env={**ambient,'PYTHONPATH':str(ROOT/'src'),'UNREST_HOME':str(parent/'.unrest'),
        'UNREST_PROJECTS_DIR':str(parent/'.unrest/projects')}
    for name in ('WORKER','VALIDATOR','TERMINAL_REVIEWER'):
        env['UNREST_'+name+'_PROVIDER']='claude'
        env['UNREST_'+name+'_ACP_COMMAND']='/bin/true'
    if mode!='orchestrator':
        runtime=parent/'.unrest/projects/p/.unrest-runtime/missions/mission-001'
        env.update(UNREST_PROJECT_ID='p',UNREST_MISSION_ID='mission-001')
        if mode=='terminal-reviewer':
            env['UNREST_TERMINAL_REVIEW_PATH']=str(runtime/'terminal-reviews/attempt-terminal_reviewer.json')
        else:
            node='worker-node' if case==roles.FALLBACK else mode+'-1'
            env.update(UNREST_NODE_ID=node,UNREST_HANDOFF_PATH=str(runtime/'attempts'/('attempt-'+mode+'__'+node+'.json')))
            if case==roles.FALLBACK:
                env.update(UNREST_NODE_TYPE='work',UNREST_NODE_ASSIGNMENT='{"targets":["VAL-A"],"task_type":"work"}')
    return env


def expected_schedule(case):
    if case==roles.FALLBACK:
        return (('http','worker',1),)
    mode=next(mode for role,mode in (('worker','worker'),('validator','validator'),('terminal_reviewer','terminal-reviewer'))
        if case.endswith('-'+role+'-'+mode+']'))
    return (('http',mode,0),('http','orchestrator',0),('http','orchestrator',0))


@pytest.mark.parametrize('case',roles.NO_GIT)
def test_existing_no_git_http_environment_and_role_paths_remain_exact(tmp_path,case):
    ambient={'HOME':'/owned/home','PATH':'/usr/bin:/bin'}
    assert roles.schedule(case)==expected_schedule(case)
    assert completion_fixture(case)==()
    for slot,(_,mode,_) in enumerate(expected_schedule(case)):
        observed=original(case,tmp_path,mode,ambient)
        assert roles.environment(ROOT,tmp_path,case,slot,ambient,observed=observed)==observed
        assert roles.program(ROOT,tmp_path,case,slot)=='from unrest_harness.server import main; main()'
        changed={**observed,'UNREST_WORKER_ACP_COMMAND':'/foreign/provider'}
        if mode=='orchestrator':
            assert roles.environment(ROOT,tmp_path,case,slot,ambient,observed=changed)!=changed
        else:
            with pytest.raises(Refused):
                roles.environment(ROOT,tmp_path,case,slot,ambient,observed=changed)
        if case in roles.CAUSAL and mode!='orchestrator':
            with pytest.raises(Refused):
                roles.environment(ROOT,tmp_path,case,slot,ambient,observed={**observed,'UNREST_NODE_TYPE':'work'})


@pytest.mark.parametrize('case',roles.NO_GIT)
def test_no_git_family_is_finite_and_fresh_orchestrator_requires_prior_actual_wait(tmp_path,monkeypatch,case):
    parent=tmp_path/'case'
    parent.mkdir()
    host=SimpleNamespace(case=case,intents={},fixture_roots={},actors={},meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},meta_environment=lambda:{'HOME':'/owned/home','PATH':'/usr/bin:/bin'},
        root_only=lambda actor:None,executed=lambda row:row['consumed'])
    host.ledger=SimpleNamespace(reaped=lambda birth,token:host.actors[birth]['waited'])
    monkeypatch.setattr(server,'root',lambda host,cwd:parent)
    monkeypatch.setattr(server,'git_ready',lambda host,cwd:None)
    def admit(actor,value,role,vector,pin,**kwargs):
        ticket=len(host.intents)+1
        host.intents[ticket]={'case':case,'role':role,'consumed':True,'birth':ticket,'token':str(ticket)}
        host.actors[ticket]={'waited':False}
        return {'ticket':ticket}
    host.admit_launch=admit
    schedule=expected_schedule(case)
    for slot,(_,mode,_) in enumerate(schedule):
        ambient={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
        raw={'executable':'/native','argv':['/native','-c','from unrest_harness.server import main; main()',
            '--mode',mode,'--transport','streamable-http','--host','127.0.0.1','--port',str(12345+slot)],
            'environment':original(case,parent,mode,ambient),'cwd':str(parent/'workspace'),'stdin':None}
        if slot==2:
            assert server.proposal(host,{},raw) is None
            for actor in host.actors.values():
                actor['waited']=True
            wrong={**raw,'argv':[*raw['argv'][:4],schedule[0][1],*raw['argv'][5:]],
                'environment':original(case,parent,schedule[0][1],ambient)}
            with pytest.raises(Refused,match='joint launch variant'):
                server.proposal(host,{},wrong)
        answer=server.proposal(host,{},raw)
        assert host.intents[answer['ticket']]['server_slot']==slot
    with pytest.raises(Refused,match='quota exhausted'):
        server.proposal(host,{},raw)


@pytest.mark.parametrize('case,code',[(roles.FALLBACK,128),(roles.FALLBACK,0),(next(iter(roles.TARGETLESS)),128),(next(iter(roles.TARGETLESS)),0)])
def test_only_missing_truth_case_expects_original_git_head_failure(case,code):
    from source_observer import Observer
    host=object.__new__(Observer)
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(None,None,code)))
    row={'ticket':1,'case':case,'role':'git-command','birth':'child','token':'token','consumed':True,'operation':'completion-head'}
    host.intents={1:row}
    actor={'case':case,'role':'git-command','birth':'child','token':'token','kernel_admitted':True,'intent':row}
    assert host.completed_child(actor) is (code==(128 if case==roles.FALLBACK else 0))
    actor['kernel_admitted']=False
    assert not host.completed_child(actor)
