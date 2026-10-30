"""Exact original inventory regression operands and owner/wait boundaries."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import mcp_inventory as inventory
import cleanup_launch
import owned_fixture
from content_manifest import Refused

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('case',inventory.INVENTORY_CASES)
@pytest.mark.parametrize('mutation',[None,'argv','environment','cwd','stdin','parent','generation','unreaped'])
def test_inventory_original_launches_require_exact_operands_and_owned_sequence(tmp_path,monkeypatch,case,mutation):
    original=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,uid:original(path,owned,os.getuid()))
    monkeypatch.setattr(cleanup_launch,'system_git',lambda:'b'*64)
    monkeypatch.setattr(cleanup_launch,'read_pipe',lambda pid,fd:[fd,1,2])
    base=tmp_path/'pytest'/(case.split('::')[1].split('[')[0][:30]+'0')
    (base/'workspace').mkdir(parents=True)
    calls=[]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':str(tmp_path)},intents={},fixture_roots={},
        binding={'entry':{'path':'/native','sha256':'a'*64}},meta_environment=lambda:{'PATH':'/bin'},
        ledger=SimpleNamespace(reaped=lambda *args:mutation!='unreaped'))
    def admit(actor,value,role,vector,pin,**kwargs):
        ticket=len(host.intents)+1
        host.intents[ticket]={'case':case,'role':role,'birth':ticket,'token':str(ticket),'consumed':True}
        calls.append((value,role,vector,kwargs))
        return {'ticket':ticket,'token':str(ticket)}
    host.admit_launch=admit
    worker=case==inventory.CASES[0]
    env={'LANG':'C','PATH':'/bin','UNREST_HOME':str(base/'.unrest'),'UNREST_PROJECT_ID':'p-worker' if worker else 'p-terminal-reviewer','UNREST_MISSION_ID':'mission-001'}
    runtime=base/'.unrest/projects'/env['UNREST_PROJECT_ID']/'.unrest-runtime/missions/mission-001'
    if worker:
        env.update(UNREST_NODE_ID='w-secret',UNREST_NODE_TYPE='work',UNREST_NODE_ASSIGNMENT='{"targets":["VAL-001"],"task_type":"work"}',
            UNREST_HANDOFF_PATH=str(runtime/'attempts/2026-08-03T00-00-00Z__w-secret.json'))
    else:
        env['UNREST_TERMINAL_REVIEW_PATH']=str(runtime/'terminal-reviews/2026-08-03T00-00-00Z.json')
    steps=[('mcp',['/native','-m','unrest_harness','--mode','worker' if worker else 'terminal-reviewer','--transport','streamable-http','--host','127.0.0.1','--port','12345','--sensitive-inventory-fd','9'],env)]
    if worker:
        git_env={'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)','ANTHROPIC_API_KEY':'plum','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1'}
        for who in ('AUTHOR','COMMITTER'):
            git_env.update({f'GIT_{who}_DATE':'2000-01-01T00:00:00+00:00',f'GIT_{who}_EMAIL':'test@example.invalid',f'GIT_{who}_NAME':'Test'})
        steps=[('git-init',['git','-c','maintenance.auto=false','-c','gc.auto=0','init','--quiet','--initial-branch=main'],git_env),('git-commit',['git','-c','maintenance.auto=false','-c','gc.auto=0','commit','--allow-empty','--quiet','-m','base'],git_env),*steps,('git-observe',['git','rev-parse','HEAD'],env)]
    for index,(role,argv,environment) in enumerate(steps):
        actor={'role':'mcp' if role=='git-observe' else 'root','birth':3 if role=='git-observe' else SimpleNamespace(pid=1),'token':'3','body_ready':True}
        raw={'case':case,'executable':'/usr/bin/git' if argv[0]=='git' else '/native','argv':list(argv),'environment':dict(environment),'cwd':str(base/'workspace'),'stdin':None}
        if mutation=='unreaped':
            if worker and index:
                assert inventory.proposal(host,actor,raw) is None
                return
        elif index==0 and mutation:
            if mutation=='argv':
                raw['argv'].append('--foreign')
            elif mutation=='environment':
                raw['environment']['FOREIGN']='1'
            elif mutation=='cwd':
                raw['cwd']=str(base/'other')
            elif mutation=='stdin':
                raw['stdin']='foreign'
            elif mutation=='parent':
                actor['role']='mcp'
            else:
                host.fixture_roots[case]=('foreign',0,0)
            with pytest.raises(Refused):
                inventory.proposal(host,actor,raw)
            assert not calls
            return
        answer=inventory.proposal(host,actor,raw)
        assert answer['ticket']==index+1 and calls[-1][1]==role
        if role=='mcp':
            assert calls[-1][3]['inherited']==[[9,1,2]] and calls[-1][3]['port']==12345
    assert len(calls)==len(steps)
    with pytest.raises(Refused):
        inventory.proposal(host,actor,raw)
