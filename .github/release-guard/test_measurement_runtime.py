"""Nested mock ACP admission derives from the actual owned worker and node cursor."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import pytest
from content_manifest import Refused
import measurement_runtime as runtime

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def fixture(tmp_path,monkeypatch):
    home=tmp_path/'rep-01/harness-home'
    project=home/'projects/project-one'
    project.mkdir(parents=True)
    birth=object()
    parent={'role':'fixed-inline','case':runtime.PROJECT,'token':'worker','birth':birth,
        'consumed':True,'measurement_nodes':('p1-work','p1-validate'),'cwd':str(home)}
    host=SimpleNamespace(case=runtime.PROJECT,meta={'checkout':str(ROOT)},
        binding={'entry':{'path':'/native/python','sha256':'a'*64}},intents={1:parent},
        ledger=SimpleNamespace(reaped=lambda *args:True),executed=lambda row:row['consumed'],seen=[])
    actor={'role':'fixed-inline','case':runtime.PROJECT,'token':'worker','birth':birth,'body_ready':True}
    def record(path):
        if path.name=='project.json':
            return {'id':'project-one','workspace_dir':str(home.parent/'workspace')}
        return {'tasks':{'p1-work':{'status':'running','last_attempt':'2026-10-29T12-00-00Z'}}}
    monkeypatch.setattr(runtime,'record',record)
    import cleanup_launch
    monkeypatch.setattr(cleanup_launch,'read_pipe',lambda pid,fd:[fd,10,20])
    # The synthetic actor has a PID only for descriptor-acquisition argument tests.
    actor['birth']=SimpleNamespace(pid=42)
    parent['birth']=actor['birth']
    def admit(actor,expected,role,vector,pin,**kwargs):
        host.seen.append((expected,role,vector,pin,kwargs))
        ticket=len(host.intents)+1
        host.intents[ticket]={'role':role,'case':runtime.PROJECT,'parent':actor['birth'],'consumed':False,'token':str(ticket)}
        return {'ok':True,'ticket':ticket,'token':str(ticket)}
    host.admit_launch=admit
    handoff=project/'.unrest-runtime/missions/mission-001/attempts/2026-10-29T12-00-00Z__p1-work.json'
    env={'LANG':'C.UTF-8','PATH':os.defpath,'UNREST_CAPABILITY_PROFILE':'safe','UNREST_CAPABILITY_POLICY_VERSION':'1',
        'UNREST_HOME':str(home),'UNREST_PROJECT_ID':'project-one','UNREST_MISSION_ID':'mission-001',
        'UNREST_NODE_ID':'p1-work','UNREST_NODE_TYPE':'work','UNREST_HANDOFF_PATH':str(handoff),
        'UNREST_NODE_ASSIGNMENT':json.dumps({'targets':['VAL-MEASURE'],'task_type':'work'},sort_keys=True,separators=(',',':'))}
    argv=['/native/python','-m','unrest_harness','--mode','worker','--transport','streamable-http','--host','127.0.0.1','--port','12345','--sensitive-inventory-fd','7']
    raw={'executable':'/native/python','argv':argv,'environment':env,'cwd':str(home.parent/'workspace'),'stdin':None}
    return host,actor,raw

@pytest.mark.parametrize('mutation',(None,'owner','readiness','unconsumed','environment','node','entry','port','input'))
def test_mcp_node_has_exact_parent_cursor_arguments_and_environment(fixture,mutation):
    host,actor,raw=fixture
    if mutation=='owner':
        actor['token']='foreign'
    elif mutation=='readiness':
        actor['body_ready']=False
    elif mutation=='unconsumed':
        host.intents[1]['consumed']=False
    elif mutation=='environment':
        raw['environment']['OPENAI_API_KEY']='canary'
    elif mutation=='node':
        raw['environment']['UNREST_NODE_ID']='foreign'
    elif mutation=='entry':
        raw['argv'][4]='orchestrator'
    elif mutation=='port':
        raw['argv'][-3]='0'
    elif mutation=='input':
        raw['stdin']='foreign'
    if mutation is None:
        answer=runtime.nested(host,actor,raw)
        assert host.intents[answer['ticket']]['measurement_node']=='p1-work'
        expected,role,vector,pin,options=host.seen[0]
        assert role=='mcp' and options['maximum']==6 and options['inherited']==[[7,10,20]]
        assert vector==['/native/python','-I','-S',*raw['argv'][1:]]
        assert dict(expected.environment)==raw['environment']
    else:
        with pytest.raises(Refused):
            runtime.nested(host,actor,raw)
        assert not host.seen


def test_acp_cannot_start_before_its_exact_server_executes(fixture):
    host,actor,raw=fixture
    raw['argv']=['/native/python',str(ROOT/runtime.MOCK)]
    with pytest.raises(Refused,match='server pair'):
        runtime.nested(host,actor,raw)
    assert not host.seen
