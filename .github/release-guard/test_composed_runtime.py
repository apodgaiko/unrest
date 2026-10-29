"""Original topology and hostile launch mutations; native execution is separate."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

import composed_cases as cases
import composed_runtime as runtime
from content_manifest import Refused

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_composed_topology_preserves_every_original_parameter_and_parent_slot():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    selectors=tuple(dict.fromkeys(case.split('[')[0] for case in cases.CASES))
    plugin=Collected()
    assert pytest.main(['--collect-only','-q',*selectors],plugins=[plugin])==0
    assert plugin.nodes==cases.CASES and len(cases.CASES)==15
    assert sum(map(len,cases.STEPS.values()))==20
    assert sum(len(cases.nodes(case)) for case in cases.CASES)==29
    assert sum(cases.HTTP.values())==28 and len(cases.ADOPT)==8
    assert cases.STEPS[cases.DIRECT[0]]==cases.STEPS[cases.DIRECT[1]]==()
    assert cases.HTTP[cases.STOP]==4
    assert all(0<=slot<cases.HTTP[case] for case in cases.CASES for slot,_,_,_ in cases.STEPS[case])


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    import measurement_runtime
    import cleanup_launch
    from tests.test_server import _write_composed_acp_adapter
    workspace=tmp_path/'workspace'
    workspace.mkdir()
    _write_composed_acp_adapter(workspace)
    project=tmp_path/'.unrest/projects/project'
    project.mkdir(parents=True)
    birth=SimpleNamespace(pid=42)
    actor={'case':cases.HERMETIC,'birth':birth,'token':'parent','body_ready':True,'role':'fixed-inline',
        'profile':{'environment':{'LANG':'C.UTF-8','PATH':os.defpath}}}
    row={'case':cases.HERMETIC,'role':'fixed-inline','birth':birth,'token':'parent','consumed':True,
        'composed_nodes':cases.PAIR,'composed_project':str(project)}
    host=SimpleNamespace(case=cases.HERMETIC,meta={'checkout':str(ROOT)},binding={'entry':{'path':'/native','sha256':'a'*64}},
        fixture_roots={('completion-role',cases.HERMETIC):(str(tmp_path),)},intents={1:row},seen=[],
        ledger=SimpleNamespace(reaped=lambda *args:True),executed=lambda row:row['consumed'])
    read=runtime.read_regular
    monkeypatch.setattr(runtime,'read_regular',lambda file,*args,**kwargs:read(file,*args,**{**kwargs,'uid':os.getuid()}))
    def record(path):
        if path.name=='project.json':
            return {'id':'project','workspace_dir':str(workspace)}
        return {'tasks':{'worker-1':{'status':'running','last_attempt':'2026-10-30T00-00-00Z'}}}
    monkeypatch.setattr(runtime,'record',record)
    monkeypatch.setattr(measurement_runtime,'record',record)
    monkeypatch.setattr(cleanup_launch,'read_pipe',lambda pid,fd:[fd,10,20])
    def admit(actor,expected,role,vector,pin,**kwargs):
        host.seen.append((expected,role,vector,pin,kwargs))
        ticket=len(host.intents)+1
        host.intents[ticket]={'case':host.case,'role':role,'parent':actor['birth'],'token':str(ticket),'consumed':False}
        return {'ticket':ticket,'token':str(ticket)}
    host.admit_launch=admit
    from node_environment import environment
    env=environment(actor['profile']['environment'],tmp_path/'.unrest','project','worker-1','work','2026-10-30T00-00-00Z')
    env['UNREST_NODE_ASSIGNMENT']='{"targets":["VAL-COMPOSED"],"task_type":"work"}'
    argv=['/native','-m','unrest_harness','--mode','worker','--transport','streamable-http','--host','127.0.0.1','--port','12345','--sensitive-inventory-fd','7']
    raw={'case':host.case,'executable':'/native','argv':argv,'cwd':str(workspace),'environment':env,'stdin':None}
    return host,actor,raw,tmp_path


@pytest.mark.parametrize('mutation',(None,'owner','environment','mode','target','script','before-mcp'))
def test_composed_node_pair_binds_owner_role_environment_and_script(fixture,mutation):
    host,actor,raw,parent=fixture
    if mutation=='owner':
        actor['token']='foreign'
    elif mutation=='environment':
        raw['environment']['PYTHONPATH']='/foreign'
    elif mutation=='mode':
        raw['argv'][4]='validator'
    elif mutation=='target':
        raw['environment']['UNREST_NODE_ASSIGNMENT']='{"targets":[],"task_type":"work"}'
    elif mutation=='script':
        (parent/'workspace/.hermetic-acp-adapter.py').write_text('raise RuntimeError("foreign")\n')
    elif mutation=='before-mcp':
        raw['argv']=['/native',str(parent/'workspace/.hermetic-acp-adapter.py'),str(parent/'workspace/.hermetic-acp-trace.jsonl')]
    if mutation is not None:
        with pytest.raises(Refused):
            runtime.nested(host,actor,raw)
        assert not host.seen
        return
    answer=runtime.nested(host,actor,raw)
    server=host.intents[answer['ticket']]
    assert server['composed_node']=='worker-1' and server['composed_role']=='work'
    server['consumed']=True
    raw['argv']=['/native',str(parent/'workspace/.hermetic-acp-adapter.py'),str(parent/'workspace/.hermetic-acp-trace.jsonl')]
    raw['environment'].pop('UNREST_NODE_ASSIGNMENT')
    assert runtime.nested(host,actor,raw)['translated']==['/native','-I','-S',*raw['argv'][1:]]
    assert host.seen[-1][1]=='cleanup-acp' and host.seen[-1][4]['maximum']==4
    with pytest.raises(Refused):
        runtime.nested(host,actor,raw)


@pytest.mark.parametrize('attention',(False,True))
def test_targetless_adapter_is_exact_original_postimage(tmp_path,monkeypatch,attention):
    from tests.test_server import _write_composed_acp_adapter
    workspace=tmp_path/'workspace'
    workspace.mkdir()
    file,_=_write_composed_acp_adapter(workspace)
    source=file.read_text()
    begin,end=source.index('    snapshot = {'),source.index('\ndef response(')
    source=source[:begin]+f'''    completed = await call("end_node", {{"done": True, "report": "local measurement", "request_attention": {attention!r} if node == "measure" else True}})
    record("targetless_completion", node=node, recorded=completed.get("recorded"))
'''+source[end:]
    file.write_text(source)
    case=cases.DIRECT[int(attention)]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT)},fixture_roots={})
    read=runtime.read_regular
    monkeypatch.setattr(runtime,'read_regular',lambda file,*args,**kwargs:read(file,*args,**{**kwargs,'uid':os.getuid()}))
    assert runtime.adapter(host,tmp_path)[0]==file
    file.write_text(source+'\n')
    with pytest.raises(Refused):
        runtime.adapter(host,tmp_path)



def test_node_targets_and_head_query_bounds_match_the_original_protocol():
    import ast
    from completion_roles import PINS
    from launch_policy import source_unit
    unit=source_unit(ROOT,cases.TEST,PINS[cases.TEST],('test_real_targetless_dispatch_consumption',))
    calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
        and node.func.id=='_call_process_mcp' and len(node.args)==3 and isinstance(node.args[1],ast.Constant)
        and node.args[1].value=='submit_plan']
    assert len(calls)==1
    document=calls[0].args[2]
    task_list=ast.literal_eval(next(value for key,value in zip(document.keys,document.values,strict=True)
        if isinstance(key,ast.Constant) and key.value=='task_list'))
    for node in ('measure','publish'):
        expected=next(row['targets'] for row in task_list['tasks'] if row['id']==node)
        assert cases.targets(cases.DIRECT[0],node)==expected
    assert cases.query_count(cases.DIRECT[0],'work')==1
    assert cases.query_count(cases.HERMETIC,'work')==2
    assert cases.query_count(cases.HERMETIC,'validate')==0


def test_actual_observer_owner_route_recognizes_worker_without_server_slot(fixture):
    from source_observer import Observer
    host,actor,_,_=fixture
    host.finished=False
    Observer.launch_owner(host,actor)
    actor['token']='foreign'
    with pytest.raises(Refused):
        Observer.launch_owner(host,actor)


@pytest.mark.parametrize('mutation',(None,'shim','module','inode'))
def test_fixed_delivery_loader_does_not_add_workspace_import_search(tmp_path,monkeypatch,mutation):
    import importlib.util
    import sys
    import unrest_harness
    import run_worker_launch
    from content_manifest import read_regular,_key
    from tests.test_server import _write_undeliverable_adapter
    workspace=tmp_path/'workspace'
    workspace.mkdir()
    shim=_write_undeliverable_adapter(workspace)
    module_path=tmp_path/'src/unrest_harness/api.py'
    module_path.parent.mkdir(parents=True)
    module_path.write_text('def apply_steering(store, request, **kwargs): return kwargs\n')
    _,info,pin=read_regular(shim,4096)
    _,_,module_pin=read_regular(module_path,4096)
    binding={'kind':'undeliverable','path':str(shim),'sha256':pin,'identity':list(_key(info)),'module_sha256':module_pin}
    before=list(sys.meta_path)
    paths=list(sys.path)
    def refuse(code):
        raise Refused(code)
    policy=SimpleNamespace(profile={'checkout':str(tmp_path),'execution':{'fixture':binding}},refuse=refuse)
    monkeypatch.delitem(sys.modules,'unrest_harness.api',raising=False)
    monkeypatch.setattr(run_worker_launch,'read_regular',lambda file,*args,**kwargs:read_regular(file,*args,**{**kwargs,'uid':os.getuid()}))
    try:
        run_worker_launch.install_fixture(policy)
        loader=sys.meta_path[0]
        assert loader.find_spec('foreign_fixture') is None
        spec=loader.find_spec('unrest_harness.api')
        module=importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules,'unrest_harness.api',module)
        monkeypatch.setattr(unrest_harness,'api',module,raising=False)
        if mutation=='shim':
            shim.write_text(shim.read_text()+'\n')
        elif mutation=='module':
            module_path.write_text('raise AssertionError("foreign product body")\n')
        elif mutation=='inode':
            replacement=workspace/'replacement'
            replacement.write_bytes(shim.read_bytes())
            replacement.replace(shim)
        if mutation is None:
            loader.exec_module(module)
            assert module.apply_steering(None,None,delivery_supported=True)=={'delivery_supported':False}
            assert sys.path==paths
        else:
            with pytest.raises(Refused):
                loader.exec_module(module)
    finally:
        sys.meta_path[:]=before
