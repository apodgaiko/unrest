"""Original topology and hostile launch mutations; native execution is separate."""
from pathlib import Path
from types import SimpleNamespace
import os
import ast
import hashlib

import pytest

import composed_cases as cases
import composed_runtime as runtime
from content_manifest import Refused

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def authored_scripts():
    from completion_roles import SERVER_TEST,PINS
    from launch_policy import source_unit,render_string
    def literal(name,receiver):
        owner=source_unit(ROOT,SERVER_TEST,PINS[SERVER_TEST],(name,))
        writes=[node for node in ast.walk(owner) if isinstance(node,ast.Call) and ast.unparse(node.func)==receiver+'.write_text']
        assert len(writes)==1 and len(writes[0].args)==1
        return ast.literal_eval(writes[0].args[0])
    base=literal('_write_composed_acp_adapter','adapter')
    result={cases.HERMETIC:base,'shim':literal('_write_undeliverable_adapter','shim')}
    for case in cases.DIRECT:
        unit=source_unit(ROOT,SERVER_TEST,PINS[SERVER_TEST],(case.split('::')[1].split('[')[0],))
        rows=[node.value for node in unit.body if isinstance(node,ast.Assign) and len(node.targets)==1
            and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='source' and isinstance(node.value,ast.BinOp)]
        assert len(rows)==1
        replacement=render_string(rows[0].left.right,(('attention',114,repr(case==cases.DIRECT[1])),))
        result[case]=base[:base.index('    snapshot = {')]+replacement+base[base.index('\ndef response('):]
    return {case:body.encode() for case,body in result.items()}


def test_authored_byte_declarations_match_every_original_literal_and_postimage():
    expected={cases.HERMETIC:runtime.ADAPTER_PIN,**runtime.DIRECT_PINS,'shim':runtime.SHIM_PIN}
    assert {case:hashlib.sha256(body).hexdigest() for case,body in authored_scripts().items()}==expected


@pytest.mark.parametrize('case',(cases.HERMETIC,*cases.DIRECT,'foreign'))
@pytest.mark.parametrize('mutation',(None,'byte','other-variant','inode'))
def test_byte_pins_do_not_admit_changed_programs_or_another_case_variant(tmp_path,monkeypatch,case,mutation):
    scripts=authored_scripts()
    file=tmp_path/'workspace/.hermetic-acp-adapter.py'
    file.parent.mkdir()
    file.write_bytes(scripts.get(case,scripts[cases.HERMETIC]))
    file.chmod(0o700)
    host=SimpleNamespace(case=case,fixture_roots={})
    read=runtime.read_regular
    monkeypatch.setattr(runtime,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    if case!='foreign':
        runtime.adapter(host,tmp_path)
    if mutation=='byte':
        file.write_bytes(file.read_bytes()+b'\n')
    elif mutation=='other-variant':
        file.write_bytes(scripts[cases.DIRECT[0] if case!=cases.DIRECT[0] else cases.DIRECT[1]])
    elif mutation=='inode':
        replacement=tmp_path/'replacement'
        replacement.write_bytes(file.read_bytes())
        replacement.chmod(0o700)
        replacement.replace(file)
    if mutation is not None or case=='foreign':
        with pytest.raises(Refused):
            runtime.adapter(host,tmp_path)
    else:
        assert runtime.adapter(host,tmp_path)[0]==file


def test_composed_topology_preserves_every_original_parameter_and_parent_slot():
    class Collected:
        def pytest_collection_finish(self,session):
            self.nodes=tuple(item.nodeid for item in session.items)
    selectors=tuple(dict.fromkeys(case.split('[')[0] for case in cases.CASES))
    plugin=Collected()
    assert pytest.main(['--collect-only','-q',*selectors],plugins=[plugin])==0
    assert plugin.nodes==cases.CASES and len(cases.CASES)==15
    assert sum(map(len,cases.STEPS.values()))==20
    assert sum(len(cases.roles(case)) for case in cases.CASES)==29
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
    row={'ticket':1,'case':cases.HERMETIC,'role':'fixed-inline','birth':birth,'token':'parent','consumed':True,
        'composed_roles':cases.PAIR,'composed_project':str(project)}
    actor['intent']=row
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


@pytest.mark.parametrize('mutation',(None,'owner','environment','mode','script','before-mcp'))
def test_composed_node_pair_binds_owner_role_environment_and_script(fixture,mutation):
    host,actor,raw,parent=fixture
    if mutation=='owner':
        actor['token']='foreign'
    elif mutation=='environment':
        raw['environment']['PYTHONPATH']='/foreign'
    elif mutation=='mode':
        raw['argv'][4]='validator'
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
    assert server['node_role']=='work'
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



def test_observer_issued_roles_keep_their_head_query_bounds():
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


def test_scoped_assignment_content_and_independent_acp_template_remain_data(fixture):
    host,actor,raw,parent=fixture
    raw['environment']['UNREST_NODE_ASSIGNMENT']='{"targets":[],"task_type":"work"}'
    assert runtime.nested(host,actor,raw)['ticket']==2
    raw['argv']=['/native',str(parent/'workspace/.hermetic-acp-adapter.py'),str(parent/'workspace/.hermetic-acp-trace.jsonl')]
    raw['environment'].pop('UNREST_NODE_ASSIGNMENT')
    # Each template descends from the authenticated parent, not its last sibling.
    assert runtime.nested(host,actor,raw)['ticket']==3
    with pytest.raises(Refused,match='budget'):
        runtime.nested(host,actor,raw)
