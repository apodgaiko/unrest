"""Finite original uv refusal operands, environment depth and child ownership."""
from pathlib import Path
from types import SimpleNamespace
import json
import os

import pytest

from content_manifest import Refused
import uv_cli as uv
import owned_fixture

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_first_and_nested_stock_uv_environment_keep_all_other_values():
    meta={'runtime_root':'/runtime'}
    first=uv.child_environment(meta,{'PATH':'/bin','KEEP':'original'})
    assert first=={'PATH':'/runtime/bin:/bin','KEEP':'original','UV':'/runtime/bin/uv','UV_RUN_RECURSION_DEPTH':'1'}
    second=uv.child_environment(meta,first)
    assert second=={**first,'PATH':'/runtime/bin:/runtime/bin:/bin','UV_RUN_RECURSION_DEPTH':'2'}
    with pytest.raises(Refused):
        uv.child_environment(meta,second)


@pytest.fixture
def original(tmp_path,monkeypatch):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    read=uv.read_regular
    monkeypatch.setattr(uv,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    monkeypatch.setattr(uv,'uv_digest',lambda path:'b'*64)
    monkeypatch.setattr(uv,'native_digest',lambda path:'b'*64 if path.name=='uv' else 'a'*64)
    monkeypatch.setattr(uv,'script',lambda host,name:(Path('/dependencies/.release-distribution/installed/bin')/name,'c'*64))
    case=uv.INVALID
    parent=tmp_path/'pytest'/(case.split('::')[-1][:30]+'0')
    parent.mkdir(parents=True)
    file=parent/'run-task-invalid.json'
    file.write_text(json.dumps({'brief':'private-subprocess-invalid-token'}))
    host=SimpleNamespace(case=case,meta={'owned':str(tmp_path),'checkout':str(ROOT),'runtime_root':'/runtime','dependencies':'/dependencies'},
        intents={},fixture_roots={},binding={'entry':{'sha256':'a'*64},'uv':{'path':'/runtime/bin/uv','sha256':'b'*64}},serial=0)
    host.root_only=lambda actor:None
    host.meta_environment=lambda:{'PATH':'/runtime/bin:/usr/bin:/bin'}
    host.admit_launch=lambda *args,**kwargs:host.intents.setdefault(1,{'case':case,'role':'uv-cli','consumed':False}) and {'ticket':1}
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)',
        'UNREST_HOME':str(parent/'run-task-invalid-home'),'UNREST_PROJECTS_DIR':str(parent/'run-task-invalid-home/projects')}
    raw={'executable':'uv','argv':['uv','run','unrest','run-task','--request',str(file)],
        'environment':env,'cwd':str(ROOT),'stdin':None}
    return host,raw,file


@pytest.mark.parametrize('mutation',[None,'command','env','request','repeat'])
def test_stock_uv_cannot_broaden_the_original_invalid_request_route(original,mutation):
    host,raw,file=original
    if mutation=='command':
        raw['argv'][2]='python'
    elif mutation=='env':
        raw['environment']['FOREIGN']='not original'
    elif mutation=='request':
        file.write_text(json.dumps({'bounds':{},'brief':'changed'}))
    if mutation is None or mutation=='repeat':
        answer=uv.proposal(host,{},raw)
        assert answer['translated']==raw['argv']
        assert host.intents[1]['uv_console']['argv']==['unrest','run-task','--request',str(file)]
        if mutation=='repeat':
            with pytest.raises(Refused,match='frontier'):
                uv.proposal(host,{},raw)
    else:
        with pytest.raises(Refused):
            uv.proposal(host,{},raw)
        assert not host.intents


def test_each_actual_uv_birth_reserves_exactly_one_bound_console_child(original):
    host,raw,_=original
    uv.proposal(host,{},raw)
    birth=object()
    host.intents[1].update(consumed=True,birth=birth,environment=raw['environment'],cwd=raw['cwd'])
    host.serial=1
    uv.reserve_child(host,host.intents[1],birth)
    child=host.intents[2]
    assert child['parent'] is birth and child['role']=='fixed-inline'
    assert child['executable']=='/runtime/bin/unrest' and child['executable_sha256']=='a'*64
    assert child['environment']==uv.child_environment(host.meta,raw['environment'])
    assert child['python_vector']==['/runtime/bin/python-unrest-guard-control','-I','-S',
        '/dependencies/.release-distribution/installed/bin/unrest',*raw['argv'][3:]]
    with pytest.raises(Refused,match='single console'):
        uv.reserve_child(host,host.intents[1],birth)
    with pytest.raises(Refused,match='actual admitted parent'):
        uv.reserve_child(host,host.intents[1],object())
    assert len(host.intents)==2


@pytest.mark.parametrize('case,command,filename,home',[
    (uv.PROJECT,'run-project','project-subprocess.json','home-subprocess'),
    (uv.IMPROVEMENT,'run-improvement','improvement-subprocess.json','unused-improvement-home'),
])
@pytest.mark.parametrize('mutation',[None,'path','json','environment'])
def test_activation_routes_bind_owned_paths_and_preserve_product_request_semantics(original,case,command,filename,home,mutation):
    host,raw,oldfile=original
    parent=oldfile.parent.with_name(case.split('::')[-1][:30]+'0')
    parent.mkdir()
    file=parent/filename
    file.write_text(json.dumps({'original_application_input':True}))
    if case==uv.PROJECT:
        (parent/home).mkdir()
    host.case=case
    host.admit_launch=lambda *args,**kwargs:host.intents.setdefault(1,{'case':case,'role':'uv-cli','consumed':False}) and {'ticket':1}
    raw.update(argv=['uv','run','unrest',command,'--request',str(file)])
    raw['environment'].update(PYTEST_CURRENT_TEST=case+' (call)',UNREST_HOME=str(parent/home),UNREST_PROJECTS_DIR=str(parent/home/'projects'))
    if mutation=='path':
        raw['argv'][-1]=str(oldfile)
    elif mutation=='json':
        file.write_text('[]')
    elif mutation=='environment':
        raw['environment']['CODEX_APP_TOOLS_PIPE_PATH']='/outside'
    if mutation is None:
        assert uv.proposal(host,{},raw)['translated']==raw['argv']
    else:
        with pytest.raises(Refused):
            uv.proposal(host,{},raw)
        assert not host.intents
