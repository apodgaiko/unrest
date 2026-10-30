"""Async error workers cannot acquire general executor or provider authority."""
from types import SimpleNamespace
from pathlib import Path
import json
import os

import pytest
import owned_fixture

from content_manifest import Refused
import run_worker_launch as worker


@pytest.mark.parametrize('case',tuple(worker.CASES))
@pytest.mark.parametrize('mutation',[None,'executor','generation','run','environment','repeat'])
def test_error_worker_admission_is_exact_and_single(tmp_path,monkeypatch,case,mutation):
    home=tmp_path/'.unrest'
    run='run:'+'a'*64
    file=home/'.unrest/runs'/run[4:]/'request.json'
    file.parent.mkdir(parents=True)
    file.write_text(json.dumps({'run_id':run,'generation':1,'operation':worker.CASES[case]}))
    file.chmod(0o600)
    monkeypatch.setattr(worker,'repository_root',lambda *args:None)
    monkeypatch.setattr(worker,'native_digest',lambda path:'b'*64)
    read=worker.read_regular
    monkeypatch.setattr(worker,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    host=SimpleNamespace(case=case,intents={},meta={'checkout':'/source'},binding={'entry':{'path':'/native','sha256':'a'*64}},
        root_only=lambda actor:None)
    host.admit_launch=lambda *args,**kwargs:host.intents.setdefault(1,{'case':case}) and {'ticket':1}
    raw={'executable':'/native','argv':['/native','-m','unrest_harness.run_worker','--project-root',str(home),'--run-id',run,
        '--executor','unrest_harness.runtime_executor:execute','--custody-root-id','local:unrest-run-control','--generation','1'],
        'cwd':str(home),'stdin':None,'environment':{'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':'/source/src',
            'UNREST_APPROVAL_RECOVERY':'0','UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}}
    if mutation=='executor':
        raw['argv'][8]='outside:execute'
    elif mutation=='generation':
        raw['argv'][-1]='2'
    elif mutation=='run':
        raw['argv'][6]='run:foreign'
    elif mutation=='environment':
        raw['environment']['UNREST_APPROVAL_RECOVERY']='1'
    elif mutation=='repeat':
        host.intents[1]={'case':case,'run_worker':True}
    if mutation is None:
        result=worker.proposal(host,{},raw)
        assert result['translated']==['/native','-I','-S',*raw['argv'][1:]]
        assert result.get('wait_at_case_close') is (True if case==worker.SERVER_INQUIRY else None)
        assert host.intents[1]['run_worker']
    else:
        with pytest.raises(Refused):
            worker.proposal(host,{},raw)
        assert mutation=='repeat' or not host.intents


@pytest.mark.parametrize('status',[0,1,-15])
def test_worker_execution_requires_ready_and_authorized_signal(status):
    from source_observer import Observer

    host=object.__new__(Observer)
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(None,None,status)))
    actor={'birth':object(),'role':'fixed-inline','case':next(iter(worker.CASES)),'body_ready':True,'token':'token','signals':set()}
    host.intents={1:{'run_worker':True,'birth':actor['birth'],'token':'token','consumed':True}}
    host.intents[1].update(ticket=1,role=actor['role'],case=actor['case'])
    actor['intent']=host.intents[1]
    assert host.completed_child(actor) is (status>=0)
    actor['body_ready']=False
    assert not host.completed_child(actor)


@pytest.mark.parametrize('name',('executor_fixture','unrest_harness.api'))
def test_fixed_loader_refuses_already_imported_module(monkeypatch,name):
    import sys
    monkeypatch.setitem(sys.modules,name,object())
    binding={'kind':'undeliverable','path':'/owned/sitecustomize.py'} if name.endswith('.api') else {'path':'/owned/executor_fixture.py'}
    def refuse(code):
        raise Refused(code)
    policy=SimpleNamespace(profile={'checkout':'/source','execution':{'fixture':binding}},refuse=refuse)
    before=list(sys.meta_path)
    with pytest.raises(Refused,match='imported before'):
        worker.install_fixture(policy)
    assert sys.meta_path==before


@pytest.mark.parametrize('mutation',[None,'body','inode','symlink','pyc'])
def test_single_executor_loader_compiles_only_acquired_source(tmp_path,monkeypatch,mutation):
    import importlib.util
    import sys
    from content_manifest import _key
    monkeypatch.delitem(sys.modules,'executor_fixture',raising=False)
    source=tmp_path/'executor_fixture.py'
    source.write_text('from pathlib import Path\nlocation=Path(__file__)\nvalue=42\n')
    read=worker.read_regular
    monkeypatch.setattr(worker,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    _,info,pin=worker.read_regular(source,16384)
    binding={'path':str(source),'identity':list(_key(info)),'sha256':pin}
    def refuse(code):
        raise Refused(code)
    policy=SimpleNamespace(profile={'execution':{'fixture':binding}},refuse=refuse)
    before=list(sys.meta_path)
    try:
        worker.install_fixture(policy)
        loader=sys.meta_path[0]
        assert loader.find_spec('foreign_fixture') is None
        if mutation=='body':
            source.write_text('raise AssertionError("unbound bytes executed")\n')
        elif mutation=='inode':
            other=tmp_path/'replacement'
            other.write_bytes(source.read_bytes())
            other.replace(source)
        elif mutation=='symlink':
            other=tmp_path/'other'
            source.rename(other)
            source.symlink_to(other)
        elif mutation=='pyc':
            cache=Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir()
            cache.write_bytes(b'untrusted cached executable')
        spec=loader.find_spec('executor_fixture')
        module=importlib.util.module_from_spec(spec)
        if mutation in ('body','inode','symlink'):
            with pytest.raises(Refused,match='import refused'):
                loader.exec_module(module)
            assert not hasattr(module,'value')
        else:
            loader.exec_module(module)
            assert module.value==42 and module.location==source and module.__file__==str(source)
            assert spec.origin==str(source) and str(tmp_path) not in sys.path
    finally:
        sys.meta_path[:]=before


@pytest.mark.parametrize('name',worker.NAMES)
def test_each_original_worker_fixture_is_pinned_and_no_cwd_import_is_added(tmp_path,monkeypatch,name):
    case=worker.TEST+'::test_'+name
    home=tmp_path/'pytest'/('test_'+name.split('[')[0])[:30]
    home=home.with_name(home.name+'0')
    home.mkdir(parents=True)
    checkout=Path(__file__).resolve().parents[2]
    from launch_policy import source_unit,literal
    body=literal(source_unit(checkout,worker.TEST,worker.PIN),'_EXECUTOR_SOURCE')
    if name==worker.NAMES[-2]:
        body=body.replace('    counter = Path.cwd()',
            '    import atexit; atexit.register(time.sleep, 0.4)\n    counter = Path.cwd()')
    elif name==worker.NAMES[-1]:
        body="import pathlib,time\nwhile not pathlib.Path(__file__).with_name('allow-start').exists(): time.sleep(0.01)\n"+body
    (home/'executor_fixture.py').write_text(body)
    acquire=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,uid:acquire(path,owned,prefix,os.getuid()))
    read=worker.read_regular
    monkeypatch.setattr(worker,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    host=SimpleNamespace(case=case,meta={'checkout':str(checkout),'owned':str(tmp_path)},fixture_roots={})
    assert worker.fixture(host,home)['path']==str(home/'executor_fixture.py')
    (home/'executor_fixture.py').write_text(body+'\n# changed')
    with pytest.raises(Refused,match='original executor bytes'):
        worker.fixture(host,home)


@pytest.mark.parametrize('case',tuple(worker.WORKERS))
@pytest.mark.parametrize('actual',(-15,-9,0,1,2,17))
def test_each_worker_ordinal_requires_real_execution_and_authorized_cleanup(case,actual):
    from source_observer import Observer
    host=object.__new__(Observer)
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(None,None,actual)))
    for _ in range(worker.MAXIMUM[case]):
        actor={'birth':object(),'role':'fixed-inline','case':case,'body_ready':True,'token':'token','signals':{9,15}}
        host.intents={1:{'run_worker':True,'birth':actor['birth'],'token':'token','consumed':True}}
        host.intents[1].update(ticket=1,role=actor['role'],case=actor['case'])
        actor['intent']=host.intents[1]
        assert host.completed_child(actor) is True
        actor['signals']=set()
        assert host.completed_child(actor) is (actual>=0)
