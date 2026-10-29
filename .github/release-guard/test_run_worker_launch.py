"""Async error workers cannot acquire general executor or provider authority."""
from types import SimpleNamespace
import json
import os

import pytest

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
        assert host.intents[1]['null_stdio'] and host.intents[1]['run_worker']
    else:
        with pytest.raises(Refused):
            worker.proposal(host,{},raw)
        assert mutation=='repeat' or not host.intents


@pytest.mark.parametrize('status',[0,1,-15])
def test_async_error_result_requires_normal_process_exit_and_ready(status):
    from source_observer import Observer

    host=object.__new__(Observer)
    host.ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=(None,None,status)))
    actor={'birth':object(),'role':'fixed-inline','case':next(iter(worker.CASES)),'body_ready':True}
    assert host.completed_child(actor) is (status==0)
    actor['body_ready']=False
    assert not host.completed_child(actor)
