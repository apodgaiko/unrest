"""Controlled relay byte reconstruction and independently observed ancestry."""
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import approval_launch as approval
from content_manifest import Refused

CHECKOUT=Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('mutation',[None,'backend','relay-body','token','socket','generation','extra-call'])
def test_relay_requires_exact_fixture_and_four_scoped_literals(tmp_path,monkeypatch,mutation):
    native='/sealed/python-unrest-guard-control'
    backend=tmp_path/'controlled-backend'
    backend.write_bytes(b'#!'+native.encode()+b'\n'+(CHECKOUT/approval.BACKEND).read_bytes())
    backend.chmod(0o700)
    pin=hashlib.sha256(backend.read_bytes()).hexdigest()
    root=tmp_path/'unrest-approval-abcdefgh'
    root.mkdir(mode=0o700)
    socket=str(root/'control')
    token='a'*64
    if mutation=='token':
        token='foreign'
    if mutation=='socket':
        socket='/foreign/control'
    path=root/'backend'
    body=(f'#!{native}\nimport sys\nsys.path.insert(0, {str(CHECKOUT/"src")!r})\n'
        'from unrest_harness.approval_relay import main\n'+f'main({socket!r}, {token!r}, {str(backend)!r}, {pin!r})\n')
    if mutation=='relay-body':
        body=body.replace('import sys','import os')
    if mutation=='extra-call':
        body+='print("extra")\n'
    path.write_text(body)
    path.chmod(0o700)
    if mutation=='backend':
        backend.write_text('foreign')
    info=root.stat()
    host=SimpleNamespace(case=approval.CASES[0],meta={'checkout':str(CHECKOUT)},
        binding={'entry':{'path':native}},fixture_roots={('approval-unix',approval.CASES[0],str(root/'control')):
            (info.st_dev,info.st_ino+int(mutation=='generation'))})
    original=approval.read_regular
    monkeypatch.setattr(approval,'read_regular',lambda file,limit,**kwargs:original(file,limit,**{**kwargs,'uid':os.getuid()}))
    if mutation:
        with pytest.raises(Refused):
            approval.relay(host,tmp_path,path)
    else:
        assert approval.relay(host,tmp_path,path)==(hashlib.sha256(path.read_bytes()).hexdigest(),pin)


@pytest.mark.parametrize('mutation',[None,'case','role','signal','group','parent','reused','not-ready','zombie','reaped'])
def test_descendant_signal_requires_actual_bound_chain(tmp_path,monkeypatch,mutation):
    root=SimpleNamespace(pid=10)
    adapter=SimpleNamespace(pid=11)
    child=SimpleNamespace(pid=12)
    owner={'birth':root,'body_ready':True,'role':'root'}
    actor={'birth':child,'case':approval.CASES[0],'role':'approval-backend','body_ready':True,'signals':set()}
    processes={12:SimpleNamespace(parent=adapter,exit=None,terminal=None),11:SimpleNamespace(parent=root)}
    host=SimpleNamespace(case=approval.CASES[0],root_only=lambda value:None,actors={12:actor},
        ledger=SimpleNamespace(process=lambda birth:processes[birth.pid],peer_birth=lambda birth:birth))
    import linux_observation
    import process_ledger
    monkeypatch.setattr(linux_observation,'process_identity',lambda pid:'identity')
    def credentials(pid):
        if mutation=='reaped':
            raise ProcessLookupError()
        return 'identity'
    monkeypatch.setattr(linux_observation,'credential_identity',credentials)
    monkeypatch.setattr(process_ledger.Birth,'read',lambda value:child if mutation!='reused' else root)
    payload={'pid':12,'signal':0,'group':False}
    if mutation=='case':
        host.case='foreign'
    elif mutation=='role':
        actor['role']='mcp'
    elif mutation=='signal':
        payload['signal']=15
    elif mutation=='group':
        payload['group']=True
    elif mutation=='parent':
        processes[11].parent=None
    elif mutation=='not-ready':
        actor['body_ready']=False
    elif mutation in ('zombie','reaped'):
        processes[12].terminal=(1,0,0)
    if mutation not in (None,'zombie','reaped'):
        with pytest.raises(Refused):
            approval.signal(host,owner,payload)
        assert actor['signals']==set()
    else:
        assert approval.signal(host,owner,payload)=={'ok':True,'live':mutation!='reaped'}
        assert actor['signals']==set()


def test_normalization_selects_only_the_measured_controlled_chain_image(monkeypatch):
    from source_entry import direct_native
    import sys
    args=(['/owned/backend','app-server'],)
    monkeypatch.setattr(sys,'executable','/sealed/python')
    for role in ('approval-adapter','approval-relay'):
        assert direct_native(args,{},approval.CASES[0],role)==(args,{'executable':'/sealed/python'})
        assert direct_native(args,{},'foreign',role)==(args,{})
    assert direct_native(args,{},approval.CASES[0],'root')==(args,{})


@pytest.mark.parametrize('mutation',[None,'argv','environment','cwd','stdin','duplicate'])
def test_owned_mcp_is_the_actual_owner_pid_and_one_inventory_pipe(tmp_path,monkeypatch,mutation):
    from cleanup_launch import environment
    native='/sealed/python'
    case=approval.CASES[0]
    base=tmp_path/'case'
    (base/'workspace').mkdir(parents=True)
    monkeypatch.setattr(approval,'retain',lambda *args:base)
    import cleanup_launch
    seen=[]
    monkeypatch.setattr(cleanup_launch,'read_pipe',lambda birth,fd:seen.append((birth,fd)) or [fd,1,2])
    host=SimpleNamespace(case=case,meta={'checkout':str(CHECKOUT)},binding={'entry':{'path':native,'sha256':'a'*64}},
        root_only=lambda actor:None,meta_environment=lambda:{'PATH':'/bin'},intents={})
    calls=[]
    host.admit_launch=lambda *args,**kwargs:calls.append((args,kwargs)) or None
    owner=SimpleNamespace(pid=17)
    actor={'role':'root','birth':owner}
    body='from unrest_harness.approval_recovery import run_owned_mcp; run_owned_mcp(17)'
    argv=[native,'-c',body,'--mode','worker','--transport','streamable-http','--host','127.0.0.1','--port','12345','--sensitive-inventory-fd','7']
    raw={'executable':native,'argv':argv,'environment':environment(base,{'PATH':'/bin'},agent=False),'cwd':str(base/'workspace'),'stdin':None}
    if mutation=='argv':
        argv[2]=body.replace('(17)','(18)')
    elif mutation=='environment':
        raw['environment']['CODEX_PATH']='/foreign'
    elif mutation=='cwd':
        raw['cwd']=str(base/'foreign')
    elif mutation=='stdin':
        raw['stdin']='foreign'
    elif mutation=='duplicate':
        host.intents={1:{'case':case}}
    if mutation:
        with pytest.raises(Refused):
            approval.proposal(host,actor,raw)
        assert not calls
    else:
        assert approval.proposal(host,actor,raw) is None
        assert seen==[(owner,7)] and calls[0][1]['inherited']==[[7,1,2]]
        assert calls[0][0][2]=='mcp' and calls[0][0][3]==[native,'-I','-S',*argv[1:]]


def test_adapter_waits_for_authenticated_mcp_ready(tmp_path,monkeypatch):
    monkeypatch.setattr(approval,'retain',lambda *args:tmp_path)
    calls=[]
    host=SimpleNamespace(case=approval.CASES[0],meta={'checkout':str(CHECKOUT)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},
        root_only=lambda actor:None,meta_environment=lambda:{},executed=lambda row:True,
        intents={1:{'case':approval.CASES[0],'role':'mcp','pid':2}},actors={2:{'body_ready':False}},
        admit_launch=lambda *args,**kwargs:calls.append(args))
    raw={'executable':'/native','argv':['/native',str(CHECKOUT/approval.ADAPTER),'scenario'],
         'cwd':str(tmp_path/'workspace'),'environment':{},'stdin':None}
    assert approval.proposal(host,{'role':'root'},raw) is None
    assert not calls


@pytest.mark.parametrize('mutation',[None,'executor','environment','request-generation','argv-generation','cwd'])
def test_durable_worker_keeps_exact_executor_request_and_private_environment(tmp_path,monkeypatch,mutation):
    import run_worker_launch
    native='/sealed/python'
    base=tmp_path/'case'
    home=base/'run-home'
    root=base/'run-fixture'
    run='run:'+'a'*64
    path=home/'.unrest/runs'/run[4:]/'request.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'run_id':run,'operation':'advance_project','generation':2 if mutation=='request-generation' else 1,'arguments':{'project_id':'project'}}))
    path.chmod(0o600)
    read=run_worker_launch.read_regular
    monkeypatch.setattr(run_worker_launch,'read_regular',lambda file,limit,**kwargs:read(file,limit,**{**kwargs,'uid':os.getuid()}))
    monkeypatch.setattr(approval,'retain',lambda *args:base)
    env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(CHECKOUT)+':'+str(CHECKOUT/'src'),
        'UNREST_HOME':str(root/'home'),'UNREST_PROJECTS_DIR':str(root/'home/projects'),
        'CONTROLLED_RUN_ROOT':str(root),'CONTROLLED_RUN_NATIVE':str(base/'controlled-backend'),
        'CONTROLLED_RUN_TRACE':str(base/'run-methods.jsonl'),
        'CONTROLLED_RUN_COMMAND':native+' '+str(CHECKOUT/approval.ADAPTER)+' '+str(base/'run-scenario.json')}
    vector=[native,'-m','unrest_harness.run_worker','--project-root',str(home),'--run-id',run,
        '--executor','tests.fixtures.approval_run_executor:execute','--custody-root-id','local:unrest-run-control','--generation','1']
    raw={'argv':vector,'environment':env,'cwd':str(home),'stdin':None}
    if mutation=='executor':
        vector[8]='foreign:execute'
    elif mutation=='environment':
        env['CODEX_PATH']='/foreign'
    elif mutation=='argv-generation':
        vector[-1]='2'
    elif mutation=='cwd':
        raw['cwd']=str(base/'foreign')
    calls=[]
    host=SimpleNamespace(case=approval.RUNS[0],meta={'checkout':str(CHECKOUT)},
        binding={'entry':{'path':native,'sha256':'a'*64}},root_only=lambda actor:None,intents={})
    def admit(actor,value,role,translated,payload,**options):
        calls.append((value,role,translated,options))
        host.intents[1]={}
        return {'ticket':1,'token':'worker'}
    host.admit_launch=admit
    if mutation:
        with pytest.raises(Refused):
            approval.worker(host,{'role':'root'},raw)
        assert not calls
    else:
        assert approval.worker(host,{'role':'root'},raw)['ticket']==1
        assert host.intents[1]['approval_worker'] is True
        assert calls[0][1]=='fixed-inline' and calls[0][3]['maximum']==1
        assert host.intents[1]['run_worker'] is True
