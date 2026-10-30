"""Exact HTTP command reconstruction; no native execution is claimed here."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from content_manifest import Refused
import http_cases


@pytest.fixture(params=http_cases.SUPERVISION)
def prepared(request,tmp_path):
    checkout=tmp_path/'source'
    cwd=tmp_path/'pytest/case/workspace'
    cwd.mkdir(parents=True)
    host=SimpleNamespace(case=request.param,root_only=lambda actor:None,
        binding={'entry':{'path':'/native','sha256':'a'*64}},
        meta={'checkout':str(checkout),'owned':str(tmp_path)},meta_environment=lambda:{'PATH':'/usr/bin:/bin'},
        probe_ports={request.param:{'socket':SimpleNamespace(local=('127.0.0.1',12345))}})
    raw={'argv':['/native','12345'], 'cwd':str(cwd), 'stdin':None}
    return host,raw


def test_exact_original_http_role_environment_and_program(prepared):
    host,raw=prepared
    value,role,port=http_cases.expected(host,{},raw)
    subject=host.case.rsplit('-',1)[1][:-1]
    assert role=='mcp' and port==12345
    assert value.argv[3:] == ('--mode',subject.replace('_','-'),'--transport','streamable-http','--host','127.0.0.1','--port','12345')
    assert str(Path(host.meta['checkout'])/'tests/fixtures/supervision_role_process.py') in value.argv[2]
    environment=dict(value.environment)
    assert environment['UNREST_PROJECT_ID']=='project-1'
    assert environment['UNREST_WORKER_ACP_COMMAND']=='/bin/true'
    assert ('UNREST_NODE_ID' in environment)==(subject!='terminal_reviewer')
    assert ('UNREST_TERMINAL_REVIEW_ID' in environment)==(subject=='terminal_reviewer')


@pytest.mark.parametrize('mutation',['foreign-case','outside','sibling','stdin','no-port'])
def test_http_declarations_cannot_select_unrelated_scope(prepared,mutation):
    host,raw=prepared
    raw=deepcopy(raw)
    if mutation=='foreign-case':
        host.case='foreign'
    elif mutation=='outside':
        raw['cwd']='/outside/workspace'
    elif mutation=='sibling':
        raw['cwd']=str(Path(raw['cwd']).with_name('other'))
    elif mutation=='stdin':
        raw['stdin']='private input'
    else:
        raw['argv'][-1]='invalid-port'
    with pytest.raises(Refused):
        http_cases.expected(host,{},raw)


@pytest.mark.parametrize('field', ['argv','environment','cwd'])
def test_changed_original_operands_never_create_http_intent(prepared,field):
    host,raw=prepared
    value,_,_=http_cases.expected(host,{},raw)
    raw.update(argv=list(value.argv),environment=dict(value.environment),cwd=value.cwd)
    calls=[]
    host.admit_launch=lambda *args,**kwargs:calls.append((args,kwargs)) or {'ticket':1,'token':'owned'}
    changed=deepcopy(raw)
    if field=='argv':
        changed[field][2]+='; import os; os.system("forbidden")'
    elif field=='environment':
        changed[field]['UNREST_WORKER_ACP_COMMAND']='/foreign/provider'
    else:
        changed[field]=str(Path(raw['cwd']).with_name('other'))
    with pytest.raises(Refused):
        http_cases.proposal(host,{},changed)
    assert not calls
    answer=http_cases.proposal(host,{},raw)
    assert answer['translated']==['/native','-I','-S',*value.argv[1:]]
    assert len(calls)==1 and calls[0][1]['port']==12345
    assert 'environment' not in calls[0][1] and calls[0][0][1].environment==value.environment
    assert 'FASTMCP_CHECK_FOR_UPDATES' not in raw['environment']


@pytest.mark.parametrize('phase',['absent','unconsumed','unreaped','reaped'])
def test_ps_inventory_is_exact_and_follows_original_server_wait(prepared,monkeypatch,phase):
    host,raw=prepared
    row={'case':host.case,'role':'mcp','consumed':phase!='unconsumed','birth':'birth','token':'server'}
    host.intents={} if phase=='absent' else {1:row}
    host.ledger=SimpleNamespace(reaped=lambda *args:phase=='reaped')
    raw.update(argv=['ps','-axo','pid=,ppid=,pgid='],cwd=host.meta['checkout'])
    monkeypatch.setattr(http_cases,'image',lambda path:'b'*64)
    if phase!='reaped':
        with pytest.raises(Refused,match='before original server wait'):
            http_cases.expected(host,{},raw)
    else:
        value,role,port=http_cases.expected(host,{},raw)
        assert role=='ps' and port is None and value.executable=='/usr/bin/ps'
        assert value.argv==('ps','-axo','pid=,ppid=,pgid=')


@pytest.mark.parametrize('subject',['http','foreign-mcp','http-extra-fd','http-mount','http-filesystem','http-filesystem-type'])
def test_http_authority_and_inherited_profile_descriptors_remain_closed(tmp_path,monkeypatch,subject):
    import os
    import source_profile as profiles
    from execution_spec import issue
    from process_ledger import canonical
    from test_multiprocess_catalogue import LOCK

    if subject=='foreign-mcp':
        host=SimpleNamespace(case=tuple(LOCK)[0],root_only=lambda actor:None,intents={})
        with pytest.raises(Refused,match='HTTP original case'):
            http_cases.proposal(host,{}, {})
        assert not host.intents
        return

    # Synthetic kernel/mount observations isolate the real role/profile validator.
    # Native CI, not this control, proves the actual credentials and mount facts.
    def identity(pid,uid,parent):
        return {'pid':pid,'tgid':pid,'ppid':parent,'start_ticks':1,'boot_id':'boot',
            'uids':[uid]*4,'gids':[uid]*4,'pgid':pid,'sid':pid,'clock_ticks_per_second':100,
            'capabilities':{},'no_new_privs':1,'seccomp':2,'namespaces':{'net':'net:[123]','mnt':'synthetic','pid':'pid:[123]'}}
    actual=identity(os.getpid(),20000,os.getppid())
    parent=identity(os.getppid(),20000,1)
    observer=identity(os.getpid()+1000,20001,1)
    case=http_cases.CASES[0] if subject.startswith('http') else tuple(LOCK)[0]
    runtime=tmp_path/'runtime'
    native=str(runtime/'bin/python-unrest-guard-control')
    vector=[native,'-I','-S','-c','pass']
    environment={'PATH':'/usr/bin:/bin'}
    profile={key:'a'*64 for key in ('entry_sha256','native_sha256','source_sha256','support_sha256','runtime_sha256','dependency_sha256')}
    profile.update(schema='unrest.bootstrap-source.v1',role='mcp',case=case,
        cases=list(http_cases.SUPERVISION if subject.startswith('http') else tuple(LOCK)),
        native=native,checkout=str(tmp_path/'source'),owned=str(tmp_path/'owned'),
        dependencies=str(tmp_path/'dependencies'),runtime_root=str(runtime),cwd=str(tmp_path),
        identity=canonical(actual),parent=canonical(parent),observer=canonical(observer),
        generation=1,argv=vector,environment=environment,token='a'*32,
        filesystem_root=[1,2],
        mount_namespace='synthetic',network_namespace='net:[123]',pid_namespace='pid:[123]',script=None,inherited=[[7,1,2]] if subject in ('http-extra-fd','foreign-mcp') else [],execution=issue('mcp',vector,None,None))
    profile['mounts']={name:[] for name in (profile['checkout'],profile['dependencies'],str(runtime),str(Path(profiles.__file__).parent))}
    monkeypatch.setattr(profiles,'process_identity',lambda pid:actual)
    monkeypatch.setattr(profiles,'credential_identity',lambda pid:parent)
    monkeypatch.setattr(profiles,'digest',lambda path:'a'*64)
    monkeypatch.setattr(profiles,'sys',SimpleNamespace(executable=native,orig_argv=vector,
        flags=SimpleNamespace(isolated=1,no_site=1,dont_write_bytecode=0,utf8_mode=1)))
    monkeypatch.setattr(profiles,'os',SimpleNamespace(getpid=os.getpid,getppid=os.getppid,stat=lambda path:SimpleNamespace(st_dev=1,st_ino=2),
        readlink=lambda path:'pid:[123]' if path.endswith('/pid') else 'net:[123]',getcwd=lambda:str(tmp_path),environ=environment,listdir=lambda path:['7'] if subject=='foreign-mcp' else [],fstat=lambda fd:object()))
    monkeypatch.setattr(profiles,'fcntl',SimpleNamespace(F_GETFL=3,fcntl=lambda *args:0))
    monkeypatch.setattr(profiles,'inherited_descriptor',lambda inherited,fd,*args:[fd,1,2])
    if subject.startswith('http-filesystem'):
        profile['filesystem_root']=[1,3] if subject=='http-filesystem' else [True,2]
        with pytest.raises(Refused,match='private filesystem generation'):
            profiles.validate(profile,'cpython.run_command',('pass\n',))
    elif subject=='http-mount':
        profile['mount_namespace']='foreign'
        with pytest.raises(Refused,match='actual profile binding'):
            profiles.validate(profile,'cpython.run_command',('pass\n',))
    elif subject=='http':
        observed=profiles.validate(profile,'cpython.run_command',('pass\n',))
        assert observed==actual
    else:
        with pytest.raises(Refused,match='finite inherited inventory'):
            profiles.validate(profile,'cpython.run_command',('pass\n',))


def test_http_proposals_reject_a_leaf_even_with_the_root_birth(tmp_path):
    from test_source_integration import backend_request
    observer,actor,_=backend_request(tmp_path)
    observer.case=http_cases.CASES[0]
    with pytest.raises(Refused,match='root-only'):
        http_cases.proposal(observer,{**actor,'role':'mcp'},{})
    assert not observer.intents








def test_http_parent_preserves_original_environment_during_translation():
    import threading
    from source_entry import Policy
    policy=object.__new__(Policy)
    policy.profile={'role':'root'}
    policy.case=http_cases.CASES[0]
    policy.local=threading.local()
    observed=[]
    def request(kind,payload):
        observed.append(payload)
        return {'ok':True,'ticket':1,'token':'owned','translated':['/native','-I','-S','-c','pass']}
    policy.client=SimpleNamespace(request=request)
    environment={'PATH':'/usr/bin:/bin'}
    vector=['/native','-c','pass']
    policy.popen(('/native',vector,'/source',environment))
    assert observed[0]['environment']=={'PATH':'/usr/bin:/bin'}
    assert environment=={'PATH':'/usr/bin:/bin'}
    assert vector==['/native','-I','-S','-c','pass']
