"""Exact HTTP command reconstruction; no native execution is claimed here."""
from copy import deepcopy
from pathlib import Path
import socket
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


@pytest.mark.parametrize('subject',['http','foreign-mcp','http-extra-fd','http-mount'])
def test_http_authority_and_inherited_profile_descriptors_remain_closed(tmp_path,monkeypatch,subject):
    import os
    import source_profile as profiles
    from execution_spec import issue
    from process_ledger import canonical
    from multiprocess_routes import LOCK

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
            'capabilities':{},'no_new_privs':1,'seccomp':2,'namespaces':{'net':'net:[123]','mnt':'synthetic'}}
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
        mount_namespace='synthetic',network_namespace='net:[123]',script=None,inherited=[[7,1,2]] if subject in ('http-extra-fd','foreign-mcp') else [],execution=issue('mcp',vector,None,None))
    profile['mounts']={name:[] for name in (profile['checkout'],profile['dependencies'],str(runtime),str(Path(profiles.__file__).parent))}
    monkeypatch.setattr(profiles,'process_identity',lambda pid:actual)
    monkeypatch.setattr(profiles,'credential_identity',lambda pid:parent)
    monkeypatch.setattr(profiles,'digest',lambda path:'a'*64)
    monkeypatch.setattr(profiles,'sys',SimpleNamespace(executable=native,orig_argv=vector,
        flags=SimpleNamespace(isolated=1,no_site=1,dont_write_bytecode=0,utf8_mode=1)))
    monkeypatch.setattr(profiles,'os',SimpleNamespace(getpid=os.getpid,getppid=os.getppid,
        readlink=lambda path:'net:[123]',getcwd=lambda:str(tmp_path),environ=environment,listdir=lambda path:['7'] if subject=='foreign-mcp' else [],fstat=lambda fd:object()))
    monkeypatch.setattr(profiles,'fcntl',SimpleNamespace(F_GETFL=3,fcntl=lambda *args:0))
    monkeypatch.setattr(profiles,'inherited_descriptor',lambda inherited,fd,*args:[fd,1,2])
    if subject=='http-mount':
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


@pytest.mark.parametrize('mutation',[None,'stdin','stderr','owner','hardlink','symlink','foreign-case'])
def test_http_stdio_requires_exact_null_and_owned_merged_log(prepared,monkeypatch,mutation):
    import stat
    host,_=prepared
    row={'case':host.case,'role':'mcp','cwd':'/owned/workspace','port':12345,
        'translated':['/native','-I','-S','-c','original','--mode','worker']}
    log=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o644,
        st_uid=20001 if mutation=='owner' else 20000,st_nlink=2 if mutation=='hardlink' else 1)
    null=SimpleNamespace(st_mode=stat.S_IFCHR,st_rdev=123)
    if mutation=='foreign-case':
        row['case']='foreign'
    monkeypatch.setattr(Path,'lstat',lambda *args,**kwargs:log)
    monkeypatch.setattr(Path,'is_symlink',lambda path:mutation=='symlink')
    def observed(path):
        if str(path)=='/dev/null' or path.name=='0' and mutation!='stdin':
            return null
        if path.name=='2' and mutation=='stderr':
            return SimpleNamespace(**{**vars(log),'st_ino':3})
        return log
    monkeypatch.setattr(Path,'stat',observed)
    if mutation is None:
        assert http_cases.stdio(host,123,row)==(1,2)
    else:
        with pytest.raises(Refused):
            http_cases.stdio(host,123,row)




@pytest.mark.parametrize('host',['127.0.0.1',b'127.0.0.1'])
@pytest.mark.parametrize('port',[12345,'12345'])
@pytest.mark.parametrize('flags',[0,socket.AI_PASSIVE,socket.AI_PASSIVE|socket.AI_ADDRCONFIG])
def test_http_literal_resolution_accepts_only_numeric_operands_without_dns(host,port,flags,monkeypatch):
    import socket
    from source_sockets import Hooks
    hooks=object.__new__(Hooks)
    def refuse(reason):
        raise Refused(reason)
    hooks.policy=SimpleNamespace(case=http_cases.CASES[0],profile={'role':'root','case':http_cases.CASES[0]},refuse=refuse)
    monkeypatch.setattr(socket,'getaddrinfo',lambda *args,**kwargs:pytest.fail('DNS resolution attempted'))
    assert hooks.literal_address(host,port,family=socket.AF_INET,type=socket.SOCK_STREAM,
        flags=socket.AddressInfo(flags))==[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,'',('127.0.0.1',12345))]


@pytest.mark.parametrize('field,value', [('host','localhost'),('host',b'example.invalid'),('port','http'),
    ('port',True),('port',65536),('port','１２３'),('flags',2),('family',10),('proto',17),('type',2)])
def test_http_literal_resolution_does_not_add_names_services_or_socket_families(field,value):
    from source_sockets import Hooks
    hooks=object.__new__(Hooks)
    def refuse(reason):
        raise Refused(reason)
    hooks.policy=SimpleNamespace(case=http_cases.CASES[0],profile={'role':'root','case':http_cases.CASES[0]},refuse=refuse)
    operands={'host':'127.0.0.1','port':12345}
    operands[field]=value
    with pytest.raises(Refused,match='nonliteral address query'):
        hooks.literal_address(**operands)


def test_literal_resolution_refusal_records_only_safe_operand_shapes():
    from source_sockets import Hooks
    hooks=object.__new__(Hooks)
    def refuse(reason):
        raise Refused(reason)
    hooks.policy=SimpleNamespace(case=http_cases.CASES[0],profile={'role':'root','case':http_cases.CASES[0]},refuse=refuse)
    with pytest.raises(Refused) as error:
        hooks.literal_address('private-host-secret.invalid',12345,flags=2)
    assert str(error.value)=='source nonliteral address query other 12345 0 0 0 2'
    assert 'private-host-secret' not in str(error.value)


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
