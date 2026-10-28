"""Finite process proposals; Python callers confer no execution authority.

The observer chooses a declaration from the externally selected case, compares
all observed operands, then applies its existing launch, kernel and wait ledger.
"""
from pathlib import Path
import hashlib

from content_manifest import Refused
from plan_launch import CASES as PLANS, expected as plan_expected
from session_launch import CASES as SESSIONS, expected as session_expected
from fixed_inline import CASES as FIXED, SEQUENCES, expected as fixed_expected, STDIO, startup_expected, translated as fixed_translated
from ordinary_acp import CASES as ORDINARY, expected as ordinary_expected
from cleanup_launch import EXECUTION_CASES as CLEANUP, expected as cleanup_expected, base_path, module_site, translated as cleanup_vector
from cleanup_inline import DECLARATIONS, INFLIGHT, expected as inline_expected
from controlled_startup import expected_entry, ACP
from controlled_cases import CASES as CONTROLLED
from bootstrap_cases import BOOTSTRAP


def proposal(host, actor, raw, *, payload=None):
    from source_observer import shape
    host.launch_owner(actor)
    from control_transport import finite
    finite(raw)
    shape(raw, ('case','executable','argv','cwd','environment','stdin'))
    case = host.case
    if raw['case'] != case or type(raw['executable']) is not str or type(raw['argv']) is not list:
        raise Refused('finite process proposal case or vector')
    argv = raw['argv']
    if (not 0 < len(argv) <= 256 or any(type(arg) is not str for arg in argv)
            or raw['executable'] != argv[0] or type(raw['cwd']) is not str
            or type(raw['environment']) is not dict
            or any(type(k) is not str or type(v) is not str for k,v in raw['environment'].items())):
        raise Refused('finite process proposal operands')
    from git_sites import CASES as GIT_CASES
    if case in GIT_CASES:
        from git_proposals import prepare
        return prepare(host,actor,raw)
    if case not in (*BOOTSTRAP,*CONTROLLED,*ORDINARY,*CLEANUP,*DECLARATIONS,*SESSIONS,*FIXED,*PLANS):
        raise Refused('finite process proposal has no declaration')
    if raw['stdin'] is not None:
        raise Refused('process proposal has undeclared commit input')
    checkout, owned = Path(host.meta['checkout']), Path(host.meta['owned'])
    native, pin = host.binding['entry']['path'], host.binding['entry']['sha256']
    cwd, root_environment = raw['cwd'], host.meta_environment()
    vector, role, maximum, inherited, port = None, None, 1, [], None
    extra_environment=None
    custody=case in CONTROLLED and argv[0]=='/usr/bin/git'
    if custody:
        from custody_git import command as custody_command,ENVIRONMENT,SOURCE
        from git_observer import image
        from launch_policy import Rule,render
        value,_=custody_command(case,tuple(argv),cwd,owned)
        expected=render(Rule('custody:git',SOURCE+':git',(case,),'/usr/bin/git',image(),value.argv,tuple(sorted(ENVIRONMENT.items())),cwd,'native'),case,SOURCE+':git',{}, {})
        site,script_pin,vector=38,None,list(value.argv)
    elif case in PLANS:
        model = plan_expected(case,cwd,owned,native,pin)
        expected, site, vector = model.expected,409,list(model.vector)
        script_pin = expected.payload_sha256
    elif case in SESSIONS:
        from session_launch import TIMEOUT,INVALID,INVALID_BYTES
        child = actor['role']=='session-adapter'
        if child and case!=TIMEOUT or not child and actor['role']!='root':
            raise Refused('session original launch parent')
        expected = session_expected(case,cwd,checkout,owned,native,pin,root_environment,child=child)
        site,script_pin = (50 if child else 75),expected.payload_sha256
        role='session-invalid' if case in INVALID else 'session-child' if child else 'session-inline' if expected.payload_kind=='python-command' else 'session-adapter'
        if role=='session-invalid':
            from git_observer import regular
            if regular(Path(expected.executable))!=INVALID_BYTES or Path(expected.executable).stat().st_mode&0o777!=0o700:
                raise Refused('session exact invalid executable fixture')
        vector = list(expected.argv) if expected.payload_kind=='expected-exec-failure' else [native,'-I','-S',*expected.argv[1:]]
    elif case in FIXED:
        query = actor['role']=='fixed-inline'
        records = [row for row in host.intents.values() if row['case']==case and row['role']=='fixed-inline']
        if not query and (len(records)>=len(SEQUENCES[case]) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records)):
            raise Refused('finite fixed proposal exhausted')
        operation = 'check' if query else SEQUENCES[case][len(records)]
        environment = {**root_environment,'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
        if case in STDIO:
            if query:
                raise Refused('fixed startup has no descendant query')
            expected = startup_expected(case,native,pin,cwd,owned)
        else:
            expected = fixed_expected(case,operation,native,pin,checkout,environment,query=query)
        site,script_pin = (507 if query else 107 if case in STDIO else 587 if operation=='mcp' else 540),expected.payload_sha256
        vector = list(expected.argv) if query else list(fixed_translated(expected))
        role,maximum='git-fixed' if query else 'fixed-inline',1 if query else len(SEQUENCES[case])
    elif case in ORDINARY:
        host.root_only(actor)
        role='sleep' if argv[0]=='/bin/sleep' else 'mock-acp'
        maximum=2 if case==ORDINARY[2] and role=='sleep' else 1
        expected = ordinary_expected(case,'sleep' if argv[0]=='/bin/sleep' else 'mock-acp',cwd,checkout,native,pin,root_environment,owned)
        site = 409 if expected.rule=='ordinary:mock-acp' else 1383 if case==ORDINARY[2] else 1843
        script_pin = expected.payload_sha256
        vector = list(expected.argv) if expected.rule=='ordinary:sleep' else [native,'-I','-S',*expected.argv[1:]]
    elif case in DECLARATIONS:
        host.root_only(actor)
        from cleanup_inline import child_count
        records = [row for row in host.intents.values() if row['case']==case]
        terminal = case in INFLIGHT and len(records)==2
        if len(records)>=child_count(case) or any(not row['consumed'] or not host.actors[row['pid']]['returned'] for row in records):
            raise Refused('cleanup inline original child order')
        role,maximum='cleanup-inline',child_count(case)
        expected,site = inline_expected(case,native,pin,checkout,root_environment,base=base_path(cwd,owned) if terminal else None,terminal=terminal)
        script_pin,vector = expected.payload_sha256,[native,'-I','-S',*expected.argv[1:]]
    elif case in CLEANUP:
        port,descriptor = None,None
        if argv[0]=='git':
            role = 'git-observe' if actor['role']=='mcp' else 'git-init' if argv[1:3]==['init','-q'] else 'git-commit'
        else:
            role = 'mcp' if argv[1:2]==['-m'] else 'cleanup-acp'
        base = base_path(str(Path(argv[-1]).parent) if role=='git-init' else str(Path(cwd).parent),owned)
        if role=='mcp':
            if len(argv)!=13 or not argv[-3].isdigit() or not argv[-1].isdigit():
                raise Refused('finite module port and descriptor')
            port,descriptor = int(argv[-3]),int(argv[-1])
        if (actor['role']=='mcp')!=(role=='git-observe'):
            raise Refused('cleanup original parent role')
        if role=='mcp':
            from cleanup_launch import read_pipe,OFFLINE
            inherited=[read_pipe(actor['birth'].pid,descriptor)]
        expected = cleanup_expected(case,role,base,native,pin,checkout,root_environment,port=port,descriptor=descriptor)
        site = {'mcp':module_site(case),'cleanup-acp':409,'git-init':131,'git-commit':132,'git-observe':266}[role]
        script_pin,vector = expected.payload_sha256,list(cleanup_vector(expected,host.directory))
        from cleanup_launch import OFFLINE
        extra_environment={**dict(expected.environment),**(OFFLINE if role=='mcp' else {})}
    elif case in (*BOOTSTRAP,*CONTROLLED):
        host.root_only(actor)
        from controlled_pairs import scope,before_spawn
        from bootstrap_cases import declaration
        if case in CONTROLLED:
            scope(case,'bridge',cwd,owned)
        elif (str(Path(cwd).resolve())!=cwd or not Path(cwd).is_relative_to(owned)
                or Path(cwd).name!='worker' or Path(cwd).parent.name!='owner' or declaration(case).children==0):
            raise Refused('source declared worker launch home')
        backend = argv[1:2]!=[str(checkout/ACP)]
        role='backend' if backend else 'acp'
        records=[row for row in host.intents.values() if row['case']==case]
        if case in CONTROLLED:
            before_spawn(case,cwd,role,records,host.actors)
        elif not backend:
            backends=[row for row in records if row['role'] in ('backend','delayed-backend')]
            if len(backends)!=1 or not backends[0]['consumed'] or not host.actors[backends[0]['pid']]['returned']:
                raise Refused('source ACP before owned backend return')
        from configuration_inputs import check_inputs
        check_inputs(checkout,Path(cwd),case)
        relay = None
        if not backend:
            bridge = host.listeners[host.listener_key(case,'bridge',cwd)]
            lifetime = host.listeners[host.listener_key(case,'lifetime',cwd)]
            relay = [bridge['socket'].local[1],bridge['nonce'],lifetime['socket'].local[1],lifetime['nonce']]
        expected,_,script_pin = expected_entry(case,checkout,Path(cwd),native,pin,backend=backend,relay=relay)
        site,vector = (506 if backend else 553),[native,'-I','-S',*expected.argv[1:]]
        if backend and expected.payload_kind=='python-command':
            role='delayed-backend'
    else:
        raise Refused('finite process proposal has no declaration')
    if (tuple(argv)!=expected.argv or cwd!=expected.cwd or raw['environment']!=dict(expected.environment)):
        raise Refused('finite process proposal differs from declaration')
    if payload is None:
        payload={'case':case,'original':expected.wire(),'translated':vector,'source_line':site,'script_sha256':script_pin}
    if case in PLANS:
        from plan_observer import launch
        answer=launch(host,actor,payload)
    elif custody:
        from custody_git import launch
        answer=launch(host,actor,payload)
    else:
        answer=host.admit_launch(actor,payload,expected,role,site,vector,script_pin,
            maximum=maximum,environment=extra_environment,inherited=inherited,port=port)
    if answer is not None and case in FIXED:
        host.intents[answer['ticket']].update(fixed_operation=operation,input_pipe=case in STDIO)
    if answer is not None and case in CLEANUP and role=='cleanup-acp':
        from cleanup_launch import scenario,snapshot_path
        from source_profile import digest
        body=scenario(case,base)
        if digest(base/'scenario.json')!=hashlib.sha256(body).hexdigest():
            raise Refused('cleanup source scenario content')
        snapshot=snapshot_path(host.directory,case)
        with snapshot.open('xb') as stream:
            stream.write(body)
        snapshot.chmod(0o444)
        host.intents[answer['ticket']]['execution_data']=[[str(snapshot),hashlib.sha256(body).hexdigest()]]
    if answer is None:
        return None
    intent=host.intents[answer['ticket']]
    command=intent.get('command')
    return {**answer,'translated':vector,'rule':expected.rule,
            'command':None if command is None else {'stdin':command.stdin,'produces':[command.produces[0],command.produces[1],list(command.produces[2])] if command.produces else None}}
