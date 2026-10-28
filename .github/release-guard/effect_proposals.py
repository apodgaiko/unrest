"""Finite process proposals; Python callers confer no execution authority.

The observer chooses a declaration from the externally selected case, compares
all observed operands, then applies its existing launch, kernel and wait ledger.
"""
from pathlib import Path

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


def proposal(host, actor, raw):
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
    if raw['stdin'] is not None:
        raise Refused('process proposal has undeclared commit input')
    checkout, owned = Path(host.meta['checkout']), Path(host.meta['owned'])
    native, pin = host.binding['entry']['path'], host.binding['entry']['sha256']
    cwd, root_environment = raw['cwd'], host.meta_environment()
    vector, extra = None, {}
    if case in CONTROLLED and argv[0]=='/usr/bin/git':
        from custody_git import command,ENVIRONMENT,SOURCE
        from git_observer import image
        from launch_policy import Rule,render
        value,_=command(case,tuple(argv),cwd,owned)
        expected=render(Rule('custody:git',SOURCE+':git',(case,),'/usr/bin/git',image(),value.argv,tuple(sorted(ENVIRONMENT.items())),cwd,'native'),case,SOURCE+':git',{}, {})
        site,script_pin,vector=38,None,list(value.argv)
    elif case in PLANS:
        model = plan_expected(case,cwd,owned,native,pin)
        expected, site, vector = model.expected,409,list(model.vector)
        script_pin = expected.payload_sha256
    elif case in SESSIONS:
        child = actor['role']=='session-adapter'
        expected = session_expected(case,cwd,checkout,owned,native,pin,root_environment,child=child)
        site,script_pin = (50 if child else 75),expected.payload_sha256
        vector = list(expected.argv) if expected.payload_kind=='expected-exec-failure' else [native,'-I','-S',*expected.argv[1:]]
    elif case in FIXED:
        query = actor['role']=='fixed-inline'
        records = [row for row in host.intents.values() if row['case']==case and row['role']=='fixed-inline']
        if not query and len(records)>=len(SEQUENCES[case]):
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
    elif case in ORDINARY:
        expected = ordinary_expected(case,'sleep' if argv[0]=='/bin/sleep' else 'mock-acp',cwd,checkout,native,pin,root_environment,owned)
        site = 409 if expected.rule=='ordinary:mock-acp' else 1383 if case==ORDINARY[2] else 1843
        script_pin = expected.payload_sha256
        vector = list(expected.argv) if expected.rule=='ordinary:sleep' else [native,'-I','-S',*expected.argv[1:]]
    elif case in DECLARATIONS:
        records = [row for row in host.intents.values() if row['case']==case]
        terminal = case in INFLIGHT and len(records)==2
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
        expected = cleanup_expected(case,role,base,native,pin,checkout,root_environment,port=port,descriptor=descriptor)
        site = {'mcp':module_site(case),'cleanup-acp':409,'git-init':131,'git-commit':132,'git-observe':266}[role]
        script_pin,vector = expected.payload_sha256,list(cleanup_vector(expected,host.directory))
    elif case in (*BOOTSTRAP,*CONTROLLED):
        backend = argv[1:2]!=[str(checkout/ACP)]
        relay = None
        if not backend:
            bridge = host.listeners[host.listener_key(case,'bridge',cwd)]
            lifetime = host.listeners[host.listener_key(case,'lifetime',cwd)]
            relay = [bridge['socket'].local[1],bridge['nonce'],lifetime['socket'].local[1],lifetime['nonce']]
        expected,_,script_pin = expected_entry(case,checkout,Path(cwd),native,pin,backend=backend,relay=relay)
        site,vector = (506 if backend else 553),[native,'-I','-S',*expected.argv[1:]]
    else:
        raise Refused('finite process proposal has no declaration')
    if (tuple(argv)!=expected.argv or cwd!=expected.cwd or raw['environment']!=dict(expected.environment)):
        raise Refused('finite process proposal differs from declaration')
    payload = {'case':case,'original':expected.wire(),'translated':vector,'source_line':site,'script_sha256':script_pin,**extra}
    answer = host.launch(actor,payload)
    if answer is None:
        return None
    intent=host.intents[answer['ticket']]
    command=intent.get('command')
    return {**answer,'translated':vector,'rule':expected.rule,
            'command':None if command is None else {'stdin':command.stdin,'produces':[command.produces[0],command.produces[1],list(command.produces[2])] if command.produces else None}}
