"""Finite process proposals; Python callers confer no execution authority.

The observer chooses a declaration from the externally selected case, compares
all observed operands, then applies its existing launch, kernel and wait ledger.
"""
from pathlib import Path

from content_manifest import Refused, refuse_if
from launch_policy import admit_expected
from plan_launch import CASES as PLANS, expected as plan_expected
from session_launch import CASES as SESSIONS, expected as session_expected
from fixed_inline import CASES as FIXED, SEQUENCES, NESTED_CASES, STORAGE_CASES, INSPECTION_CASES, MEASUREMENT_CASE, COMPLETION_CASES, DRAIN_CASE, expected as fixed_expected, STDIO, startup_expected, translated as fixed_translated
from ordinary_acp import EXECUTION_CASES as ORDINARY, expected as ordinary_expected
from cleanup_launch import EXECUTION_CASES as CLEANUP, expected as cleanup_expected, base_path, translated as cleanup_vector
from controlled_startup import expected_entry, ACP
from controlled_cases import eligible as CONTROLLED, custody as CUSTODY
from cohort_cases import GIT_ONLY as COHORT_GIT
from bootstrap_cases import BOOTSTRAP


def proposal_operands(raw,case,native=None):
    from source_observer import shape
    from inline_leaves import STREAM_CASES
    shape(raw, ('case','executable','argv','cwd','environment','stdin')+(('inventory_fd',) if case in STREAM_CASES else ()))
    refuse_if(type(raw['case']) is not str or raw['case'] != case or type(raw['executable']) is not str or type(raw['argv']) is not list, 'finite process proposal case or vector')
    argv = raw['argv']
    from approval_launch import CASES as APPROVAL
    refuse_if(not 0 < len(argv) <= 256 or any(type(arg) is not str for arg in argv)
            or (raw['executable'] != argv[0] and not (argv[0] in ('git','ps','sleep') and raw['executable']=='/usr/bin/'+argv[0])
                and not (case in APPROVAL and native is not None and raw['executable']==native)) or type(raw['cwd']) is not str
            or type(raw['environment']) is not dict
            or any(type(k) is not str or type(v) is not str for k,v in raw['environment'].items()), 'finite process proposal operands')
    values=[raw['executable'],raw['cwd'],*argv,*raw['environment'],*raw['environment'].values()]
    try:
        for value in values:
            refuse_if('\0' in value, 'finite process text')
            value.encode('utf-8')
    except UnicodeError:
        raise Refused('finite process text encoding') from None
    refuse_if(any('=' in key for key in raw['environment']), 'finite process environment key')
    from launch_policy import _absolute
    _absolute(raw['cwd'])
    return argv


def proposal(host, actor, raw):
    host.launch_owner(actor)
    from approval_launch import CASES as APPROVAL
    argv=proposal_operands(raw,host.case,host.binding['entry']['path'] if host.case in APPROVAL else None)
    case=host.case
    for name in ('approval_launch','repository_cli','mcp_inventory','package_proposals','desktop_launch','completion_server',
                 'inline_leaves','uv_cli','console_entries','http_cases'):
        module=__import__(name)
        selected=module.eligible(case) if name=='repository_cli' else case in (module.CASES if hasattr(module,'CASES') else (module.CASE,))
        if selected and (name!='uv_cli' or argv[0]=='uv'):
            return module.proposal(host,actor,raw)
    from run_worker_launch import ALL_CASES as RUN_WORKERS,proposal as run_proposal,descendant,DESCENDANTS
    if case in DESCENDANTS and actor['role']=='fixed-inline':
        return descendant(host,actor,raw)
    if case in RUN_WORKERS and argv[1:3]==['-m','unrest_harness.run_worker']:
        return run_proposal(host,actor,raw)
    from cohort_controller import CASES as CRASH, proposal as crash_proposal
    if case in CRASH and argv[1:2]==['-c']:
        return crash_proposal(host,actor,raw)
    from git_policy import local_case,OWNED_CASE,HISTORY_CASES,MEASUREMENT_WORKERS
    if (case in HISTORY_CASES or case in MEASUREMENT_WORKERS and actor['role']!='root'
            or local_case(case) and argv[0] in ('git','/usr/bin/git') or case==OWNED_CASE):
        from git_policy import workspace_prepare as prepare
        return prepare(host,actor,raw)
    from review_wire import CASES as REVIEW_CASES,proposal as review_proposal
    if case in REVIEW_CASES:
        return review_proposal(host,actor,raw)
    refuse_if(not CONTROLLED(case) and not CUSTODY(case) and case not in (*BOOTSTRAP,*COHORT_GIT,*ORDINARY,*CLEANUP,*SESSIONS,*FIXED,*PLANS), 'finite process proposal has no declaration')
    refuse_if(raw['stdin'] is not None, 'process proposal has undeclared commit input')
    checkout, owned = Path(host.meta['checkout']), Path(host.meta['owned'])
    native, pin = host.binding['entry']['path'], host.binding['entry']['sha256']
    cwd, root_environment = raw['cwd'], host.meta_environment()
    vector, role, maximum, inherited, port, variant = None, None, 1, [], None, None
    custody=(CUSTODY(case) or case in COHORT_GIT) and argv[0]=='/usr/bin/git'
    if custody:
        from git_policy import custody_command, custody_launch as launch
        value,kind=custody_command(case,tuple(argv),cwd,owned)
        return launch(host,actor,value,kind,raw)
    elif case in PLANS:
        model = plan_expected(case,cwd,owned,native,pin)
        expected, vector = model.expected,list(model.vector)
        script_pin = expected.payload_sha256
    elif case in SESSIONS:
        from session_launch import TIMEOUT,INVALID,INVALID_BYTES
        child = actor['role']=='session-adapter'
        refuse_if(child and case!=TIMEOUT or not child and actor['role']!='root', 'session original launch parent')
        expected = session_expected(case,cwd,checkout,owned,native,pin,root_environment,child=child)
        script_pin = expected.payload_sha256
        role='session-invalid' if case in INVALID else 'session-child' if child else 'session-inline' if expected.payload_kind=='python-command' else 'session-adapter'
        if role=='session-invalid':
            from git_policy import regular
            refuse_if(regular(Path(expected.executable))!=INVALID_BYTES or Path(expected.executable).stat().st_mode&0o777!=0o700, 'session exact invalid executable fixture')
        vector = list(expected.argv) if expected.payload_kind=='expected-exec-failure' else [native,'-I','-S',*expected.argv[1:]]
    elif case in FIXED:
        environment = {**root_environment,'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
        if actor['role']=='fixed-inline':
            from fixed_inline import query_expected
            expected=query_expected(case,'check',checkout,environment)
            return admit_expected(host,actor,raw,expected,'git-fixed',
                ['/usr/bin/git','-c','safe.directory='+str(checkout),*expected.argv[1:]],expected.payload_sha256)
        records = [row for row in host.intents.values() if row['case']==case and row['role']=='fixed-inline']
        refuse_if(len(records)>=len(SEQUENCES[case]) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records), 'finite fixed proposal exhausted')
        operation = SEQUENCES[case][len(records)]
        if case==DRAIN_CASE:
            import ast
            from fixed_inline import DRAIN_TEST,PINS
            from owned_fixture import retain
            from launch_policy import source_unit,build_expected
            unit=source_unit(checkout,DRAIN_TEST,PINS[DRAIN_TEST],(case.split('::')[-1],))
            calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call)
                   and isinstance(node.func,ast.Attribute) and node.func.attr=='create_subprocess_exec']
            body=ast.literal_eval(calls[0].args[2])
            parent=retain(host,Path(cwd).parent, 20000)
            refuse_if(Path(cwd)!=parent/'workspace', 'pipe drain original workspace generation')
            expected=build_expected(case,native,pin,(native,'-c',body),
                (('PATH',root_environment['PATH']),),cwd,'python-command')
        elif case in (*COMPLETION_CASES,MEASUREMENT_CASE,*INSPECTION_CASES,*STORAGE_CASES):
            from fixed_leaves import expected as leaf_expected
            expected=leaf_expected(host,operation,argv,cwd,environment,native,pin)
        elif case in STDIO:
            expected = startup_expected(case,native,pin,cwd,owned)
        else:
            from speed_inline import CASES as SPEED_CASES,fixture,CLI_CASE,directory
            if case==CLI_CASE:
                refuse_if(len(argv)!=14, 'speed CLI original argument count')
                value=directory(str(Path(argv[7]).parent.parent),owned,case)
                refuse_if(host.fixture_roots.setdefault(case,value)!=value, 'speed CLI fixture reuse generation')
            root=fixture(host) if case in (*SPEED_CASES,CLI_CASE) else None
            expected = fixed_expected(case,operation,native,pin,checkout,environment,root=root)
        script_pin = expected.payload_sha256
        vector = list(fixed_translated(expected))
        role,maximum='pytest-regression' if case in NESTED_CASES else 'fixed-inline',len(SEQUENCES[case])
    elif case in ORDINARY:
        host.root_only(actor)
        from ordinary_acp import MOCK_CASE,STARTUP_CASES,TEMPLATE_CASES,BATCH_CASES,CRASH_CASES
        base=None
        if case==MOCK_CASE or (case in (*TEMPLATE_CASES,*BATCH_CASES) and argv[0]!='/bin/sleep'):
            from owned_fixture import retain
            candidate=(Path(raw['environment'].get('UNREST_HANDOFF_PATH','')).parents[7]
                       if argv[0]=='sleep' else Path(cwd).parent)
            base=retain(host,candidate, 20000)
        role='sleep' if argv[0] in ('/bin/sleep','sleep') else 'session-invalid' if case in STARTUP_CASES else 'mock-acp'
        maximum=2 if case in BATCH_CASES or (case in CRASH_CASES and role=='sleep') else 1
        expected = ordinary_expected(case,role,cwd,checkout,native,pin,root_environment,owned,base=base,observed=raw['environment'])
        script_pin = expected.payload_sha256
        vector = list(expected.argv) if role in ('sleep','session-invalid') else [native,'-I','-S',*expected.argv[1:]]
    elif case in CLEANUP:
        port,descriptor = None,None
        if argv[0]=='git':
            role = 'git-observe' if actor['role']=='mcp' else 'git-init' if argv[1:3]==['init','-q'] else 'git-commit'
        else:
            role = 'mcp' if argv[1:2]==['-m'] else 'cleanup-acp'
        base = base_path(str(Path(argv[-1]).parent) if role=='git-init' else str(Path(cwd).parent),owned)
        if role=='mcp':
            refuse_if(len(argv)!=13 or not argv[-3].isdigit() or not argv[-1].isdigit(), 'finite module port and descriptor')
            port,descriptor = int(argv[-3]),int(argv[-1])
        refuse_if((actor['role']=='mcp')!=(role=='git-observe'), 'cleanup original parent role')
        if role=='mcp':
            from cleanup_launch import read_pipe
            inherited=[read_pipe(actor['birth'],descriptor)]
        expected = cleanup_expected(case,role,base,native,pin,checkout,root_environment,port=port,descriptor=descriptor)
        script_pin,vector = expected.payload_sha256,list(cleanup_vector(expected,host.directory,role))
    elif (case in BOOTSTRAP or CONTROLLED(case)):
        from cohort_controller import parent
        parent(host,actor)
        from controlled_pairs import scope,before_spawn
        if CONTROLLED(case):
            scope(case,'bridge',cwd,owned)
        elif (str(Path(cwd).resolve())!=cwd or not Path(cwd).is_relative_to(owned)
                or Path(cwd).name!='worker' or Path(cwd).parent.name!='owner'):
            raise Refused('source declared worker launch home')
        backend = argv[1:2]!=[str(checkout/ACP)]
        role='backend' if backend else 'acp'
        records=[row for row in host.intents.values() if row['case']==case]
        if CONTROLLED(case):
            if not before_spawn(case,cwd,role,records,host.executed):
                return None
        elif not backend:
            backends=[row for row in records if row['role'] in ('backend','delayed-backend')]
            refuse_if(len(backends)!=1, 'source ACP before owned backend')
            if not host.executed(backends[0]):
                return None
        relay = None
        if not backend:
            import json
            from control_transport import unique
            relay=json.loads(raw['environment'].get('SYNTHETIC_RELAY','null'),object_pairs_hook=unique)
            refuse_if(type(relay) is not list or len(relay)!=4, 'controlled original relay tuple')
        if CONTROLLED(case):
            from controlled_cases import select_entry
            (expected,_,script_pin),variant=select_entry(case,checkout,Path(cwd),native,pin,raw,backend=backend,relay=relay,records=records)
        else:
            expected,_,script_pin = expected_entry(case,checkout,Path(cwd),native,pin,backend=backend,relay=relay)
        vector = [native,'-I','-S',*expected.argv[1:]]
        if backend and expected.payload_kind=='python-command':
            role='delayed-backend'
    else:
        raise Refused('finite process proposal has no declaration')
    if case in PLANS:
        from plan_observer import launch
        return launch(host,actor,raw,model)
    answer=admit_expected(host,actor,raw,expected,role,vector,script_pin,
        maximum=maximum,inherited=inherited,port=port,
        fields={'fixed_operation':operation} if case in FIXED else {'controlled_variant':variant} if variant is not None else None)
    if answer is None:
        return None
    if case in ORDINARY and role=='session-invalid':
        host.intents[answer['ticket']]['attempt_path']=expected.argv[0]
    if case in CLEANUP and role=='cleanup-acp':
        from cleanup_launch import scenario,snapshot_path
        body=scenario(case,base)
        snapshot=snapshot_path(host.directory,case)
        with snapshot.open('xb') as stream:
            stream.write(body)
        snapshot.chmod(0o444)
    return answer
