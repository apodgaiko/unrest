"""Finite process proposals; Python callers confer no execution authority.

The observer chooses a declaration from the externally selected case, compares
all observed operands, then applies its existing launch, kernel and wait ledger.
"""
from pathlib import Path
import hashlib

from content_manifest import Refused
from plan_launch import CASES as PLANS, expected as plan_expected
from session_launch import CASES as SESSIONS, expected as session_expected
from fixed_inline import CASES as FIXED, SEQUENCES, NESTED_CASES, STORAGE_CASES, INSPECTION_CASES, MEASUREMENT_CASE, COMPLETION_CASES, DRAIN_CASE, expected as fixed_expected, STDIO, startup_expected, translated as fixed_translated
from ordinary_acp import EXECUTION_CASES as ORDINARY, expected as ordinary_expected
from cleanup_launch import EXECUTION_CASES as CLEANUP, expected as cleanup_expected, base_path, translated as cleanup_vector
from cleanup_inline import DECLARATIONS, INFLIGHT, expected as inline_expected
from controlled_startup import expected_entry, ACP
from controlled_cases import CASES as CONTROLLED
from cohort_cases import GIT_ONLY as COHORT_GIT
from bootstrap_cases import BOOTSTRAP


def proposal_operands(raw,case):
    from source_observer import shape
    shape(raw, ('case','executable','argv','cwd','environment','stdin'))
    if type(raw['case']) is not str or raw['case'] != case or type(raw['executable']) is not str or type(raw['argv']) is not list:
        raise Refused('finite process proposal case or vector')
    argv = raw['argv']
    if (not 0 < len(argv) <= 256 or any(type(arg) is not str for arg in argv)
            or (raw['executable'] != argv[0] and not (argv[0] in ('git','ps','sleep') and raw['executable']=='/usr/bin/'+argv[0])) or type(raw['cwd']) is not str
            or type(raw['environment']) is not dict
            or any(type(k) is not str or type(v) is not str for k,v in raw['environment'].items())):
        raise Refused('finite process proposal operands')
    values=[raw['executable'],raw['cwd'],*argv,*raw['environment'],*raw['environment'].values()]
    try:
        for value in values:
            if '\0' in value:
                raise Refused('finite process text')
            value.encode('utf-8')
    except UnicodeError:
        raise Refused('finite process text encoding') from None
    if any('=' in key for key in raw['environment']):
        raise Refused('finite process environment key')
    from launch_policy import _absolute
    _absolute(raw['cwd'])
    return argv


def proposal(host, actor, raw):
    host.launch_owner(actor)
    argv=proposal_operands(raw,host.case)
    case=host.case
    for name in ('mcp_inventory','package_proposals','desktop_launch','completion_server',
                 'terminal_leaves','readiness_launch','uv_cli','console_entries','http_cases'):
        module=__import__(name)
        selected=module.CASES if hasattr(module,'CASES') else (module.CASE,)
        if case in selected and (name!='uv_cli' or argv[0]=='uv'):
            return module.proposal(host,actor,raw)
    from run_worker_launch import ALL_CASES as RUN_WORKERS,proposal as run_proposal,descendant,DESCENDANT
    if case==DESCENDANT and actor['role']=='fixed-inline':
        return descendant(host,actor,raw)
    if case in RUN_WORKERS and argv[1:3]==['-m','unrest_harness.run_worker']:
        return run_proposal(host,actor,raw)
    from cohort_controller import CASES as CRASH, proposal as crash_proposal
    if case in CRASH and argv[1:2]==['-c']:
        return crash_proposal(host,actor,raw)
    from git_sites import CASES as GIT_CASES
    if case in GIT_CASES:
        from git_proposals import prepare
        return prepare(host,actor,raw)
    from review_wire import CASES as REVIEW_CASES,proposal as review_proposal
    if case in REVIEW_CASES:
        return review_proposal(host,actor,raw)
    if case not in (*BOOTSTRAP,*CONTROLLED,*COHORT_GIT,*ORDINARY,*CLEANUP,*DECLARATIONS,*SESSIONS,*FIXED,*PLANS):
        raise Refused('finite process proposal has no declaration')
    if raw['stdin'] is not None:
        raise Refused('process proposal has undeclared commit input')
    checkout, owned = Path(host.meta['checkout']), Path(host.meta['owned'])
    native, pin = host.binding['entry']['path'], host.binding['entry']['sha256']
    cwd, root_environment = raw['cwd'], host.meta_environment()
    vector, role, maximum, inherited, port = None, None, 1, [], None
    custody=case in (*CONTROLLED,*COHORT_GIT) and argv[0]=='/usr/bin/git'
    if custody:
        from custody_git import command as custody_command,ENVIRONMENT
        from git_observer import image
        from launch_policy import build_expected
        value,custody_kind=custody_command(case,tuple(argv),cwd,owned)
        expected=build_expected(
            case,
            '/usr/bin/git', image(),
            value.argv,
            tuple(sorted(ENVIRONMENT.items())),
            cwd, 'native',
        )
        script_pin,vector=None,list(value.argv)
    elif case in PLANS:
        model = plan_expected(case,cwd,owned,native,pin)
        expected, vector = model.expected,list(model.vector)
        script_pin = expected.payload_sha256
    elif case in SESSIONS:
        from session_launch import TIMEOUT,INVALID,INVALID_BYTES
        child = actor['role']=='session-adapter'
        if child and case!=TIMEOUT or not child and actor['role']!='root':
            raise Refused('session original launch parent')
        expected = session_expected(case,cwd,checkout,owned,native,pin,root_environment,child=child)
        script_pin = expected.payload_sha256
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
        if case==DRAIN_CASE:
            if query:
                raise Refused('pipe drain child has no descendants')
            import ast
            from fixed_inline import DRAIN_TEST,PINS
            from owned_fixture import retain
            from launch_policy import source_unit,build_expected
            unit=source_unit(checkout,DRAIN_TEST,PINS[DRAIN_TEST],(case.split('::')[-1],))
            calls=[node for node in ast.walk(unit) if isinstance(node,ast.Call)
                   and isinstance(node.func,ast.Attribute) and node.func.attr=='create_subprocess_exec']
            if len(calls)!=1 or len(calls[0].args)!=3:
                raise Refused('pipe drain sole original child')
            body=ast.literal_eval(calls[0].args[2])
            parent=retain(host,Path(cwd).parent,case.split('::')[-1][:30],20000)
            if Path(cwd)!=parent/'workspace':
                raise Refused('pipe drain original workspace generation')
            expected=build_expected(case,native,pin,(native,'-c',body),
                (('PATH',root_environment['PATH']),),cwd,'python-command')
        elif case in COMPLETION_CASES:
            if query:
                raise Refused('completion primitive has no descendants')
            from completion_launch import expected as completion_expected
            expected=completion_expected(host,operation,argv,cwd,environment,native,pin)
        elif case==MEASUREMENT_CASE:
            if query:
                raise Refused('simulation child has no descendants')
            from measurement_launch import expected as measurement_expected
            expected=measurement_expected(host,argv,cwd,environment,native,pin)
        elif case in INSPECTION_CASES:
            if query:
                raise Refused('inspection child has no descendants')
            from inspection_launch import expected as inspection_expected
            expected=inspection_expected(host,argv,cwd,environment,native,pin)
        elif case in STORAGE_CASES:
            if query:
                raise Refused('storage read child has no descendants')
            from storage_launch import expected as storage_expected
            expected=storage_expected(host,argv,cwd,environment,native,pin)
        elif case in STDIO:
            if query:
                raise Refused('fixed startup has no descendant query')
            expected = startup_expected(case,native,pin,cwd,owned)
        else:
            from speed_inline import CASES as SPEED_CASES,fixture,CLI_CASE,directory
            if case==CLI_CASE:
                if len(argv)!=14:
                    raise Refused('speed CLI original argument count')
                value=directory(str(Path(argv[7]).parent.parent),owned,case)
                if host.fixture_roots.setdefault(case,value)!=value:
                    raise Refused('speed CLI fixture reuse generation')
            root=fixture(host) if case in (*SPEED_CASES,CLI_CASE) else None
            expected = fixed_expected(case,operation,native,pin,checkout,environment,query=query,root=root)
        script_pin = expected.payload_sha256
        vector = list(expected.argv) if query else list(fixed_translated(expected))
        role,maximum='git-fixed' if query else 'pytest-regression' if case in NESTED_CASES else 'fixed-inline',1 if query else len(SEQUENCES[case])
    elif case in ORDINARY:
        host.root_only(actor)
        from ordinary_acp import MOCK_CASE,STARTUP_CASES,TEMPLATE_CASES,BATCH_CASES
        base=None
        if case==MOCK_CASE or (case in (*TEMPLATE_CASES,*BATCH_CASES) and argv[0]!='/bin/sleep'):
            from owned_fixture import retain
            candidate=(Path(raw['environment'].get('UNREST_HANDOFF_PATH','')).parents[7]
                       if argv[0]=='sleep' else Path(cwd).parent)
            base=retain(host,candidate,case.split('::')[1][:30],20000)
        role='sleep' if argv[0] in ('/bin/sleep','sleep') else 'session-invalid' if case in STARTUP_CASES else 'mock-acp'
        maximum=2 if case in BATCH_CASES or (case==ORDINARY[2] and role=='sleep') else 1
        expected = ordinary_expected(case,role,cwd,checkout,native,pin,root_environment,owned,base=base,observed=raw['environment'])
        script_pin = expected.payload_sha256
        vector = list(expected.argv) if role in ('sleep','session-invalid') else [native,'-I','-S',*expected.argv[1:]]
    elif case in DECLARATIONS:
        host.root_only(actor)
        from cleanup_inline import child_count
        records = [row for row in host.intents.values() if row['case']==case]
        terminal = case in INFLIGHT and len(records)==2
        if len(records)>=child_count(case):
            raise Refused('cleanup inline original child order')
        if any(not host.executed(row) for row in records):
            return None
        role,maximum='cleanup-inline',child_count(case)
        expected = inline_expected(case,native,pin,checkout,root_environment,base=base_path(cwd,owned) if terminal else None,terminal=terminal)
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
            from cleanup_launch import read_pipe
            inherited=[read_pipe(actor['birth'].pid,descriptor)]
        expected = cleanup_expected(case,role,base,native,pin,checkout,root_environment,port=port,descriptor=descriptor)
        script_pin,vector = expected.payload_sha256,list(cleanup_vector(expected,host.directory,role))
    elif case in (*BOOTSTRAP,*CONTROLLED):
        from cohort_controller import parent
        parent(host,actor)
        from controlled_pairs import scope,before_spawn
        if case in CONTROLLED:
            scope(case,'bridge',cwd,owned)
        elif (str(Path(cwd).resolve())!=cwd or not Path(cwd).is_relative_to(owned)
                or Path(cwd).name!='worker' or Path(cwd).parent.name!='owner'):
            raise Refused('source declared worker launch home')
        backend = argv[1:2]!=[str(checkout/ACP)]
        role='backend' if backend else 'acp'
        records=[row for row in host.intents.values() if row['case']==case]
        if case in CONTROLLED:
            if not before_spawn(case,cwd,role,records,host.executed):
                return None
        elif not backend:
            backends=[row for row in records if row['role'] in ('backend','delayed-backend')]
            if len(backends)!=1:
                raise Refused('source ACP before owned backend')
            if not host.executed(backends[0]):
                return None
        relay = None
        if not backend:
            import json
            from control_transport import unique
            relay=json.loads(raw['environment'].get('SYNTHETIC_RELAY','null'),object_pairs_hook=unique)
            if type(relay) is not list or len(relay)!=4:
                raise Refused('controlled original relay tuple')
        expected,_,script_pin = expected_entry(case,checkout,Path(cwd),native,pin,backend=backend,relay=relay)
        vector = [native,'-I','-S',*expected.argv[1:]]
        if backend and expected.payload_kind=='python-command':
            role='delayed-backend'
    else:
        raise Refused('finite process proposal has no declaration')
    if (tuple(argv)!=expected.argv or cwd!=expected.cwd or raw['environment']!=dict(expected.environment)):
        raise Refused('finite process proposal differs from declaration')
    if case in PLANS:
        from plan_observer import launch
        answer=launch(host,actor,model)
    elif custody:
        from custody_git import launch
        answer=launch(host,actor,value,custody_kind,expected)
    else:
        answer=host.admit_launch(actor,expected,role,vector,script_pin,
            maximum=maximum,inherited=inherited,port=port)
    if answer is not None and case in ORDINARY and role=='session-invalid':
        host.intents[answer['ticket']]['attempt_path']=expected.argv[0]
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
    if answer is None:
        return None
    return {**answer,'translated':vector}
