"""Two original inventory-FD regressions; no ACP/provider process authority."""
from pathlib import Path
from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected
from ordinary_acp import TEST,PINS

CASES=tuple(TEST+'::test_real_mcp_inventory_fd_redacts_before_crash_and_restart['+mode+']'
            for mode in ('worker','terminal-reviewer'))


def inventory_proposal(host,actor,raw):
    from cleanup_launch import read_pipe,system_git,SERVER,PINS as CLEANUP_PINS
    case=host.case
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PINS[TEST])
    worker=case==CASES[0]
    records=[row for row in host.intents.values() if row['case']==case]
    sequence=('git-init','git-commit','mcp','git-observe') if worker else ('mcp',)
    if case not in CASES or len(records)>=len(sequence) or raw['stdin'] is not None:
        raise Refused('inventory finite original sequence')
    role=sequence[len(records)]
    if (actor['role']=='mcp')!=(role=='git-observe') or actor['role'] not in ('root','mcp'):
        raise Refused('inventory original parent role')
    if any(not row['consumed'] or row['role']!='mcp' and not host.ledger.reaped(row['birth'],row['token']) for row in records):
        return None
    if role=='git-observe' and (not actor['body_ready'] or records[-1]['birth']!=actor['birth'] or records[-1]['token']!=actor['token']):
        raise Refused('inventory actual live MCP owner')
    from owned_fixture import retain
    base=retain(host,Path(raw['cwd']).parent,case.split('::')[1].split('[')[0][:30],20000)
    home=base/'.unrest'
    project='p-worker' if worker else 'p-terminal-reviewer'
    runtime=home/'projects'/project/'.unrest-runtime/missions/mission-001'
    env={'LANG':'C','PATH':host.meta_environment()['PATH'],'UNREST_HOME':str(home),
         'UNREST_PROJECT_ID':project,'UNREST_MISSION_ID':'mission-001'}
    if worker:
        env.update(UNREST_NODE_ID='w-secret',UNREST_NODE_TYPE='work',
            UNREST_HANDOFF_PATH=str(runtime/'attempts/2026-08-03T00-00-00Z__w-secret.json'),
            UNREST_NODE_ASSIGNMENT='{"targets":["VAL-001"],"task_type":"work"}')
    else:
        env['UNREST_TERMINAL_REVIEW_PATH']=str(runtime/'terminal-reviews/2026-08-03T00-00-00Z.json')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    port,inherited,reference=None,[],None
    if role=='mcp':
        from network_scope import port_argument
        if len(raw['argv'])!=13 or not raw['argv'][-1].isascii() or not raw['argv'][-1].isdigit():
            raise Refused('inventory finite MCP operands')
        port,fd=port_argument(raw['argv'][-3]),int(raw['argv'][-1])
        inherited=[read_pipe(actor['birth'],fd)]
        argv=(native,'-m','unrest_harness','--mode','worker' if worker else 'terminal-reviewer',
              '--transport','streamable-http','--host','127.0.0.1','--port',str(port),'--sensitive-inventory-fd',str(fd))
        image,kind,reference=native,'python-module',CLEANUP_PINS[SERVER]
        vector=[native,'-I','-S',*argv[1:]]
    else:
        argv=('git',*(('-c','maintenance.auto=false','-c','gc.auto=0') if role!='git-observe' else ()),*{'git-init':('init','--quiet','--initial-branch=main'),
             'git-commit':('commit','--allow-empty','--quiet','-m','base'),'git-observe':('rev-parse','HEAD')}[role])
        if role!='git-observe':
            env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)','ANTHROPIC_API_KEY':'plum',
                 **{'GIT_'+who+'_'+key:value for who in ('AUTHOR','COMMITTER') for key,value in (('DATE','2000-01-01T00:00:00+00:00'),('EMAIL','test@example.invalid'),('NAME','Test'))},
                 'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1'}
        image,pin,kind='/usr/bin/git',system_git(),'native'
        vector=[image,*argv[1:]]
    value=build_expected(case,image,pin,argv,tuple(sorted(env.items())),str(base/'workspace'),kind,reference)
    return admit_expected(host,actor,raw,value,role,vector,reference,port=port,inherited=inherited)


DIAGNOSTICS=tuple(TEST+'::test_'+name for name in (
    'missing_end_node_diagnostics_survive_production_dispatch_and_attention',
    'worker_mcp_readiness_timeout_persists_generation_before_dispatch_return'))
INVENTORY_CASES=CASES
CASES=(*CASES,*DIAGNOSTICS)


def proposal(host,actor,raw):
    if host.case in INVENTORY_CASES:
        return inventory_proposal(host,actor,raw)
    import re
    from owned_fixture import retain
    from node_launch import proposal as node
    from ordinary_acp import MOCK
    host.root_only(actor)
    case=host.case
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PINS[TEST])
    base=retain(host,Path(raw['cwd']).parent,case.split('::')[1][:30],20000)
    first=case==DIAGNOSTICS[0]
    project=raw['environment'].get('UNREST_PROJECT_ID','')
    slug='missing-handoff-regression' if first else 'worker-mcp-timeout-regression'
    if (case not in DIAGNOSTICS or re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-'+slug,project) is None
            or raw['environment'].get('UNREST_MISSION_ID')!='mission-001'
            or raw['environment'].get('UNREST_NODE_ID')!=('w1' if first else 'w-timeout')):
        raise Refused('diagnostic exact project and node')
    if host.fixture_roots.setdefault(('diagnostic-project',case),project)!=project:
        raise Refused('diagnostic project changed')
    module=raw['argv'][1:2]==['-m']
    if module and raw['environment'].get('UNREST_NODE_ASSIGNMENT')!='{"targets":["VAL-001"],"task_type":"work"}':
        raise Refused('diagnostic exact assignment')
    if not module:
        records=[row for row in host.intents.values() if row['case']==case and row['role']=='mcp' and row['parent']==actor['birth']]
        if not first or len(records)!=1 or not host.executed(records[0]) or not host.actors[records[0]['pid']]['body_ready']:
            raise Refused('diagnostic mock before actual MCP ready')
    return node(host,actor,raw,base/'workspace',host.meta_environment(),base/'.unrest',project,{'work':1},
        checkout/MOCK,PINS[MOCK],('--missing-handoff-session-error',),1,{},'mock-acp')
