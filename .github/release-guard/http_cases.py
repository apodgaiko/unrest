"""Finite real-MCP supervision fixtures; provider command strings grant no launch."""
from pathlib import Path
from mcp_inventory import CASES as INVENTORY
import stat

from content_manifest import Refused
from git_observer import image
from launch_policy import admit_expected,build_expected
from multiprocess_routes import TRANSACTIONS
from cleanup_launch import EXECUTION_CASES

from completion_roles import HTTP as ROLE_HTTP

SUPERVISION = tuple(TRANSACTIONS)[:9]
CASES = (*SUPERVISION, *ROLE_HTTP)
TRANSPORT = (*EXECUTION_CASES, *CASES, *INVENTORY)


def expected(host, actor, raw):
    host.root_only(actor)
    case = host.case
    if case not in SUPERVISION or raw['stdin'] is not None:
        raise Refused('HTTP original case or input')
    native, pin = host.binding['entry']['path'], host.binding['entry']['sha256']
    checkout, owned = Path(host.meta['checkout']), Path(host.meta['owned'])
    environment = {**host.meta_environment(), 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case+' (call)'}
    if raw['argv'][:1] == ['ps']:
        servers = [row for row in host.intents.values() if row['case']==case and row['role']=='mcp']
        if len(servers)!=1 or not servers[0]['consumed'] or not host.ledger.reaped(servers[0]['birth'],servers[0]['token']):
            raise Refused('HTTP inventory before original server wait')
        role, executable, kind = 'ps', '/usr/bin/ps', 'native'
        vector, cwd = ('ps', '-axo', 'pid=,ppid=,pgid='), str(checkout)
        pin = image(executable)
        port = None
    else:
        root = Path(raw['cwd'])
        if str(root.resolve())!=raw['cwd'] or root.name!='workspace' or not root.parent.is_relative_to(owned/'pytest'):
            raise Refused('HTTP original owned workspace')
        base, role, executable, kind = root.parent, 'mcp', native, 'python-command'
        subject = case.rsplit('-',1)[1][:-1]
        mode = subject.replace('_','-')
        from network_scope import port_argument
        port=port_argument(raw['argv'][-1])
        code = f"import runpy; runpy.run_path({str(checkout/'tests/fixtures/supervision_role_process.py')!r}, run_name='__main__')"
        vector = (native,'-c',code,'--mode',mode,'--transport','streamable-http','--host','127.0.0.1','--port',str(port))
        environment.update(PYTHONPATH=str(checkout/'src'), UNREST_HOME=str(base/'home'),
            UNREST_PROJECTS_DIR=str(base/'home/projects'), UNREST_PROJECT_ID='project-1',
            UNREST_MISSION_ID='mission-001', SUPERVISION_TEST_BARRIER=str(base/'barrier'))
        for name in ('WORKER','VALIDATOR','TERMINAL_REVIEWER'):
            environment['UNREST_'+name+'_PROVIDER'] = 'claude'
            environment['UNREST_'+name+'_ACP_COMMAND'] = '/bin/true'
        runtime = base/'home/projects/project-1/.unrest-runtime/missions/mission-001'
        if subject=='terminal_reviewer':
            environment.update(UNREST_TERMINAL_REVIEW_ID='review-spawn-1',
                UNREST_TERMINAL_REVIEW_PATH=str(runtime/'terminal-reviews/review-spawn-1.json'))
        else:
            node = 'work-1' if subject=='worker' else 'validate-1'
            environment.update(UNREST_NODE_ID=node,
                UNREST_HANDOFF_PATH=str(runtime/'attempts'/('attempt-'+subject+'__'+node+'.json')))
        cwd = str(root)
    value = build_expected(case, executable, pin, vector, tuple(sorted(environment.items())), cwd, kind)
    return value, role, port


def stdio(host,pid,row):
    # Operands come from the independently matched kernel exec intent.
    if host.case not in CASES or row['case']!=host.case or row['role']!='mcp':
        raise Refused('HTTP exact prebody output intent')
    mode = row['translated'][6]
    log = Path(row['cwd'])/('.'+mode+'-'+str(row['port'])+'.log')
    info = log.lstat()
    descriptors = [(Path('/proc')/str(pid)/'fd'/str(fd)).stat() for fd in (0,1,2)]
    null = Path('/dev/null').stat()
    if (log.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=20000 or info.st_nlink!=1
            or not stat.S_ISCHR(descriptors[0].st_mode) or descriptors[0].st_rdev!=null.st_rdev
            or any((value.st_dev,value.st_ino,value.st_mode,value.st_uid)!=(info.st_dev,info.st_ino,info.st_mode,info.st_uid) for value in descriptors[1:])):
        raise Refused('HTTP exact null and owned merged log descriptors')
    return info.st_dev,info.st_ino


def proposal(host,actor,raw):
    value,role,port = expected(host,actor,raw)
    vector = [value.executable,*value.argv[1:]] if role=='ps' else [value.executable,'-I','-S',*value.argv[1:]]
    return admit_expected(host,actor,raw,value,role,vector,port=port)
