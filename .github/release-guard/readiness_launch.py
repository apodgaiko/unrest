"""Four original local-readiness leaves; connect permission never grants payload."""
import ast
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected
from socket_observation import acquire_tcp

TEST='tests/test_acp_runner.py'
NAME='test_readiness_attributes_local_child_and_drains'
CASES=tuple(TEST+'::'+NAME+'['+mode+']' for mode in ('early_exit','never_ready','ready','cancel'))
READY=CASES[2]
PIN='0edac8224b6b1760230026567fb1c3a1d591dc70d0b70e9990b0b52d68a71561'


def proposal(host,actor,raw):
    host.root_only(actor)
    if host.case not in CASES or raw['stdin'] is not None:
        raise Refused('readiness original child scope')
    unit=source_unit(Path(host.meta['checkout']),TEST,PIN,(NAME,'exercise'))
    bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
            and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='body']
    if len(bodies)!=3 or any(type(body) is not str for body in bodies):
        raise Refused('readiness three pinned original literal branches')
    body=bodies[0 if host.case==READY else 1 if host.case==CASES[0] else 2]
    native=host.binding['entry']['path']
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value=build_expected('fixed:readiness',host.case,native,host.binding['entry']['sha256'],
        (native,'-c',body),tuple(sorted(env.items())),host.meta['checkout'],'python-command')
    return admit_expected(host,actor,raw,value,'fixed-inline',[native,'-I','-S','-c',body])


def target(host,actor):
    rows=[row for row in host.intents.values() if row['case']==READY and row['role']=='fixed-inline'
          and row['consumed'] and row.get('birth')==actor['birth'] and row['token']==actor['token']]
    if (host.case!=READY or actor['role']!='fixed-inline' or actor['case']!=READY or len(rows)!=1
            or not host.ledger.body_ready(actor['birth'],actor['token'])):
        raise Refused('readiness actual independently ready listener owner')


def connect(host,actor,payload,port):
    host.root_only(actor)
    case=host.case
    if case not in CASES[1:] or host.readiness_attempts.get(case) is not None:
        raise Refused('readiness single original probe')
    fresh=acquire_tcp(actor['birth'],payload['fd'])
    if fresh is None or fresh.state!=7 or fresh.local!=('0.0.0.0',0) or fresh.remote is not None:
        raise Refused('readiness actual fresh client descriptor')
    server=None
    if case==READY:
        slot=host.listeners.get((case,'readiness'))
        if slot is None:
            return None
        server=host.actors[slot['socket'].owner.pid]
        target(host,server)
        if port!=slot['socket'].local[1] or acquire_tcp(server['birth'],slot['socket'].fd)!=slot['socket']:
            raise Refused('readiness exact actual owned listener port')
    elif port!=1:
        raise Refused('readiness original negative port')
    host.readiness_attempts[case]={'fd':payload['fd'],'client_token':actor['token'],'port':port,
        'server_token':None if server is None else server['token'],'payload_authority':False,'accepted_peer_proven':False}
    return {'ok':True,'probe':True,'readiness_only':True}


def completed(actor,terminal):
    if terminal is None or not actor['body_ready']:
        return False
    if actor['case']==CASES[0]:
        return terminal[2]==23
    return terminal[2]==0 or terminal[2] in (-9,-15) and -terminal[2] in actor['signals']
