"""Finite controlled approval chain; fixture pins never authorize a provider."""
import ast
import hashlib
import json
import re
from pathlib import Path

from approval_fixture import TEST
from content_manifest import Refused, read_regular
from control_transport import unique
from launch_policy import source_unit, build_expected, admit_expected
from owned_fixture import retain

CASES=tuple(TEST+'::test_actual_acp_owner_native_subprocess_order_and_cleanup['+mode+']'
    for mode in ('success','delayed_interrupt','drop_ack','re_denied','multiple',
                 'failed_interrupt','outstanding','late_ack','crash_after_send'))
ADAPTER='tests/fixtures/approval_recovery_acp.py'
BACKEND='tests/fixtures/approval_native_backend.py'
PINS={TEST:'59f3eb0a28b856081bfd32173e6259f7f916eda711e3911d2ab76843c695efcb',
    ADAPTER:'1813512c5ad2177af6738fbfb99e9d43f6884394878e1034d3956ca5f0f31d46',
    BACKEND:'a18a3a8c87c86b5629304e99c6667b8c6accd31b72ded5885ffe386a6e803ba3'}
ROLES=('approval-adapter','approval-relay','approval-backend')


def relay(host,base,path):
    """Reconstruct the generated transport from four literal, scoped operands."""
    checkout=Path(host.meta['checkout'])
    native=host.binding['entry']['path']
    backend=base/'controlled-backend'
    expected=b'#!'+native.encode()+b'\n'+(checkout/BACKEND).read_bytes()
    source_unit(checkout,BACKEND,PINS[BACKEND])
    body,_,pin=read_regular(backend,32768,uid=20000,mode=0o700)
    if body!=expected:
        raise Refused('approval controlled backend exact bytes')
    body,_,relay_pin=read_regular(path,4096,uid=20000,mode=0o700)
    try:
        call=ast.parse(body).body[-1].value
        args=tuple(ast.literal_eval(arg) for arg in call.args)
    except (ValueError,SyntaxError,AttributeError,TypeError):
        raise Refused('approval relay literal transport') from None
    if (len(args)!=4 or any(type(value) is not str for value in args)
            or args[0]!=str(path.parent/'control') or args[2:]!=(str(backend),pin)
            or re.fullmatch('[a-f0-9]{64}',args[1]) is None):
        raise Refused('approval relay scoped transport operands')
    directory=path.parent.lstat()
    if (path.name!='backend' or path.resolve()!=path
            or host.fixture_roots.get(('approval-unix',host.case,args[0]))!=(directory.st_dev,directory.st_ino)):
        raise Refused('approval relay requires acquired socket generation')
    expected=(f'#!{native}\nimport sys\nsys.path.insert(0, {str(checkout/"src")!r})\n'
        'from unrest_harness.approval_relay import main\n'+f'main({args[0]!r}, {args[1]!r}, {args[2]!r}, {args[3]!r})\n').encode()
    if body!=expected:
        raise Refused('approval relay exact generated body')
    return relay_pin,pin


def proposal(host,actor,raw):
    case=host.case
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PINS[TEST])
    if case not in CASES or raw['stdin'] is not None or raw['executable']!=host.binding['entry']['path']:
        raise Refused('approval controlled case and input')
    base=retain(host,Path(raw['cwd']).parent,case.split('::')[1].split('[')[0][:30],20000)
    if raw['cwd']!=str(base/'workspace'):
        raise Refused('approval original workspace')
    from cleanup_launch import environment,read_pipe
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    module=raw['argv'][1:2]==['-c']
    rows=[row for row in host.intents.values() if row['case']==case]
    fields={}
    inherited,port=[],None
    if actor['role']=='root':
        host.root_only(actor)
        env=environment(base,host.meta_environment(),agent=not module)
        if module:
            if rows or len(raw['argv'])!=13:
                raise Refused('approval exact first MCP constructor')
            from network_scope import port_argument
            port=port_argument(raw['argv'][-3])
            fd=int(raw['argv'][-1])
            inherited=[read_pipe(actor['birth'],fd)]
            body='from unrest_harness.approval_recovery import run_owned_mcp; run_owned_mcp('+str(actor['birth'].pid)+')'
            vector=(native,'-c',body,'--mode','worker','--transport','streamable-http','--host','127.0.0.1','--port',str(port),'--sensitive-inventory-fd',str(fd))
            role,kind,payload='mcp','python-command',None
        else:
            if len(rows)!=1 or rows[0]['role']!='mcp':
                raise Refused('approval adapter before actual MCP execution')
            if not host.executed(rows[0]) or not host.actors[rows[0]['pid']]['body_ready']:
                return None
            source_unit(checkout,ADAPTER,PINS[ADAPTER])
            file=base/'scenario.json'
            body,_,_=read_regular(file,4096,uid=20000,mode=0o644)
            value=json.loads(body,object_pairs_hook=unique)
            expected={'mode':case.rsplit('[',1)[1][:-1],'trace':str(base/'trace.jsonl'),
                'handoff':str(base/'home/projects/project/.unrest-runtime/missions/mission-001/attempts/attempt-1__w1.json')}
            if value!=expected:
                raise Refused('approval bounded scenario operands')
            path=Path(raw['environment'].get('CODEX_PATH',''))
            relay(host,base,path)
            env['CODEX_PATH']=str(path)
            vector=(native,str(checkout/ADAPTER),str(file))
            role,kind,payload='approval-adapter','python-script',PINS[ADAPTER]
            fields={'approval_relay':str(path),'approval_base':str(base)}
            snapshot=host.directory/('approval-'+hashlib.sha256(case.encode()).hexdigest()+'.json')
    else:
        from source_observer import bound_intent
        parent=bound_intent(host,actor)
        if parent is None or not actor['body_ready'] or not host.executed(parent):
            raise Refused('approval actual ready chain parent')
        env=dict(parent['environment'])
        path=Path(parent.get('approval_relay',''))
        relay_pin,backend_pin=relay(host,base,path)
        if actor['role']=='approval-adapter':
            env.update(CONTROLLED_APPROVAL_MODE=case.rsplit('[',1)[1][:-1],CONTROLLED_APPROVAL_TRACE=str(base/'trace.jsonl'))
            vector=(str(path),'app-server')
            role,payload='approval-relay',relay_pin
        elif actor['role']=='approval-relay':
            env['CODEX_PATH']=str(base/'controlled-backend')
            vector=(str(base/'controlled-backend'),'app-server')
            role,payload='approval-backend',backend_pin
        else:
            raise Refused('approval chain has no further descendants')
        kind='python-script'
        fields={'approval_relay':str(path),'approval_base':str(base)}
    expected=build_expected(case,native,pin,vector,tuple(sorted(env.items())),raw['cwd'],kind,payload)
    translated=[native,'-I','-S',*vector[1:]] if vector[0]==native else [native,'-I','-S',*vector]
    if role=='approval-adapter':
        translated[-1]=str(snapshot)
    fields.update(executable=native,executable_sha256=pin)
    answer=admit_expected(host,actor,raw,expected,role,translated,payload,inherited=inherited,port=port,fields=fields)
    if answer is not None and role=='approval-adapter':
        with snapshot.open('xb') as stream:
            stream.write(body)
        snapshot.chmod(0o444)
    return answer


def signal(host,actor,payload):
    from process_ledger import Birth
    from linux_observation import process_identity
    host.root_only(actor)
    child=host.actors.get(payload['pid']) if type(payload['pid']) is int else None
    if (host.case not in CASES or not actor['body_ready'] or child is None
            or child['case']!=host.case or child['role'] not in ('approval-relay','approval-backend')
            or type(payload['signal']) is not int or payload['signal'] not in (0,9) or payload['group'] is not False):
        raise Refused('approval exact owned descendant signal')
    current=child['birth']
    for _ in range(3):
        current=host.ledger.process(current).parent
        if current==actor['birth']:
            break
        if current is None:
            raise Refused('approval descendant actual ancestry')
    else:
        raise Refused('approval descendant chain bound')
    process=host.ledger.process(child['birth'])
    if process.exit is not None or process.terminal is not None:
        return {'ok':True,'live':False}
    if (not child['body_ready'] or Birth.read(process_identity(child['birth'].pid))!=host.ledger.peer_birth(child['birth'])):
        raise Refused('approval descendant actual generation')
    child['signals'].add(payload['signal'])
    return {'ok':True,'live':True}
