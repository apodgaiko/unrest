"""Finite concurrent role-server slots; reservations never confer listener authority."""
from pathlib import Path

from completion_roles import CASES,root,schedule,program,environment,mode
from completion_git import proposal as git_proposal,ready as git_ready
from content_manifest import Refused
from launch_policy import admit_expected,build_expected


def rows(host):
    found={}
    for row in host.intents.values():
        if row['case']==host.case and 'server_slot' in row:
            slot=row['server_slot']
            if type(slot) is not int or slot in found or not 0<=slot<len(schedule(host.case)):
                raise Refused('completion unique authored server slot')
            found[slot]=row
    return found


def status(host,actor,slot):
    process=host.ledger.process(actor['birth'])
    terminal=process.terminal
    if terminal is None or not actor['body_ready']:
        return False
    if CASES[actor['case']][0]=='crash' and slot==0:
        return terminal[2]==73
    return terminal[2]==0 or terminal[2] in (-9,-15) and -terminal[2] in actor['signals']


def before(host,slot):
    existing=rows(host)
    family,_,_=CASES[host.case]
    key=('completion-role',host.case)
    value=host.fixture_roots.get(key)
    if value is None:
        raise Refused('completion server before fixture Git')
    parent=Path(value[0])
    root(host,str(parent/'workspace'))
    git_ready(host,parent/'workspace')
    if slot in existing or family!='setup' and slot!=len(existing):
        raise Refused('completion original server sequence')
    if any(not host.executed(row) for row in existing.values()):
        return None
    return parent


def proposal(host,actor,raw):
    if raw['argv'][:1]==['ps']:
        from http_cases import proposal as inventory
        return inventory(host,actor,raw)
    from composed_cases import CASES as COMPOSED,roles
    if host.case in COMPOSED and raw['argv'][1:3]==['-m','unrest_harness.run_worker']:
        from composed_runtime import worker
        return worker(host,actor,raw)
    if host.case in COMPOSED and actor['role']!='root' and raw['executable']!='/usr/bin/git':
        from composed_runtime import nested
        return nested(host,actor,raw)
    if raw['executable']=='/usr/bin/git':
        return git_proposal(host,actor,raw)
    host.root_only(actor)
    if raw['stdin'] is not None:
        raise Refused('completion server undeclared constructor input')
    case=host.case
    existing=rows(host)
    family,role,_=CASES[case]
    slot=(int(raw['argv'][3]) if family=='setup' and len(raw['argv'])==6 and raw['argv'][3] in ('0','1')
          else len(existing))
    if slot>=len(schedule(case)):
        raise Refused('completion server quota exhausted')
    parent=before(host,slot)
    if parent is None:
        return None
    kind=schedule(case)[slot][0]
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    checkout=Path(host.meta['checkout'])
    selected_mode=mode(case,slot)
    ambient={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    env=environment(checkout,parent,case,slot,ambient,native=native,observed=raw['environment'])
    body=program(checkout,parent,case,slot)
    port=None
    if kind=='http':
        from network_scope import port_argument
        port=port_argument(raw['argv'][-1])
        vector=(native,'-c',body,'--mode',selected_mode,'--transport','streamable-http','--host','127.0.0.1','--port',str(port))
    else:
        vector=(native,'-c',body,*((str(slot),) if family=='setup' else ()),*(('--mode',selected_mode) if kind=='stdio' else ()))
    value=build_expected(case,native,pin,vector,
        tuple(sorted(env.items())),str(parent/'workspace'),'python-command')
    translated=[native,'-I','-S',*vector[1:]]
    from composed_runtime import bootstrap
    answer=admit_expected(host,actor,raw,value,'mcp' if kind=='http' else 'fixed-inline',translated,
        fields={'server_slot':slot,
            'execution_fixture':bootstrap(host,parent) if case in COMPOSED else None},
        maximum=len(schedule(case))+(len(roles(case)) if case in COMPOSED else 0),port=port)
    return answer
