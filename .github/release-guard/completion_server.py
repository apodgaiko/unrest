"""Finite concurrent role-server slots; reservations never confer listener authority."""
from pathlib import Path

from completion_roles import CASES,root,schedule,program,environment,mode
from git_policy import completion_proposal as git_proposal, completion_ready as git_ready
from content_manifest import Refused, refuse_if
from launch_policy import admit_expected,build_expected,check_expected



def status(host,actor,slot):
    process=host.ledger.process(actor['birth'])
    terminal=process.terminal
    if terminal is None or not actor['body_ready']:
        return False
    if CASES[actor['case']][0]=='crash' and slot==0:
        return terminal[2]==73
    return terminal[2]==0 or terminal[2] in (-9,-15) and -terminal[2] in actor['signals']



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
    refuse_if(raw['stdin'] is not None, 'completion server undeclared constructor input')
    case=host.case
    existing=[row for row in host.intents.values() if row['case']==case and 'server_slot' in row]
    family,_,_=CASES[case]
    profiles=schedule(case)
    slot=(int(raw['argv'][3]) if family=='setup' and len(raw['argv'])==6 and raw['argv'][3] in ('0','1')
          else len(existing))
    refuse_if(slot>=len(profiles) or any(row['server_slot']==slot for row in existing), 'completion server quota exhausted')
    selected=host.fixture_roots.get(('completion-role',case))
    refuse_if(selected is None, 'completion server before fixture Git')
    parent=root(host,str(Path(selected[0])/'workspace'))
    git_ready(host,parent/'workspace')
    if any(not host.executed(row) for row in existing):
        return None
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    checkout=Path(host.meta['checkout'])
    ambient={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    for variant in ((slot,) if family in ('setup','crash') else range(len(profiles))):
        kind=profiles[variant][0]
        try:
            env=environment(checkout,parent,case,variant,ambient,native=native,observed=raw['environment'])
            body=program(checkout,parent,case,variant,env)
            port=None
            if kind=='http':
                from network_scope import port_argument
                refuse_if(len(raw['argv'])!=11, 'completion HTTP constructor arity')
                port=port_argument(raw['argv'][-1])
                vector=(native,'-c',body,'--mode',mode(case,variant),'--transport','streamable-http','--host','127.0.0.1','--port',str(port))
            else:
                vector=(native,'-c',body,*((str(slot),) if family=='setup' else ()),*(('--mode',mode(case,variant)) if kind=='stdio' else ()))
            value=build_expected(case,native,pin,vector,tuple(sorted(env.items())),str(parent/'workspace'),'python-command')
            check_expected(raw,value)
        except Refused:
            continue
        from composed_runtime import bootstrap
        return admit_expected(host,actor,raw,value,'mcp' if kind=='http' else 'fixed-inline',[native,'-I','-S',*vector[1:]],
            fields={'server_slot':slot,'server_kind':kind,
                'execution_fixture':bootstrap(host,parent) if case in COMPOSED else None},
            maximum=len(profiles)+(len(roles(case)) if case in COMPOSED else 0),port=port)
    raise Refused('completion joint launch variant')
