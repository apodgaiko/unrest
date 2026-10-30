"""One exact ACP/MCP constructor after the owner and node sequence are bound."""
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected

SERVER='src/unrest_harness/__main__.py'
SERVER_PIN='b1fd5ade6e15ae7d24d6e14a68cef15cd5b626c2650716172719de100ca43e48'


def proposal(host,actor,raw,cwd,ambient,home,project,roles,script,script_pin,script_args,maximum,fields,acp_role):
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    module=raw['argv'][1:3]==['-m','unrest_harness']
    inherited,port=[],None
    selected={'worker':'work','validator':'validate','terminal-reviewer':'terminal_reviewer'}
    role=selected.get(raw['argv'][4]) if module and len(raw['argv'])>4 else ('terminal_reviewer'
        if 'UNREST_TERMINAL_REVIEW_PATH' in raw['environment'] else raw['environment'].get('UNREST_NODE_TYPE'))
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('parent')==actor['birth']
        and row['role']==('mcp' if module else acp_role) and row.get('node_role')==role]
    if role not in roles or len(records)>=roles[role]:
        raise Refused('node parent role/template budget')
    from node_environment import scoped,baseline
    environment=scoped(raw['environment'],baseline(ambient,home,project),home,project,role,module=module)
    if module:
        argv=raw['argv']
        if len(argv)!=13 or not argv[-3].isdigit() or not 0<int(argv[-3])<=65535 or not argv[-1].isdigit():
            raise Refused('original MCP port or descriptor')
        port,fd=int(argv[-3]),int(argv[-1])
        from cleanup_launch import read_pipe
        inherited=[read_pipe(actor['birth'],fd)]
        mode={'work':'worker','validate':'validator','terminal_reviewer':'terminal-reviewer'}[role]
        vector=(native,'-m','unrest_harness','--mode',mode,'--transport','streamable-http','--host','127.0.0.1','--port',str(port),'--sensitive-inventory-fd',str(fd))
        source_unit(Path(host.meta['checkout']),SERVER,SERVER_PIN)
        domain,kind,payload='mcp','python-module',SERVER_PIN
    else:
        vector=(native,str(script),*script_args)
        domain,kind,payload=acp_role,'python-script',script_pin
    if raw['executable']!=native or raw['stdin'] is not None:
        raise Refused('exact node Python image or input')
    expected=build_expected(host.case,native,pin,vector,tuple(sorted(environment.items())),str(cwd),kind,payload)
    return admit_expected(host,actor,raw,expected,domain,[native,'-I','-S',*vector[1:]],payload,
        maximum=maximum,inherited=inherited,port=port,fields={**fields,'node_role':role})
