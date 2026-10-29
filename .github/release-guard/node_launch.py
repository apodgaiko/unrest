"""One exact ACP/MCP constructor after the owner and node sequence are bound."""
from pathlib import Path
import json

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected

SERVER='src/unrest_harness/__main__.py'
SERVER_PIN='b1fd5ade6e15ae7d24d6e14a68cef15cd5b626c2650716172719de100ca43e48'


def proposal(host,actor,raw,cwd,environment,role,targets,script,script_pin,script_args,maximum,fields,acp_role):
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    module=raw['argv'][1:3]==['-m','unrest_harness']
    inherited,port=[],None
    if module:
        argv=raw['argv']
        if len(argv)!=13 or not argv[-3].isdigit() or not 0<int(argv[-3])<=65535 or not argv[-1].isdigit():
            raise Refused('original MCP port or descriptor')
        port,fd=int(argv[-3]),int(argv[-1])
        from cleanup_launch import read_pipe
        inherited=[read_pipe(actor['birth'].pid,fd)]
        if role!='terminal_reviewer':
            environment={**environment,'UNREST_NODE_ASSIGNMENT':json.dumps({'targets':targets,'task_type':role},sort_keys=True,separators=(',',':'))}
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
        maximum=maximum,inherited=inherited,port=port,fields=fields)
