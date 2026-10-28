"""Pinned literal inline entries and their sole read-only repository query."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from content_manifest import Refused
from git_observer import image
from launch_policy import build_expected

TEST = 'tests/test_repository_contract.py'
PRODUCT = 'src/unrest_harness/repository_contract.py'
REMOVED = ('unrest_harness.baseline', 'unrest_harness.governance', 'unrest_harness.repository_contract')
ARGUMENTS = {'help': ('--help',), 'init': ('init', '--help'), 'list': ('list-projects',), 'check': ('check-repository',)}
IMPORT_CASES = tuple(TEST + '::' + name for name in (
    *(f'test_ordinary_cli_entrypoints_do_not_import_repository_modules[arguments{i}]' for i in range(3)),
    'test_repository_command_is_the_lazy_positive_control', 'test_mcp_help_does_not_import_repository_modules',
    'test_real_entrypoint_import_boundary'))
SEQUENCES = dict(zip(IMPORT_CASES, (('help',), ('init',), ('list',), ('check',), ('mcp',), ('help','init','list','mcp','check')), strict=True))
PINS = {'tests/test_repository_contract.py': '12b3f3d7dd5b52bef6d88d5bd2761469a89d748f33f0ef77640579b2228b9f6c', 'src/unrest_harness/repository_contract.py': '619255f96649e14a931e6e0dbf888c1589f023dde96c3a977cda473f08404b86'}


STDIO_TEST = 'tests/test_stdio_startup.py'
STDIO_BODY = 'from unrest_harness.server import main; main()'
STDIO_INVALID = ({'UNREST_CAPABILITY_POLICY_VERSION':'2'}, {'UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS':'invalid'})
STDIO = {STDIO_TEST+'::test_real_startup_rejection_is_bounded_and_body_free[invalid'+str(index)+'-'+role+']':(role,index)
         for index in range(2) for role in ('orchestrator','worker','validator','terminal-reviewer')}
OBSERVATION_TEST = 'tests/test_runtime_observability.py'
OBSERVATION_CASE = OBSERVATION_TEST+'::test_fresh_entrypoint_import_boundary'
OBSERVATION_OPERATIONS = ('observe-help','observe-list','observe-positive')
OBSERVATION_ARGUMENTS = {
    'observe-help': ('["--help"]','1'),
    'observe-list': ('["list-projects"]','1'),
    'observe-positive': ('["observe-project", "--help"]','0'),
}
PINS[OBSERVATION_TEST] = 'bc4977de515c9f3a3b3ccab626a245525deccd9a6449fce8ad02253d220af305'
RELOAD_TEST = 'tests/test_v04_speed_runner.py'
RELOAD_NAME = 'test_process_installs_only_one_audit_hook_across_reload'
RELOAD_CASE = RELOAD_TEST + '::' + RELOAD_NAME
PINS[RELOAD_TEST] = 'b54e199791a0ad5e9a9e34ebc0eb6b2e93e333435faba86cb6481f502c1027c4'
METHOD_NAME = 'test_preexisting_socket_and_bound_alias_refuse_entry_before_payload'
METHODS = ('connect','connect_ex','bind','listen','accept','send','sendall','sendto','sendmsg',
           'sendfile','recv','recv_into','recvfrom','recvfrom_into','recvmsg','recvmsg_into','makefile','shutdown')
METHOD_CASES = tuple(RELOAD_TEST+'::'+METHOD_NAME+'['+method+']' for method in METHODS)
ISOLATED = {RELOAD_CASE:'reload', **dict(zip(METHOD_CASES,METHODS,strict=True))}
CASES = (*IMPORT_CASES,*STDIO,OBSERVATION_CASE,*ISOLATED)
GROUPS = (IMPORT_CASES,tuple(STDIO),(OBSERVATION_CASE,),(RELOAD_CASE,),METHOD_CASES,CASES)
SEQUENCES.update({case:('startup',) for case in STDIO})
SEQUENCES[OBSERVATION_CASE] = OBSERVATION_OPERATIONS
SEQUENCES.update({case:(operation,) for case,operation in ISOLATED.items()})
PINS[STDIO_TEST] = '588e6f2128c32f4020cae0dfaf00182bdc117ea640760da1790dd687f5246105'


def translated(value):
    return (value.argv[0],'-I','-S',*value.argv[2 if value.case in STDIO else 1:])


def startup_expected(case,native,pin,cwd,owned):
    if type(case) is not str or case not in STDIO or type(cwd) is not str:
        raise Refused('fixed startup declaration')
    root=Path(cwd)
    if str(root.resolve())!=cwd or root==owned/'pytest' or not root.is_relative_to(owned/'pytest'):
        raise Refused('fixed startup original fixture root')
    role,index=STDIO[case]
    environment={'PATH':'/bin:/usr/bin','HOME':cwd,'UNREST_HOME':str(root/'home'),**STDIO_INVALID[index]}
    vector=(native,'-I','-c',STDIO_BODY,'--mode',role)
    return build_expected('fixed:startup', case, native, pin, vector, tuple(sorted(environment.items())), cwd, 'python-command')


def script(checkout, operation):
    path = RELOAD_TEST if operation in ('reload',*METHODS) else OBSERVATION_TEST if operation in OBSERVATION_OPERATIONS else TEST
    data = (checkout / path).read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[path]:
        raise Refused('fixed inline source bytes')
    name = RELOAD_NAME if operation=='reload' else METHOD_NAME if operation in METHODS else 'test_fresh_entrypoint_import_boundary' if operation in OBSERVATION_OPERATIONS else 'test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe'
    functions = [node for node in ast.parse(data).body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(functions) != 1:
        raise Refused('fixed inline literal owner')
    if operation in ('reload',*METHODS):
        bodies=[node.args[0] for node in ast.walk(functions[0]) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name) and node.func.id=='_isolated_python'
                and len(node.args)==1]
        if len(bodies)!=1:
            raise Refused('fixed isolated sole literal body')
        body=bodies[0]
        if operation=='reload' and isinstance(body,ast.Constant) and type(body.value) is str:
            return body.value
        if operation not in METHODS or not isinstance(body,ast.JoinedStr):
            raise Refused('fixed isolated literal template')
        parts=[]
        for part in body.values:
            if isinstance(part,ast.Constant) and type(part.value) is str:
                parts.append(part.value)
            elif (isinstance(part,ast.FormattedValue) and isinstance(part.value,ast.Name)
                  and part.value.id=='method' and part.conversion==-1 and part.format_spec is None):
                parts.append(operation)
            else:
                raise Refused('fixed isolated template substitution')
        return ''.join(parts)
    values = [node.value.value for node in functions[0].body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'script'
              and isinstance(node.value, ast.Constant) and type(node.value.value) is str]
    if len(values) != 1:
        raise Refused('fixed inline literal declaration')
    return values[0]


def expected(case, operation, native, pin, checkout, environment, *, query=False):
    if type(case) is not str or case not in (*IMPORT_CASES,OBSERVATION_CASE,*ISOLATED) or type(operation) is not str or operation not in SEQUENCES[case] or type(query) is not bool:
        raise Refused('fixed inline closed operation')
    if case in ISOLATED:
        if query:
            raise Refused('fixed isolated has no descendant authority')
        return build_expected('fixed:isolated',case,native,pin,(native,'-c',script(checkout,ISOLATED[case])),
                              tuple(sorted({**environment,'PYTHONDONTWRITEBYTECODE':'1'}.items())),str(checkout),'python-command')
    if case==OBSERVATION_CASE:
        if query or operation not in OBSERVATION_OPERATIONS:
            raise Refused('observation probe has no query authority')
        argv=(native,'-c',script(checkout,operation),*OBSERVATION_ARGUMENTS[operation])
        return build_expected(
            'fixed:'+operation, case,
            native, pin,
            argv,
            tuple(sorted(environment.items())),
            str(checkout), 'python-command',
        )
    if query:
        if operation != 'check':
            raise Refused('fixed inline query scope')
        argv, executable, pin, kind = ('git','-C',str(checkout),'rev-parse','--show-toplevel'), '/usr/bin/git', image(), 'native'
    else:
        body = script(checkout, operation)
        tail = (json.dumps(REMOVED),) if operation == 'mcp' else (json.dumps(() if operation == 'check' else REMOVED), json.dumps(ARGUMENTS[operation]))
        argv, executable, kind = (native,'-c',body,*tail), native, 'python-command'
    return build_expected(
        'fixed:' + ('query' if query else operation), case,
        executable, pin,
        argv,
        tuple(sorted(environment.items())),
        str(checkout), kind, None,
    )
