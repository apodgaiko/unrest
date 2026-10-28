"""Pinned literal inline entries and their sole read-only repository query."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from content_manifest import Refused
from git_observer import image
from launch_policy import Rule, render

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
CASES = (*IMPORT_CASES,*STDIO,OBSERVATION_CASE)
GROUPS = (IMPORT_CASES,tuple(STDIO),(OBSERVATION_CASE,),CASES)
SEQUENCES.update({case:('startup',) for case in STDIO})
SEQUENCES[OBSERVATION_CASE] = OBSERVATION_OPERATIONS
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
    owner=STDIO_TEST+':test_real_startup_rejection_is_bounded_and_body_free'
    return render(Rule('fixed:startup',owner,(case,),native,pin,vector,tuple(sorted(environment.items())),cwd,'python-command'),case,owner,{}, {})



def script(checkout, operation):
    path = OBSERVATION_TEST if operation in OBSERVATION_OPERATIONS else TEST
    data = (checkout / path).read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[path]:
        raise Refused('fixed inline source bytes')
    name = 'test_fresh_entrypoint_import_boundary' if operation in OBSERVATION_OPERATIONS else 'test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe'
    functions = [node for node in ast.parse(data).body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(functions) != 1:
        raise Refused('fixed inline literal owner')
    values = [node.value.value for node in functions[0].body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'script'
              and isinstance(node.value, ast.Constant) and type(node.value.value) is str]
    if len(values) != 1:
        raise Refused('fixed inline literal declaration')
    return values[0]


def expected(case, operation, native, pin, checkout, environment, *, query=False):
    if type(case) is not str or case not in (*IMPORT_CASES,OBSERVATION_CASE) or type(operation) is not str or operation not in SEQUENCES[case] or type(query) is not bool:
        raise Refused('fixed inline closed operation')
    if case==OBSERVATION_CASE:
        if query or operation not in OBSERVATION_OPERATIONS:
            raise Refused('observation probe has no query authority')
        argv=(native,'-c',script(checkout,operation),*OBSERVATION_ARGUMENTS[operation])
        owner=OBSERVATION_TEST+':test_fresh_entrypoint_import_boundary'
        return render(Rule('fixed:'+operation,owner,(case,),native,pin,argv,
            tuple(sorted(environment.items())),str(checkout),'python-command'),case,owner,{}, {})
    if query:
        if operation != 'check':
            raise Refused('fixed inline query scope')
        argv, executable, pin, kind = ('git','-C',str(checkout),'rev-parse','--show-toplevel'), '/usr/bin/git', image(), 'native'
        owner = PRODUCT + ':find_repository_root'
    else:
        body = script(checkout, operation)
        tail = (json.dumps(REMOVED),) if operation == 'mcp' else (json.dumps(() if operation == 'check' else REMOVED), json.dumps(ARGUMENTS[operation]))
        argv, executable, kind = (native,'-c',body,*tail), native, 'python-command'
        owner = TEST + ':' + ('test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe')
    rule = Rule('fixed:' + ('query' if query else operation), owner, (case,), executable, pin, argv,
                tuple(sorted(environment.items())), str(checkout), kind, None)
    return render(rule, case, owner, {}, {})
