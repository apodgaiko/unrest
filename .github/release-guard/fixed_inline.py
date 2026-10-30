"""Pinned literal inline entries and their sole read-only repository query."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from content_manifest import Refused
from git_policy import image
from launch_policy import build_expected,source_unit,literal,render_string
from speed_inline import CASES as SPEED_CASES, PRELUDE, CLI_CASE, cli_expected
from nested_pytest import CASE as NESTED_CASE, NODES, PYTEST_PIN, CASES as NESTED_CASES, HERMETIC, hermetic

from storage_launch import CASES as STORAGE_CASES, DIRECTORY as STORAGE_DIRECTORY
from inspection_launch import CASES as INSPECTION_CASES, FRONTIER
from measurement_launch import CASE as MEASUREMENT_CASE
from completion_launch import CASES as COMPLETION_CASES, SEQUENCES as COMPLETION_SEQUENCES

TEST = 'tests/test_repository_contract.py'
REMOVED = ('unrest_harness.baseline', 'unrest_harness.governance', 'unrest_harness.repository_contract')
ARGUMENTS = {'help': ('--help',), 'init': ('init', '--help'), 'list': ('list-projects',), 'check': ('check-repository',)}
IMPORT_CASES = tuple(TEST + '::' + name for name in (
    *(f'test_ordinary_cli_entrypoints_do_not_import_repository_modules[arguments{i}]' for i in range(3)),
    'test_repository_command_is_the_lazy_positive_control', 'test_mcp_help_does_not_import_repository_modules',
    'test_real_entrypoint_import_boundary'))
SEQUENCES = dict(zip(IMPORT_CASES, (('help',), ('init',), ('list',), ('check',), ('mcp',), ('help','init','list','mcp','check')), strict=True))
PINS = {'tests/test_repository_contract.py': '1c1fcfee0aefd633452a4515e451a0008cef5e758a47f09fbc1e16e8d988d72c', 'src/unrest_harness/repository_contract.py': '619255f96649e14a931e6e0dbf888c1589f023dde96c3a977cda473f08404b86'}


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
JOURNAL_TEST='tests/test_mutation_journal.py'
JOURNAL_CASE=JOURNAL_TEST+'::test_live_foreign_owner_is_busy_and_record_is_unchanged'
PINS[JOURNAL_TEST]='dbaec57f5937ce7583c1de5819ee87b55dd30f45d8e4a3cc0c2d8d9b1607ea49'
RELOAD_TEST = 'tests/test_v04_speed_runner.py'
RELOAD_NAME = 'test_process_installs_only_one_audit_hook_across_reload'
RELOAD_CASE = RELOAD_TEST + '::' + RELOAD_NAME
PINS[RELOAD_TEST] = 'b54e199791a0ad5e9a9e34ebc0eb6b2e93e333435faba86cb6481f502c1027c4'
PINS['tests/test_task_adapter.py'] = '3adc28c5825c8f9c83c79e36193941490f362aaef259088b4a81e777c54d84f3'
METHOD_NAME = 'test_preexisting_socket_and_bound_alias_refuse_entry_before_payload'
METHODS = ('connect','connect_ex','bind','listen','accept','send','sendall','sendto','sendmsg',
           'sendfile','recv','recv_into','recvfrom','recvfrom_into','recvmsg','recvmsg_into','makefile','shutdown')
METHOD_CASES = tuple(RELOAD_TEST+'::'+METHOD_NAME+'['+method+']' for method in METHODS)
NETWORK_NAME = 'test_preexisting_network_socket_objects_and_descriptors_refuse_entry_once'
NETWORK = {RELOAD_TEST+'::'+NETWORK_NAME+f'[{detached}-{family}]':(family,detached)
           for detached in (False,True) for family in (2,10)}
DETACHED_CASE = RELOAD_TEST+'::test_detached_socket_descriptor_is_preflight_evidence'
ISOLATED = {RELOAD_CASE:'reload', DETACHED_CASE:'detached', **dict(zip(METHOD_CASES,METHODS,strict=True)),
            **{case:case for case in (*NETWORK,*SPEED_CASES)}}
DRAIN_TEST='tests/test_lean_provider_security_runtime.py'
DRAIN_CASE=DRAIN_TEST+'::test_chatty_child_pipes_are_continuously_drained_bounded_and_reaped'
PINS[DRAIN_TEST]='f0984a07bd8bb410c3f6046afd4578cb3dad6d10137aceff09fb696b8880183e'
CASES = (DRAIN_CASE,*IMPORT_CASES,*STDIO,OBSERVATION_CASE,CLI_CASE,*NESTED_CASES,JOURNAL_CASE,MEASUREMENT_CASE,*STORAGE_CASES,*INSPECTION_CASES,*COMPLETION_CASES,*ISOLATED)
SEQUENCES.update({case:('startup',) for case in STDIO})
SEQUENCES[OBSERVATION_CASE] = OBSERVATION_OPERATIONS
SEQUENCES[CLI_CASE] = tuple('run-'+str(i) for i in range(5))
SEQUENCES.update({case:('pytest',) for case in NESTED_CASES})
SEQUENCES.update({case:('read0','read1') if case==STORAGE_DIRECTORY else ('read0',) for case in STORAGE_CASES})
SEQUENCES[JOURNAL_CASE]=('sleep',)
SEQUENCES[MEASUREMENT_CASE]=('simulate',)
SEQUENCES[DRAIN_CASE]=('drain',)
SEQUENCES.update(COMPLETION_SEQUENCES)
SEQUENCES.update({case:('read0','read1') if case==FRONTIER else ('read0',) for case in INSPECTION_CASES})
SEQUENCES.update({case:(operation,) for case,operation in ISOLATED.items()})
PINS[STDIO_TEST] = '588e6f2128c32f4020cae0dfaf00182bdc117ea640760da1790dd687f5246105'


def translated(value):
    if value.case in SPEED_CASES:
        return (value.argv[0],'-I','-S','-c',PRELUDE+value.argv[2])
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
    return build_expected(case, native, pin, vector, tuple(sorted(environment.items())), cwd, 'python-command')


def script(checkout, operation, root=None):
    path = RELOAD_TEST if operation in ('reload','detached',*METHODS,*NETWORK,*SPEED_CASES) else OBSERVATION_TEST if operation in OBSERVATION_OPERATIONS else TEST
    tree=source_unit(checkout,path,PINS[path])
    if operation in SPEED_CASES:
        from speed_inline import body
        return body(tree,operation,root,checkout)
    name = NETWORK_NAME if operation in NETWORK else 'test_detached_socket_descriptor_is_preflight_evidence' if operation=='detached' else RELOAD_NAME if operation=='reload' else METHOD_NAME if operation in METHODS else 'test_fresh_entrypoint_import_boundary' if operation in OBSERVATION_OPERATIONS else 'test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe'
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if operation in ('reload','detached',*METHODS,*NETWORK):
        bodies=[node.args[0] for node in ast.walk(functions[0]) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name) and node.func.id=='_isolated_python'
                and len(node.args)==1]
        body=bodies[0]
        if operation in ('reload','detached'):
            return body.value
        substitutions=(('method',-1,operation),) if operation in METHODS else (
            ('family',-1,str(NETWORK[operation][0])),('detached',114,repr(NETWORK[operation][1])))
        return render_string(body,substitutions)
    return literal(functions[0],'script')


def expected(case, operation, native, pin, checkout, environment, *, query=False, root=None):
    if type(case) is not str or case not in (*IMPORT_CASES,OBSERVATION_CASE,CLI_CASE,JOURNAL_CASE,*NESTED_CASES,*ISOLATED) or type(operation) is not str or operation not in SEQUENCES[case] or type(query) is not bool:
        raise Refused('fixed inline closed operation')
    if case==JOURNAL_CASE:
        if query:
            raise Refused('journal sleep has no descendants')
        owner=source_unit(checkout,JOURNAL_TEST,PINS[JOURNAL_TEST],(JOURNAL_CASE.split('::')[-1],))
        calls=[node for node in ast.walk(owner) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='Popen']
        program=ast.literal_eval(calls[0].args[0].elts[2])
        return build_expected(case,native,pin,(native,'-c',program),tuple(sorted(environment.items())),str(checkout),'python-command')
    if case==HERMETIC and not query:
        body,environment=hermetic(checkout,environment)
        nodes=NESTED_CASES[case]
        vector=(native,'-c',body,'-q',*(str(checkout/node) for node in nodes[:2]),nodes[2])
        return build_expected(case,native,pin,vector,tuple(sorted(environment.items())),str(checkout),'python-command')
    if case==NESTED_CASE and not query:
        for path in ('tests/test_task_adapter.py',RELOAD_TEST):
            if hashlib.sha256((checkout/path).read_bytes()).hexdigest()!=PINS[path]:
                raise Refused('preselected original source bytes')
        return build_expected(case,native,pin,(native,'-m','pytest','-q',*NODES),
            tuple(sorted({**environment,'PYTHONDONTWRITEBYTECODE':'1'}.items())),str(checkout),'python-module',PYTEST_PIN)
    if case==CLI_CASE and not query:
        return cli_expected(native,pin,checkout,root,operation)
    if case in ISOLATED:
        if query:
            raise Refused('fixed isolated has no descendant authority')
        return build_expected(case,native,pin,(native,'-c',script(checkout,ISOLATED[case],root)),
                              tuple(sorted({**environment,'PYTHONDONTWRITEBYTECODE':'1'}.items())),str(checkout),'python-command')
    if case==OBSERVATION_CASE:
        if query or operation not in OBSERVATION_OPERATIONS:
            raise Refused('observation probe has no query authority')
        argv=(native,'-c',script(checkout,operation),*OBSERVATION_ARGUMENTS[operation])
        return build_expected(
            case,
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
        case,
        executable, pin,
        argv,
        tuple(sorted(environment.items())),
        str(checkout), kind, None,
    )
