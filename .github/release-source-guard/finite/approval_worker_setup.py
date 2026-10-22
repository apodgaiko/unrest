"""Only the exact controlled executor defers unused SDK setup to its MCP child."""
from __future__ import annotations
import hashlib
import inspect
import os
from pathlib import Path
import sys
import types

MODULE = 'unrest_harness.run_worker'
EXECUTOR = 'tests.fixtures.approval_run_executor:execute'
PREFIX = 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives'
CASES = frozenset(PREFIX + '[' + value + ']' for value in
                  ('success', 'cancel', 'crash', 'cancel_after_send', 'crash_after_send',
                   'cancel_after_continue', 'crash_after_continue'))
PINS = {'src/unrest_harness/run_worker.py': 'bef584879b0c8da5e9db56321864dee1075b9bfeb00c0192712206efa1740e3d', 'src/unrest_harness/run_control.py': '61e11d65da2ee52735a45d38c87594ec68784b43ddca8abc3dc6c084ab00480f', 'src/unrest_harness/approval_recovery.py': '8a378de950500f2bb6e4b6bbcf55392343d0127aa68716671208b82c27e5533f', 'tests/fixtures/approval_run_executor.py': 'f6e24716d1b9103035fe99fe2af9f00bf42544d31086caa94486f3e8259a4d33'}
BINDING = {'path': '/source/src/unrest_harness/run_control.py', 'line': 1123,
           'sha256': PINS['src/unrest_harness/run_control.py'], 'function': '_spawn',
           'function_ast_sha256': 'f1677ea4b75d0195e779761d4cbf2d27cc3c87f4627eb41e53e9cd2e14fc4d43'}
FLAGS = ['--project-root', '--run-id', '--executor', '--custody-root-id', '--generation']


def named(code, name):
    matches = [value for value in code.co_consts if type(value) is types.CodeType and value.co_name == name]
    if len(matches) != 1:
        raise RuntimeError('approval_worker_setup_code_identity')
    return matches[0]


def eligible(state, endpoint, payload):
    if (state.get('class') != 'source-run-worker' or state.get('source_selection') != 'primary-source'
            or state.get('setup_mode') not in {None, 'source'} or state.get('phase') != 'READY'
            or state.get('case') not in CASES or type(payload) is not dict
            or payload.get('mode') != 'module' or payload.get('target') != MODULE
            or payload.get('class') != state['class'] or payload.get('case') != state['case']
            or type(state.get('token')) is not str or not state['token']
            or payload.get('token') != state['token'] or endpoint.get('token') != state['token']
            or endpoint.get('identity', {}).get('pid') != os.getpid()
            or payload.get('source_binding') != BINDING):
        return False
    vector = payload.get('orig_argv')
    if (type(vector) is not list or len(vector) != 13 or any(type(value) is not str for value in vector)
            or vector[0] not in state['runtime']['paths'] or vector[1:3] != ['-m', MODULE]
            or vector[3::2] != FLAGS or vector[8] != EXECUTOR
            or any(not value or '\0' in value for value in vector[4::2])
            or not vector[12].isdigit() or int(vector[12]) <= 0
            or payload.get('sys_argv') != [MODULE, *vector[3:]]
            or payload.get('path0') != vector[4] or payload.get('isolated') is not False):
        return False
    path = Path(vector[4])
    return (path.is_absolute() and path.is_relative_to(state['owned_root'])
            and '..' not in path.parts and path != Path(state['owned_root']))


def select(guard, endpoint):
    state = guard._STATE
    if state.get('class') != 'source-run-worker':
        return None
    current = inspect.currentframe()
    caller = current.f_back if current else None
    child = caller.f_back if caller else None
    module = sys.modules.get('endpoint')
    try:
        if (module is None or caller is None or child is None
                or caller.f_globals is not vars(module) or module.STATE is not endpoint
                or guard.install.__code__ is not caller.f_code or guard.install.__globals__ is not caller.f_globals
                or child.f_globals is not vars(guard) or guard.child.__code__ is not child.f_code):
            return None
        payload = child.f_locals.get('payload')
        if not eligible(state, endpoint, payload):
            guard.append({'kind': 'dependency_configuration_required', 'component': 'FastMCP',
                          'scope': 'controlled_run_executor', 'code': 'metadata'})
            return None
        guard_path, endpoint_path = Path(state['guard']), Path(module.__file__)
        guard_body, endpoint_body = guard_path.read_bytes(), endpoint_path.read_bytes()
        if (hashlib.sha256(guard_body).hexdigest() != state['guard_sha256']
                or hashlib.sha256(endpoint_body).hexdigest() != state['endpoint']['sha256']
                or child.f_code != named(compile(guard_body, str(guard_path), 'exec', dont_inherit=True), 'child')
                or caller.f_code != named(named(compile(endpoint_body, str(endpoint_path), 'exec', dont_inherit=True), 'attach'), 'install')):
            guard.append({'kind': 'dependency_configuration_required', 'component': 'FastMCP',
                          'scope': 'controlled_run_executor', 'code': 'guard_owner_pin'})
            return None
        for name, pin in PINS.items():
            if state['product_pins'].get(name) != pin or hashlib.sha256((Path(state['checkout']) / name).read_bytes()).hexdigest() != pin:
                guard.append({'kind': 'dependency_configuration_required', 'component': 'FastMCP',
                              'scope': 'controlled_run_executor', 'code': 'source_pin'})
                return None
        runtime = Path(payload['orig_argv'][0])
        if (str(runtime.resolve(strict=True)) != state['runtime']['realpath']
                or hashlib.sha256(runtime.read_bytes()).hexdigest() != state['runtime']['sha256']
                or Path(payload['path0']).resolve(strict=True) != Path(payload['path0'])
                or Path(payload['path0']) != Path.cwd()):
            guard.append({'kind': 'dependency_configuration_required', 'component': 'FastMCP',
                          'scope': 'controlled_run_executor', 'code': 'runtime_or_cwd'})
            return None
        guard.require_ready(state['token'])
        return {'kind': 'dependency_configuration_not_applicable', 'component': 'FastMCP',
                'reason': 'pinned_controlled_run_executor', 'class': state['class'],
                'executor': EXECUTOR, 'token': state['token'],
                'actual_mcp_child_setup_required': True, 'shared_startup_checks_retained': True}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, SyntaxError):
        return None
    finally:
        del current, caller, child
