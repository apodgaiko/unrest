"""FastMCP configuration is inapplicable only to the exact JSON mock backend."""
from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
import os
import sys
import types

SCRIPT = 'tests/mock_acp_agent.py'
PIN = '8141170328ff5fc28acf10dfd70bbf22f4062cceb1b2de8b8ea11ab0c17a48b6'
CLASSES = frozenset({'source-cohort2:mock-agent', 'source-cohort3:mock-agent',
                     'reference-descendant:ordinary-mock-acp'})

ACP = 'tests/fixtures/controlled_python_acp.py'
ACP_PIN = 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'
BACKEND = 'tests/fixtures/experimental_session_app_server.py'
BACKEND_PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'
BARRIER_PIN = '1dc876d29f45800ac9cad82037fdb41e9a584a0c17d39e4eb811edad6f0b8fb1'
SESSION = 'src/unrest_harness/experimental_session.py'
SESSION_PIN = '7a3df1d049cd8a72aac48bc376154f7701335397ad8a0e0634cf2d0a9509cbd2'
JSON_LEAVES = frozenset({'controlled-acp', 'canonical-backend',
                         'source-controlled-backend-postimage'})
CONFIGURATION_CASES = frozenset(
    prefix + '[' + skills + '-' + context + ']'
    for prefix in (
        'tests/test_controlled_acp_warnings.py::test_original_private_configuration',
        'tests/test_experimental_provider_config.py::test_startup_and_thread_controls_through_actual_owned_adapter')
    for skills in ('False', 'True') for context in ('False', 'True'))


INITIALIZATION_CASES = frozenset((
    'tests/test_controlled_python_acp.py::test_programmatic_private_preflight',
    'tests/test_experimental_startup_diagnostics.py::test_initialization_probe_real_controlled_path_no_prompt',
    'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[refusal]',
    'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[timeout]',
    'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[permission]',
    'tests/test_experimental_startup_diagnostics.py::test_initialized_owner_has_no_http_mutation_authority',
    'tests/test_experimental_startup_diagnostics.py::test_coordinator_persists_startup_and_separate_cleanup_failure',
))

def selected_script(state, payload):
    kind, root = state.get('class'), Path(state['checkout'])
    if kind in CLASSES:
        return str(root / SCRIPT), PIN
    if kind == 'controlled-acp':
        return str(root / ACP), ACP_PIN
    if kind in {'canonical-backend', 'source-controlled-backend-postimage'}:
        target = payload.get('target')
        if type(target) is not str or type(state.get('owned_root')) is not str:
            return None
        path = Path(target)
        if (not path.is_absolute() or '..' in path.parts or path.name != 'fake-app-server'
                or not path.is_relative_to(Path(state['owned_root']))):
            return None
        return target, (BACKEND_PIN if kind == 'canonical-backend'
                        or state.get('case') in CONFIGURATION_CASES | INITIALIZATION_CASES else BARRIER_PIN)
    return None


def named(code, name):
    matches = [value for value in code.co_consts if type(value) is types.CodeType and value.co_name == name]
    if len(matches) != 1:
        raise RuntimeError('mock_backend_setup_code_identity')
    return matches[0]


def eligible(state, endpoint, payload):
    if (type(state.get('class')) is not str or state.get('class') not in CLASSES | JSON_LEAVES
            or type(state.get('token')) is not str or not state['token']
            or state.get('setup_mode') not in {None, 'source'}
            or state.get('phase') != 'READY' or type(payload) is not dict):
        return False
    selected = selected_script(state, payload)
    if selected is None:
        return False
    script, _ = selected
    vector = payload.get('orig_argv')
    arguments = payload.get('sys_argv')
    if (payload.get('class') != state['class'] or payload.get('mode') != 'script'
            or payload.get('target') != script or payload.get('path0') != str(Path(script).parent)
            or payload.get('token') != state.get('token') or payload.get('case') != state.get('case')
            or endpoint.get('token') != state.get('token')
            or type(endpoint.get('identity')) is not dict or endpoint['identity'].get('pid') != os.getpid()
            or type(vector) is not list or not vector or any(type(v) is not str for v in vector)
            or type(arguments) is not list or not arguments or arguments[0] != script
            or any(type(v) is not str for v in arguments)
            or vector[0] not in state['runtime']['paths']):
        return False
    index = 1
    while index < len(vector) and vector[index] in {'-I', '-S', '-u', '-B', '-E', '-s'}:
        index += 1
    if (index == len(vector) or vector[index] != script or vector[index:] != arguments
            or type(payload.get('isolated')) is not bool
            or payload['isolated'] != ('-I' in vector[1:index])):
        return False
    source = payload.get('source_binding')
    if type(source) is not dict or type(source.get('path')) is not str:
        return False
    path = Path(source['path'])
    if not path.is_relative_to(Path(state['checkout'])) or '..' in path.parts:
        return False
    kind = state['class']
    if kind in JSON_LEAVES:
        source_name, line, pin = ((ACP, 1, ACP_PIN) if kind == 'controlled-acp'
                             else (BACKEND, 1, BACKEND_PIN) if kind == 'canonical-backend'
                             else (SESSION, 506, SESSION_PIN))
        expected_binding = {'path': str(Path(state['checkout']) / source_name),
                            'line': line, 'sha256': pin}
        if kind == 'source-controlled-backend-postimage':
            expected_binding['function'] = '_open_role_owned'
        if payload['source_binding'] != expected_binding:
            return False
    expected = state['product_pins'].get(path.relative_to(state['checkout']).as_posix())
    return (expected is not None and source.get('sha256') == expected
            and type(source.get('line')) is int and source['line'] > 0)


def select(guard, endpoint):
    state = guard._STATE
    if state.get('class') not in CLASSES | JSON_LEAVES or state.get('setup_mode') not in {None, 'source'}:
        return None
    current = inspect.currentframe()
    caller = current.f_back if current else None
    child = caller.f_back if caller else None
    module = sys.modules.get('endpoint')
    try:
        if (module is None or caller is None or child is None
                or type(caller) is not types.FrameType or type(child) is not types.FrameType
                or caller.f_globals is not vars(module) or module.STATE is not endpoint
                or guard.install.__code__ is not caller.f_code
                or guard.install.__globals__ is not caller.f_globals
                or child.f_globals is not vars(guard) or guard.child.__code__ is not child.f_code):
            return None
        payload = child.f_locals.get('payload')
        if not eligible(state, endpoint, payload):
            return None
        guard_path = Path(state['guard'])
        guard_body = guard_path.read_bytes()
        endpoint_path = Path(module.__file__)
        endpoint_body = endpoint_path.read_bytes()
        if (hashlib.sha256(guard_body).hexdigest() != state['guard_sha256']
                or hashlib.sha256(endpoint_body).hexdigest() != state['endpoint']['sha256']
                or child.f_code != named(compile(guard_body, str(guard_path), 'exec', dont_inherit=True), 'child')
                or caller.f_code != named(named(compile(endpoint_body, str(endpoint_path), 'exec', dont_inherit=True), 'attach'), 'install')):
            return None
        _, script_pin = selected_script(state, payload)
        if state['class'] == 'source-controlled-backend-postimage':
            catalog_path = Path(state['guard']).with_name('backend_postimage_catalog.py')
            catalog = guard.checked_source(catalog_path,
                state['direct_support']['files'][str(catalog_path)])
            row = catalog['CASES'].get(state.get('case'))
            if (row is None or row['script_sha256'] != script_pin
                    or row['filename'] != 'fake-app-server'
                    or any(state['product_pins'].get(name) != pin
                           or hashlib.sha256((Path(state['checkout']) / name).read_bytes()).hexdigest() != pin
                           for name, pin in row['sources'].items())):
                return None
        script = Path(payload['target'])
        binding = Path(payload['source_binding']['path'])
        runtime = Path(payload['orig_argv'][0])
        if (script.resolve(strict=True) != script or script.is_symlink()
                or hashlib.sha256(script.read_bytes()).hexdigest() != script_pin
                or hashlib.sha256(binding.read_bytes()).hexdigest() != payload['source_binding']['sha256']
                or str(runtime.resolve(strict=True)) != state['runtime']['realpath']
                or hashlib.sha256(runtime.read_bytes()).hexdigest() != state['runtime']['sha256']):
            return None
        guard.require_ready(state['token'])
        return {'kind': 'dependency_configuration_not_applicable',
                'component': 'FastMCP', 'reason': 'pinned_json_only_mock_backend',
                'script_sha256': script_pin, 'class': state['class'], 'token': state['token'],
                'shared_startup_checks_retained': True}
    finally:
        del current, caller, child
