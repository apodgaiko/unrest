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


def named(code, name):
    matches = [value for value in code.co_consts if type(value) is types.CodeType and value.co_name == name]
    if len(matches) != 1:
        raise RuntimeError('mock_backend_setup_code_identity')
    return matches[0]


def eligible(state, endpoint, payload):
    if (type(state.get('class')) is not str or state.get('class') not in CLASSES
            or type(state.get('token')) is not str or not state['token']
            or state.get('setup_mode') not in {None, 'source'}
            or state.get('phase') != 'READY' or type(payload) is not dict):
        return False
    script = str(Path(state['checkout']) / SCRIPT)
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
    expected = state['product_pins'].get(path.relative_to(state['checkout']).as_posix())
    return (expected is not None and source.get('sha256') == expected
            and type(source.get('line')) is int and source['line'] > 0)


def select(guard, endpoint):
    state = guard._STATE
    if state.get('class') not in CLASSES or state.get('setup_mode') not in {None, 'source'}:
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
        script = Path(payload['target'])
        binding = Path(payload['source_binding']['path'])
        runtime = Path(payload['orig_argv'][0])
        if (script.resolve(strict=True) != script or script.is_symlink()
                or hashlib.sha256(script.read_bytes()).hexdigest() != PIN
                or hashlib.sha256(binding.read_bytes()).hexdigest() != payload['source_binding']['sha256']
                or str(runtime.resolve(strict=True)) != state['runtime']['realpath']
                or hashlib.sha256(runtime.read_bytes()).hexdigest() != state['runtime']['sha256']):
            return None
        guard.require_ready(state['token'])
        return {'kind': 'dependency_configuration_not_applicable',
                'component': 'FastMCP', 'reason': 'pinned_json_only_mock_backend',
                'script_sha256': PIN, 'class': state['class'], 'token': state['token'],
                'shared_startup_checks_retained': True}
    finally:
        del current, caller, child
