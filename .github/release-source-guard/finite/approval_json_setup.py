"""Omit FastMCP-only setup for three exact controlled JSON fixture actors."""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import re
import sys
import types

BINDINGS = {
    'source-approval-adapter': ('src/unrest_harness/acp_runner.py', 409,
        '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'),
    'source-approval-relay': ('tests/fixtures/approval_recovery_acp.py', 17,
        '1813512c5ad2177af6738fbfb99e9d43f6884394878e1034d3956ca5f0f31d46'),
    'source-approval-python-backend': ('src/unrest_harness/approval_relay.py', 131,
        'efaba9521aa12d6fbdb228f05da210a4027675c79830d1a5ca93627faa80da44'),
}
PURE = {
    'tests/fixtures/approval_recovery_acp.py': '1813512c5ad2177af6738fbfb99e9d43f6884394878e1034d3956ca5f0f31d46',
    'tests/fixtures/approval_native_backend.py': 'a18a3a8c87c86b5629304e99c6667b8c6accd31b72ded5885ffe386a6e803ba3',
    'src/unrest_harness/approval_relay.py': 'efaba9521aa12d6fbdb228f05da210a4027675c79830d1a5ca93627faa80da44',
    'src/unrest_harness/approval_native.py': 'ea3b81842f15d41f4bda01a94ef81c97781e93ffe4a1216be4805201bd305e84',
    'src/unrest_harness/provider_review.py': '527a43a77a0fcb022ca535fd68f071cdbe5c6d9616846e25e35c4966313ae468',
    'src/unrest_harness/__init__.py': '74850da5471db9efec89961960c9568c05a8f38787e8e624b3c9f7800e4841fb',
}


def named(code, name):
    matches = [v for v in code.co_consts if type(v) is types.CodeType and v.co_name == name]
    if len(matches) != 1:
        raise RuntimeError('approval_json_setup_code_identity')
    return matches[0]


def eligible(state, endpoint, payload, mode):
    kind = state.get('class')
    if (kind not in BINDINGS or mode is None or state.get('setup_mode') not in {None, 'source'}
            or state.get('phase') != 'READY' or type(payload) is not dict):
        return False
    source, line, pin = BINDINGS[kind]
    target = payload.get('target')
    vector, arguments = payload.get('orig_argv'), payload.get('sys_argv')
    if (type(target) is not str or payload.get('mode') != 'script'
            or payload.get('class') != kind or payload.get('case') != state.get('case')
            or type(state.get('token')) is not str or not state['token']
            or payload.get('token') != state['token'] or endpoint.get('token') != state['token']
            or endpoint.get('identity', {}).get('pid') != os.getpid()
            or type(vector) is not list or not vector or vector[0] not in state['runtime']['paths']
            or type(arguments) is not list or len(arguments) != 2 or arguments[0] != target
            or any(type(v) is not str for v in [*vector, *arguments])
            or payload.get('path0') != str(Path(target).parent)
            or payload.get('source_binding') != {'path': str(Path(state['checkout']) / source),
                                                'line': line, 'sha256': pin}
            or state['product_pins'].get(source) != pin):
        return False
    index = 1
    while index < len(vector) and vector[index] in {'-I', '-S', '-u', '-B', '-E', '-s'}:
        index += 1
    return (vector[index:] == arguments and type(payload.get('isolated')) is bool
            and payload['isolated'] == ('-I' in vector[1:index]))


def script_identity(state, payload):
    root, owned, script = Path(state['checkout']), Path(state['owned_root']), Path(payload['target'])
    for name, pin in PURE.items():
        if state['product_pins'].get(name) != pin or hashlib.sha256((root / name).read_bytes()).hexdigest() != pin:
            return None
    if script.resolve(strict=True) != script or script.is_symlink():
        return None
    body = script.read_bytes()
    if state['class'] == 'source-approval-adapter':
        if script != root / 'tests/fixtures/approval_recovery_acp.py':
            return None
        scenario = Path(payload['sys_argv'][1])
        if scenario.resolve(strict=True) != scenario or not scenario.is_relative_to(owned):
            return None
    else:
        private_root = False
        if state['class'] == 'source-approval-relay' and not script.is_relative_to(owned):
            staging = Path(state['guard']).with_name('approval_private_staging.py')
            guard = sys.modules['runtime_guard']
            private = guard.checked_source(staging, state['direct_support']['files'][str(staging)])
            private_root = private['control_address'](state, script.parent / 'control')
        if not (script.is_relative_to(owned) or private_root) or payload['sys_argv'][1] != 'app-server':
            return None
        backend_body = f'#!{sys.executable}\n'.encode() + (root / 'tests/fixtures/approval_native_backend.py').read_bytes()
        if state['class'] == 'source-approval-python-backend':
            if script.name != 'controlled-backend' or body != backend_body:
                return None
        else:
            tree = ast.parse(body)
            call = tree.body[-1].value
            socket, token, backend, digest = [ast.literal_eval(n) for n in call.args]
            backend_path = Path(backend)
            expected = (f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(root / "src")!r})\n'
                        'from unrest_harness.approval_relay import main\n'
                        f'main({socket!r}, {token!r}, {backend!r}, {digest!r})\n').encode()
            if (body != expected or script.name != 'backend'
                    or re.fullmatch('unrest-approval-[a-z0-9_]{8}', script.parent.name) is None
                    or Path(socket) != script.parent / 'control' or re.fullmatch('[0-9a-f]{64}', token) is None
                    or not backend_path.is_relative_to(owned) or backend_path.resolve(strict=True) != backend_path
                    or backend_path.name != 'controlled-backend' or backend_path.read_bytes() != backend_body
                    or hashlib.sha256(backend_body).hexdigest() != digest):
                return None
    return hashlib.sha256(body).hexdigest()


def select(guard, endpoint):
    state = guard._STATE
    if state.get('class') not in BINDINGS or state.get('setup_mode') not in {None, 'source'}:
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
        path = Path(state['guard']).with_name('approval_routes.py')
        routes = guard.checked_source(path, state['direct_support']['files'][str(path)])
        payload = child.f_locals.get('payload')
        if not eligible(state, endpoint, payload, routes['selected_mode'](state.get('case'))):
            return None
        guard_path, endpoint_path = Path(state['guard']), Path(module.__file__)
        guard_body, endpoint_body = guard_path.read_bytes(), endpoint_path.read_bytes()
        if (hashlib.sha256(guard_body).hexdigest() != state['guard_sha256']
                or hashlib.sha256(endpoint_body).hexdigest() != state['endpoint']['sha256']
                or child.f_code != named(compile(guard_body, str(guard_path), 'exec', dont_inherit=True), 'child')
                or caller.f_code != named(named(compile(endpoint_body, str(endpoint_path), 'exec', dont_inherit=True), 'attach'), 'install')):
            return None
        digest = script_identity(state, payload)
        runtime = Path(payload['orig_argv'][0])
        if (digest is None or str(runtime.resolve(strict=True)) != state['runtime']['realpath']
                or hashlib.sha256(runtime.read_bytes()).hexdigest() != state['runtime']['sha256']):
            return None
        guard.require_ready(state['token'])
        return {'kind': 'dependency_configuration_not_applicable', 'component': 'FastMCP',
                'reason': 'pinned_controlled_json_approval_fixture', 'script_sha256': digest,
                'class': state['class'], 'token': state['token'], 'shared_startup_checks_retained': True}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, SyntaxError):
        return None
    finally:
        del current, caller, child
