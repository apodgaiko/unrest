"""Closed stdlib startup for the already admitted, byte-pinned JSON backend."""
from __future__ import annotations

from pathlib import Path
import sys

CLASSES = frozenset({'source-approval-python-backend'})


def support(state, name):
    path = Path(state['guard']).with_name(name)
    return sys.modules['runtime_guard'].checked_source(path, state['direct_support']['files'][str(path)])


def translate(registration, argv, state):
    # Called only after every original approval resolver check, with its result.
    if registration['class'] not in CLASSES:
        return registration, argv
    caller = sys._getframe(1)
    if caller.f_code.co_name != 'registration':
        raise RuntimeError('approval_stdlib_original_admission')
    routes = support(state, 'approval_routes.py')
    outer = caller.f_back
    import types
    nested = [item for item in routes['select'].__code__.co_consts
              if type(item) is types.CodeType and item.co_name == 'registration']
    if (len(nested) != 1 or caller.f_code != nested[0] or outer is None
            or caller.f_globals is not outer.f_globals
            or caller.f_locals.get('registered') is not registration
            or caller.f_locals.get('translated') is not argv
            or caller.f_globals.get('select').__code__ != routes['select'].__code__
            or outer.f_code != routes['select'].__code__
            or outer.f_locals.get('state') is not state
            or routes['selected_mode'](state.get('case')) is None
            or len(argv) != 3 or argv[0] != sys.executable):
        raise RuntimeError('approval_stdlib_original_admission')
    return registration, [argv[0], '-I', '-S', *argv[1:]]


def activation(activation, guard, launch, argv, cwd, environment, registration):
    state = activation.state
    # The base before_python already binds the actual constructor/frame/token.
    # Re-run the same original resolver on the original vector; no new route.
    actual = support(state, 'approval_routes.py')['select'](
        launch['args'], cwd, environment, state, activation.emit, activation.refuse)
    if (registration['class'] not in CLASSES or actual != (registration, argv)
            or argv[1:3] != ['-I', '-S']):
        activation.refuse('approval_stdlib_activation')
    support(state, 'stdlib_backend.py')['shared'](activation)
    activation.emit({'kind': 'source_approval_stdlib_startup_consumption',
                     'class': registration['class'], 'launch_token': launch['launch_token'],
                     'original_admission_retained': True,
                     'third_party_execution': 'refused',
                     'native_provider_acceptance': 'UNVERIFIED'})


def payload_pin(state, payload):
    setup = support(state, 'approval_json_setup.py')
    if state.get('class') not in CLASSES or payload.get('orig_argv', [])[1:3] != ['-I', '-S']:
        raise RuntimeError('approval_stdlib_payload_domain')
    pin = setup['script_identity'](state, payload)
    if pin is None:
        raise RuntimeError('approval_stdlib_payload_bytes')
    return pin


def seal(guard, endpoint):
    state = guard._STATE
    caller = sys._getframe(1)
    child = caller.f_back
    payload = child.f_locals.get('payload') if child else None
    setup = support(state, 'approval_json_setup.py')
    routes = support(state, 'approval_routes.py')
    if (caller.f_globals is not vars(endpoint) or caller.f_code is not guard.install.__code__
            or child is None or child.f_globals is not vars(guard)
            or child.f_code is not guard.child.__code__
            or not setup['eligible'](state, endpoint.STATE, payload, routes['selected_mode'](state.get('case')))
            or sys.flags.isolated != 1 or sys.flags.no_site != 1):
        guard.refuse('approval_stdlib_seal_context')
    pin = payload_pin(state, payload)
    # Freeze the same lazy stdlib closure as the existing controlled ACP domain.
    import asyncio  # noqa: F401
    import copy  # noqa: F401
    import email.parser  # noqa: F401
    import encodings.idna  # noqa: F401
    import pkgutil  # noqa: F401
    import secrets  # noqa: F401
    import stringprep  # noqa: F401
    import tomllib  # noqa: F401
    import unicodedata  # noqa: F401
    import urllib.request  # noqa: F401
    import zipimport  # noqa: F401
    support(state, 'stdlib_backend.py')['install_barrier'](state, guard, payload)
    guard.append({'kind': 'approval_stdlib_execution_sealed', 'class': state['class'],
                  'token': state['token'], 'case': state['case'], 'script_sha256': pin,
                  'isolated_flags': [1, 1], 'third_party_execution': 'refused',
                  'native_provider_acceptance': 'UNVERIFIED'})
