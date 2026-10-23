"""Closed stdlib translation only after the original ACP registry admission."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

CLASS = 'source-canonical-stdlib-acp'
ORIGINAL = 'controlled-acp'


def support(state, name):
    guard = sys.modules['runtime_guard']
    path = Path(state['guard']).with_name(name)
    return guard.checked_source(path, state['direct_support']['files'][str(path)])


def resolve(registration, argv, cwd, environment, state, refuse):
    setup = support(state, 'mock_backend_setup.py')
    if state.get('case') not in setup['ACP_ISOLATED_CASES']:
        return None
    rows = [r for r in state['commands'] if r.get('class') == ORIGINAL]
    if len(rows) != 1:
        refuse('stdlib_acp_original_registry')
    original = rows[0]
    if registration != original:
        refuse('stdlib_acp_original_registration')
    fixture = Path(state['checkout']) / setup['ACP']
    expected = [str(Path(state['runtime']['realpath'])), str(fixture), '--controlled-local-acp-v1']
    if (list(argv) != expected or fixture.is_symlink()
            or fixture.resolve(strict=True) != fixture
            or hashlib.sha256(fixture.read_bytes()).hexdigest() != setup['ACP_PIN']
            or not Path(cwd).resolve().is_relative_to(Path(state['owned_root']))
            or original['source_binding'] != {'path': str(fixture), 'line': 1, 'sha256': setup['ACP_PIN']}
            or original['files'] != {str(fixture): setup['ACP_PIN']}):
        refuse('stdlib_acp_original_vector')
    binding = support(state, 'fallback_binding.py')['matches'](
        original, list(argv), cwd, environment, state)
    if (binding is None or binding.get('source') != str(Path(state['checkout']) / setup['SESSION'])
            or binding.get('line') != 553 or binding.get('function') != '_open_role_owned'):
        refuse('stdlib_acp_original_caller')
    return {**original, 'class': CLASS, 'case': state['case']}, [argv[0], '-I', '-S', *argv[1:]]


def after_admission(registration, argv, cwd, environment, state, emit, refuse):
    guard = sys.modules['runtime_guard']
    caller = sys._getframe(1)
    if (caller.f_code is not guard.admit.__code__ or caller.f_globals is not vars(guard)
            or caller.f_locals.get('registration') is not registration
            or caller.f_locals.get('state') is not state
            or not any(registration is row for row in state['commands'])):
        refuse('stdlib_acp_post_admission_boundary')
    selected = resolve(registration, argv, cwd, environment, state, refuse)
    if selected is not None:
        emit({'kind': 'source_stdlib_acp_post_admission', 'case': state['case'],
              'original_argv_sha256': hashlib.sha256(json.dumps(list(argv)).encode()).hexdigest(),
              'isolated_argv_sha256': hashlib.sha256(json.dumps(selected[1]).encode()).hexdigest(),
              'original_registry_and_caller_retained': True})
    return selected


def activation(registration, argv, launch, cwd, environment, state, refuse):
    rows = [r for r in state['commands'] if r.get('class') == ORIGINAL]
    if len(rows) != 1:
        refuse('stdlib_acp_activation_registry')
    selected = resolve(rows[0], launch['args'], cwd, environment, state, refuse)
    if selected != (registration, argv):
        refuse('stdlib_acp_activation_registration')
