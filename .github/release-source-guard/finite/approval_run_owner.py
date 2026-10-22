"""One pinned disposable RunControl executor for the seven original crash cases."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shlex
import sys

TEST = 'tests/test_approval_recovery.py'

PREFIX = TEST + '::test_durable_run_owner_and_restart_never_revives'
BOUNDARIES = ('success', 'cancel', 'crash', 'cancel_after_send', 'crash_after_send',
              'cancel_after_continue', 'crash_after_continue')
EXECUTOR = 'tests.fixtures.approval_run_executor:execute'
FILES = {
    TEST: '5f594cd2b8921e01cbb6e1d3aa11ed3cb84d5a9e7d07843b9e2c7a34fc36798c',
    'tests/fixtures/approval_run_executor.py': 'f6e24716d1b9103035fe99fe2af9f00bf42544d31086caa94486f3e8259a4d33',
    'tests/fixtures/approval_recovery_acp.py': '1813512c5ad2177af6738fbfb99e9d43f6884394878e1034d3956ca5f0f31d46',
    'tests/fixtures/approval_native_backend.py': 'a18a3a8c87c86b5629304e99c6667b8c6accd31b72ded5885ffe386a6e803ba3',
}


def boundary(case):
    if type(case) is not str:
        return None
    return next((value for value in BOUNDARIES if case == PREFIX + '[' + value + ']'), None)


def validate(control, environment, state, refuse):
    if boundary(state.get('case')) is None or control.executor_ref != EXECUTOR:
        refuse('approval_run_executor_case_drift')
    root, owned = Path(state['checkout']), Path(state['owned_root'])
    for name, pin in FILES.items():
        if state['product_pins'].get(name) != pin or hashlib.sha256((root / name).read_bytes()).hexdigest() != pin:
            refuse('approval_run_executor_source_drift')
    helper = Path(state['guard']).with_name('fallback_binding.py')
    guard = sys.modules['runtime_guard']
    frames = guard.checked_source(helper, state['direct_support']['files'][str(helper)])['active_frames']()
    try:
        source = root / TEST
        candidates = {id(f): f for f in frames if f.f_code.co_filename == str(source)
                      and f.f_code.co_name == 'test_durable_run_owner_and_restart_never_revives'}
        if len(candidates) != 1:
            refuse('approval_run_executor_owner_missing')
        frame = next(iter(candidates.values()))
        module = sys.modules.get(frame.f_globals.get('__name__'))
        local = frame.f_locals
        original = state['isolated_named'](state['isolated_source_code'](source), frame.f_code.co_name)
        if (module is None or vars(module) is not frame.f_globals or frame.f_code != original
                or local.get('control') is not control or local.get('boundary') != boundary(state['case'])
                or control.project_root != local['run_home'] or not control.project_root.resolve().is_relative_to(owned)):
            refuse('approval_run_executor_original_owner_drift')
        expected = local['worker_environment']
        if (set(expected) != {'PYTHONPATH', 'UNREST_HOME', 'UNREST_PROJECTS_DIR', 'CONTROLLED_RUN_ROOT',
                             'CONTROLLED_RUN_NATIVE', 'CONTROLLED_RUN_TRACE', 'CONTROLLED_RUN_COMMAND'}
                or any(environment.get(k) != v for k, v in expected.items())
                or expected['CONTROLLED_RUN_ROOT'] != str(local['root'])
                or expected['CONTROLLED_RUN_NATIVE'] != str(local['native'])
                or expected['CONTROLLED_RUN_TRACE'] != str(local['trace'])
                or shlex.split(expected['CONTROLLED_RUN_COMMAND']) != [sys.executable, str(root / 'tests/fixtures/approval_recovery_acp.py'), str(local['scenario'])]):
            refuse('approval_run_executor_environment_drift')
        native = Path(expected['CONTROLLED_RUN_NATIVE'])
        if (not native.resolve().is_relative_to(owned) or native.name != 'controlled-backend'
                or native.read_bytes() != ('#!' + sys.executable + '\n').encode() + (root / 'tests/fixtures/approval_native_backend.py').read_bytes()):
            refuse('approval_run_executor_backend_drift')
    finally:
        frames.clear()
