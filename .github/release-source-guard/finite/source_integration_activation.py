"""Closed lease/environment composition around the unchanged SOURCE activation."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import sys
import subprocess


def create(state, emit, refuse, ready):
    guard = sys.modules['runtime_guard']
    root = Path(state['guard']).parent
    def checked(name):
        path = root / name
        return guard.checked_source(path, state['direct_support']['files'][str(path)])
    original = checked('source_activation.py')['SourceActivation']

    class SourceIntegrationActivation(original):
        def __init__(self):
            super().__init__(state, emit, refuse, ready)
            state['lease_popen'] = subprocess.Popen
            self.owned_environment = None
            if (state.get('source_selection') == 'primary-source'
                    and state.get('class') == 'pytest-root' and state.get('token') == 'root'):
                self.owned_environment = checked('source_environment.py')['capture'](state)

        def shared(self):
            super().shared()
            if hasattr(self, 'capture_child_relative'):
                self.capture_child_relative()

        def ordinary_python(self, guard, launch, argv, cwd, environment, registration):
            owner = checked('execution_owner.py')['current'](state, self.refuse)
            if owner != state.get('case', ''):
                self.emit({'kind': 'source_nested_execution_owner',
                           'custody_case': state['case'], 'execution_owner': owner,
                           'launch_token': launch['launch_token']})
            if registration['class'] in {'source-approval-python-backend'}:
                caller = inspect.currentframe().f_back
                if (caller.f_code is not original.before_python.__code__
                        or caller.f_globals is not original.before_python.__globals__
                        or caller.f_locals.get('self') is not self
                        or caller.f_locals.get('launch') is not launch
                        or caller.f_locals.get('registration') is not registration
                        or caller.f_locals.get('guard') is not guard):
                    self.refuse('approval_stdlib_activation_caller')
                checked('approval_stdlib.py')['activation'](
                    self, guard, launch, argv, cwd, environment, registration)
                return
            if registration['class'] == 'source-canonical-stdlib-acp':
                caller = inspect.currentframe().f_back
                if (caller.f_code is not original.before_python.__code__
                        or caller.f_globals is not original.before_python.__globals__
                        or caller.f_locals.get('self') is not self
                        or caller.f_locals.get('launch') is not launch
                        or caller.f_locals.get('registration') is not registration
                        or caller.f_locals.get('guard') is not guard):
                    self.refuse('stdlib_acp_activation_caller')
                checked('stdlib_acp.py')['activation'](
                    registration, argv, launch, cwd, environment, state, self.refuse)
                checked('stdlib_backend.py')['shared'](self)
                self.emit({'kind': 'source_stdlib_acp_startup_consumption',
                           'launch_token': launch['launch_token'],
                           'original_argv_sha256': hashlib.sha256(json.dumps(list(launch['args'])).encode()).hexdigest(),
                           'isolated_argv_sha256': hashlib.sha256(json.dumps(list(argv)).encode()).hexdigest(),
                           'source_binding': registration['source_binding'],
                           'translation_flags': ['-I', '-S'],
                           'third_party_execution': 'refused',
                           'current_shared_startup_checks': True})
                return
            if registration['class'] == 'source-canonical-stdlib-backend':
                caller = inspect.currentframe().f_back
                if (caller.f_code is not original.before_python.__code__
                        or caller.f_globals is not original.before_python.__globals__
                        or caller.f_locals.get('self') is not self
                        or caller.f_locals.get('launch') is not launch
                        or caller.f_locals.get('registration') is not registration
                        or caller.f_locals.get('guard') is not guard):
                    self.refuse('stdlib_backend_activation_caller')
                actual = checked('stdlib_backend.py')['select'](
                    launch['args'], cwd, environment, state, self.emit, self.refuse)
                if actual != (registration, argv):
                    self.refuse('stdlib_backend_activation_registration')
                checked('stdlib_backend.py')['shared'](self)
                self.emit({'kind': 'source_stdlib_backend_startup_consumption',
                           'launch_token': launch['launch_token'],
                           'source_binding': registration['source_binding'],
                           'original_argv_sha256': hashlib.sha256(json.dumps(list(launch['args'])).encode()).hexdigest(),
                           'isolated_argv_sha256': hashlib.sha256(json.dumps(list(argv)).encode()).hexdigest(),
                           'translation_flags': ['-I', '-S'],
                           'third_party_execution': 'refused',
                           'current_shared_startup_checks': True})
                return
            if registration['class'] in {'source-execution-owner-probe', 'source-execution-owner-leaf', 'source-child-relative-probe'}:
                caller = inspect.currentframe().f_back
                if (caller.f_code is not original.before_python.__code__
                        or caller.f_globals is not original.before_python.__globals__
                        or caller.f_locals.get('self') is not self
                        or caller.f_locals.get('launch') is not launch
                        or caller.f_locals.get('registration') is not registration):
                    self.refuse('source_owner_probe_activation_caller_drift')
                actual = checked('owner_probe.py')['admit'](
                    argv, cwd, environment, state, self.emit, self.refuse)
                if actual != registration:
                    self.refuse('source_owner_probe_activation_registration_drift')
                self.shared()
                self.emit({'kind': ('source_child_relative_startup_consumption'
                                    if registration['class'] == 'source-child-relative-probe'
                                    else 'source_execution_owner_startup_consumption'),
                           'launch_token': launch['launch_token'],
                           'source_binding': registration['source_binding'],
                           'custody_case': state['case'], 'execution_owner': owner})
                return
            if (registration['class'] == 'inline:test_acp_cleanup.py:51'
                    and state.get('case') in {
                        'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[False]',
                        'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[True]'}):
                caller = inspect.currentframe().f_back
                if (caller.f_code is not original.before_python.__code__
                        or caller.f_globals is not original.before_python.__globals__
                        or caller.f_locals.get('self') is not self
                        or caller.f_locals.get('launch') is not launch
                        or caller.f_locals.get('registration') is not registration
                        or caller.f_locals.get('guard') is not guard):
                    self.refuse('source_inflight_activation_caller_drift')
                frames = checked('cleanup_routes.py')['inflight_frames'](state)
                try:
                    actual = checked('inflight_cleanup.py')['admit'](
                        argv, cwd, environment, state, frames, self.refuse)
                    if actual is None or actual != registration:
                        self.refuse('source_inflight_activation_registration_drift')
                finally:
                    frames.clear()
                # Keep the actual captured-alias source anchor. It is a bound
                # use of the existing literal, not the registry's line-51 caller.
                self.shared()
                self.emit({'kind': 'source_ordinary_startup_consumption',
                           'class': registration['class'],
                           'source_binding': registration['source_binding'],
                           'launch_token': launch['launch_token'],
                           'shared_startup_seal': True})
                return
            if registration['class'] != 'source-lease-owned-child':
                return super().ordinary_python(guard, launch, argv, cwd, environment, registration)
            caller = inspect.currentframe().f_back
            if (caller.f_code is not original.before_python.__code__
                    or caller.f_globals is not original.before_python.__globals__
                    or caller.f_locals.get('self') is not self
                    or caller.f_locals.get('launch') is not launch
                    or caller.f_locals.get('registration') is not registration
                    or caller.f_locals.get('guard') is not guard):
                self.refuse('source_lease_activation_caller_drift')
            # The inherited before_python already consumed the immutable live
            # initialize_inner frame/token. Resolve the factory again here.
            legacy = any(item is registration for item in state['commands'])
            if legacy:
                # Retain all original registry/fallback checks and the original
                # source anchor before adding its startup-only consumption.
                super().ordinary_python(guard, launch, argv, cwd, environment, registration)
            actual = checked('lease_routes.py')['admit'](
                argv, cwd, environment, state, self.emit, self.refuse, legacy=legacy)
            if actual is None or (not legacy and actual != registration):
                self.refuse('source_lease_activation_registration_drift')
            self.shared()
            self.emit({'kind': 'source_lease_startup_consumption',
                       'launch_token': launch['launch_token'],
                       'source_binding': registration['source_binding'],
                       'factory': actual['lease_factory'], 'argv': list(argv),
                       'cwd': str(cwd), 'environment': dict(environment)})
            if legacy:
                return
            self.emit({'kind': 'source_ordinary_startup_consumption',
                       'class': registration['class'], 'source_binding': registration['source_binding'],
                       'launch_token': launch['launch_token'], 'shared_startup_seal': True})

    activation = SourceIntegrationActivation()
    if (state.get('source_selection') == 'primary-source'
            and state['operation_support']['path'] in {
                '/guard/primary_operations.py', '/guard/primary_operation_journal.py'}):
        activation.capture_child_relative = checked('child_relative.py')['install'](
            state, activation, emit, refuse, checked)
    return activation
