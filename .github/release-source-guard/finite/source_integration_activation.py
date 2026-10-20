"""Closed lease/environment composition around the unchanged SOURCE activation."""
from __future__ import annotations

import inspect
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

        def ordinary_python(self, guard, launch, argv, cwd, environment, registration):
            if hasattr(self, 'arm_child_relative'):
                self.arm_child_relative(argv, cwd, environment, registration)
            owner = checked('execution_owner.py')['current'](state, self.refuse)
            if owner != state.get('case', ''):
                self.emit({'kind': 'source_nested_execution_owner',
                           'custody_case': state['case'], 'execution_owner': owner,
                           'launch_token': launch['launch_token']})
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
                self.emit({'kind': 'source_execution_owner_startup_consumption',
                           'launch_token': launch['launch_token'],
                           'source_binding': registration['source_binding'],
                           'custody_case': state['case'], 'execution_owner': owner})
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
    if state.get('source_selection') == 'primary-source':
        activation.arm_child_relative = checked('child_relative.py')['install'](
            state, activation, emit, refuse, checked)
    return activation
