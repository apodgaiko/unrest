"""Closed lease/environment composition around the unchanged SOURCE activation."""
from __future__ import annotations

import inspect
from pathlib import Path
import sys


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
            self.owned_environment = None
            if (state.get('source_selection') == 'primary-source'
                    and state.get('class') == 'pytest-root' and state.get('token') == 'root'):
                self.owned_environment = checked('source_environment.py')['capture'](state)

        def ordinary_python(self, guard, launch, argv, cwd, environment, registration):
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
            actual = checked('lease_routes.py')['admit'](
                argv, cwd, environment, state, self.emit, self.refuse)
            if actual != registration:
                self.refuse('source_lease_activation_registration_drift')
            self.shared()
            self.emit({'kind': 'source_lease_startup_consumption',
                       'launch_token': launch['launch_token'],
                       'source_binding': registration['source_binding'],
                       'factory': registration['lease_factory'], 'argv': list(argv),
                       'cwd': str(cwd), 'environment': dict(environment)})
            self.emit({'kind': 'source_ordinary_startup_consumption',
                       'class': registration['class'], 'source_binding': registration['source_binding'],
                       'launch_token': launch['launch_token'], 'shared_startup_seal': True})

    return SourceIntegrationActivation()
