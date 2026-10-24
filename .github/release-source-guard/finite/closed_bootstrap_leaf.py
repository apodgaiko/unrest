"""Deny-all launch setup for two exact, separately sealed bootstrap fixtures.

This is not a general operation observer. The original parent admission and
endpoint execution seal remain responsible for their original obligations.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import types

CASES = (
    'tests/test_experimental_bootstrap.py::test_actual_sequential_initialize_and_session_share_cutoff',
    'tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout',
)
CLASSES = frozenset({'source-canonical-stdlib-backend', 'source-canonical-stdlib-acp'})
PROCESS_EVENTS = frozenset({'subprocess.Popen', 'os.exec', 'os.posix_spawn',
                            'os.system', 'os.fork', 'os.forkpty'})
PROFILE_EVENTS = frozenset({'sys.setprofile', 'sys.settrace'})
DENIED_EVENTS = PROCESS_EVENTS | PROFILE_EVENTS


def support(guard, state, name):
    path = Path(state['guard']).with_name(name)
    return guard.checked_source(path, state['direct_support']['files'][str(path)])


def payload_bound(guard, state, payload):
    if (type(payload) is not dict or type(payload.get('operation_lineage')) is not list
            or payload['operation_lineage'] != []
            or payload.get('class') != state['class'] or payload.get('case') != state['case']
            or payload.get('token') != state['token'] or payload.get('isolated') is not True):
        return False
    setup = support(guard, state, 'mock_backend_setup.py')
    root = Path(state['checkout'])
    vector, arguments = payload.get('orig_argv'), payload.get('sys_argv')
    if (type(vector) is not list or not vector or any(type(v) is not str for v in vector)
            or vector[0] not in state['runtime']['paths'] or vector[1:3] != ['-I', '-S']
            or type(arguments) is not list):
        return False
    if state['class'] == 'source-canonical-stdlib-acp':
        target = root / setup['ACP']
        expected = [str(target), '--controlled-local-acp-v1']
        binding = {'path': str(target), 'line': 1, 'sha256': setup['ACP_PIN']}
        digest = setup['ACP_PIN']
    else:
        if payload.get('mode') == 'inline':
            wrapper = support(guard, state, 'bootstrap_stdlib.py')
            if (state['case'] != wrapper['CASE'] or len(vector) != 7
                    or vector[3:5] != ['-c', wrapper['BODY']]
                    or arguments != ['-c', *vector[5:]] or vector[-1] != 'app-server'
                    or payload.get('target') != wrapper['BODY'] or payload.get('path0') != ''
                    or payload.get('source_binding') != {
                        'path': str(root / wrapper['SOURCE']), 'line': 38, 'sha256': wrapper['PIN']}
                    or state['product_pins'].get(wrapper['SOURCE']) != wrapper['PIN']
                    or guard.digest(root / wrapper['SOURCE']) != wrapper['PIN']):
                return False
            target = Path(vector[5])
            expected = None
        else:
            if type(payload.get('target')) is not str:
                return False
            target = Path(payload['target'])
            expected = [str(target), 'app-server']
        if (not target.is_absolute() or '..' in target.parts or target.name != 'fake-app-server'
                or not target.is_relative_to(Path(state['owned_root']))):
            return False
        binding = {'path': str(root / setup['SESSION']), 'line': 506,
                   'function': '_open_role_owned', 'sha256': setup['SESSION_PIN']}
        digest = setup['BACKEND_PIN']
    if expected is not None and (
            payload.get('mode') != 'script' or payload.get('target') != str(target)
            or payload.get('path0') != str(target.parent) or arguments != expected
            or vector != [vector[0], '-I', '-S', *expected]
            or payload.get('source_binding') != binding):
        return False
    source = root / setup['SESSION'] if state['class'] == 'source-canonical-stdlib-backend' else target
    source_pin = setup['SESSION_PIN'] if state['class'] == 'source-canonical-stdlib-backend' else setup['ACP_PIN']
    return (not target.is_symlink() and target.resolve(strict=True) == target
            and guard.digest(target) == digest
            and state['product_pins'].get(str(source.relative_to(root))) == source_pin
            and guard.digest(source) == source_pin)


def select(guard, state, frame):
    if (guard._STATE is not state or frame.f_locals.get('state') is not state
            or sys.platform != 'linux' or state.get('phase') != 'INSTALLING'
            or state.get('class') not in CLASSES or state.get('case') not in CASES
            or type(state.get('token')) is not str or state['token'] in ('', 'root')
            or sys.flags.isolated != 1 or sys.flags.no_site != 1
            or getattr(sys, '_unrest_primary_source_bootstrap_consumed', None) is not True):
        return None
    endpoint = sys.modules.get('endpoint')
    wrapper = guard.install
    if (endpoint is None or type(wrapper) is not types.FunctionType
            or wrapper.__globals__ is not vars(endpoint) or frame.f_globals is not vars(guard)):
        return None
    cells = dict(zip(wrapper.__code__.co_freevars, wrapper.__closure__ or ()))
    original = cells.get('original_install')
    caller = frame.f_back
    child = caller.f_back if caller is not None else None
    if (original is None or type(original.cell_contents) is not types.FunctionType
            or original.cell_contents.__code__ is not frame.f_code
            or cells.get('guard') is None or cells['guard'].cell_contents is not guard
            or caller is None or caller.f_code is not wrapper.__code__
            or caller.f_globals is not vars(endpoint) or child is None
            or child.f_code is not guard.child.__code__ or child.f_globals is not vars(guard)
            or child.f_locals.get('manifest') != state['manifest_path']
            or child.f_locals.get('pin') != state['pin']):
        return None
    payload = child.f_locals.get('payload')
    if not payload_bound(guard, state, payload):
        return None
    return ClosedLeaf(guard, state, payload)


class ClosedLeaf:
    def __init__(self, guard, state, payload):
        self.guard, self.state, self.payload = guard, state, payload
        self.identity = (state['class'], state['case'], state['token'])

    def audit(self, event, args):
        if event in DENIED_EVENTS:
            self.guard.refuse('closed_bootstrap_leaf_denied:' + event)

    def validate_ready(self):
        state, guard = self.state, self.guard
        if (guard._STATE is not state or guard._CLOSED_LEAF is not self
                or state.get('closed_bootstrap_leaf') is not self
                or (state['class'], state['case'], state['token']) != self.identity
                or sys.getprofile() is not None or threading.getprofile() is not None
                or not payload_bound(guard, state, self.payload)):
            guard.refuse('closed_bootstrap_leaf_identity_drift')

    def install(self):
        state, guard = self.state, self.guard
        # Acquire the original authenticated spec through its original reader.
        # This does not claim that a general operation observer was installed.
        isolated = state['isolated_support']
        # -I/-S has no guard search path. Preserve the original explicit,
        # authenticated dependency loading used by operation_activation.create.
        for path, pin, name in (
                (state['activation_support']['path'], state['activation_support']['sha256'], 'operation_activation'),
                (isolated['inputs_path'], isolated['inputs_sha256'], 'isolated_inputs')):
            body = Path(path).read_bytes()
            if hashlib.sha256(body).hexdigest() != pin:
                guard.refuse('closed_bootstrap_leaf_dependency_drift')
            module = types.ModuleType(name)
            module.__file__ = path
            sys.modules[name] = module
            exec(compile(body, path, 'exec', dont_inherit=True), vars(module))
        namespace = guard.checked_source(isolated['path'], isolated['sha256'])
        activation = namespace['IsolatedActivation'](state, guard.append, guard.refuse, guard.require_ready)
        state['operation_activation'] = state['activation_owner'] = activation
        atexit.register(lambda: guard.append({'kind': 'finished', 'token': state['token']}))
        record = {
            'kind': 'ready', 'token': state['token'], 'class': state['class'],
            'owner_pid': os.getpid(), 'parent_pid': os.getppid(), 'case': state['case'],
            'sid': os.getsid(0), 'pgid': os.getpgid(0),
            'runtime_sha256': state['runtime']['sha256'], 'manifest_sha256': state['pin'],
            'guard_sha256': state['guard_sha256'], 'registry_sha256': state['registry']['sha256'],
            'support_sha256': hashlib.sha256(json.dumps(
                state['direct_support']['files'], sort_keys=True).encode()).hexdigest(),
        }
        guard.append({'kind': 'closed_bootstrap_leaf_installed', 'token': state['token'],
                      'case': state['case'], 'class': state['class'],
                      'process_launch_policy': 'deny-all', 'general_operation_observer': False,
                      'original_endpoint_and_execution_seal_still_required': True})
        guard.append(record)
        state['ready_record'], state['phase'] = record, 'READY'
        guard.require_ready(state['token'])
        gate = getattr(sys, '_finite_source_bootstrap_gate', None)
        if gate is not None:
            gate['active'] = False
