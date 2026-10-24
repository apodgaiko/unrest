"""Finite prospective selection and deny-all leaf policy; no provider launch."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from finite import closed_bootstrap_leaf as leaf
from finite import mock_backend_setup as setup
from finite import bootstrap_stdlib as wrapper

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = Path(__file__).parent / 'finite'


@pytest.fixture
def context(tmp_path, monkeypatch):
    def create(kind, case):
        target = tmp_path / 'owned/fake-app-server'
        target.parent.mkdir(exist_ok=True)
        target.write_bytes((ROOT / setup.BACKEND).read_bytes())
        interpreter = '/pinned/python'
        binding = {'path': str(ROOT / setup.SESSION), 'line': 506,
                   'function': '_open_role_owned', 'sha256': setup.SESSION_PIN}
        if kind == 'source-canonical-stdlib-acp':
            target = ROOT / setup.ACP
            args = [str(target), '--controlled-local-acp-v1']
            binding = {'path': str(target), 'line': 1, 'sha256': setup.ACP_PIN}
        else:
            args = [str(target), 'app-server']
        payload = {'class': kind, 'case': case, 'token': 'actual-child',
                   'isolated': True, 'operation_lineage': [], 'mode': 'script',
                   'target': str(target), 'path0': str(target.parent),
                   'orig_argv': [interpreter, '-I', '-S', *args],
                   'sys_argv': args, 'source_binding': binding}
        if kind == 'source-canonical-stdlib-backend' and case == leaf.CASES[1]:
            payload.update(mode='inline', target=wrapper.BODY, path0='',
                           orig_argv=[interpreter, '-I', '-S', '-c', wrapper.BODY, *args],
                           sys_argv=['-c', *args], source_binding={
                               'path': str(ROOT / wrapper.SOURCE), 'line': 38, 'sha256': wrapper.PIN})
        state = {'class': kind, 'case': case, 'phase': 'INSTALLING', 'token': payload['token'],
                 'manifest_path': '/manifest', 'pin': 'exact', 'checkout': str(ROOT),
                 'owned_root': str(tmp_path / 'owned'), 'runtime': {'paths': [interpreter]},
                 'guard': str(SUPPORT / 'runtime_guard.py'),
                 'direct_support': {'files': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                             for p in SUPPORT.glob('*.py')}},
                 'product_pins': {setup.SESSION: setup.SESSION_PIN, setup.ACP: setup.ACP_PIN,
                                  wrapper.SOURCE: wrapper.PIN}}
        guard = ModuleType('runtime_guard')
        guard.state, guard.leaf, guard.sys = state, leaf, sys
        exec('def install(manifest,pin,token,command_class,case):\n'
             '    state=globals()["state"]\n'
             '    return leaf.select(sys.modules[__name__],state,sys._getframe())\n'
             'def child(manifest,pin,payload):\n'
             '    return install(manifest,pin,payload["token"],payload["class"],payload["case"])\n', vars(guard))
        guard._STATE = state
        guard.digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
        def checked(path, pin):
            body = Path(path).read_bytes()
            assert hashlib.sha256(body).hexdigest() == pin
            namespace = {'__file__': str(path), '__name__': '_finite_support'}
            exec(compile(body, str(path), 'exec'), namespace)
            return namespace
        guard.checked_source = checked
        endpoint = ModuleType('endpoint')
        exec('def attach(guard):\n'
             '    original_install=guard.install\n'
             '    def install(*args,**kwargs):\n'
             '        assert guard._STATE is guard.state\n'
             '        return original_install(*args,**kwargs)\n'
             '    guard.install=install\n', vars(endpoint))
        endpoint.attach(guard)
        monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
        monkeypatch.setitem(sys.modules, 'endpoint', endpoint)
        monkeypatch.setattr(leaf, 'sys', SimpleNamespace(
            platform='linux', flags=SimpleNamespace(isolated=1, no_site=1), modules=sys.modules,
            _unrest_primary_source_bootstrap_consumed=True, getprofile=lambda: None))
        return guard, state, payload
    return create


@pytest.mark.parametrize('kind', sorted(leaf.CLASSES))
@pytest.mark.parametrize('case', leaf.CASES)
@pytest.mark.parametrize('change', [None, 'case', 'token', 'class', 'lineage', 'argv',
                                  'binding', 'phase', 'flags', 'native', 'caller', 'source-pin'])
def test_actual_child_frame_and_exact_payload_are_required(context, kind, case, change):
    guard, state, payload = context(kind, case)
    if change in {'case', 'class', 'token', 'phase'}:
        state[change] = 'foreign'
    elif change == 'lineage':
        payload['operation_lineage'] = [{'foreign': True}]
    elif change == 'argv':
        payload['orig_argv'].append('foreign')
    elif change == 'binding':
        payload['source_binding']['line'] += 1
    elif change == 'flags':
        leaf.sys.flags.isolated = 0
    elif change == 'native':
        leaf.sys._unrest_primary_source_bootstrap_consumed = False
    elif change == 'source-pin':
        state['product_pins'][setup.SESSION if kind.endswith('backend') else setup.ACP] = '0' * 64
    if change == 'caller':
        result = guard.install('/manifest', 'exact', state['token'], kind, case)
    else:
        result = guard.child('/manifest', 'exact', payload)
    assert (result is not None) is (change is None)
    if result is not None:
        assert result.state is state and result.payload is payload
        # Prospective setup selection never manufactures authenticated READY.
        assert state['phase'] == 'INSTALLING' and 'ready_record' not in state
        assert setup.eligible(state, {}, payload) is False


def test_all_launch_and_profile_routes_are_denied_and_caught_refusals_stay_recorded():
    rows = []
    class Refused(RuntimeError):
        pass
    def refuse(reason):
        rows.append({'kind': 'forbidden', 'reason': reason})
        raise Refused(reason)
    guard = SimpleNamespace(refuse=refuse)
    domain = leaf.ClosedLeaf(guard, {'class': sorted(leaf.CLASSES)[0],
                                    'case': leaf.CASES[0], 'token': 'child'}, {})
    for event in sorted(leaf.PROCESS_EVENTS | leaf.PROFILE_EVENTS):
        with pytest.raises(Refused, match='closed_bootstrap_leaf_denied'):
            domain.audit(event, ())
    assert len(rows) == len(leaf.PROCESS_EVENTS | leaf.PROFILE_EVENTS)
    assert all(row['kind'] == 'forbidden' for row in rows)
    domain.audit('open', ('read-only-input', None, os.O_RDONLY))
    assert len(rows) == 8


@pytest.mark.parametrize('kind', sorted(leaf.CLASSES))
@pytest.mark.parametrize('case', leaf.CASES)
def test_original_authenticated_eligibility_and_post_selection_drift_remain_live(context, kind, case):
    guard, state, payload = context(kind, case)
    before = deepcopy(payload)
    result = guard.child('/manifest', 'exact', payload)
    assert result is not None and payload == before
    state['phase'] = 'READY'
    endpoint = {'token': state['token'], 'identity': {'pid': os.getpid()}}
    assert setup.eligible(state, endpoint, payload)
    assert not setup.eligible(state, {**endpoint, 'identity': {'pid': os.getpid()+1}}, payload)
    guard._CLOSED_LEAF = state['closed_bootstrap_leaf'] = result
    result.validate_ready()
    payload['orig_argv'].append('foreign')
    guard.refuse = lambda reason: (_ for _ in ()).throw(RuntimeError(reason))
    with pytest.raises(RuntimeError, match='closed_bootstrap_leaf_identity_drift'):
        result.validate_ready()


def test_clean_isolated_install_dependencies_then_original_execution_barrier(tmp_path):
    """Unit-only dependency/seal proof; native endpoint authentication is separate."""
    import json
    import subprocess
    from test_stdlib_backend import RUNNER
    runner = RUNNER.replace(
        "('runtime_guard','operation_activation','isolated_inputs','stdlib_backend')",
        "('runtime_guard','stdlib_backend')")
    marker = "if mode=='execution-spec':state['operation_activation'].spec={}"
    assert runner.count(marker) == 1
    install = r'''
assert 'operation_activation' not in sys.modules and 'isolated_inputs' not in sys.modules
leaf_path=base/'closed_bootstrap_leaf.py'
leaf=types.ModuleType('closed_bootstrap_leaf');leaf.__file__=str(leaf_path)
sys.modules['closed_bootstrap_leaf']=leaf
exec(compile(leaf_path.read_bytes(),str(leaf_path),'exec'),vars(leaf))
state.update(token='unit-leaf', case=leaf.CASES[0], **{'class':'source-canonical-stdlib-backend'},
             runtime={'sha256':'unit-runtime'},registry={'sha256':'unit-registry'},pin='unit-manifest')
state['activation_support']={'path':str(base/'operation_activation.py'),
                             'sha256':files[str(base/'operation_activation.py')]}
state['isolated_support'].update(path=str(base/'isolated_activation.py'),
    sha256=files[str(base/'isolated_activation.py')],inputs_path=str(base/'isolated_inputs.py'),
    inputs_sha256=files[str(base/'isolated_inputs.py')])
observed=[]
guard.append=observed.append
# This callback checks the unit's actual local installation result; it makes
# no observer/native READY or parent-wait assertion.
def unit_ready(token):
 assert token=='unit-leaf' and state['phase']=='READY'
 assert state['ready_record'] in observed
 assert state['operation_activation'] is state['activation_owner']
 assert state['operation_activation'].spec==execution
 assert type(state['operation_activation']).__name__=='IsolatedActivation'
guard.require_ready=unit_ready
domain_leaf=leaf.ClosedLeaf(guard,state,payload)
domain_leaf.install()
assert [row['kind'] for row in observed]==['closed_bootstrap_leaf_installed','ready']
assert sys.modules['operation_activation'].__file__==state['activation_support']['path']
assert sys.modules['isolated_inputs'].__file__==state['isolated_support']['inputs_path']
assert 'source_operations' not in sys.modules
'''
    runner = runner.replace(marker, install + '\n' + marker)
    script = tmp_path / 'isolated-install.py'
    script.write_text(runner)
    result = subprocess.run([sys.executable, '-I', '-S', str(script), str(ROOT), 'original'],
                            cwd=tmp_path, env={**os.environ, 'CODEX_HOME': str(tmp_path),
                                              'PYTHONPATH': str(tmp_path / 'forbidden-site')},
                            input='{"id":1,"method":"initialize","params":{}}\n',
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['result'] == {'userAgent': 'synthetic-only'}
    assert not (tmp_path / 'backend-error.json').exists()
