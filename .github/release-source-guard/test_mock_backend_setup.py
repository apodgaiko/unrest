"""Only the pinned JSON mock omits unrelated setup; all authority stays intact."""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from finite import mock_backend_setup as setup

ROOT = Path(__file__).parent


def context():
    script = '/source/' + setup.SCRIPT
    state = {'class': 'source-cohort2:mock-agent', 'setup_mode': 'source', 'phase': 'READY',
             'checkout': '/source', 'token': 'actual-launch', 'case': 'original-case',
             'runtime': {'paths': ['/source/.venv/bin/python']},
             'product_pins': {'src/unrest_harness/acp_runner.py': 'caller-pin'}}
    endpoint = {'token': state['token'], 'identity': {'pid': os.getpid()}}
    payload = {'class': state['class'], 'mode': 'script', 'target': script,
               'path0': '/source/tests', 'token': state['token'], 'case': state['case'],
               'orig_argv': ['/source/.venv/bin/python', script], 'sys_argv': [script],
               'isolated': False, 'source_binding': {'path': '/source/src/unrest_harness/acp_runner.py',
                                                    'line': 409, 'sha256': 'caller-pin'}}
    return state, endpoint, payload


def test_exact_json_backend_metadata_and_original_argument_modes():
    state, endpoint, payload = context()
    assert setup.eligible(state, endpoint, payload)
    payload['orig_argv'].insert(1, '-I')
    payload['isolated'] = True
    payload['orig_argv'].append('--missing-handoff-session-error')
    payload['sys_argv'].append('--missing-handoff-session-error')
    assert setup.eligible(state, endpoint, payload)


@pytest.mark.parametrize('change', ['class', 'module', 'target', 'path0', 'token', 'case',
                                    'identity', 'runtime', 'argv', 'isolated', 'binding',
                                    'phase', 'profile-timing', 'dependency-source-negative',
                                    'dependency-launch-negative'])
def test_unknown_roles_or_changed_metadata_keep_original_setup(change):
    state, endpoint, payload = context()
    if change == 'class':
        state['class'] = payload['class'] = 'source-owned-role:worker'
    elif change == 'module':
        payload['mode'] = 'module'
    elif change in {'target', 'path0', 'token', 'case', 'isolated'}:
        payload[change] = 'foreign'
    elif change == 'identity':
        endpoint['identity']['pid'] += 1
    elif change == 'runtime':
        payload['orig_argv'][0] = '/foreign/python'
    elif change == 'argv':
        payload['orig_argv'].append('foreign')
    elif change == 'binding':
        payload['source_binding']['sha256'] = 'foreign'
    elif change == 'phase':
        state['phase'] = 'INSTALLING'
    else:
        state['setup_mode'] = change
    assert not setup.eligible(state, endpoint, payload)


def test_a_direct_caller_cannot_select_a_setup_exception():
    guard = SimpleNamespace(_STATE=context()[0])
    assert setup.select(guard, context()[1]) is None


def test_actual_mock_source_has_no_fastmcp_import_or_dynamic_import_path():
    source = ROOT.parent.parent / 'tests/mock_acp_agent.py'
    if not source.is_file():
        pytest.skip('original source is intentionally absent from control compartment')
    assert hashlib.sha256(source.read_bytes()).hexdigest() == setup.PIN
    tree = ast.parse(source.read_bytes())
    imports = {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
    imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imports == {'__future__', 'json', 'os', 'sys', 'pathlib'}
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id in {'eval', 'exec', '__import__'} for node in ast.walk(tree))


def test_unknown_contexts_and_all_negative_controls_retain_original_setup_body():
    module = ast.parse((ROOT / 'finite/endpoint.py').read_bytes())
    attach = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'attach')
    install = next(n for n in attach.body if isinstance(n, ast.FunctionDef) and n.name == 'install')
    gate = next(n for n in install.body if isinstance(n, ast.If)
                and ast.unparse(n.test) == 'inapplicable is not None')
    assert len(gate.body) == 1 and ast.unparse(gate.body[0]) == 'guard.append(inapplicable)'
    actual = hashlib.sha256(ast.dump(ast.Module(body=deepcopy(gate.orelse), type_ignores=[]), include_attributes=False).encode()).hexdigest()
    assert actual == '2054eb8c6d0c8de7fca8b91aae95abfa20531e24649ee977abb8f6abce0b957b'
    lifetime = next(n for n in install.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'lifetime' for t in n.targets))
    assert install.body.index(gate) < install.body.index(lifetime)
    assert 'descriptor_lifetime.py' in ast.unparse(lifetime)
    assert 'endpoint_install_complete' in ast.unparse(install.body[-1])


def leaf_context(kind):
    state, endpoint, payload = context()
    state['class'] = payload['class'] = kind
    state['owned_root'] = '/work/owned'
    if kind == 'controlled-acp':
        source, line, pin = setup.ACP, 1, setup.ACP_PIN
        target, argument = '/source/' + setup.ACP, '--controlled-local-acp-v1'
    elif kind == 'canonical-backend':
        source, line, pin = setup.BACKEND, 1, setup.BACKEND_PIN
        target, argument = '/work/owned/lane/fake-app-server', 'app-server'
    else:
        source, line, pin = setup.SESSION, 506, setup.SESSION_PIN
        target, argument = '/work/owned/lane/fake-app-server', 'app-server'
    state['product_pins'][source] = pin
    payload.update(target=target, path0=str(Path(target).parent),
                   orig_argv=[state['runtime']['paths'][0], target, argument],
                   sys_argv=[target, argument],
                   source_binding={'path': '/source/' + source, 'line': line, 'sha256': pin})
    if kind == 'source-controlled-backend-postimage':
        payload['source_binding']['function'] = '_open_role_owned'
    return state, endpoint, payload


@pytest.mark.parametrize('kind', sorted(setup.JSON_LEAVES - {'source-canonical-stdlib-backend', 'source-canonical-stdlib-acp'}))
def test_exact_controlled_stdlib_leaf_metadata_has_no_launch_grant(kind):
    state, endpoint, payload = leaf_context(kind)
    assert setup.eligible(state, endpoint, payload)
    assert setup.select(SimpleNamespace(_STATE=state), endpoint) is None
    for name in ['token', 'case', 'path0']:
        changed = deepcopy(payload)
        changed[name] = 'foreign'
        assert not setup.eligible(state, endpoint, changed)
    changed = deepcopy(payload)
    changed['source_binding']['line'] += 1
    assert not setup.eligible(state, endpoint, changed)
    for mode in ['dependency-source-negative', 'dependency-launch-negative', 'profile-timing']:
        assert not setup.eligible({**state, 'setup_mode': mode}, endpoint, payload)


@pytest.mark.parametrize('kind', ['canonical-backend', 'source-controlled-backend-postimage'])
@pytest.mark.parametrize('target', ['/foreign/fake-app-server', '/work/owned/not-the-script',
                                    '/work/owned/../foreign/fake-app-server', 'fake-app-server'])
def test_generated_leaf_does_not_select_unknown_script_locations(kind, target):
    state, endpoint, payload = leaf_context(kind)
    payload['target'] = payload['sys_argv'][0] = payload['orig_argv'][1] = target
    payload['path0'] = str(Path(target).parent)
    assert not setup.eligible(state, endpoint, payload)


@pytest.mark.parametrize(('source', 'pin', 'imports'), [
    (setup.ACP, setup.ACP_PIN, {'asyncio', 'json', 'os', 'sys'}),
    (setup.BACKEND, setup.BACKEND_PIN,
     {'copy', 'json', 'os', 'pathlib', 'sys', 'signal', 'secrets', 'time', 'tomllib', 'urllib.request'}),
])
def test_controlled_leaf_source_is_exact_stdlib_only(source, pin, imports):
    path = ROOT.parent.parent / source
    if not path.is_file():
        pytest.skip('original source is intentionally absent from control compartment')
    body = path.read_bytes()
    assert hashlib.sha256(body).hexdigest() == pin
    tree = ast.parse(body)
    actual = {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
    actual |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert actual == imports
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id in {'eval', 'exec', '__import__'} for node in ast.walk(tree))


@pytest.mark.parametrize('case', sorted(setup.CONFIGURATION_CASES))
def test_only_exact_original_configuration_cases_select_canonical_postimage(case):
    from finite import backend_postimage_catalog as catalog
    state, endpoint, payload = leaf_context('source-controlled-backend-postimage')
    state['case'] = payload['case'] = case
    assert catalog.CASES[case]['script_sha256'] == setup.BACKEND_PIN
    assert setup.selected_script(state, payload) == (payload['target'], setup.BACKEND_PIN)
    assert setup.eligible(state, endpoint, payload)
    assert setup.select(SimpleNamespace(_STATE=state), endpoint) is None
    state['case'] = payload['case'] = case + '-foreign'
    assert setup.selected_script(state, payload)[1] == setup.BARRIER_PIN


@pytest.mark.parametrize('case', sorted(setup.INITIALIZATION_CASES))
def test_initialization_canonical_backend_uses_existing_stdlib_setup_gate(case):
    from primary_policy import INITIALIZATION_POSTIMAGE_CASES
    from finite import backend_postimage_catalog as catalog
    assert setup.INITIALIZATION_CASES == frozenset(INITIALIZATION_POSTIMAGE_CASES)
    state, endpoint, payload = leaf_context('source-controlled-backend-postimage')
    state['case'] = payload['case'] = case
    row = catalog.CASES[case]
    assert row['script_sha256'] == setup.BACKEND_PIN
    assert row['filename'] == 'fake-app-server'
    assert setup.selected_script(state, payload) == (payload['target'], setup.BACKEND_PIN)
    assert setup.eligible(state, endpoint, payload)
    # A case/pin match is setup classification, never the actual caller proof.
    assert setup.select(SimpleNamespace(_STATE=state), endpoint) is None
    state['case'] = payload['case'] = case + '-foreign'
    assert setup.selected_script(state, payload)[1] == setup.BARRIER_PIN
    assert not (setup.INITIALIZATION_CASES & setup.CONFIGURATION_CASES)


def test_initialization_setup_repair_preserves_entire_original_selector():
    tree = ast.parse((ROOT / 'finite/mock_backend_setup.py').read_bytes())
    selector = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'select')
    gates = [n for n in ast.walk(selector) if isinstance(n, ast.Compare)
             and ast.unparse(n) == "state['class'] in {'source-controlled-backend-postimage', 'source-canonical-stdlib-backend'}"]
    assert len(gates) == 1
    gate = gates[0]
    gate.ops = [ast.Eq()]
    gate.comparators = [ast.Constant(value='source-controlled-backend-postimage')]
    assert hashlib.sha256(ast.dump(selector, include_attributes=False).encode()).hexdigest() == '89c1817868b35b4b38a191ca68b5dc4764bfec2bdcb046c8b8064a04e860b9f1'
