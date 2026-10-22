"""Empty-env locale mapping needs the exact consumed inflight fixture event."""
from copy import deepcopy
import json

import pytest

import primary_source_inputs as inputs
from primary_policy import PYTHON


def fixture():
    vector = ['/source/.venv/bin/python', '-c', 'authenticated finite bootstrap']
    case = 'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[False]'
    binding = {'path': '/source/src/unrest_harness/acp_runner.py', 'line': 1034,
               'sha256': '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'}
    registration = {'kind': 'admitted', 'class': 'inline:test_acp_cleanup.py:51',
        'case': case, 'source_binding': binding, 'owner_pid': 77, 'token': 'owned-token',
        'argv_sha256': inputs.sha(json.dumps([vector[0], '-c', 'import time; time.sleep(30)']).encode())}
    cwd = '/work/owned/pytest/test_inflight_terminal_regist0'
    selected = {'registration': registration, 'owner_pid': 77, 'token': 'owned-token',
        'case': case, 'cwd': cwd, 'environment_sha256': inputs.sha(b'{}'),
        'transformed_argv_sha256': inputs.sha(json.dumps(vector).encode()),
        'bootstrap_sha256': inputs.sha(vector[2].encode())}
    context = {'selected': selected, 'vector': vector, 'cwd': cwd, 'parent': 77,
        'manifest': {'checkout': '/source', 'owned_root': '/work/owned',
            'runtime': {'realpath': PYTHON, 'paths': [vector[0]]}, 'product_pins': {
                'src/unrest_harness/acp_runner.py': binding['sha256'],
                'tests/test_acp_cleanup.py': 'f63f37e40e925d409c4f8203ebabe85dcc0bc5d7e9c77feb267c485eacfce321'}}}
    return registration, context


def test_bound_locale_mapping_leaves_exec_and_registration_unchanged(monkeypatch):
    registration, context = fixture()
    before = deepcopy((registration, context))
    monkeypatch.setattr(inputs, 'lease_profile_context', lambda *a: context)
    assert inputs.python_environment({}, registration, [0, 0, 0]) == {'LC_CTYPE': 'C.UTF-8'}
    assert (registration, context) == before


@pytest.mark.parametrize('change', ['case', 'kind', 'class', 'line', 'path', 'source', 'owner',
                                   'token', 'cwd', 'vector', 'bootstrap', 'environment', 'manifest'])
def test_unbound_or_unrelated_claims_cannot_gain_locale_mapping(change):
    registration, context = fixture()
    if change in {'case', 'kind', 'class', 'token'}:
        registration[change] = 'foreign'
    elif change in {'line', 'path', 'source'}:
        key = {'line': 'line', 'path': 'path', 'source': 'sha256'}[change]
        registration['source_binding'][key] = 'foreign'
    elif change == 'owner':
        context['parent'] += 1
    elif change == 'cwd':
        context['cwd'] = '/foreign'
    elif change == 'vector':
        context['vector'][-1] += 'foreign'
    elif change == 'manifest':
        context['manifest']['product_pins']['tests/test_acp_cleanup.py'] = '0' * 64
    else:
        context['selected'][{'bootstrap': 'bootstrap_sha256', 'environment': 'environment_sha256'}[change]] = '0' * 64
    assert not inputs.exact_inflight_environment({}, registration, [0, 0, 0], context)


def test_no_context_or_foreign_env_or_flags_preserves_original_environment():
    registration, context = fixture()
    assert inputs.python_environment({}, registration, [0, 0, 0]) == {}
    for env, flags in [({'X': 'foreign'}, [0, 0, 0]), ({}, [1, 0, 0])]:
        assert inputs.python_environment(env, registration, flags, lease_context=context) == env


def test_historical_fixture_hash_cannot_gain_current_locale_mapping():
    registration, context = fixture()
    context['manifest']['product_pins']['tests/test_acp_cleanup.py'] = (
        '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8')
    assert not inputs.exact_inflight_environment({}, registration, [0, 0, 0], context)
