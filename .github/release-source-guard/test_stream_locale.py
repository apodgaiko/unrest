"""Consumed output-only role fixtures keep exact exec and FD custody."""
from copy import deepcopy
import json

import pytest

import primary_source_inputs as inputs
from primary_policy import PYTHON
from finite.chatty_role import BODY, OWNER, PIN, PRODUCT_PIN


def fixture(role):
    env = {'PATH': '/source/.venv/bin:/usr/bin:/bin'}
    if role == 'worker':
        env['UNREST_NODE_ASSIGNMENT'] = '{"targets":["VAL-SEC-014"],"task_type":"work"}'
    vector = ['/source/.venv/bin/python', '-c', 'bound bootstrap']
    case = 'tests/test_acp_runner.py::' + OWNER + '[' + role + ']'
    binding = {'path': '/source/tests/test_acp_runner.py', 'line': 341, 'sha256': PIN}
    registration = {'kind': 'admitted', 'class': 'source-owned-role:' + role, 'case': case,
                    'source_binding': binding, 'owner_pid': 77, 'token': 'owned-token',
                    'argv_sha256': inputs.sha(json.dumps([vector[0], '-c', BODY]).encode())}
    cwd = '/work/owned/pytest/test_mcp_role_child_oversized_s0/workspace'
    selected = {'registration': registration, 'owner_pid': 77, 'token': 'owned-token', 'case': case, 'cwd': cwd,
                'environment_sha256': inputs.sha(json.dumps(env, sort_keys=True).encode()),
                'transformed_argv_sha256': inputs.sha(json.dumps(vector).encode()),
                'bootstrap_sha256': inputs.sha(vector[2].encode())}
    context = {'selected': selected, 'vector': vector, 'cwd': cwd, 'parent': 77,
               'events': [{'kind': 'source_ordinary_startup_consumption', 'owner_pid': 77,
                           'launch_token': 'owned-token', 'class': registration['class'],
                           'source_binding': binding, 'shared_startup_seal': True}],
               'manifest': {'checkout': '/source', 'owned_root': '/work/owned',
                            'runtime': {'realpath': PYTHON, 'paths': [vector[0]]},
                            'product_pins': {'src/unrest_harness/acp_runner.py': PRODUCT_PIN,
                                             'tests/test_acp_runner.py': PIN}}}
    return env, registration, context


@pytest.mark.parametrize('role', ['worker', 'terminal-reviewer'])
def test_exact_mapping_leaves_exec_environment_and_consumption_unchanged(role, monkeypatch):
    env, registration, context = fixture(role)
    before = deepcopy((env, registration, context))
    monkeypatch.setattr(inputs, 'lease_profile_context', lambda *a: context)
    assert inputs.python_environment(env, registration, [0, 0, 0]) == {**env, 'LC_CTYPE': 'C.UTF-8'}
    assert (env, registration, context) == before


@pytest.mark.parametrize('change', ['case', 'kind', 'class', 'line', 'source', 'owner', 'token', 'cwd',
                                   'vector', 'bootstrap', 'environment', 'manifest', 'no-consumption',
                                   'duplicate-consumption', 'seal', 'flags', 'foreign-env', 'assignment',
                                   'argv', 'no-context'])
def test_changed_or_unconsumed_fixture_cannot_gain_a_locale_exception(change):
    env, registration, context = fixture('worker')
    flags = [0, 0, 0]
    if change in {'case', 'kind', 'class', 'token'}:
        registration[change] = 'foreign'
    elif change in {'line', 'source'}:
        registration['source_binding'][{'line': 'line', 'source': 'sha256'}[change]] = 'foreign'
    elif change == 'owner':
        context['parent'] += 1
    elif change == 'cwd':
        context['cwd'] = '/foreign'
    elif change == 'vector':
        context['vector'][-1] += 'foreign'
    elif change == 'manifest':
        context['manifest']['product_pins']['tests/test_acp_runner.py'] = '0' * 64
    elif change == 'no-consumption':
        context['events'] = []
    elif change == 'duplicate-consumption':
        context['events'] *= 2
    elif change == 'seal':
        context['events'][0]['shared_startup_seal'] = False
    elif change == 'flags':
        flags = [1, 0, 0]
    elif change == 'foreign-env':
        env['FOREIGN'] = 'foreign'
    elif change == 'assignment':
        env['UNREST_NODE_ASSIGNMENT'] = 'foreign'
    elif change == 'argv':
        registration['argv_sha256'] = '0' * 64
    elif change == 'no-context':
        context = None
    else:
        context['selected'][{'bootstrap': 'bootstrap_sha256', 'environment': 'environment_sha256'}[change]] = '0' * 64
    assert inputs.python_environment(env, registration, flags, lease_context=context) == env
