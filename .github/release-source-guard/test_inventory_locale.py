"""Exact consumed inventory roles retain exec environment and native binding."""
from copy import deepcopy
import json

import pytest

import primary_source_inputs as inputs
from primary_policy import PYTHON


def fixture(role):
    env = {'LANG': 'C', 'PATH': '/source/.venv/bin:/usr/bin:/bin',
           'UNREST_HOME': '/work/owned/home', 'UNREST_MISSION_ID': 'mission', 'UNREST_PROJECT_ID': 'project'}
    env.update({'UNREST_HANDOFF_PATH': '/work/owned/report', 'UNREST_NODE_ID': 'w-secret',
                'UNREST_NODE_TYPE': 'work', 'UNREST_NODE_ASSIGNMENT': '{"targets":["VAL-001"],"task_type":"work"}'}
               if role == 'worker' else {'UNREST_TERMINAL_REVIEW_PATH': '/work/owned/review'})
    vector = ['/source/.venv/bin/python', '-c', 'bound bootstrap']
    case = 'tests/test_acp_runner.py::test_real_mcp_inventory_fd_redacts_before_crash_and_restart[' + role + ']'
    binding = {'path': '/source/src/unrest_harness/acp_runner.py', 'line': 2139 if role == 'worker' else 2219,
               'sha256': '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'}
    registration = {'kind': 'admitted', 'class': 'source-owned-role:' + role, 'case': case,
                    'source_binding': binding, 'owner_pid': 77, 'token': 'owned-token'}
    cwd = '/work/owned/pytest/test_real_mcp_inventory_fd_red0/workspace'
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
                            'product_pins': {'src/unrest_harness/acp_runner.py': binding['sha256'],
                                             'tests/test_acp_runner.py': '0edac8224b6b1760230026567fb1c3a1d591dc70d0b70e9990b0b52d68a71561'}}}
    return env, registration, context


@pytest.mark.parametrize('role', ['worker', 'terminal-reviewer'])
def test_only_postinit_mapping_changes_for_exact_consumed_role(role, monkeypatch):
    env, registration, context = fixture(role)
    before = deepcopy((env, registration, context))
    monkeypatch.setattr(inputs, 'lease_profile_context', lambda *a: context)
    assert inputs.python_environment(env, registration, [0, 0, 0]) == {**env, 'LC_CTYPE': 'C.UTF-8'}
    assert (env, registration, context) == before


@pytest.mark.parametrize('change', ['case', 'kind', 'class', 'line', 'source', 'owner', 'token', 'cwd',
                                   'vector', 'bootstrap', 'environment', 'manifest', 'no-consumption',
                                   'duplicate-consumption', 'seal', 'flags', 'foreign-env', 'locale', 'no-context'])
def test_foreign_or_unconsumed_context_keeps_exact_environment(change):
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
    elif change == 'locale':
        env['LANG'] = 'C.UTF-8'
    elif change == 'no-context':
        context = None
    else:
        context['selected'][{'bootstrap': 'bootstrap_sha256', 'environment': 'environment_sha256'}[change]] = '0' * 64
    assert inputs.python_environment(env, registration, flags, lease_context=context) == env
