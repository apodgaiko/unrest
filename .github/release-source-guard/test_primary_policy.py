"""Exact original-script root authority and finite negative controls."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_policy import backend_request, command_environment, environment, plan
from test_ci_commands import workflow
from ci_commands import REGISTRY


def test_original_import_script_is_the_executed_shell_input():
    registry = json.loads(REGISTRY.read_bytes())
    script = registry['Import package'].removesuffix('\n').encode()
    actual = plan(script, workflow(registry))
    assert actual['shell_argv'] == ['/bin/bash', '--noprofile', '--norc', '-e', '-o',
                                   'pipefail', '/inputs/github-script.sh']
    assert actual['commands'] == [['uv', 'run', 'python', '-c',
        'import unrest_harness; from unrest_harness.config import HarnessConfig; HarnessConfig.discover()']]
    assert actual['timeout_seconds'] == 180 and actual['source_checkpoint_ready'] is False


@pytest.mark.parametrize('name', ['v0.4.7 source suite', 'Build wheel and source distribution',
                                  'Smoke-test installed wheel', 'Check distribution archives'])
def test_focused_root_never_grants_full_or_package_authority(name):
    registry = json.loads(REGISTRY.read_bytes())
    with pytest.raises(RuntimeError, match='closure_missing'):
        plan((registry[name] if '\n' in registry[name].rstrip('\n') else registry[name].removesuffix('\n')).encode(), workflow(registry))


@pytest.mark.parametrize('addition', [{'OPENAI_API_KEY': 'forbidden'}, {'GITHUB_TOKEN': 'forbidden'},
                                      {'LD_PRELOAD': '/foreign'}, {'PYTHONPATH': '/foreign'},
                                      {'PATH': '/foreign'}, {'SHLVL': '2'}])
def test_credential_runtime_and_shell_drift_refused(addition):
    root = environment()
    assert not command_environment({**root, **addition}, root)


def test_shell_finite_environment_additions():
    root = environment()
    assert command_environment({**root, 'PWD': '/source', 'SHLVL': '1', '_': '/bin/bash'}, root)


@pytest.mark.parametrize('script', ['print(1)', 'import os; os.system("true")',
                                    'with open("/private/response", "w") as fp:\n fp.write(1)'])
def test_unregistered_native_helpers_refused(script):
    assert backend_request(script) is None


def test_native_backend_renderer_is_closed_and_bound_to_finite_cache():
    prefix = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
              'sys.path = [] + sys.path\n\nimport setuptools.build_meta as backend\n')
    request = '/work/cache/builds-v0/.tmpUnit/get_requires_for_build_editable.txt'
    script = (prefix + '\nimport json\n\nget_requires_for_build = getattr(backend, "get_requires_for_build_editable", None)\n'
                'if get_requires_for_build:\n    requires = get_requires_for_build({})\nelse:\n    requires = []\n\n'
                f'with open("{request}", "w") as fp:\n    json.dump(requires, fp)\n')
    assert backend_request(script) == 'get_requires_for_build_editable'
    for drift in (script + '\nprint(1)', script.replace('/work/cache/', '/foreign/'),
                  script.replace('requires = []', 'requires = ["foreign"]')):
        assert backend_request(drift) is None


def test_public_evidence_never_carries_actual_script_argv_or_arbitrary_fields():
    from primary_policy import public_plan
    registry = json.loads(REGISTRY.read_bytes())
    spec = plan(registry['Import package'].removesuffix('\n').encode(), workflow(registry))
    spec['commands'] = [['PRIVATE-CANARY-PRIMARY-ARGV']]
    spec['shell_argv'] = ['PRIVATE-CANARY-PRIMARY-SHELL']
    spec['unrecognized'] = 'PRIVATE-CANARY-PRIMARY-UNKNOWN'
    result = public_plan(spec)
    assert 'PRIVATE-CANARY' not in json.dumps(result)
    assert set(result) == {'schema', 'duty', 'script_sha256', 'workflow_sha256', 'command_count',
                           'timeout_seconds', 'source_checkpoint_ready', 'selected_carrier'}
    spec['script_sha256'] = 'PRIVATE-CANARY-PRIMARY-HASH'
    with pytest.raises(RuntimeError):
        public_plan(spec)


def test_registration_diagnosis_selects_only_four_original_cases_and_no_full_authority():
    import primary_policy as policy
    cases = policy.TEST_CONTROLLED_REGISTRATION_CASES
    assert cases == tuple('tests/test_controlled_python_acp.py::test_actual_registration['
                         + name + '-' + str(number) + ']'
                         for name in ('delayed', 'late') for number in (1, 2))
    assert cases in policy.TEST_SELECTIONS
    assert len(set(cases)) == 4
    assert policy.SOURCE_BUDGET == {'root_seconds': 7200, 'collection_seconds': 300, 'drain_seconds': 60}
    from primary_source_inputs import test_plan as make_test_plan
    text = workflow(json.loads(REGISTRY.read_bytes()))
    script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(cases)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['timeout_seconds'] == policy.root_seconds(result) == 180
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert result['source_mode'] == 'TEST-positive'
    for changed in (script.replace(b'[late-2]', b'[foreign-2]'), script + b' -k late'):
        with pytest.raises(RuntimeError, match='primary_source_test_script'):
            make_test_plan(changed, text, 'TEST-positive')
    with pytest.raises(RuntimeError):
        plan(script, text)
