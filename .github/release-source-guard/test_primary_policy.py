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


@pytest.mark.parametrize('name', ['v0.4.6 source suite', 'Build wheel and source distribution',
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
