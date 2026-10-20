"""Owned cache configuration controls; original guard controls remain unchanged."""
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_policy import command_environment, environment, plan
from primary_type_cache import configured_environment, SETTING

from ci_commands import REGISTRY
from test_ci_commands import workflow

WORKFLOW = workflow(json.loads(REGISTRY.read_bytes()))
SCRIPT = b'uv run mypy src'


def selected():
    base = environment()
    return base, configured_environment(base, SCRIPT, WORKFLOW, plan(SCRIPT, WORKFLOW))


def test_original_type_duty_has_only_fixed_storage_delta():
    base, actual = selected()
    assert actual == {**base, **SETTING}
    assert command_environment(actual, actual)
    assert plan(SCRIPT, WORKFLOW)['commands'] == [['uv', 'run', 'mypy', 'src']]


@pytest.mark.parametrize('duty', ['Install dependencies', 'Import package', 'Supported CLI surfaces',
                                  'Lint (ruff)', 'Repository contract'])
def test_other_original_focused_duties_retain_exact_environment(duty):
    from ci_commands import primary_commands
    command = primary_commands(WORKFLOW)[duty]
    wire = command.encode() if '\n' in command.rstrip('\n') else command.rstrip('\n').encode()
    base = environment()
    assert configured_environment(base, wire, WORKFLOW, plan(wire, WORKFLOW)) == base
    assert not command_environment({**base, **SETTING}, base)


@pytest.mark.parametrize('change', ['missing', 'wrong_value', 'extra', 'wrong_duty'])
def test_exact_child_environment_refuses_cache_drift(change):
    base, actual = selected()
    value = dict(actual)
    if change == 'missing':
        del value['MYPY_CACHE_DIR']
    elif change == 'wrong_value':
        value['MYPY_CACHE_DIR'] = '/work/cache'
    elif change == 'extra':
        value['MYPY_FORCE_COLOR'] = '1'
    else:
        actual = base
    assert not command_environment(value, actual)


@pytest.mark.parametrize('key,value', [('duty', 'Lint (ruff)'), ('commands', [['uv', 'run', 'mypy', '.']]),
                                      ('script_sha256', '0' * 64), ('workflow_sha256', '0' * 64),
                                      ('source_mode', 'SOURCE'), ('extra', True)])
def test_type_plan_substitution_refused(key, value):
    supplied = {**plan(SCRIPT, WORKFLOW), key: value}
    with pytest.raises(RuntimeError, match='type_cache_duty_binding'):
        configured_environment(environment(), SCRIPT, WORKFLOW, supplied)


@pytest.mark.parametrize('value', ['/dev/null', '/tmp', ''])
def test_incoming_override_is_never_optional(value):
    with pytest.raises(RuntimeError, match='type_cache_initial_environment'):
        configured_environment({**environment(), 'MYPY_CACHE_DIR': value}, SCRIPT, WORKFLOW,
                               plan(SCRIPT, WORKFLOW))


def test_configuration_grants_no_executable_or_core_change():
    root = Path(__file__).parent
    assert hashlib.sha256((root / 'primary_authority.py').read_bytes()).hexdigest() == (
        '8660867109287601279c2014157ce3cd704d9e0afb96334a188447a892c87f4c')
    tree = ast.parse((root / 'primary_type_cache.py').read_bytes())
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr in {'Popen', 'run', 'execve', 'system', 'spawnv'}
                   for n in ast.walk(tree))
    assert 'MYPY_CACHE_DIR' not in environment(source=True)


def test_pinned_checker_diagnostics_and_null_storage(tmp_path):
    assert importlib.metadata.version('mypy') == '1.19.1'
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*'))
    source = tmp_path / 'cache_contract.py'
    source.write_text('value: int = 1\n')
    env = {**os.environ, **SETTING, 'PYTHONDONTWRITEBYTECODE': '1'}
    command = [sys.executable, '-m', 'mypy', str(source)]
    success = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert success.returncode == 0, success.stdout + success.stderr
    assert 'Success: no issues found' in success.stdout
    source.write_text('value: int = "wrong"\n')
    failure = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert failure.returncode == 1, failure.stdout + failure.stderr
    assert '[assignment]' in failure.stdout and 'Incompatible types' in failure.stdout
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*')) == before + [source.name]
    assert not (tmp_path / '.mypy_cache').exists()


@pytest.mark.parametrize('mode', ['type', 'other', 'plan_drift', 'source'])
def test_fixed_runtime_inputs_select_only_authenticated_type_duty(tmp_path, monkeypatch, mode):
    import primary_type_cache as cache
    from ci_commands import primary_commands
    base = environment(source=mode == 'source')
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    script = SCRIPT if mode != 'other' else primary_commands(WORKFLOW)['Lint (ruff)'].rstrip('\n').encode()
    spec = plan(script, WORKFLOW)
    if mode == 'plan_drift':
        spec['duty'] = 'Lint (ruff)'
    (inputs / 'github-script.sh').write_bytes(script)
    (inputs / 'plan.json').write_text(json.dumps(spec))
    wf = tmp_path / 'ci.yml'
    wf.write_text(WORKFLOW)
    original_path = Path
    def fixed_path(value):
        if value == '/inputs':
            return inputs
        if value.startswith('/inputs/'):
            return inputs / value.removeprefix('/inputs/')
        if value == '/source/.github/workflows/ci.yml':
            return wf
        return original_path(value)
    monkeypatch.setattr(cache, 'Path', fixed_path)
    monkeypatch.setattr(cache.sys, 'platform', 'linux')
    if mode == 'plan_drift':
        with pytest.raises(RuntimeError, match='type_cache_duty_binding'):
            cache.runtime_environment(base, source=False)
    else:
        actual = cache.runtime_environment(base, source=mode == 'source')
        assert actual == ({**base, **SETTING} if mode == 'type' else base)
