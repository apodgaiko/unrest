"""Exact workflow command binding; no source or package execution is simulated."""
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('ci_commands', Path(__file__).with_name('ci_commands.py'))
assert spec is not None and spec.loader is not None
commands = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commands)


def workflow(registry):
    lines = ['jobs:\n', '  primary:\n', '    steps:\n']
    for name, script in registry.items():
        lines.append('      - name: ' + name + '\n')
        if '\n' in script.rstrip('\n'):
            lines.append('        run: |\n')
            lines.extend('          ' + row for row in script.splitlines(keepends=True))
        else:
            lines.append('        run: ' + script)
        lines.append('        shell: python3 .github/release-source-guard/ci_shell.py {0}\n')
    return ''.join(lines)


def test_every_original_run_block_binds_exact_actual_bytes():
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry)
    assert commands.primary_commands(actual) == registry
    for name, script in registry.items():
        result = commands.bind(script.encode(), actual)
        assert result['name'] == name and result['script'] == script.encode()
        assert result['full_source'] == (name == 'v0.4.6 source suite')


@pytest.mark.parametrize('mutation', ['echo', 'filter', 'extra', 'newline', 'changed_other_duty'])
def test_script_or_any_original_duty_drift_is_refused(mutation):
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry)
    script = registry['v0.4.6 source suite'].encode()
    if mutation == 'echo':
        script = b'echo ' + script
    elif mutation == 'filter':
        script = script.rstrip() + b' -k partial\n'
    elif mutation == 'extra':
        script += b'true\n'
    elif mutation == 'newline':
        script = script.rstrip(b'\n')
    elif mutation == 'changed_other_duty':
        actual = actual.replace('run: uv run mypy src', 'run: echo uv run mypy src')
    with pytest.raises(RuntimeError):
        commands.bind(script, actual)
