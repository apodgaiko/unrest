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
    lines = ['jobs:\n', '  primary:\n', '    name: primary source and package gate (py3.13)\n',
             '    runs-on: ubuntu-latest\n', '    steps:\n']
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


@pytest.mark.parametrize('control', ['job', 'step'])
@pytest.mark.parametrize('condition', ['false', '${{ false && true }}', '${{ github.ref }}'])
def test_actual_original_duties_cannot_be_made_conditional(control, condition):
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry)
    if control == 'job':
        actual = actual.replace('  primary:\n', '  primary:\n    if: ' + condition + '\n')
    else:
        actual = actual.replace('      - name: Type-check (mypy)\n',
                                '      - name: Type-check (mypy)\n        if: ' + condition + '\n')
    with pytest.raises(RuntimeError):
        commands.bind(registry['v0.4.6 source suite'].encode(), actual)



def test_generated_scalar_and_literal_wire_bytes_are_distinct_and_not_rewritten():
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry)
    scalar = registry['Import package'].removesuffix('\n').encode()
    literal = registry['Supported CLI surfaces'].encode()
    assert commands.bind_generated(scalar, actual)['script'] is scalar
    assert commands.bind_generated(literal, actual)['script'] is literal
    for drift in (scalar + b'\n', b'true\n' + scalar, literal.rstrip(b'\n')):
        with pytest.raises(RuntimeError):
            commands.bind_generated(drift, actual)


@pytest.mark.parametrize('field', ['continue-on-error: true', 'working-directory: /foreign'])
def test_duty_cannot_change_failure_or_working_directory_semantics(field):
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry).replace('      - name: Type-check (mypy)\n',
        '      - name: Type-check (mypy)\n        ' + field + '\n')
    with pytest.raises(RuntimeError):
        commands.bind_generated(registry['Type-check (mypy)'].removesuffix('\n').encode(), actual)


@pytest.mark.parametrize('field', ['"if": false', 'if : false', '<<: *dead',
                                  '"continue-on-error": true', 'env: {UV_NO_SYNC: "1"}'])
def test_noncanonical_or_merged_execution_controls_are_refused(field):
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry).replace('      - name: Type-check (mypy)\n',
        '      - name: Type-check (mypy)\n        ' + field + '\n')
    with pytest.raises(RuntimeError):
        commands.bind_generated(registry['Type-check (mypy)'].removesuffix('\n').encode(), actual)


def test_generated_script_cannot_be_bound_to_a_different_primary_job():
    registry = json.loads(commands.REGISTRY.read_bytes())
    actual = workflow(registry).replace('primary source and package gate (py3.13)', 'foreign job')
    with pytest.raises(RuntimeError, match='identity'):
        commands.bind_generated(registry['Import package'].removesuffix('\n').encode(), actual)


def test_decorative_or_duplicate_custom_shell_cannot_skip_an_original_duty():
    registry = json.loads(commands.REGISTRY.read_bytes())
    original = workflow(registry)
    marker = '        shell: python3 .github/release-source-guard/ci_shell.py {0}\n'
    for drift in (original.replace(marker, '        shell: echo {0}\n', 1),
                  original.replace(marker, marker + marker, 1), original.replace(marker, '', 1)):
        with pytest.raises(RuntimeError, match='shell'):
            commands.bind_generated(registry['Import package'].removesuffix('\n').encode(), drift)
