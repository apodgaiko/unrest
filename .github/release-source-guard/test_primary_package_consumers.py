"""Package-only native domains and the exact original scripts stay closed."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from primary_custody import INSTALLED, CHECKSUM, WHEEL, SDIST

ROOT = Path(__file__).parent


def shell():
    class Base:
        def refuse(self, code):
            self.denials.append(code)
            return False
        def resolve(self, *args):
            raise AssertionError('unknown execution reached original authority')
    path = ROOT / 'primary_package_shell.py'
    nodes = [n for n in ast.parse(path.read_bytes()).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    module = ModuleType('controlled_shell')
    module.__dict__.update(Authority=Base, INSTALLED=INSTALLED, CHECKSUM=CHECKSUM,
                           WHEEL=WHEEL, SDIST=SDIST, Path=Path, hashlib=hashlib, json=json,
                           PREFIX='/source/.wheel-venv', UNSET=('ANTHROPIC_API_KEY',))
    module.LIFECYCLE = ['env', '-u', 'ANTHROPIC_API_KEY', '/source/.wheel-venv/bin/python',
                        '-m', 'unrest_harness.installed_wheel_check']
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), module.__dict__)
    return module


@pytest.mark.parametrize('duty', [INSTALLED, CHECKSUM])
def test_workflow_runs_literal_original_package_script(duty):
    registry = json.loads((ROOT / 'ci_commands.json').read_text())
    workflow = yaml.safe_load((ROOT.parent / 'workflows/v046-source-readiness.yml').read_text())
    steps = workflow['jobs']['compartment-controls']['steps']
    matches = [row for row in steps if row.get('run') == registry[duty]]
    assert len(matches) == 1
    assert matches[0]['shell'] == 'python3 .github/release-source-guard/ci_shell.py --package-test {0}'


@pytest.mark.parametrize('field', ['foreign-key', 'cwd', 'underscore', 'unsupported', 'credential'])
def test_shell_environment_cannot_add_credentials_or_redirect_execution(field):
    module = shell()
    original = {'PATH': '/fixed', 'HOME': '/owned'}
    actual = {**original, 'PWD': '/source/dist', '_': '/usr/bin/sha256sum', 'SHLVL': '1'}
    assert module.environment_matches(actual, original, '/source/dist', '/usr/bin/sha256sum')
    if field == 'foreign-key':
        actual['FOREIGN'] = '1'
    elif field == 'cwd':
        actual['PWD'] = '/foreign'
    elif field == 'underscore':
        actual['_'] = '/foreign'
    elif field == 'unsupported':
        actual['UNREST_CAPABILITY_PROFILE'] = 'unsupported'
    else:
        actual['OPENAI_API_KEY'] = 'canary'
    assert not module.environment_matches(actual, original, '/source/dist', '/usr/bin/sha256sum')


@pytest.mark.parametrize('vector', [['python', '-c', 'pass'], ['uv', 'venv', '--clear', '.wheel-venv'],
                                  ['claude'], ['codex'], ['sha256sum', 'foreign'], ['env', 'python']])
def test_completed_or_unknown_shell_path_never_falls_back_to_generic_native_admission(vector):
    module = shell()
    owner = module.PackageShellAuthority.__new__(module.PackageShellAuthority)
    owner.contexts, owner.denials = {}, []
    owner.pending_env = None
    owner.operation_index = 2
    owner.operations = module.operations(CHECKSUM)
    trace = SimpleNamespace(identities={12: {'ppid': 7}})
    assert owner.resolve(trace, 12, '/foreign', vector, {}, '/source/dist') is False
    assert owner.denials == ['package_shell_unknown_exec']


@pytest.mark.parametrize('name', ['cohort3_plan.py', 'cohort_plan.py'])
def test_actual_original_cohort_selector_reproduces_none_case_and_accepts_bound_package_case(name):
    path = ROOT / 'finite' / name
    node = next(n for n in ast.parse(path.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == 'select')
    namespace = {'Path': Path, 'Any': object}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    with pytest.raises(AttributeError):
        namespace['select']([], None, None, {'checkout': '/source', 'case': None}, None, None)
    assert namespace['select']([], None, None, {'checkout': '/source', 'case': 'PRIMARY-package-TEST'}, None, None) is None


def test_package_archive_entry_binds_case_without_changing_original_guard():
    tree = ast.parse((ROOT / 'primary_package_entry.py').read_bytes())
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'guard.install')
    assert {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords} == {
        'command_class': "'source-checker'", 'case': "manifest['source_case']"}
    assert hashlib.sha256((ROOT / 'finite/runtime_guard.py').read_bytes()).hexdigest() == '475f460e197fa896a7a8ef59ca48f986445e7749ba7efd09137d9cc480f5686e'


def test_installed_public_metadata_contains_hashes_instead_of_private_fixture_ids(monkeypatch):
    import checkpoint_issuer
    import primary_package_probe as probe
    from primary_custody import canonical
    from test_primary_custody import records
    from test_checkpoint_issuer import archives
    data = records(INSTALLED, archives())
    kernel = json.loads(data['kernel-source.json'])
    kernel['primary_plan'].update(package_mode='TEST')
    kernel.update(guard_poison=False, receipt_ledger_poison=[],
                  native_source_records=[{'kind': 'primary_package_installed_corruption',
                                          'corrupt_state_refused': True, 'original_bytes_restored': True}])
    data['kernel-source.json'] = canonical(kernel)
    proof = {'result': {'attempts': 2, 'terminal_reviews': 1, 'restart_resume': True, 'state': 'done',
                        'mission_id': 'private-fixture-mission-canary', 'project_id': 'private-fixture-project-canary'}}
    data['package-proof.json'] = canonical(proof)
    monkeypatch.setattr(checkpoint_issuer, 'observed_return', lambda *a: None)
    result = probe.check_installed(data)
    assert 'private-fixture-' not in json.dumps(result)
    assert result['original_return_sha256'] == hashlib.sha256(canonical(proof)).hexdigest()
