"""Closed source-home defaults suppress incidental Git children, not tests."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from producer_setup import SOURCE_GITCONFIG, source_git_setup


def plan():
    return {'source_mode': 'SOURCE', 'duty': 'v0.4.7 source suite',
            'commands': [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']]}


def test_only_new_full_source_home_receives_the_exact_readonly_config(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    source_git_setup(home, plan())
    config = home / '.gitconfig'
    assert config.read_bytes() == SOURCE_GITCONFIG
    assert config.stat().st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        source_git_setup(home, plan())
    assert config.read_bytes() == SOURCE_GITCONFIG


@pytest.mark.parametrize('mode', [None, 'TEST-positive', 'TEST-poison', 'package', 'foreign'])
def test_other_capsules_are_unchanged(tmp_path, mode):
    home = tmp_path / 'home'
    home.mkdir()
    source_git_setup(home, {**plan(), 'source_mode': mode})
    assert list(home.iterdir()) == []


@pytest.mark.parametrize('change', ['duty', 'commands', 'symlink', 'existing-file', 'existing-link'])
def test_drift_or_existing_home_data_is_not_overwritten(tmp_path, change):
    home = tmp_path / 'home'
    home.mkdir()
    selected = plan()
    if change in {'duty', 'commands'}:
        selected[change] = 'foreign'
    elif change == 'symlink':
        home.rename(tmp_path / 'target')
        home.symlink_to(tmp_path / 'target', target_is_directory=True)
    elif change == 'existing-file':
        (home / '.gitconfig').write_text('retained user data')
    else:
        (home / '.gitconfig').symlink_to(tmp_path / 'absent')
    with pytest.raises((RuntimeError, FileExistsError)):
        source_git_setup(home, selected)
    if change == 'existing-file':
        assert (home / '.gitconfig').read_text() == 'retained user data'
    assert not (tmp_path / 'absent').exists()


def test_actual_original_empty_commit_has_no_automatic_maintenance_child(tmp_path):
    git = shutil.which('git')
    assert git is not None
    home, workspace = tmp_path / 'home', tmp_path / 'workspace'
    home.mkdir()
    workspace.mkdir()
    source_git_setup(home, plan())
    environment = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TRACE': '1'}
    def run(*args):
        return subprocess.run([git, *args], cwd=workspace, env=environment,
                              capture_output=True, check=True, timeout=10)
    run('init', '-q')
    result = run('-c', 'user.name=Controlled', '-c', 'user.email=controlled@example.invalid',
                 'commit', '--allow-empty', '-qm', 'Controlled')
    assert b'built-in: git commit' in result.stderr
    assert b'maintenance run --auto' not in result.stderr and b'gc --auto' not in result.stderr
    assert run('log', '-1', '--format=%an <%ae>%n%s').stdout == b'Controlled <controlled@example.invalid>\nControlled\n'
    assert run('status', '--porcelain').stdout == b''
    assert run('config', '--global', '--get', 'maintenance.auto').stdout == b'false\n'
    assert run('config', '--global', '--get', 'gc.auto').stdout == b'0\n'


def test_setup_is_wired_to_the_real_primary_child_before_body_execution():
    import ast
    root = Path(__file__).parent
    producer = ast.parse((root / 'producer_setup.py').read_bytes())
    setup = next(n for n in producer.body if isinstance(n, ast.FunctionDef) and n.name == 'source_child_setup')
    branch = next(n for n in setup.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'primary')
    assert ast.unparse(branch.body[0]) == "source_git_setup(Path('/work/home'), json.loads(Path('/inputs/plan.json').read_bytes()))"
    assert isinstance(branch.body[1], ast.Return)
    controls = ast.parse((root / 'compartment_probe.py').read_bytes())
    assert sum(isinstance(n, ast.Constant) and n.value == '/guard/test_source_git_setup.py'
               for n in ast.walk(controls)) == 1
