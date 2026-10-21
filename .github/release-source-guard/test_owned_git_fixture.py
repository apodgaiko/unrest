"""Bound repository-only setup, original native Git argv/environment preserved."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

import pytest

from finite import owned_git_fixture as helper


def named(code, name):
    for value in code.co_consts:
        if type(value) is types.CodeType:
            if value.co_name == name:
                return value
            found = named(value, name)
            if found is not None:
                return found
    return None


@pytest.fixture
def model(tmp_path, monkeypatch):
    source_body = (Path(__file__).resolve().parents[2] / helper.SOURCE).read_bytes()
    assert hashlib.sha256(source_body).hexdigest() == helper.PIN
    virtual = '/source/' + helper.SOURCE
    class Paths(type(Path())):
        def read_bytes(self):
            return source_body if str(self) == virtual else super().read_bytes()
    monkeypatch.setattr(helper, 'Path', Paths)
    root = tmp_path / 'owned'
    workspace = root / 'workspace'
    (workspace / '.git').mkdir(parents=True)
    target = workspace / '.git/config'
    target.write_bytes(b'[core]\n\trepositoryformatversion = 0\n\tbare = false\n')
    code = compile(source_body, virtual, 'exec', dont_inherit=True)
    module = types.ModuleType('owned_git_fixture_control')
    function = types.FunctionType(named(code, helper.OWNER), vars(module))
    setattr(module, helper.OWNER, function)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    environment = {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    frame = types.SimpleNamespace(f_code=function.__code__, f_globals=vars(module), f_lineno=214,
        f_locals={'mode': 'worker', 'git_args': tuple(helper.COMMAND[1:]), 'workspace': workspace,
                  'git_environment': environment, 'git_process': types.SimpleNamespace(pid=123, returncode=0)})
    state = {'case': helper.CASE, 'class': 'pytest-root', 'token': 'root', 'checkout': '/source',
             'owned_root': str(root), 'product_pins': {helper.SOURCE: helper.PIN},
             'isolated_named': named, 'isolated_source_code': lambda path: code}
    events = []
    def refuse(reason):
        raise RuntimeError(reason)
    def configure():
        return helper.configure(frame, list(helper.COMMAND), workspace, environment, state, events.append, refuse)
    return types.SimpleNamespace(target=target, workspace=workspace, frame=frame, state=state,
                                 environment=environment, events=events, configure=configure)


def test_owned_config_setup_is_idempotent_and_preserves_existing_bytes_mode_and_inputs(model):
    m = model
    before = m.target.read_bytes()
    mode = stat.S_IMODE(m.target.stat().st_mode)
    environment = dict(m.environment)
    m.configure()
    assert m.target.read_bytes() == before + helper.SUFFIX
    assert stat.S_IMODE(m.target.stat().st_mode) == mode and m.environment == environment
    m.configure()
    assert len(m.events) == 1 and m.events[0]['native_launch_permission_added'] is False
    m.target.write_bytes(m.target.read_bytes() + b'# foreign\n')
    with pytest.raises(RuntimeError, match='config_drift'):
        m.configure()


@pytest.mark.parametrize('change', ['case', 'code', 'line', 'mode', 'argv', 'environment',
                                   'root', 'source', 'failed-init', 'boolean-init', 'symlink', 'hardlink'])
def test_foreign_context_and_unsafe_files_refuse_before_configuration_write(model, change):
    m = model
    before = m.target.read_bytes()
    if change == 'case':
        m.state['case'] = 'foreign'
    elif change == 'code':
        m.frame.f_code = compile('pass', '/foreign', 'exec')
    elif change == 'line':
        m.frame.f_lineno = 220
    elif change == 'mode':
        m.frame.f_locals['mode'] = 'terminal-reviewer'
    elif change == 'argv':
        m.frame.f_locals['git_args'] = ('status',)
    elif change == 'environment':
        m.environment['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif change == 'root':
        m.state['owned_root'] = str(m.workspace / 'other')
    elif change == 'source':
        m.state['product_pins'][helper.SOURCE] = 'foreign'
    elif change.endswith('init'):
        m.frame.f_locals['git_process'].returncode = False if change == 'boolean-init' else 1
    elif change == 'symlink':
        other = m.workspace / 'outside-config'
        m.target.rename(other)
        m.target.symlink_to(other)
    else:
        os.link(m.target, m.workspace / 'alias-config')
    with pytest.raises(RuntimeError):
        m.configure()
    assert m.target.read_bytes() == before and m.events == []


def test_actual_empty_commit_with_global_config_disabled_has_no_maintenance_child(model):
    m = model
    # This is an isolated ordinary Git control; it does not launch a provider.
    m.target.unlink()
    (m.workspace / '.git').rmdir()
    environment = {'PATH': os.environ['PATH'], 'HOME': str(m.workspace.parent),
        'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TRACE': '1',
        'GIT_AUTHOR_DATE': '2000-01-01T00:00:00+00:00', 'GIT_AUTHOR_NAME': 'Test',
        'GIT_AUTHOR_EMAIL': 'test@example.invalid', 'GIT_COMMITTER_DATE': '2000-01-01T00:00:00+00:00',
        'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
    m.environment.clear()
    m.environment.update(environment)
    initialized = subprocess.run(['git', 'init', '--quiet', '--initial-branch=main'],
                                 cwd=m.workspace, env=environment, capture_output=True, check=True)
    assert initialized.returncode == 0
    m.configure()
    result = subprocess.run(helper.COMMAND, cwd=m.workspace, env=environment, capture_output=True, check=True)
    assert b'maintenance run --auto' not in result.stderr and b'gc --auto' not in result.stderr
    assert m.events[0]['argv_environment_unchanged'] is True
