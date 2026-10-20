"""Constructor/custody negatives; the own-identity Linux probe proves integration."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

import child_relative_custody as custody

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('child_relative', ROOT / 'finite/child_relative.py')
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


def test_closed_applicable_inventory_includes_ordinary_routes():
    from finite.registry import COMMANDS
    assert {row['class'] for row in COMMANDS if row['python']} <= boundary.APPLICABLE
    assert 'source-child-relative-probe' in boundary.APPLICABLE
    assert 'unknown' not in boundary.APPLICABLE


@pytest.mark.parametrize('mutation', ['count', 'cwd', 'argv', 'class', 'original', 'transform'])
def test_stopped_child_binding_refuses_before_receipt(monkeypatch, mutation):
    import hashlib
    import json
    vector = ['python', '-c', 'pass']
    pin = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
    facts = {'cwd': '/source', 'identity': [1, 2]}
    row = {'kind': 'child_relative_constructor', 'owner_pid': 11, 'token': 'token',
           'original_cwd': None, 'constructor_cwd': '.', 'class': 'class',
           'argv_sha256': pin, 'parent_view': facts}
    selected = {'owner_pid': 11, 'token': 'token', 'bootstrap_sha256': 'pin',
                'registration': {'class': 'class'}, 'transformed_argv_sha256': pin, 'cwd': '/source'}
    rows = [row]
    if mutation == 'count':
        rows.append(dict(row))
    elif mutation == 'cwd':
        facts = {**facts, 'identity': [1, 3]}
    elif mutation == 'argv':
        vector = [*vector, 'other']
    elif mutation == 'class':
        row['class'] = 'other'
    elif mutation == 'original':
        row['original_cwd'] = '/source'
    else:
        row['constructor_cwd'] = '/source'
    monkeypatch.setattr(custody, 'view', lambda **kwargs: facts)
    poison = []
    authority = SimpleNamespace(bound={22: selected}, supervisor=SimpleNamespace(
        events=lambda: rows, poison=poison.append))
    trace = SimpleNamespace(poison=[])
    with pytest.raises(RuntimeError):
        custody.check(authority, trace, 22, vector)
    assert poison == trace.poison == ['primary_source_child_relative_cwd']


def test_no_constructor_record_retains_original_custody():
    authority = SimpleNamespace(bound={22: {'bootstrap_sha256': 'pin'}},
                                supervisor=SimpleNamespace(events=lambda: []))
    custody.check(authority, None, 22, [])


def test_prebody_extension_precedes_bootstrap_ready():
    source = (ROOT / 'primary_source_entry.py').read_text()
    assert source.index('module.view()') < source.index("if profile['source_role'] == 'source-bootstrap':")
    assert source.index('module.view()') < source.index('endpoint.early(')


def test_stock_constructor_has_no_retry_or_private_execute_child_copy():
    source = (ROOT / 'finite/child_relative.py').read_text()
    assert 'except' not in source[source.index('        # No catch/retry:') :]
    import ast
    assert not any(isinstance(node, ast.FunctionDef) and node.name == '_execute_child'
                   for node in ast.walk(ast.parse(source)))
    assert "'cwd': '.'" in source


def test_install_never_accepts_a_direct_caller(monkeypatch):
    import subprocess
    import sys
    import importlib.util
    spec = importlib.util.spec_from_file_location('runtime_guard', ROOT / 'finite/runtime_guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    state = {'guard': str(ROOT / 'finite/runtime_guard.py')}
    guard._STATE = state
    class Refusal(RuntimeError):
        pass
    def refuse(reason):
        raise Refusal(reason)
    def checked(name):
        return {'view': lambda: None}
    stock = subprocess.Popen.__init__
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, '__init__', stock)
        with pytest.raises(Refusal, match='child_relative_install_context'):
            boundary.install(state, object(), lambda row: None, refuse, checked)


@pytest.mark.skipif(__import__('sys').platform != 'linux', reason='Linux stock fork/exec primitive')
@pytest.mark.parametrize('change', ['before-fork', 'after-fork'])
def test_stock_relative_cwd_follows_child_inheritance(tmp_path, change):
    import json
    import os
    import subprocess
    import sys
    before = len(os.listdir('/proc/self/fd'))
    original = Path.cwd()
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    gate = tmp_path / 'gate'
    child = None
    # Exact own control body; it launches nothing and waits on an owned file.
    code = ('import os,json,sys,time;from pathlib import Path;'
            'gate=Path(sys.argv[1]);deadline=time.monotonic()+5\n'
            'while not gate.exists():\n'
            ' if time.monotonic()>deadline: raise RuntimeError("gate deadline")\n'
            ' time.sleep(.001)\n'
            's=os.stat(".");print(json.dumps([s.st_dev,s.st_ino]),flush=True)')
    try:
        os.chdir(first)
        if change == 'before-fork':
            os.chdir(second)
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', code, str(gate)],
                                 cwd='.', stdout=subprocess.PIPE)
        if change == 'after-fork':
            os.chdir(second)
        gate.touch()
        output, _ = child.communicate(timeout=8)
        assert child.returncode == 0
        expected = (second if change == 'before-fork' else first).stat()
        assert json.loads(output) == [expected.st_dev, expected.st_ino]
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
    finally:
        os.chdir(original)
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait()
            if child.stdout is not None:
                child.stdout.close()
    assert before == len(os.listdir('/proc/self/fd'))


@pytest.mark.skipif(__import__('sys').platform != 'linux', reason='Linux search permission/chdir errno')
def test_stock_relative_cwd_preserves_search_permission_error(tmp_path):
    import errno
    import os
    import subprocess
    import sys
    assert os.geteuid() != 0  # Actual compartment source identity; never root's override.
    before = len(os.listdir('/proc/self/fd'))
    original = Path.cwd()
    directory = tmp_path / 'unsearchable'
    directory.mkdir()
    try:
        os.chdir(directory)
        directory.chmod(0o600)
        with pytest.raises(PermissionError) as caught:
            subprocess.Popen([sys.executable, '-I', '-S', '-c', 'pass'], cwd='.')
        assert caught.value.errno == errno.EACCES and caught.value.filename == '.'
    finally:
        directory.chmod(0o700)
        os.chdir(original)
    assert before == len(os.listdir('/proc/self/fd'))


@pytest.mark.parametrize('mutation', ['token', 'handle', 'argv-object', 'constructor', 'activation',
                                    'registration', 'options', 'explicit-cwd', 'reused',
                                    'preexec_fn', 'user', 'group', 'extra_groups', 'executable', 'shell'])
def test_context_data_mutation_refuses_without_launch_authority(mutation):
    # Pure data checks: no fake core frame, original case, receipt or child.
    handle, constructor = object(), object()
    argv = ['owned-control']
    activation = SimpleNamespace(python_consumed={'token'})
    options = {'cwd': None}
    launch = {'launch_token': 'token', 'registration': {'class': 'source-child-relative-probe',
                                                      'python': True},
              'original_init': constructor, 'handle': handle, 'child_argv': argv,
              'activation': activation, 'kwargs': options}
    used = set()
    if mutation == 'token':
        launch['launch_token'] = 'other'
    elif mutation == 'handle':
        handle = object()
    elif mutation == 'argv-object':
        argv = list(argv)
    elif mutation == 'constructor':
        constructor = object()
    elif mutation == 'activation':
        activation = SimpleNamespace(python_consumed={'token'})
    elif mutation == 'registration':
        launch['registration'] = {'class': 'unknown', 'python': True}
    elif mutation == 'options':
        options = {'cwd': None, 'stdout': -1}
    elif mutation == 'explicit-cwd':
        options['cwd'] = '/source'
    elif mutation == 'reused':
        used.add('token')
    else:
        options[mutation] = True
    refused = []
    def refuse(reason):
        refused.append(reason)
        raise RuntimeError(reason)
    with pytest.raises(RuntimeError):
        boundary.consume(launch, handle, argv, options, activation, constructor, used, refuse)
    assert len(refused) == 1


def test_context_data_is_single_use_without_launch_authority():
    handle, constructor = object(), object()
    argv, options = [], {}
    activation = SimpleNamespace(python_consumed={'token'})
    launch = {'launch_token': 'token', 'registration': {'class': 'source-child-relative-probe',
                                                      'python': True},
              'original_init': constructor, 'handle': handle, 'child_argv': argv,
              'activation': activation, 'kwargs': options}
    def refuse(reason):
        raise RuntimeError(reason)
    used = set()
    assert boundary.consume(launch, handle, argv, options, activation, constructor, used, refuse)[0] == 'token'
    with pytest.raises(RuntimeError, match='reused_context'):
        boundary.consume(launch, handle, argv, options, activation, constructor, used, refuse)


@pytest.mark.parametrize('mutation', ['platform', 'version', 'implementation', 'uids', 'gids',
                                    'stdlib', 'native', 'use_spawn', 'use_vfork', 'runtime'])
def test_runtime_inventory_mutations_are_not_equivalent(mutation):
    actual = boundary.expected_runtime('bound-runtime-pin')
    actual[mutation] = 'drift'
    def refuse(reason):
        raise RuntimeError(reason)
    with pytest.raises(RuntimeError, match='child_relative_runtime'):
        boundary.validate_runtime(actual, 'bound-runtime-pin', refuse)


def test_existing_primary_wrapper_self_reference_is_checked():
    compiled = compile((ROOT / 'primary_operations.py').read_bytes(),
                       '/guard/primary_operations.py', 'exec', dont_inherit=True)
    code = boundary.named(compiled, 'native_init')
    assert set(code.co_freevars) == {'guard', 'initialize', 'native_init', 'original_init',
                                    'require_ready', 'self', 'state'}
    source = (ROOT / 'finite/child_relative.py').read_text()
    assert "cells['native_init'].cell_contents is not captured" in source


@pytest.mark.parametrize('mutation', ['none', 'missing', 'code', 'defaults', 'keyword-defaults', 'globals'])
def test_saved_stock_constructor_metadata(mutation):
    import subprocess
    stock = subprocess.Popen.__init__
    code, defaults, keywords = stock.__code__, stock.__defaults__, stock.__kwdefaults__
    if mutation == 'missing':
        stock = None
    elif mutation == 'code':
        code = test_saved_stock_constructor_metadata.__code__
    elif mutation == 'defaults':
        defaults = ('wrong-default',)
    elif mutation == 'keyword-defaults':
        keywords = {'unknown': True}
    elif mutation == 'globals':
        stock = test_saved_stock_constructor_metadata
    assert boundary.stock_matches(stock, code, defaults, keywords) is (mutation == 'none')
