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
    parent_view = {'cwd': '/source', 'identity': [1, 2], 'mount': {'options': ['ro']},
                   'readonly': True, 'searchable': True}
    facts = {**parent_view, 'searchable': None}
    row = {'kind': 'child_relative_constructor', 'owner_pid': 11, 'token': 'token',
           'original_cwd': None, 'constructor_cwd': '.', 'class': 'class',
           'argv_sha256': pin, 'parent_view': parent_view}
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
    # Exercise the shared predicate without manufacturing a controller receipt,
    # a kernel identity, a core frame or a READY record.
    with pytest.raises(RuntimeError):
        custody.validate(selected, rows[0] if len(rows) == 1 else None, facts, vector)


def test_no_constructor_record_retains_original_custody():
    authority = SimpleNamespace(bound={22: {'bootstrap_sha256': 'pin'}},
                                supervisor=SimpleNamespace(events=lambda: []))
    custody.check(authority, None, 22, [])


def test_prebody_extension_precedes_bootstrap_ready():
    source = (ROOT / 'primary_source_entry.py').read_text()
    assert source.index('actual_view = module.view()') < source.index("if profile['source_role'] == 'source-bootstrap':")
    assert source.index('actual_view = module.view()') < source.index('endpoint.early(')


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
    require_linux_stock()
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
    require_linux_stock()
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
                                    'stdlib', 'native', 'library', 'use_spawn', 'use_vfork', 'runtime'])
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


@pytest.mark.parametrize('mutation', ['none', 'argv', 'cwd', 'environment', 'pin'])
def test_plain_own_probe_uses_its_real_frame(tmp_path, monkeypatch, mutation):
    import hashlib
    import os
    import subprocess
    import sys
    from finite import owner_probe
    checkout = tmp_path / 'own-source'
    source = checkout / '.github/release-source-guard/child_relative_methods.py'
    source.parent.mkdir(parents=True)
    source.write_bytes((ROOT / 'child_relative_methods.py').read_bytes())
    spec = importlib.util.spec_from_file_location('child_relative_methods', source)
    child_relative_methods = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, 'child_relative_methods', child_relative_methods)
    spec.loader.exec_module(child_relative_methods)
    state = {'checkout': str(checkout), 'product_pins': {
        '.github/release-source-guard/child_relative_methods.py': hashlib.sha256(source.read_bytes()).hexdigest()},
        'isolated_named': boundary.named}
    if mutation == 'pin':
        state['product_pins']['.github/release-source-guard/child_relative_methods.py'] = '0' * 64
    class StopProbe(RuntimeError):
        pass
    def refuse(reason):
        raise RuntimeError(reason)
    def consume(argv, **options):
        changed = [*argv, 'drift'] if mutation == 'argv' else argv
        cwd = checkout if mutation == 'cwd' else None
        env = {} if mutation == 'environment' else None
        row = owner_probe.child_relative(changed, cwd, env, state, None, refuse)
        assert mutation == 'none' and row['class'] == 'source-child-relative-probe'
        raise StopProbe()
    monkeypatch.chdir(checkout)
    monkeypatch.setitem(sys.modules, 'runtime_guard', SimpleNamespace(_STATE=state))
    monkeypatch.setattr(subprocess, 'run', consume)
    original_listdir = os.listdir
    monkeypatch.setattr(os, 'listdir', lambda path: [] if path == '/proc/self/fd' else original_listdir(path))
    if mutation == 'none':
        with pytest.raises(StopProbe):
            child_relative_methods.probe()
    else:
        with pytest.raises(RuntimeError, match='child_relative_probe_binding'):
            child_relative_methods.probe()


@pytest.mark.parametrize('mutation', ['none', 'handle', 'registration-id', 'registration-bytes',
                                    'argv-id', 'argv-bytes', 'options', 'option-type', 'environment'])
def test_saved_context_mutations_are_not_rebound(mutation):
    import copy
    import json
    import weakref
    class OwnHandle:
        pass
    handle = OwnHandle()
    registration = {'class': 'source-child-relative-probe', 'python': True}
    argv = ['owned-control']
    env = {'OWN_CONTROL': 'original'}
    options = {'env': env, 'close_fds': True}
    launch = {'registration': registration, 'argv': argv}
    saved = {'handle': weakref.ref(handle), 'value': {
        'registration_id': id(registration), 'registration': json.dumps(registration, sort_keys=True),
        'argv_id': id(argv), 'argv': list(argv), 'options': dict(options),
        'environment': copy.deepcopy(env)}}
    if mutation == 'handle':
        handle = OwnHandle()
    elif mutation == 'registration-id':
        launch['registration'] = dict(registration)
    elif mutation == 'registration-bytes':
        registration['python'] = 1
    elif mutation == 'argv-id':
        launch['argv'] = list(argv)
    elif mutation == 'argv-bytes':
        argv.append('drift')
    elif mutation == 'options':
        options['stdout'] = -1
    elif mutation == 'option-type':
        options['close_fds'] = 1
    elif mutation == 'environment':
        env['OWN_CONTROL'] = 'drift'
    assert boundary.matches_saved(saved, launch, handle, options) is (mutation == 'none')


def require_linux_stock():
    import hashlib
    import subprocess
    import sys
    import _posixsubprocess
    assert sys.version == boundary.VERSION and sys.implementation.name == 'cpython'
    assert subprocess._USE_POSIX_SPAWN and subprocess._USE_VFORK
    assert hashlib.sha256(Path(subprocess.__file__).read_bytes()).hexdigest() == boundary.STDLIB
    assert hashlib.sha256(Path(_posixsubprocess.__file__).read_bytes()).hexdigest() == boundary.NATIVE
    assert hashlib.sha256(Path('/usr/local/lib/libpython3.13.so.1.0').read_bytes()).hexdigest() == boundary.LIBRARY


@pytest.mark.parametrize('mutation', ['none', 'child-search', 'identity', 'mount', 'readonly', 'unknown-field'])
def test_search_is_attested_by_child_against_stopped_object(mutation):
    from finite.child_relative_view import child_matches
    stopped = {'cwd': '/source', 'identity': [1, 2], 'mount': {'options': ['ro']},
               'readonly': True, 'searchable': None}
    actual = {**stopped, 'searchable': True}
    if mutation == 'child-search':
        actual['searchable'] = False
    elif mutation == 'identity':
        actual['identity'] = [1, 3]
    elif mutation == 'mount':
        actual['mount'] = {'options': ['rw']}
    elif mutation == 'readonly':
        actual['readonly'] = False
    elif mutation == 'unknown-field':
        actual['unknown'] = True
    assert child_matches(actual, stopped) is (mutation == 'none')


def test_outer_predicate_requires_parent_search_and_pending_child_search():
    import hashlib
    import json
    vector = ['owned-control']
    pin = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
    parent = {'cwd': '/source', 'identity': [1, 2], 'mount': {'options': ['ro']},
              'readonly': True, 'searchable': True}
    actual = {**parent, 'searchable': None}
    selected = {'registration': {'class': 'source-child-relative-probe'},
                'transformed_argv_sha256': pin, 'cwd': '/source'}
    row = {'original_cwd': None, 'constructor_cwd': '.', 'class': 'source-child-relative-probe',
           'argv_sha256': pin, 'parent_view': parent}
    custody.validate(selected, row, actual, vector)
    for target in (parent, actual):
        previous = target['searchable']
        target['searchable'] = False
        with pytest.raises(RuntimeError):
            custody.validate(selected, row, actual, vector)
        target['searchable'] = previous
