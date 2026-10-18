"""Exact original literal-UV source operation and actual CPython executable choice."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path, PosixPath
from types import ModuleType, SimpleNamespace
import subprocess
import sys

import pytest

ROOT = Path(__file__).parent


@pytest.fixture
def route(tmp_path):
    source = tmp_path / 'test_distribution_check.py'
    source.write_bytes(b'def built_distribution(): pass\n')
    native = tmp_path / 'pinned-bin/uv'
    native.parent.mkdir()
    native.write_bytes(b'synthetic immutable UV image')
    native.chmod(0o555)
    first = tmp_path / 'venv-bin'
    first.mkdir()
    flags = {'readonly': True, 'uid': 0}
    def info(path, **kwargs):
        value = os.stat(path, **kwargs)
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        if os.fspath(path) == str(native):
            fields.update(st_uid=flags['uid'], st_gid=0)
        return SimpleNamespace(**fields)
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in (
        'open', 'close', 'fstat', 'fdopen', 'getpid', 'O_RDONLY', 'O_NOFOLLOW', 'ST_RDONLY')})
    proxy.stat = info
    proxy.statvfs = lambda path: SimpleNamespace(f_flag=os.ST_RDONLY if flags['readonly'] else 0)
    # Model only image-selection properties for writable metadata fixtures.
    # The Linux positive below uses the real immutable UV image and real which.
    def fixture_which(command, path):
        if command != 'uv':
            return None
        return next((str(candidate) for directory in path.split(os.pathsep)
                     if (candidate := Path(directory) / command).is_file()
                     and candidate.stat().st_mode & 0o111), None)
    namespace = {'Path': Path, 'PosixPath': PosixPath, 'hashlib': hashlib, 'json': json,
                 'os': proxy, 'shutil': SimpleNamespace(which=fixture_which), 'stat': __import__('stat'),
                 '_UV_NATIVE': str(native), '_CHECKER_SOURCE': str(source),
                 'sha': lambda body: hashlib.sha256(body).hexdigest()}
    namespace['hashed'] = lambda value: namespace['sha'](json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    legacy = ast.parse((ROOT / 'finite/source_operations.py').read_bytes())
    identity = next(node for node in legacy.body if isinstance(node, ast.FunctionDef) and node.name == 'identity')
    exec(compile(ast.Module(body=[identity], type_ignores=[]), '<legacy-identity>', 'exec'), namespace)
    original_class = next(node for node in legacy.body if isinstance(node, ast.ClassDef) and node.name == 'Operations')
    tool = next(node for node in original_class.body if isinstance(node, ast.FunctionDef) and node.name == 'tool')
    base = ast.ClassDef(name='Legacy', bases=[], keywords=[], body=[tool], decorator_list=[])
    exec(compile(ast.fix_missing_locations(ast.Module(body=[base], type_ignores=[])), '<legacy-tool>', 'exec'), namespace)
    namespace['_LegacyOperations'] = namespace['Legacy']
    cls = next(node for node in ast.parse((ROOT / 'primary_operations.py').read_bytes()).body if isinstance(node, ast.ClassDef))
    exec(compile(ast.Module(body=[cls], type_ignores=[]), '<primary-operation>', 'exec'), namespace)
    operation = object.__new__(namespace['Operations'])
    operation.refuse = lambda code: (_ for _ in ()).throw(RuntimeError(code))
    emitted = []
    operation.emit = emitted.append
    environment = {'PATH': str(first) + ':' + str(native.parent)}
    argv = ['uv', 'build', '--out-dir', '/work/owned/dist']
    origin = namespace['identity'](source)
    binding = {'path': str(source), 'function': 'built_distribution', 'sha256': origin['sha256']}
    record = {'kind': 'operation_admission', 'operation': 'source-build', 'token': 'original-token',
              'binding': binding, 'owner_pid': os.getpid(), 'argv_sha256': namespace['sha'](json.dumps(argv).encode()),
              'cwd': '/source', 'environment_sha256': namespace['hashed'](environment), 'output': argv[3],
              'native_profile': {'argv': list(argv), 'environment': dict(environment), 'cwd': '/source',
                                 'source_binding': copy.deepcopy(binding)}}
    operation.pending = {'original-token': {'record': record}}
    operation.spec = {'uv': namespace['identity'](native), 'files': [origin], 'primary_dependency': {'observer': 'pinned'},
                      'backend_distribution': {'immutable_fixture': 'sealed'}}
    registration = {'class': 'source-build', 'python': False, 'source_binding': copy.deepcopy(binding),
                    'operation_token': 'original-token'}
    return SimpleNamespace(operation=operation, registration=registration, argv=argv, environment=environment,
                           native=native, first=first, source=source, record=record, flags=flags, emitted=emitted,
                           namespace=namespace)


@pytest.mark.parametrize('change', ['none', 'token', 'role', 'binding', 'source_hash', 'source_bytes', 'owner',
                                     'argv', 'environment', 'cwd', 'missing_dependency', 'missing_profile',
                                     'missing_backend', 'missing_image', 'foreign_PATH_image', 'image_bytes', 'writable', 'image_uid', 'wrong_mode', 'hardlink', 'symlink'])
def test_only_original_immutable_uv_operation_selects_an_executable(route, change):
    f = route
    cwd = '/source'
    if change == 'token':
        f.registration['operation_token'] = 'unknown'
    elif change == 'role':
        f.record['operation'] = 'source-install'
    elif change == 'binding':
        f.record['binding']['function'] = 'foreign'
    elif change == 'source_hash':
        f.record['binding']['sha256'] = 'f' * 64
        f.registration['source_binding']['sha256'] = 'f' * 64
        f.record['native_profile']['source_binding']['sha256'] = 'f' * 64
    elif change == 'source_bytes':
        f.source.write_bytes(b'foreign source')
    elif change == 'owner':
        f.record['owner_pid'] += 1
    elif change == 'argv':
        f.argv[-1] = '/foreign'
    elif change == 'environment':
        f.environment['FOREIGN'] = 'value'
    elif change == 'cwd':
        cwd = '/foreign'
    elif change == 'missing_dependency':
        f.operation.spec.pop('primary_dependency')
    elif change == 'missing_backend':
        f.operation.spec.pop('backend_distribution')
    elif change == 'missing_profile':
        f.record.pop('native_profile')
    elif change == 'foreign_PATH_image':
        other = f.first / 'uv'
        other.write_bytes(b'foreign image')
        other.chmod(0o755)
    elif change == 'missing_image':
        f.native.unlink()
    elif change == 'image_bytes':
        f.native.chmod(0o755)
        f.native.write_bytes(b'foreign image')
        f.native.chmod(0o555)
    elif change == 'writable':
        f.flags['readonly'] = False
    elif change == 'wrong_mode':
        f.native.chmod(0o755)
    elif change == 'image_uid':
        f.flags['uid'] = 1
    elif change == 'hardlink':
        os.link(f.native, f.native.parent / 'alias')
    elif change == 'symlink':
        f.native.rename(f.native.parent / 'actual')
        f.native.symlink_to('actual')
    before = list(f.argv)
    if change == 'none':
        assert f.operation.native_executable(f.registration, f.argv, cwd, f.environment) == str(f.native)
        assert f.argv == before and len(f.emitted) == 1 and f.emitted[0]['arguments_preserved'] is True
    else:
        with pytest.raises(RuntimeError):
            f.operation.native_executable(f.registration, f.argv, cwd, f.environment)
        assert not f.emitted


def test_other_operations_and_absolute_calls_get_no_route(route):
    for registration, argv in [({'class': 'foreign'}, ['uv']),
                               ({'class': 'source-install'}, ['uv', 'pip']),
                               ({'class': 'source-build'}, [str(route.native), 'build']),
                               ({'class': 'source-build'}, [])]:
        assert route.operation.native_executable(registration, argv, '/source', route.environment) is None
    assert not route.emitted


def test_actual_cpython_uses_one_selected_image_without_changing_arguments(route, monkeypatch):
    captured = []
    def stop(*args, **kwargs):
        captured.append((list(args[0]), list(args[1])))
        raise OSError('synthetic_stop_before_fork')
    monkeypatch.setattr(subprocess, '_fork_exec', stop)
    with pytest.raises(OSError, match='synthetic_stop_before_fork'):
        subprocess.Popen(route.argv, env=route.environment, cwd=route.source.parent)
    selected = route.operation.native_executable(route.registration, route.argv, '/source', route.environment)
    with pytest.raises(OSError, match='synthetic_stop_before_fork'):
        subprocess.Popen(route.argv, env=route.environment, cwd=route.source.parent, executable=selected)
    assert captured[0][0] == captured[1][0] == route.argv
    assert captured[0][1][0] == os.fsencode(route.first / 'uv')
    assert captured[1][1] == [os.fsencode(route.native)]


@pytest.mark.parametrize('change', ['missing_guard', 'wrong_state', 'ready', 'foreign_caller', 'guard_drift'])
def test_route_constructor_cannot_be_installed_by_a_source_caller(route, monkeypatch, change):
    namespace = route.namespace
    def legacy_init(self, state, emit, refuse, ready):
        self.state, self.emit, self.refuse, self.ready = state, emit, refuse, ready
    monkeypatch.setattr(namespace['Legacy'], '__init__', legacy_init)
    state = {'phase': 'INSTALLING', 'guard': str(ROOT / 'finite/runtime_guard.py')}
    guard = ModuleType('synthetic_guard')
    guard._STATE = state
    guard.install = lambda: None
    if change == 'missing_guard':
        monkeypatch.delitem(sys.modules, 'runtime_guard', raising=False)
    else:
        monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    if change == 'wrong_state':
        guard._STATE = {}
    elif change == 'ready':
        state['phase'] = 'READY'
    elif change == 'guard_drift':
        state['guard'] = str(route.source)
    namespace['sys'], namespace['types'], namespace['subprocess'] = sys, __import__('types'), subprocess
    before = subprocess.Popen.__init__
    with pytest.raises(RuntimeError, match='primary_native_route_'):
        namespace['Operations'](state, route.emitted.append, route.operation.refuse, lambda token: None)
    assert subprocess.Popen.__init__ is before


@pytest.mark.parametrize('change', ['none', 'direct', 'foreign_namespace', 'wrong_state', 'explicit_override'])
def test_captured_constructor_requires_the_admitted_guard_frame_and_preserves_argv(route, monkeypatch, change):
    tree = ast.parse((ROOT / 'primary_operations.py').read_bytes())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    constructor = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
    wrapper = next(node for node in constructor.body if isinstance(node, ast.FunctionDef) and node.name == 'native_init')
    guard = ModuleType('synthetic_guard')
    exec("def invoke(handle, argv, registration, cwd, env, callback, override=None):\n"
         "    original_init = callback\n"
         "    child_argv = argv\n"
         "    return original_init(handle, child_argv, cwd=cwd, env=env, executable=override)\n", guard.__dict__)
    state = {'token': 'fixture-token', 'operations': route.operation}
    guard._STATE = state
    ready, captured = [], []
    def stopped(*args, **kwargs):
        captured.append((list(args[0]), list(args[1])))
        raise OSError('synthetic_stop_before_fork')
    monkeypatch.setattr(subprocess, '_fork_exec', stopped)
    namespace = {'guard': guard, 'initialize': guard.invoke.__code__, 'state': state, 'self': route.operation,
                 'require_ready': ready.append, 'original_init': subprocess.Popen.__init__, 'sys': sys}
    exec(compile(ast.Module(body=[wrapper], type_ignores=[]), '<production-constructor-adapter>', 'exec'), namespace)
    callback = namespace['native_init']
    if change == 'direct':
        with pytest.raises(RuntimeError, match='primary_native_route_launch_caller'):
            callback(object(), route.argv, env=route.environment, cwd='/source')
    else:
        invoke = guard.invoke
        if change == 'foreign_namespace':
            foreign = {}
            exec(compile(ast.parse("def invoke(handle, argv, registration, cwd, env, callback, override=None):\n"
                                   "    original_init = callback\n"
                                   "    child_argv = argv\n"
                                   "    return original_init(handle, child_argv, cwd=cwd, env=env, executable=override)\n"),
                         '<foreign>', 'exec'), foreign)
            invoke = foreign['invoke']
        elif change == 'wrong_state':
            guard._STATE = {}
        if change == 'none':
            # Use an actual uninitialized Popen object; the real stdlib constructor
            # reaches the intercepted fork with one image and original arguments.
            handle = object.__new__(subprocess.Popen)
            with pytest.raises(OSError, match='synthetic_stop_before_fork'):
                invoke(handle, route.argv, route.registration, '/source', route.environment, callback)
            assert captured == [(route.argv, [os.fsencode(route.native)])]
            assert ready == ['fixture-token']
        else:
            with pytest.raises(RuntimeError, match='primary_native_route_launch_caller'):
                invoke(object(), route.argv, route.registration, '/source', route.environment, callback,
                       override='/foreign' if change == 'explicit_override' else None)
    if change != 'none':
        assert not captured and not ready
