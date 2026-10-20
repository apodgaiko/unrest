"""Exercise real import/CLI/checker frames with the OS Git call intercepted."""
import ast
import hashlib
import importlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types
from contextlib import redirect_stdout

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = Path(__file__).with_name('finite')
spec = importlib.util.spec_from_file_location('repository_probe_git_control', SUPPORT / 'repository_probe_git.py')
route = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route)
frames_spec = importlib.util.spec_from_file_location('repository_probe_frames', SUPPORT / 'fallback_binding.py')
stack = importlib.util.module_from_spec(frames_spec)
frames_spec.loader.exec_module(stack)


def named(code, name):
    if code.co_name == name:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType) and (result := named(value, name)) is not None:
            return result
    return None


@pytest.mark.parametrize('mutation', ['none', 'class', 'phase', 'token', 'payload-token', 'payload-case',
    'payload-class', 'mode', 'isolated', 'path0', 'binding', 'literal', 'original-argv', 'sys-argv',
    'code', 'globals', 'vector', 'repository', 'cwd', 'environment', 'git-redirect', 'native-git-redirect', 'image',
    'source', 'checker-binding', 'cli-binding', 'missing-checker', 'missing-payload', 'loader'])
def test_original_inline_positive_control_needs_the_complete_read_only_join(tmp_path, monkeypatch, mutation):
    for key in list(__import__('os').environ):
        if key.startswith('GIT_'):
            monkeypatch.delenv(key)
    monkeypatch.setenv('UNREST_HOME', str(tmp_path / 'home'))
    monkeypatch.setenv('UNREST_PROJECTS_DIR', str(tmp_path / 'projects'))
    monkeypatch.chdir(ROOT)
    cli = importlib.import_module('unrest_harness.cli')
    product = importlib.import_module('unrest_harness.repository_contract')
    source = ROOT / 'tests/test_repository_contract.py'
    owner = next(node for node in ast.parse(source.read_bytes()).body
                 if isinstance(node, ast.FunctionDef) and node.name == '_import_probe')
    body = ast.literal_eval(next(node.value for node in owner.body if isinstance(node, ast.Assign)
         and any(isinstance(target, ast.Name) and target.id == 'script' for target in node.targets)))
    code = compile(body, '<string>', 'exec', dont_inherit=True)
    namespace = {'__name__': '__main__', '__package__': None, '__spec__': None}
    case = 'tests/test_repository_contract.py::test_repository_command_is_the_lazy_positive_control'
    payload = {'token': 'owned-probe', 'class': route.KIND, 'case': case, 'mode': 'inline',
        'isolated': False, 'path0': '', 'target': body,
        'orig_argv': [sys.executable, '-c', body, '[]', '["check-repository"]'],
        'sys_argv': ['-c', '[]', '["check-repository"]'],
        'source_binding': {'path': str(source), 'line': 518, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}}
    executable = shutil.which('git')
    assert executable is not None
    pins = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        'tests/test_repository_contract.py', 'src/unrest_harness/repository_contract.py', 'src/unrest_harness/cli.py')}
    state = {'checkout': str(ROOT), 'class': route.KIND, 'phase': 'READY', 'token': 'owned-probe',
        'case': case, 'product_pins': pins, 'registered_payload': payload,
        'payload_code': code, 'payload_globals': namespace, 'isolated_named': named,
        'copy_git': {executable: hashlib.sha256(Path(executable).read_bytes()).hexdigest()}}
    ready, events, results, returns = [], [], [], []
    guard = types.SimpleNamespace(_STATE=state, require_ready=ready.append, inherited_environment=lambda: dict(os.environ))
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.setattr(sys, 'argv', list(payload['sys_argv']))
    monkeypatch.setattr(sys, 'path', ['', *sys.path])
    before = list(sys.meta_path)
    def native_intercept(argv, **kwargs):
        assert argv == ['git', '-C', str(ROOT), 'rev-parse', '--show-toplevel']
        cwd, env = kwargs.get('cwd'), kwargs.get('env')
        frames = stack.active_frames()
        if mutation in {'class', 'phase', 'token'}:
            state[mutation] = 'foreign'
        elif mutation.startswith('payload-'):
            payload[mutation.removeprefix('payload-')] = 'foreign'
        elif mutation in {'mode', 'isolated', 'path0'}:
            payload[mutation] = 'foreign'
        elif mutation == 'binding':
            payload['source_binding'] = {}
        elif mutation == 'literal':
            payload['target'] = 'pass'
        elif mutation == 'original-argv':
            payload['orig_argv'][-1] = '["--help"]'
        elif mutation == 'sys-argv':
            payload['sys_argv'] = []
        elif mutation == 'code':
            state['payload_code'] = compile('pass', '<string>', 'exec')
        elif mutation == 'globals':
            state['payload_globals'] = dict(namespace)
        elif mutation == 'vector':
            argv = ['git', 'status']
        elif mutation == 'repository':
            argv = ['git', '-C', str(tmp_path), 'rev-parse', '--show-toplevel']
        elif mutation == 'cwd':
            cwd = ROOT
        elif mutation == 'environment':
            env = {}
        elif mutation == 'git-redirect':
            monkeypatch.setenv('GIT_DIR', str(tmp_path / 'foreign'))
        elif mutation == 'native-git-redirect':
            guard.inherited_environment = lambda: {**dict(os.environ), 'GIT_DIR': 'foreign'}
        elif mutation == 'image':
            state['copy_git'][executable] = '0' * 64
        elif mutation == 'source':
            pins['src/unrest_harness/repository_contract.py'] = '0' * 64
        elif mutation == 'checker-binding':
            monkeypatch.setattr(product, 'find_repository_root', lambda _: ROOT)
        elif mutation == 'cli-binding':
            monkeypatch.setattr(cli.check_repository_cmd, 'callback', lambda: None)
        elif mutation == 'missing-checker':
            frames = [f for f in frames if f.f_code.co_name != 'find_repository_root']
        elif mutation == 'missing-payload':
            frames = [f for f in frames if f.f_code is not code]
        elif mutation == 'loader':
            monkeypatch.setattr(product, '__loader__', None)
        def trace(frame, event, value):
            if frame.f_code is route.admit.__code__ and event == 'return':
                returns.append(frame.f_lineno)
            return trace
        previous_trace = sys.gettrace()
        sys.settrace(trace)
        try:
            results.append(route.admit(argv, cwd, env, state, events.append, lambda r: None, frames))
        finally:
            sys.settrace(previous_trace)
        return subprocess.CompletedProcess(argv, 0, str(ROOT) + '\n', '')
    monkeypatch.setattr(subprocess, 'run', native_intercept)
    try:
        with redirect_stdout(io.StringIO()):
            exec(code, namespace)
    finally:
        sys.meta_path[:] = before
    assert len(results) == 1
    assert bool(results[0]) is (mutation == 'none'), returns
    if results[0]:
        assert results[0]['class'] == 'source-original-import-probe-git'
        assert len(events) == 1 and ready == ['owned-probe']


@pytest.mark.parametrize('existing_refusal', [False, True])
def test_probe_support_errors_keep_the_original_sticky_refusal(monkeypatch, existing_refusal):
    import runpy
    source_git = runpy.run_path(str(SUPPORT / 'source_git.py'))
    class Refusal(RuntimeError):
        pass
    error = Refusal('original-poison') if existing_refusal else ValueError('private-body')
    def checked(*args):
        raise error
    guard = types.SimpleNamespace(GuardRefusal=Refusal, checked_source=checked)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    state = {'checkout': str(ROOT), 'class': route.KIND, 'guard': str(SUPPORT / 'runtime_guard.py'),
             'direct_support': {'files': {str(SUPPORT / 'repository_probe_git.py'): 'bound-pin'}}}
    poisoned = []
    def refuse(reason):
        poisoned.append(reason)
        raise Refusal(reason)
    with pytest.raises(Refusal) as caught:
        source_git['admit'](['git'], None, None, state, lambda event: None, refuse)
    if existing_refusal:
        assert caught.value is error and poisoned == []
    else:
        assert poisoned == ['original_import_probe_git_binding_error']
        assert 'private-body' not in str(caught.value)
