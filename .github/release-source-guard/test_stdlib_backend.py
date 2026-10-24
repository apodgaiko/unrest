"""Closed-domain controls; original product tests and deadlines remain unchanged."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from finite import mock_backend_setup as setup, stdlib_backend as domain

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('case', sorted(setup.INITIALIZATION_CASES | setup.CANCELLATION_CASES | setup.WITNESS_CASES))
@pytest.mark.parametrize('vector_type', [list, tuple])
@pytest.mark.parametrize('change', [None, 'case', 'original-refusal', 'class', 'script'])
def test_translation_follows_unchanged_original_admission(monkeypatch, case, vector_type, change):
    state = {'case': case}
    argv = ['/original/python', '/owned/fake-app-server', '-c', 'sandbox_mode="read-only"', 'app-server']
    environment = {'CODEX_HOME': '/owned/home'}
    original = {'class': domain.ORIGINAL, 'script_sha256': domain.PIN,
                'source_binding': {'path': '/source/session.py', 'line': 506}}
    if change == 'case':
        state['case'] += '-foreign'
    if change == 'class':
        original['class'] = 'foreign'
    if change == 'script':
        original['script_sha256'] = 'foreign'
    calls = []
    def admit(*args):
        calls.append(args)
        assert args[:4] == (argv, '/owned/worker', environment, state)
        return None if change == 'original-refusal' else original
    def support(actual_state, name):
        assert actual_state is state
        if name == 'mock_backend_setup.py':
            return vars(setup)
        assert name == 'backend_postimage_route.py'
        return {'admit': admit}
    monkeypatch.setattr(domain, 'support', support)
    def refuse(reason):
        raise RuntimeError(reason)
    if change in {'class', 'script'}:
        with pytest.raises(RuntimeError, match='original_registration'):
            domain.select(argv, '/owned/worker', environment, state, None, refuse)
    else:
        selected = domain.select(vector_type(argv), '/owned/worker', environment, state, None, refuse)
        if change in {'case', 'original-refusal'}:
            assert selected is None
        else:
            assert selected == ({**original, 'class': domain.CLASS},
                                [argv[0], '-I', '-S', *argv[1:]])
            assert argv == ['/original/python', '/owned/fake-app-server', '-c',
                            'sandbox_mode="read-only"', 'app-server']
    assert len(calls) == (0 if change == 'case' else 1)


RUNNER = r'''
from pathlib import Path
import hashlib,json,os,runpy,sys,types
source=Path(sys.argv[1]); mode=sys.argv[2]; base=source/'.github/release-source-guard/finite'
for name in ('runtime_guard','operation_activation','isolated_inputs','stdlib_backend'):
 p=base/(name+'.py'); m=types.ModuleType(name); m.__file__=str(p); sys.modules[name]=m
 exec(compile(p.read_bytes(),str(p),'exec'),vars(m))
guard=sys.modules['runtime_guard']; domain=sys.modules['stdlib_backend']
root=Path(sys.base_prefix)/'lib/python3.13'
rows=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
      for p in root.rglob('*') if p.is_file() and not p.is_symlink()]
files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in base.glob('*.py')}
payload={'target':str(source/domain.SCRIPT)}
execution={'shared_trees':{str(root):rows}}
p=Path.cwd()/'execution.json';data=json.dumps(execution).encode();p.write_bytes(data)
state={'guard':str(base/'runtime_guard.py'),'guard_sha256':files[str(base/'runtime_guard.py')],
       'direct_support':{'files':files},'activation_spec':{'general_record_not_the_execution_spec':True},
       'isolated_support':{'spec_path':str(p),'spec_sha256':hashlib.sha256(data).hexdigest()},
       'operation_activation':types.SimpleNamespace(spec=execution),
       'endpoint':{'sha256':files[str(base/'endpoint.py')]}}
def refuse(reason):raise RuntimeError(reason)
guard.refuse=refuse
import asyncio,copy,email.parser,encodings.idna,pkgutil,secrets,stringprep,tomllib,unicodedata,urllib.request,zipimport
from multiprocessing import util
assert sys.modules['__mp_main__'] is sys.modules['__main__']
assert sys.flags.isolated and sys.flags.no_site and sys.version_info[:2]==(3,13)
expected=[str(root.parent/'python313.zip'),str(root),str(root/'lib-dynload')]
# Unit controls accept only ordered aliases of the exact three stdlib paths.
# The production native seal still requires exact strings and performs no repair.
if mode=='initial-path':sys.path.append('/foreign')
if mode=='initial-order':sys.path[:]=list(reversed(sys.path))
if mode=='initial-missing':sys.path.pop()
layout={'actual':list(sys.path),'expected':expected,'base_prefix':sys.base_prefix,
        'zip_exists':Path(expected[0]).exists(),'zip_symlink':Path(expected[0]).is_symlink()}
assert [Path(p).resolve() for p in sys.path]==[Path(p).resolve() for p in expected], ('unit_stdlib_path_layout',layout)
assert not layout['zip_exists'] and not layout['zip_symlink'], ('unit_stdlib_zip_present',layout)
sys.path[:]=expected
if sys.platform=='linux':
 # Unit controls do not fabricate the privileged native-startup receipt. Their
 # direct barrier omits the native bootstrap module, which it never loaded.
 state['manifest_path']='unit-no-native-bootstrap'
 original_platform=sys.platform;sys.platform='unit-stdlib-control'
if mode=='execution-spec':state['operation_activation'].spec={}
if mode=='execution-bytes':p.write_bytes(data+b' ')
try:domain.install_barrier(state,guard,payload)
finally:
 if 'original_platform' in globals():sys.platform=original_platform
if mode=='path':sys.path.append('/foreign');exec('pass')
elif mode=='exec':exec('pass')
elif mode=='forged':exec(compile('pass',payload['target'],'exec'),{})
elif mode=='module':sys.modules['json']=types.ModuleType('json');exec('pass')
elif mode=='new-module':
 m=types.ModuleType('foreign');m.__file__=str(root/'json/__init__.py');sys.modules['foreign']=m;exec('pass')
elif mode=='support':
 p=base/'mock_backend_setup.py';exec(compile(p.read_bytes(),str(p),'exec'),{})
elif mode=='import':__import__('fractions')
elif mode=='extension-import':
 assert 'cmath' not in sys.modules
 __import__('cmath')
elif mode=='checked-support':
 p=base/'mock_backend_setup.py';assert guard.checked_source(p,files[str(p)])['BACKEND_PIN']==domain.PIN
 p=base/'custody_ipc.py';assert guard.checked_source(p,files[str(p)])['__file__']==str(p)
 print('checked-support-complete')
else:
 sys.argv=[payload['target'],'app-server']
 runpy.run_path(payload['target'],run_name='__main__')
'''


@pytest.mark.parametrize(('mode', 'expected'), [
    ('original', None), ('checked-support', None),
    ('execution-spec', 'execution_spec_drift'), ('execution-bytes', 'isolated_profile_source_drift'),
    ('path', 'import_path_drift'), ('exec', 'unknown_exec'),
    ('forged', 'payload_dispatch'), ('module', 'new_module'),
    ('new-module', 'new_module'), ('support', 'support_exec'),
    ('import', 'unsealed_import'), ('extension-import', 'unsealed_import'),
])
def test_real_isolated_interpreter_execution_barrier(tmp_path, mode, expected):
    script = tmp_path / 'control.py'
    script.write_text(RUNNER)
    result = subprocess.run([sys.executable, '-I', '-S', str(script), str(ROOT), mode],
                            cwd=tmp_path, env={**os.environ, 'CODEX_HOME': str(tmp_path),
                                              'PYTHONPATH': str(tmp_path / 'forbidden-site')},
                            input='{"id":1,"method":"initialize","params":{}}\n',
                            text=True, capture_output=True, timeout=15)
    if expected is None:
        assert result.returncode == 0, result.stderr
        if mode == 'original':
            assert json.loads(result.stdout)['result'] == {'userAgent': 'synthetic-only'}
            assert not (tmp_path / 'backend-error.json').exists()
        else:
            assert result.stdout.strip() == 'checked-support-complete'
    else:
        assert result.returncode != 0
        assert (expected if expected == 'isolated_profile_source_drift'
                else 'stdlib_backend_' + expected) in result.stderr, result.stderr


def test_original_fixture_bytes_and_no_product_test_change():
    assert hashlib.sha256((ROOT / domain.SCRIPT).read_bytes()).hexdigest() == domain.PIN
    module = ast.parse(Path(domain.__file__).read_bytes())
    shared = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'shared')
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == 'inputs' for node in ast.walk(shared))
    assert 'shared_trees' in ast.unparse(shared) and 'shared_files' in ast.unparse(shared)
    # Ordinary startup retains its independent, complete dependency consumption.
    original = (Path(domain.__file__).with_name('source_activation.py')).read_text()
    assert 'self.state["operations"].inputs()' in original


def test_new_class_requires_exact_flags_and_original_case():
    from test_mock_backend_setup import leaf_context
    state, endpoint, payload = leaf_context(domain.ORIGINAL)
    state['class'] = payload['class'] = domain.CLASS
    state['case'] = payload['case'] = sorted(setup.INITIALIZATION_CASES)[0]
    payload['orig_argv'][1:1] = ['-I', '-S']
    payload['isolated'] = True
    assert setup.eligible(state, endpoint, payload)
    for flags in ([], ['-I'], ['-S'], ['-S', '-I'], ['-I', '-S', '-B']):
        changed = {**payload, 'orig_argv': [payload['orig_argv'][0], *flags, *payload['sys_argv']],
                   'isolated': '-I' in flags}
        assert not setup.eligible(state, endpoint, changed)
    state['case'] = payload['case'] = 'foreign'
    assert not setup.eligible(state, endpoint, payload)


@pytest.mark.parametrize('change', [None, 'case', 'class', 'flags', 'binding'])
def test_native_environment_projection_is_exact_initialization_domain(change):
    from primary_source_inputs import python_environment
    row = {'class': domain.CLASS, 'case': sorted(setup.INITIALIZATION_CASES)[0],
           'source_binding': {'path': '/source/src/unrest_harness/experimental_session.py',
                              'line': 506, 'sha256': setup.SESSION_PIN,
                              'function': '_open_role_owned'}}
    flags = [1, 1, 0]
    if change == 'case':
        row['case'] += '-foreign'
    elif change == 'class':
        row['class'] = 'foreign'
    elif change == 'flags':
        flags = [0, 0, 0]
    elif change == 'binding':
        row['source_binding'] = {**row['source_binding'], 'line': 507}
    environment = {'CODEX_HOME': '/owned/home'}
    assert python_environment(environment, row, flags) == (
        {**environment, 'LC_CTYPE': 'C.UTF-8'} if change is None else environment)


@pytest.mark.parametrize('case', sorted(setup.CANCELLATION_CASES | setup.WITNESS_CASES))
def test_cancellation_and_witness_domains_use_same_exact_backend_setup(case):
    from test_mock_backend_setup import leaf_context
    state, endpoint, payload = leaf_context(domain.ORIGINAL)
    state['class'] = payload['class'] = domain.CLASS
    state['case'] = payload['case'] = case
    payload['orig_argv'][1:1] = ['-I', '-S']
    payload['isolated'] = True
    assert setup.selected_script(state,payload) == (payload['target'], setup.BACKEND_PIN)
    assert setup.eligible(state,endpoint,payload)
    assert setup.INITIALIZATION_CASES.isdisjoint(setup.CANCELLATION_CASES)
    state['case'] = payload['case'] = case + '-foreign'
    assert not setup.eligible(state,endpoint,payload)


@pytest.mark.parametrize('kind', [domain.CLASS, 'source-canonical-stdlib-acp'])
@pytest.mark.parametrize('change', [None, 'token', 'guard', 'manifest', 'registry', 'runtime', 'pid', 'parent'])
def test_new_class_consumes_original_five_second_core_ready_handshake(change, kind):
    from types import SimpleNamespace
    source = (Path(domain.__file__).with_name('runtime_guard.py')).read_bytes()
    tree = ast.parse(source)
    blocks = [node for node in ast.walk(tree) if isinstance(node, ast.If)
              and 'source-canonical-stdlib-backend' in ast.unparse(node.test)
              and 'bounded_controlled_READY_handshake' in ast.unparse(node)]
    assert len(blocks) == 1
    emitted = []
    state = {'events': '/unit/events', 'guard_sha256': 'guard',
             'registry': {'sha256': 'registry'}, 'runtime': {'sha256': 'runtime'}}
    ready = {'kind': 'ready', 'token': 'actual-token', 'class': kind,
             'owner_pid': 123, 'parent_pid': os.getpid(),
             'guard_sha256': 'guard', 'manifest_sha256': 'manifest',
             'registry_sha256': 'registry', 'runtime_sha256': 'runtime'}
    fields = {'token': 'token', 'guard': 'guard_sha256', 'manifest': 'manifest_sha256',
              'registry': 'registry_sha256', 'runtime': 'runtime_sha256',
              'pid': 'owner_pid', 'parent': 'parent_pid'}
    if change is not None:
        ready[fields[change]] = 'foreign'
    class Journal:
        def __truediv__(self, name):
            assert name == '123.jsonl'
            return self
        def exists(self):
            return True
        def read_text(self):
            return json.dumps(ready) + '\n'
    handle = SimpleNamespace(pid=123, poll=lambda: 0, wait=lambda **kw: 0)
    def refuse(reason):
        raise RuntimeError(reason)
    environment = {'registration': {'class': kind, 'python': True},
                   'state': state, 'handle': handle, 'launch_token': 'actual-token',
                   'pin': 'manifest', 'time': SimpleNamespace(monotonic=lambda: 0),
                   'Path': lambda value: Journal(), 'json': json, 'os': os,
                   'append': emitted.append, 'refuse': refuse}
    code = compile(ast.Module(body=[blocks[0]], type_ignores=[]), '/unit/ready-control', 'exec')
    if change is None:
        exec(code, environment)
        assert len(emitted) == 1
        assert emitted[0]['kind'] == 'bounded_controlled_READY_handshake'
        assert emitted[0]['deadline_seconds'] == 5
        assert emitted[0]['original_probe_deadline_changed'] is False
    else:
        with pytest.raises(RuntimeError, match='controlled_startup_not_READY'):
            exec(code, environment)
        assert not emitted


@pytest.mark.parametrize('mode', ['initial-path','initial-order','initial-missing'])
def test_unit_path_normalization_rejects_foreign_order_or_members(tmp_path,mode):
    script=tmp_path/'unit-path-control.py'
    script.write_text(RUNNER)
    result=subprocess.run([sys.executable,'-I','-S',str(script),str(ROOT),mode],
                          cwd=tmp_path,text=True,capture_output=True,timeout=15)
    assert result.returncode != 0 and 'unit_stdlib_path_layout' in result.stderr
