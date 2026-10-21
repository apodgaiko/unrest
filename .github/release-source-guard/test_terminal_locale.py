"""Actual admitted-event shape and consumed-exec locale binding controls."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from finite.registry import COMMANDS
from primary_policy import PYTHON
import primary_source_inputs as inputs

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    command = deepcopy(next(row for row in COMMANDS
                             if row['class'] == 'reference-descendant:terminal-redaction'))
    source = ROOT / 'tests/test_capability_policy.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == command['source_binding']['sha256']
    owner = next(node for node in ast.parse(source.read_bytes()).body
                 if isinstance(node, ast.AsyncFunctionDef)
                 and node.name == 'test_raw_acp_terminal_protocol_redacts_credential_values')
    secret = next(ast.literal_eval(node.value) for node in owner.body
                  if isinstance(node, ast.Assign) and any(
                      isinstance(target, ast.Name) and target.id == 'secret' for target in node.targets))
    environment = {'PATH': '/source/.venv/bin:/usr/bin:/bin', 'ZAI_API_KEY': secret}
    vector = ['/source/.venv/bin/python', '-c', 'exact-consumed-bootstrap']
    def sha(value):
        return hashlib.sha256(value).hexdigest()
    registration = {'kind': 'admitted', 'class': command['class'],
                    'source_binding': command['source_binding'], 'owner_pid': 20, 'parent_pid': 8,
                    'token': 'a' * 32, 'case': 'original-frozen-case',
                    'argv_sha256': sha(json.dumps([vector[0], *command['argv']]).encode())}
    selected = {'registration': registration, 'owner_pid': 20, 'parent_pid': 8,
                'token': registration['token'], 'case': registration['case'], 'cwd': '/work/owned/tmp/test-redaction/workspace',
                'transformed_argv_sha256': sha(json.dumps(vector).encode()),
                'bootstrap_sha256': sha(vector[2].encode()),
                'environment_sha256': sha(json.dumps(environment, sort_keys=True).encode())}
    context = {'selected': selected, 'parent': 20, 'cwd': selected['cwd'], 'vector': vector,
               'manifest': {'checkout': '/source', 'owned_root': '/work/owned',
                            'runtime': {'realpath': PYTHON, 'paths': [vector[0]]},
                            'product_pins': {'tests/test_capability_policy.py':
                                             command['source_binding']['sha256']}}}
    return registration, environment, context


def test_actual_profile_producer_event_is_consumed_without_mutation(monkeypatch):
    registration, environment, context = fixture()
    before = deepcopy((registration, environment, context))
    monkeypatch.setattr(inputs, 'lease_profile_context', lambda e, r, f: context)
    assert inputs.python_environment(environment, registration, [0, 0, 0]) == {
        **environment, 'LC_CTYPE': 'C.UTF-8'}
    assert (registration, environment, context) == before


@pytest.mark.parametrize('change', ['kind', 'class', 'argv_sha256', 'owner_pid', 'token', 'case',
                                    'path', 'line', 'source'])
def test_admitted_event_mutations_refuse(change):
    registration, environment, context = fixture()
    if change in {'path', 'line', 'source'}:
        key, value = {'path': ('path', '/foreign/test.py'), 'line': ('line', 548),
                      'source': ('sha256', '0' * 64)}[change]
        registration['source_binding'][key] = value
    else:
        registration[change] = 'other'
    assert not inputs.exact_terminal_environment(environment, registration, [0, 0, 0], context)


@pytest.mark.parametrize('change', ['secret', 'secret-type', 'path-empty', 'path-type',
                                    'missing-secret', 'extra', 'LANG', 'LC_ALL', 'LC_CTYPE'])
def test_only_the_original_two_key_environment_can_be_normalized(change):
    registration, environment, context = fixture()
    if change == 'secret':
        environment['ZAI_API_KEY'] = 'other-value'
    elif change == 'secret-type':
        environment['ZAI_API_KEY'] = None
    elif change == 'path-empty':
        environment['PATH'] = ''
    elif change == 'path-type':
        environment['PATH'] = None
    elif change == 'missing-secret':
        del environment['ZAI_API_KEY']
    else:
        environment[change] = 'C'
    assert inputs.python_environment(environment, registration, [0, 0, 0], lease_context=context) == environment


@pytest.mark.parametrize('change', ['registration', 'parent', 'cwd', 'token', 'case', 'bootstrap_sha256',
                                    'transformed_argv_sha256', 'environment_sha256', 'runtime', 'checkout', 'pin'])
def test_consumed_exec_context_mutations_refuse(change):
    registration, environment, context = fixture()
    if change == 'registration':
        context['selected']['registration'] = deepcopy(registration)
    elif change in {'parent', 'cwd'}:
        context[change] = 'foreign'
    elif change in {'runtime', 'checkout', 'pin'}:
        if change == 'runtime':
            context['manifest']['runtime']['realpath'] = '/foreign/python'
        elif change == 'pin':
            context['manifest']['product_pins']['tests/test_capability_policy.py'] = '0' * 64
        else:
            context['manifest']['checkout'] = '/foreign'
    else:
        context['selected'][change] = 'foreign'
    assert not inputs.exact_terminal_environment(environment, registration, [0, 0, 0], context)


@pytest.mark.parametrize('flags', [[1, 0, 0], [0, 1, 0], [0, 0, 1], [1, 1, 1]])
def test_no_other_interpreter_flags_receive_this_transition(flags):
    registration, environment, context = fixture()
    assert inputs.python_environment(environment, registration, flags, lease_context=context) == environment


def test_registry_shape_and_absent_context_are_not_profile_authority():
    registration, environment, _ = fixture()
    assert inputs.python_environment(environment, registration, [0, 0, 0]) == environment
    command = next(row for row in COMMANDS if row['class'] == registration['class'])
    assert not inputs.exact_terminal_environment(environment, command, [0, 0, 0], None)


def test_real_unchanged_profile_producer_consumes_the_live_frame(tmp_path, monkeypatch):
    import pathlib
    from types import ModuleType, SimpleNamespace
    original_path = Path(__file__).with_name('primary_authority.py')
    body = original_path.read_bytes()
    assert hashlib.sha256(body).hexdigest() == '8660867109287601279c2014157ce3cd704d9e0afb96334a188447a892c87f4c'
    module = ModuleType('primary_authority')
    module.__file__ = '/guard/primary_authority.py'
    # The profile method does not execute producer startup or package queries.
    # Keep their Linux-only import-time filesystem setup outside this control.
    producer = ModuleType('producer_inputs')
    producer.SOURCE_UV_ELF_SHA256 = '0' * 64
    queries = ModuleType('producer_profile')
    queries.query_package = lambda *a: None
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, 'producer_inputs', producer)
        patch.setitem(sys.modules, 'producer_profile', queries)
        exec(compile(body, module.__file__, 'exec', dont_inherit=True), vars(module))
    registration, environment, context = fixture()
    owner = module.Authority.__new__(module.Authority)
    owner.source = SimpleNamespace(
        bound={170: context['selected']}, manifest=context['manifest'], path='manifest', pin='pin',
        supervisor=SimpleNamespace(events=lambda: []), exec_descriptors=lambda *a: {})
    owner.plan = {'source_mode': 'SOURCE', 'source_budget': {}}
    owner.records, owner.contexts = [], {}
    module.identity = lambda pid: {'start_ticks': 101, 'boot_id': 'boot'}
    module.digest = lambda path: '0' * 64
    module.Path = lambda path: tmp_path
    concrete = type(Path())
    class SourcePath(concrete):
        def read_bytes(self):
            if str(self) == module.__file__:
                return body
            return super().read_bytes()
    # Only filesystem adaptation is synthetic. The protected function, live
    # frame/code/globals, object type, registration identity and mapper are real.
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, 'primary_authority', module)
        patch.setattr(pathlib, 'Path', SourcePath)
        assert owner.profile(170, context['parent'], context['vector'], environment,
                             context['cwd'], 'cpython.run_command', 'bootstrap\n',
                             [0, 0, 0], 'source-bootstrap') is True
    profile = json.loads((tmp_path / '170.json').read_bytes())
    assert profile['environment'] == environment
    assert profile['python_environment'] == {**environment, 'LC_CTYPE': 'C.UTF-8'}


@pytest.mark.parametrize('cwd', ['/source', '/foreign/workspace', '/work/owned',
                                 '/work/owned/x/../workspace', '/work/owned/x/not-workspace'])
def test_no_foreign_or_noncanonical_terminal_workspace_is_normalized(cwd):
    registration, environment, context = fixture()
    context['cwd'] = context['selected']['cwd'] = cwd
    assert not inputs.exact_terminal_environment(environment, registration, [0, 0, 0], context)
