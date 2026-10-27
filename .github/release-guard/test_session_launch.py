"""Independent finite session declaration mutations and original collection parity."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from session_launch import ARGS, CASES, LIVE, INVALID, INVALID_BYTES, PINS, PLAN, SCRIPT, TIMEOUT, expected, node, stream_limit
from source_observer import Observer
from process_ledger import Birth

ROOT = Path(__file__).resolve().parents[2]


def test_original_session_source_pins_and_all_collected_cases():
    import importlib.util
    for path, pin in PINS.items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == pin
    collected = []
    class Collector:
        def pytest_collection_finish(self, session):
            collected.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only', '-q', str(ROOT / 'tests/test_provider_sessions.py')], plugins=[Collector()]) == 0
    assert tuple(collected) == CASES and len(CASES) == 69 and len(LIVE) == 19
    assert importlib.util.find_spec('unrest_harness.provider_sessions') is not None


@pytest.mark.parametrize('case', LIVE)
def test_one_closed_adapter_declaration_and_exact_timeout_child(case, tmp_path):
    owned = tmp_path / 'owned'
    workspace = owned / 'pytest/case/workspace'
    workspace.mkdir(parents=True)
    environment = {'HOME': '/private-home', 'TMPDIR': '/private-tmp', 'PATH': '/usr/bin:/bin', 'PRIVATE_NOT_FORWARDED': 'no'}
    result = expected(case, str(workspace), ROOT, owned, '/native/python', 'a' * 64, environment)
    assert dict(result.environment).keys() <= {'HOME', 'TMPDIR', 'PATH', 'ANTHROPIC_API_KEY'}
    if case in INVALID:
        assert result.argv == (str(workspace.parent / 'private-canary-startup_failed'),)
        assert result.executable_sha256 == hashlib.sha256(INVALID_BYTES).hexdigest()
    else:
        assert result.argv[0] == '/native/python'
    assert result.payload_kind in ('python-command', 'python-script', 'expected-exec-failure')
    assert stream_limit(case) in (196608, 67584, 65792)
    if case == TIMEOUT:
        child = expected(case, str(workspace), ROOT, owned, '/native/python', 'a' * 64, environment, child=True)
        assert child.argv == ('/native/python', str(ROOT / SCRIPT), '--child', str(workspace.parent / 'child.stopped'))
    else:
        with pytest.raises(Refused, match='descendant'):
            expected(case, str(workspace), ROOT, owned, '/native/python', 'a' * 64, environment, child=True)


@pytest.mark.parametrize('case', [case for case in CASES if case not in LIVE])
def test_zero_launch_cases_cannot_select_any_adapter(case, tmp_path):
    with pytest.raises(Refused, match='closed'):
        expected(case, str(tmp_path), ROOT, tmp_path, '/native/python', 'a' * 64, {})


def test_observer_independently_reconstructs_adapter_and_rejects_mutations(tmp_path):
    observer = object.__new__(Observer)
    observer.case, observer.finished, observer.serial = PLAN[0], False, 0
    observer.root_birth = Birth(1, 1, 1, 1, 'boot', 20000)
    observer.meta = {'checkout': str(ROOT), 'owned': str(tmp_path)}
    observer.binding = {'entry': {'path': '/native/python', 'sha256': 'a' * 64}}
    observer.intents = {}
    workspace = tmp_path / 'pytest/case/workspace'
    workspace.mkdir(parents=True)
    actor = {'birth': observer.root_birth, 'role': 'root'}
    result = expected(PLAN[0], str(workspace), ROOT, tmp_path, '/native/python', 'a' * 64, observer.meta_environment())
    payload = {'case': PLAN[0], 'original': result.wire(), 'translated': ['/native/python', '-I', '-S', *result.argv[1:]],
               'source_line': 75, 'script_sha256': result.payload_sha256}
    for key, value in (('source_line', 76), ('script_sha256', 'b' * 64), ('translated', ['/native/python', '-c', 'pass'])):
        with pytest.raises(Refused, match='independent'):
            observer.launch(actor, {**payload, key: value})
    assert observer.launch(actor, payload)['ok']
    with pytest.raises(Refused, match='independent'):
        observer.launch(actor, payload)


def test_self_stop_requires_exact_case_signal_and_actual_descendant_wait():
    observer = object.__new__(Observer)
    observer.case = TIMEOUT
    parent, child = Birth(1, 1, 1, 1, 'boot', 20000), Birth(2, 2, 2, 2, 'boot', 20000)
    actor = {'birth': parent, 'role': 'session-adapter', 'case': TIMEOUT, 'signals': {15}}
    observer.actors = {1: actor, 2: {'birth': child, 'token': 'child'}}
    reaped = False
    observer.ledger = SimpleNamespace(process=lambda birth: SimpleNamespace(parent=parent if birth == child else None),
                                      reaped=lambda *args: reaped)
    request = {'kind': 'self-stop', 'payload': {'signal': 15}}
    with pytest.raises(Refused, match='original child wait'):
        observer.dispatch(actor, request)
    reaped = True
    assert observer.dispatch(actor, request) == {'ok': True}
    for changed in ({**actor, 'signals': set()}, {**actor, 'role': 'session-child'}):
        with pytest.raises(Refused, match='original child wait'):
            observer.dispatch(changed, request)


def test_stream_limits_keep_original_parameter_cases():
    assert stream_limit(tuple(ARGS)[4]) == 67584
    assert stream_limit(tuple(ARGS)[5]) == 65792
    assert stream_limit(node('timeout_kills_adapter_process_group')) == 196608


class CallbackTrap:
    def __eq__(self, other):
        pytest.fail('admission equality callback')
    def __ne__(self, other):
        pytest.fail('admission inequality callback')
    def __iter__(self):
        pytest.fail('admission iteration callback')
    def __bool__(self):
        pytest.fail('admission truth callback')
    def __hash__(self):
        return 1


@pytest.mark.parametrize('field', ('argv', 'cwd', 'environment', 'path'))
def test_session_plan_fields_refuse_callbacks_first(field):
    from types import MappingProxyType
    from session_calls import plan_fields
    values = dict(argv=('/native/python', '/fixed.py'), cwd='/workspace', environment=MappingProxyType({'PATH': '/bin'}), path='/bin')
    values[field] = CallbackTrap()
    with pytest.raises(Refused):
        plan_fields(SimpleNamespace(**values))


@pytest.mark.parametrize('field', ('program', 'args', 'kwds', 'stdin', 'limit'))
def test_session_constructor_fields_refuse_callbacks_first(field):
    from types import MappingProxyType
    from session_calls import constructor_options
    environment = MappingProxyType({'PATH': '/bin'})
    plan = dict(argv=('/native/python', '/fixed.py'), cwd='/workspace', environment=environment, path='/bin')
    options = dict(program='/native/python', args=('/fixed.py',), kwds=dict(cwd='/workspace', env=environment, start_new_session=True), stdin=-1, stdout=-1, stderr=-1, limit=196608)
    options[field] = CallbackTrap()
    with pytest.raises(Refused):
        constructor_options(options, plan, 196608)
    options['kwds'] = {CallbackTrap(): 1}
    with pytest.raises(Refused):
        constructor_options(options, plan, 196608)


def test_session_child_descriptor_options_refuse_callbacks_first():
    from session_calls import inherited_options
    options = dict(stdin=None, stdout=None, stderr=None, preexec_fn=None, shell=False, start_new_session=False, pass_fds=CallbackTrap())
    with pytest.raises(Refused):
        inherited_options(options)


@pytest.mark.parametrize('generation,code,error,accepted', ((0,255,-8,True),(1,255,-8,False),(0,0,-8,False),(0,255,0,False),(0,255,-1,False)))
def test_invalid_image_requires_real_exec_errno_and_no_successful_exec(generation, code, error, accepted):
    observer = object.__new__(Observer)
    birth = Birth(2,2,2,2,'boot',20000)
    observer.ledger = SimpleNamespace(process=lambda value: SimpleNamespace(generation=generation, terminal=(5,code << 8,code)))
    observer.ledger_trace = SimpleNamespace(records=[dict(kind='exec_syscall_return',pid=2,return_value=error)])
    observer.ledger_trace.records[0]['return'] = observer.ledger_trace.records[0].pop('return_value')
    assert observer.completed_child(dict(birth=birth,role='session-invalid')) is accepted



def test_fixed_descendant_site_uses_the_call_line_not_its_argument_line():
    import ast
    tree = ast.parse((ROOT / SCRIPT).read_bytes())
    calls = [call for call in ast.walk(tree) if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
             and isinstance(call.func.value, ast.Name) and call.func.value.id == 'subprocess' and call.func.attr == 'Popen']
    assert len(calls) == 1 and calls[0].lineno == 50
