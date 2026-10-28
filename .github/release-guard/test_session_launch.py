"""Independent finite session declaration mutations and original collection parity."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from effect_proposals import proposal
from test_proposal_support import operands
from content_manifest import Refused
from session_launch import ARGS, CASES, LIVE, INVALID, INVALID_BYTES, PINS, PLAN, SCRIPT, TIMEOUT, expected, node
from source_observer import Observer
from process_ledger import Birth

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


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
    observer.full, observer.outcomes = False, []
    observer.case, observer.finished, observer.serial = PLAN[0], False, 0
    observer.root_birth = Birth(1, 1, 1, 1, 'boot', 20000)
    observer.meta = {'mounts': {}, 'checkout': str(ROOT), 'owned': str(tmp_path)}
    observer.binding = {'entry': {'path': '/native/python', 'sha256': 'a' * 64}}
    observer.intents = {}
    workspace = tmp_path / 'pytest/case/workspace'
    workspace.mkdir(parents=True)
    actor = {'birth': observer.root_birth, 'role': 'root'}
    result = expected(PLAN[0], str(workspace), ROOT, tmp_path, '/native/python', 'a' * 64, observer.meta_environment())
    payload = operands(result)
    for key, value in (('source_line', 76), ('script_sha256', 'b' * 64), ('translated', ['/native/python', '-c', 'pass'])):
        with pytest.raises(Refused):
            proposal(observer, actor, {**payload, key: value})
    assert proposal(observer, actor, payload)['ok']
    with pytest.raises(Refused):
        proposal(observer, actor, payload)


def test_self_stop_requires_exact_case_signal_and_actual_descendant_wait():
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
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


def test_response_parameters_keep_original_case_and_argv_identity():
    assert '--invalid-1024-invalid_structured_output' in tuple(ARGS)[4]
    assert ARGS[tuple(ARGS)[4]] == ('--invalid',)
    assert '--payload-size 4096-128-output_limit_exceeded' in tuple(ARGS)[5]
    assert ARGS[tuple(ARGS)[5]] == ('--payload-size', '4096')
    assert ARGS[node('timeout_kills_adapter_process_group')] == ('--sleep', '30')


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








@pytest.mark.parametrize('generation,code,error,accepted', ((0,255,-8,True),(1,255,-8,False),(0,0,-8,False),(0,255,0,False),(0,255,-1,False)))
def test_invalid_image_requires_real_exec_errno_and_no_successful_exec(generation, code, error, accepted):
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    birth = Birth(2,2,2,2,'boot',20000)
    observer.ledger = SimpleNamespace(process=lambda value: SimpleNamespace(generation=generation, terminal=(5,code << 8,code)))
    observer.ledger_trace = SimpleNamespace(records=[dict(kind='exec_syscall_return',pid=2,return_value=error)])
    observer.ledger_trace.records[0]['return'] = observer.ledger_trace.records[0].pop('return_value')
    assert observer.completed_child(dict(birth=birth,role='session-invalid',case=INVALID[0])) is accepted





def test_synchronous_guard_import_does_not_initialize_asyncio():
    import subprocess
    import sys
    body = 'import sys;sys.path.insert(0,sys.argv[1]);import source_entry;assert "asyncio" not in sys.modules'
    result = subprocess.run([sys.executable, '-I', '-S', '-c', body, str(ROOT / '.github/release-guard')],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_fixed_script_socket_creation_is_private_channel_only():
    import socket
    from source_entry import Policy
    policy = object.__new__(Policy)
    policy.sockets, policy.poison = None, False
    policy.client = SimpleNamespace(request=lambda *args: {'ok': True})
    policy.private_call = lambda: True
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        assert policy.audit('socket.__new__', (stream, socket.AF_UNIX.value, socket.SOCK_STREAM.value, 0))
    for args in ((stream, socket.AF_INET.value, socket.SOCK_STREAM.value, 0),
                 (stream, socket.AF_UNIX.value, socket.SOCK_DGRAM.value, 0),
                 (stream, CallbackTrap(), 1, 0)):
        with pytest.raises(Refused, match='private channel'):
            policy.audit('socket.__new__', args)
    policy.private_call = lambda: False
    with pytest.raises(Refused, match='private channel'):
        policy.audit('socket.__new__', (stream, socket.AF_UNIX.value, socket.SOCK_STREAM.value, 0))
