"""No-network plan and existing-budget authenticated setup boundary controls."""
from copy import deepcopy
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from finite import negative_startup as negative


def fixture():
    parent = {'pid': os.getpid(), 'uid': 20000, 'boot_id': 'boot',
              'clock_ticks_per_second': 100, 'pgid': 20, 'sid': 20, 'start_ticks': 100}
    endpoint = {'identity': parent, 'spec': {'nonce': 'nonce'}}
    state = {'pin': 'manifest', 'guard_sha256': 'guard'}
    child = {**parent, 'pid': 170, 'ppid': os.getpid(), 'start_ticks': 101}
    row = {'kind': 'endpoint_install_complete', 'owner_pid': 170, 'parent_pid': os.getpid(),
           'identity': child, 'nonce': 'nonce', 'manifest_sha256': 'manifest',
           'guard_sha256': 'guard', 'token': 'token'}
    return row, state, endpoint


def test_actual_authenticated_marker_allows_only_the_same_owned_birth():
    row, state, endpoint = fixture()
    before = deepcopy((row, state, endpoint))
    assert negative.complete(row, state, endpoint, 'token', 170)
    assert (row, state, endpoint) == before


@pytest.mark.parametrize('field', ['kind', 'token', 'owner_pid', 'parent_pid', 'nonce',
                                    'manifest_sha256', 'guard_sha256'])
def test_marker_mutations_refuse(field):
    row, state, endpoint = fixture()
    row[field] = 'foreign'
    assert not negative.complete(row, state, endpoint, 'token', 170)


@pytest.mark.parametrize('field', ['pid', 'ppid', 'uid', 'boot_id', 'clock_ticks_per_second',
                                    'pgid', 'sid', 'start_ticks'])
def test_kernel_birth_mutations_refuse(field):
    row, state, endpoint = fixture()
    row['identity'][field] = 99 if field == 'start_ticks' else 'foreign'
    assert not negative.complete(row, state, endpoint, 'token', 170)


def guard():
    def refuse(reason):
        raise RuntimeError(reason)
    return SimpleNamespace(_STATE={'case': next(iter(negative.CASES)), 'class': 'pytest-root',
                                  'token': 'root', 'checkout': '/source'}, refuse=refuse)


def test_existing_plan_rpc_has_no_listener_or_connection_grant(monkeypatch):
    value = guard()
    context = {'port': 12345, 'token': 'exact', 'argv_sha256': 'argv', 'class': 'inline:test_acp_cleanup.py:50'}
    calls = []
    monkeypatch.setattr(negative, 'fixture_context', lambda g, p: context)
    negative.plan(value, {'class': context['class']}, lambda kind, **kw: calls.append((kind, kw)))
    assert calls == [('plan', {'host': '127.0.0.1', 'port': 12345,
                               'child_token': 'exact', 'argv_sha256': 'argv'})]
    assert value._STATE['negative_startup_plans'] == {'exact': context}
    with pytest.raises(RuntimeError, match='duplicate_plan'):
        negative.plan(value, {'class': context['class']}, lambda *a, **k: pytest.fail('duplicate RPC'))


def test_unbound_inline_cannot_publish_a_plan(monkeypatch):
    monkeypatch.setattr(negative, 'fixture_context', lambda *a: None)
    with pytest.raises(RuntimeError, match='unbound_inline'):
        negative.plan(guard(), {'class': 'inline:test_acp_cleanup.py:51'},
                      lambda *a, **k: pytest.fail('unbound RPC'))


@pytest.mark.parametrize('name', ['foreign', 'inline:test_acp_cleanup.py:52', 'controlled-acp'])
def test_other_children_do_not_receive_a_plan(name, monkeypatch):
    monkeypatch.setattr(negative, 'fixture_context', lambda *a: pytest.fail('expanded fixture scope'))
    negative.plan(guard(), {'class': name}, lambda *a, **k: pytest.fail('expanded RPC scope'))


def test_exact_nine_cases_and_source_pin_match_original():
    import hashlib
    source = Path(__file__).resolve().parents[2] / 'tests/test_acp_cleanup.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == negative.PIN
    assert len(negative.CASES) == 9
    for case in negative.CASES:
        state = {'case': case, 'class': 'pytest-root', 'token': 'root', 'checkout': '/source'}
        assert negative.owned_case(state)
        for key in state:
            changed = {**state, key: 'foreign'}
            assert not negative.owned_case(changed)


def barrier(tmp_path):
    import types
    from finite.child_relative import named
    row, state, endpoint = fixture()
    source = Path(__file__).parent / 'finite/runtime_guard.py'
    state.update({'case': next(iter(negative.CASES)), 'class': 'pytest-root', 'token': 'root',
                  'checkout': '/source', 'guard': str(source), 'guard_sha256': negative.hashlib.sha256(
                      source.read_bytes()).hexdigest(), 'events': str(tmp_path), 'isolated_named': named,
                  'negative_startup_plans': {'token': {'class': 'inline:test_acp_cleanup.py:50'}}})
    state['negative_startup_plans']['token']['case'] = state['case']
    row['guard_sha256'] = state['guard_sha256']
    value = types.ModuleType('runtime_guard_control')
    value._STATE = state
    value.digest = lambda p: negative.hashlib.sha256(Path(p).read_bytes()).hexdigest()
    def refuse(reason):
        raise RuntimeError(reason)
    value.refuse = refuse
    code = named(compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), 'initialize_inner')
    frame = SimpleNamespace(f_globals=vars(value), f_code=code,
                            f_locals={'launch_token': 'token', 'state': state,
                                      'registration': {'class': 'inline:test_acp_cleanup.py:50'},
                                      'deadline': 10.0, 'kwargs': {}, 'handle': SimpleNamespace(pid=170)})
    return value, endpoint, frame, row


def test_constructor_return_consumes_authenticated_completion_within_original_budget(tmp_path, monkeypatch):
    import json
    value, endpoint, frame, row = barrier(tmp_path)
    (tmp_path / '170.jsonl').write_text(json.dumps(row) + '\n')
    monkeypatch.setattr(negative.time, 'monotonic', lambda: 9.99)
    negative.observe(value, endpoint, frame, 'return', None)
    assert value._STATE['negative_startup_plans'] == {}
    assert frame.f_locals['deadline'] == 10.0


def test_expired_original_budget_refuses_without_additional_wait(tmp_path, monkeypatch):
    value, endpoint, frame, row = barrier(tmp_path)
    monkeypatch.setattr(negative.time, 'monotonic', lambda: 10.0)
    monkeypatch.setattr(negative.time, 'sleep', lambda *a: pytest.fail('extended deadline'))
    with pytest.raises(RuntimeError, match='authenticated_READY_deadline'):
        negative.observe(value, endpoint, frame, 'return', None)
    assert frame.f_locals['deadline'] == 10.0


@pytest.mark.parametrize('change', ['code', 'globals', 'deadline', 'env', 'cwd', 'class', 'state'])
def test_constructor_identity_and_original_options_cannot_be_substituted(tmp_path, change):
    value, endpoint, frame, row = barrier(tmp_path)
    if change == 'code':
        frame.f_code = compile('pass', 'foreign', 'exec')
    elif change == 'globals':
        frame.f_globals = dict(vars(value))
    elif change in {'env', 'cwd'}:
        frame.f_locals['kwargs'][change] = {} if change == 'env' else '/foreign'
    elif change == 'class':
        frame.f_locals['registration']['class'] = 'foreign'
    elif change == 'state':
        frame.f_locals['state'] = dict(value._STATE)
    else:
        frame.f_locals['deadline'] = None
    if change in {'code', 'globals'}:
        negative.observe(value, endpoint, frame, 'return', None)
    else:
        with pytest.raises(RuntimeError, match='ready_context'):
            negative.observe(value, endpoint, frame, 'return', None)
    assert 'token' in value._STATE['negative_startup_plans']


def test_unselected_source_profile_does_not_load_startup_support():
    from primary_source_entry import Observer
    for case in (None, '', 'tests/test_server.py::other'):
        value = SimpleNamespace(_STATE={'case': case})
        observer = Observer(value, None, {}, {})
        observer.observe_snapshot_rpc(None, 'call', None)
        assert observer.negative_startup is None
