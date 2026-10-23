"""Original authority decisions and fresh-byte errors survive READY indexing."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

import event_journal as journal
from journal_supervisor import JournalSupervisor
import linux_supervisor as original

ROOT = Path(__file__).parent
KINDS = ('payload', 'socketpair', 'listen', 'connected')
PINS = dict(manifest_sha256='a' * 64, guard_sha256='b' * 64,
            registry_sha256='c' * 64, runtime_sha256='d' * 64)
IDENTITY = {'pid': 20, 'uid': 20000, 'start': 123}


def ready():
    return {'kind': 'ready', 'owner_pid': 20, 'token': 'owned', **PINS}


def make_owner(composed):
    owner = original.Supervisor.__new__(original.Supervisor)
    owner.spec = {'endpoint': {'nonce': 'n'}}
    owner.manifest_pin = PINS['manifest_sha256']
    owner.manifest = {'guard_sha256': PINS['guard_sha256'],
                      'registry': {'sha256': PINS['registry_sha256']},
                      'runtime': {'sha256': PINS['runtime_sha256']}}
    owner.registered = {20: {'identity': IDENTITY, 'token': 'owned'}}
    owner.poisoned = False
    owner.plans, owner.listeners, owner.connections = {}, {}, set()
    owner.pairs = {(20, (6, 7)): [{'fd': 6}, {'fd': 7}]}
    listener = {'pid': 20, 'fd': 8, 'local_host': '127.0.0.1',
                'local_port': 1001, 'state': 10}
    owner.connect_admissions = {(20, 6): listener}
    return JournalSupervisor.adopt(owner) if composed else owner


def execute(owner, request, events, monkeypatch):
    calls = []
    def identity(pid):
        calls.append(('identity', pid))
        return IDENTITY
    def sockets(pid):
        calls.append(('sockets', pid))
        return [{'pid': 20, 'fd': 8, 'local_host': '127.0.0.1',
                 'local_port': 1001, 'state': 10},
                {'pid': 20, 'fd': 6, 'remote_host': '127.0.0.1',
                 'remote_port': 1001, 'local_port': 1002, 'state': 1,
                 'socket_cookie': 123, 'inode': 456}]
    def pair(pid, fds):
        calls.append(('pair', pid, tuple(fds)))
        return [{'fd': 6}, {'fd': 7}]
    monkeypatch.setattr(original.kernel, 'identity', identity)
    monkeypatch.setattr(original.kernel, 'sockets', sockets)
    monkeypatch.setattr(original.kernel, 'unix_pair', pair)
    monkeypatch.setattr(original.sockets, 'reciprocal_peer', lambda *args: None)
    try:
        result = owner.handle(request, events)
    except Exception as error:
        result = (type(error), error.args)
    return result, calls, (owner.listeners, owner.connections, owner.pairs)


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('mutation', [None, 'missing', 'pins', 'nonce', 'token',
                                     'identity', 'poison', 'malformed-before',
                                     'malformed-after', 'missing-owner', 'first-wrong-pins'])
def test_original_handler_results_errors_and_kernel_calls_match(tmp_path, monkeypatch, kind, mutation):
    rows = [{'kind': 'unrelated', 'nested': [n]} for n in range(150)]
    rows.insert(70, ready())
    request = {'kind': kind, 'pid': 20, 'token': 'owned', 'nonce': 'n',
               'fd': 6 if kind in {'payload', 'connected'} else 8,
               'fds': [6, 7], 'host': '127.0.0.1', 'port': 1001}
    if mutation == 'missing':
        rows.pop(70)
    elif mutation == 'pins':
        rows[70]['guard_sha256'] = 'bad'
    elif mutation == 'nonce':
        request['nonce'] = 'wrong'
    elif mutation == 'token':
        request['token'] = 'wrong'
    elif mutation == 'identity':
        request['identity'] = {'start': -1}
    elif mutation == 'malformed-before':
        rows.insert(0, {})
    elif mutation == 'malformed-after':
        rows.append(None)
    elif mutation == 'missing-owner':
        rows.insert(0, {'kind': 'ready'})
    elif mutation == 'first-wrong-pins':
        rows.insert(0, {**ready(), 'guard_sha256': 'wrong'})
    (tmp_path / '20.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    left, right = make_owner(False), make_owner(True)
    left.poisoned = right.poisoned = mutation == 'poison'
    snapshot = journal.EventJournal().snapshot(tmp_path)
    assert execute(left, deepcopy(request), deepcopy(rows), monkeypatch) == execute(
        right, deepcopy(request), snapshot, monkeypatch)


def test_closed_handler_branches_have_no_other_journal_reads():
    tree = ast.parse((ROOT / 'linux_supervisor.py').read_text())
    handle = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle')
    for kind in KINDS:
        matches = [n for n in ast.walk(handle) if isinstance(n, ast.If)
                   and ast.unparse(n.test) == 'kind == ' + repr(kind)]
        assert len(matches) == 1
        assert not any(isinstance(n, ast.Name) and n.id == 'events'
                       for statement in matches[0].body for n in ast.walk(statement))
    authenticate = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'authenticate')
    assert hashlib.sha256(ast.dump(authenticate, include_attributes=False).encode()).hexdigest() == 'c90b138b92d6a4f0ef58de0e61cba7ba44faefde74358f3ca55ce7deea21cc5a'


def test_large_snapshot_materializes_only_ready_rows_without_reusing_a_verdict(tmp_path):
    path = tmp_path / '20.jsonl'
    rows = [{'kind': 'irrelevant', 'nested': [n]} for n in range(10000)]
    rows.insert(5000, ready())
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    reader = journal.EventJournal()
    first = reader.snapshot(tmp_path)
    assert first.authentication_events() == [ready()]
    assert first.full is None and set(first.parsed) == {5000}
    first.parsed[5000]['token'] = 'mutated'
    second = reader.snapshot(tmp_path)
    assert second.authentication_events() == [ready()]
    assert second.parsed[5000] is not first.parsed[5000]
    path.write_text(json.dumps({**ready(), 'token': 'replacement'}) + '\n')
    assert reader.snapshot(tmp_path).authentication_events()[0]['token'] == 'replacement'


@pytest.mark.parametrize('literal', ['9' * 700, 'NaN', '[' * 20 + '0' + ']' * 20])
def test_nonportable_rows_keep_complete_original_decoding(tmp_path, literal):
    path = tmp_path / '20.jsonl'
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(0)
        path.write_text(json.dumps(ready()) + '\n{"kind":"other","value":' + literal + '}\n')
        reader = journal.EventJournal()
        reader.snapshot(tmp_path).materialize()
        if literal.startswith('9'):
            sys.set_int_max_str_digits(640)
            with pytest.raises(ValueError):
                reader.snapshot(tmp_path).authentication_events()
        else:
            snapshot = reader.snapshot(tmp_path)
            rows = snapshot.authentication_events()
            assert rows is snapshot.full and len(rows) == 2
    finally:
        sys.set_int_max_str_digits(previous)


def test_changed_decoder_and_exposed_mutable_rows_use_complete_list(tmp_path, monkeypatch):
    (tmp_path / '20.jsonl').write_text(json.dumps(ready()) + '\n{"kind":"other"}\n')
    reader = journal.EventJournal()
    snapshot = reader.snapshot(tmp_path)
    snapshot[1]['kind'] = 'changed'
    assert snapshot.authentication_events() is snapshot.full
    assert snapshot.full[1]['kind'] == 'changed'
    snapshot = reader.snapshot(tmp_path)
    loads = json.loads
    monkeypatch.setattr(json, 'loads', lambda value: loads(value))
    assert snapshot.authentication_events() is snapshot.full


def test_metadata_from_changed_decoder_cannot_supply_a_restored_policy_projection(tmp_path, monkeypatch):
    (tmp_path / '20.jsonl').write_text('{}\n' + json.dumps(ready()) + '\n')
    loads = json.loads
    def changed(value):
        row = loads(value)
        return {'kind': 'hidden-malformed-row'} if row == {} else row
    reader = journal.EventJournal()
    with monkeypatch.context() as patch:
        patch.setattr(json, 'loads', changed)
        snapshot = reader.snapshot(tmp_path)
    rows = snapshot.authentication_events()
    assert rows is snapshot.full and rows[0] == {}
    owner = make_owner(False)
    monkeypatch.setattr(original.kernel, 'identity', lambda pid: IDENTITY)
    with pytest.raises(KeyError, match='kind'):
        owner.authenticate({'kind': 'payload', 'pid': 20, 'token': 'owned', 'nonce': 'n'}, rows)


def test_real_refresh_poison_cannot_be_hidden_by_ready_projection(tmp_path):
    (tmp_path / '20.jsonl').write_text(json.dumps(ready()) + '\n'
                                     + '{"kind":"forbidden","reason":"caught-launch"}\n')
    owner = make_owner(True)
    owner.manifest['events'] = str(tmp_path)
    owner.timed_events, owner.event_timings = set(), []
    owner.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    reasons = []
    def poison(reason):
        reasons.append(reason)
        owner.poisoned = True
    owner.poison = poison
    snapshot = owner.refresh()
    assert reasons == ['finite_guard:caught-launch'] and owner.poisoned
    with pytest.raises(RuntimeError, match='global_poison_retained'):
        owner.handle({'kind': 'payload', 'pid': 20, 'fd': 6, 'token': 'owned', 'nonce': 'n'}, snapshot)
