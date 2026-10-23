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
KINDS = ('payload', 'socketpair', 'listen', 'connected',
         'ready', 'poison', 'source_response_output')
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
    owner.source_response_output = lambda request: {'pid': request['pid'], 'observed': True}
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
               'fds': [6, 7], 'host': '127.0.0.1', 'port': 1001, 'reason': 'controlled-poison'}
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


@pytest.mark.parametrize('mutation', ['pins', 'token', 'owner', 'kind', 'missing-kind', 'duplicate'])
def test_repeated_authentication_preserves_same_acquisition_mutations_and_original_checks(
        tmp_path, monkeypatch, mutation):
    rows = [{'kind': 'other', 'value': [n]} for n in range(100)]
    rows.insert(50, ready())
    if mutation == 'duplicate':
        rows.append(ready())
    (tmp_path / '20.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    snapshot = journal.EventJournal().snapshot(tmp_path)
    exposed = snapshot.authentication_events()
    assert snapshot.full is None
    if mutation in {'pins', 'duplicate'}:
        exposed[0]['guard_sha256'] = rows[50]['guard_sha256'] = 'wrong'
    elif mutation == 'token':
        exposed[0]['token'] = rows[50]['token'] = 'wrong'
    elif mutation == 'owner':
        exposed[0]['owner_pid'] = rows[50]['owner_pid'] = -1
    elif mutation == 'kind':
        exposed[0]['kind'] = rows[50]['kind'] = 'other'
    else:
        del exposed[0]['kind']
        del rows[50]['kind']
    assert snapshot.authentication_events()[0] is exposed[0]
    assert snapshot.full is None
    left, right = make_owner(False), make_owner(True)
    request = {'kind': 'payload', 'pid': 20, 'token': 'owned', 'nonce': 'n', 'fd': 6}
    assert execute(left, request, rows, monkeypatch) == execute(right, request, snapshot, monkeypatch)
    assert snapshot.full is None
    assert snapshot.materialize() == rows


def test_repeated_projection_falls_back_after_a_nonready_row_is_exposed(tmp_path):
    (tmp_path / '20.jsonl').write_text('{"kind":"other"}\n' + json.dumps(ready()) + '\n')
    snapshot = journal.EventJournal().snapshot(tmp_path)
    snapshot.authentication_events()
    snapshot[0].update(ready(), guard_sha256='wrong')
    rows = snapshot.authentication_events()
    assert rows is snapshot.full and rows[0]['guard_sha256'] == 'wrong'


def test_repeated_projection_does_not_decode_or_expand_unrelated_rows(tmp_path, monkeypatch):
    (tmp_path / '20.jsonl').write_text(''.join(json.dumps({'kind': 'other', 'n': n}) + '\n'
                                              for n in range(10000)) + json.dumps(ready()) + '\n')
    reader = journal.EventJournal()
    snapshot = reader.snapshot(tmp_path)
    first = snapshot.authentication_events()
    def refuse_expansion():
        raise AssertionError('unrelated journal expansion')
    monkeypatch.setattr(snapshot, 'materialize', refuse_expansion)
    for _ in range(5):
        assert snapshot.authentication_events()[0] is first[0]
    fresh = reader.snapshot(tmp_path)
    assert fresh.authentication_events()[0] is not first[0]


@pytest.mark.parametrize('change', ['none', 'no-plan', 'missing-admitted', 'wrong-token',
    'wrong-argv', 'wrong-owner', 'missing-child', 'stale-child', 'foreign-host',
    'missing-port', 'malformed-before', 'malformed-after', 'malformed-admitted',
    'pins', 'nonce', 'poison', 'current-listener', 'changed-listener'])
def test_connect_keeps_original_ready_admission_listener_and_error_order(tmp_path, monkeypatch, change):
    rows = [{'kind': 'unrelated', 'value': [n]} for n in range(150)]
    rows.insert(40, ready())
    admitted = {'kind': 'admitted', 'owner_pid': 20, 'token': 'child', 'argv_sha256': 'argv'}
    rows.insert(80, admitted)
    request = {'kind': 'connect', 'pid': 20, 'token': 'owned', 'nonce': 'n',
               'host': '127.0.0.1', 'port': 1001, 'fd': 6}
    if change == 'missing-admitted':
        rows.remove(admitted)
    elif change == 'wrong-token':
        admitted['token'] = 'foreign'
    elif change == 'wrong-argv':
        admitted['argv_sha256'] = 'foreign'
    elif change == 'wrong-owner':
        admitted['owner_pid'] = 99
    elif change == 'foreign-host':
        request['host'] = 'outside'
    elif change == 'missing-port':
        del request['port']
    elif change == 'malformed-before':
        rows.insert(0, {})
    elif change == 'malformed-after':
        rows.append(None)
    elif change == 'malformed-admitted':
        del admitted['owner_pid']
    elif change == 'pins':
        rows[40]['guard_sha256'] = 'foreign'
    elif change == 'nonce':
        request['nonce'] = 'foreign'
    (tmp_path / '20.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    left, right = make_owner(False), make_owner(True)
    for owner in (left, right):
        owner.poisoned = change == 'poison'
        owner.plans = {} if change == 'no-plan' else {1001: {
            'pid': 20, 'child_token': 'child', 'argv_sha256': 'argv'}}
        if change != 'missing-child':
            owner.registered[21] = {'token': 'child', 'identity': (
                {'wrong': True} if change == 'stale-child' else IDENTITY)}
        if change in {'current-listener', 'changed-listener'}:
            owner.listeners[1001] = {'pid': 20, 'fd': 8, 'local_host': '127.0.0.1',
                'local_port': 1001, 'state': 10 if change == 'current-listener' else 1}
    snapshot = journal.EventJournal().snapshot(tmp_path)
    assert execute(left, deepcopy(request), deepcopy(rows), monkeypatch) == execute(
        right, deepcopy(request), snapshot, monkeypatch)
    assert (left.plans, left.registered, left.connect_admissions) == (
        right.plans, right.registered, right.connect_admissions)


@pytest.mark.parametrize('first,second', [(False, True), (True, False)])
def test_switching_projection_retains_mutable_exposed_values(tmp_path, first, second):
    (tmp_path / '20.jsonl').write_text(json.dumps(ready()) + '\n'
        + '{"kind":"admitted","owner_pid":20,"token":"child"}\n')
    snapshot = journal.EventJournal().snapshot(tmp_path)
    exposed = snapshot.authentication_events(include_admitted=first)
    assert snapshot.full is None
    exposed[-1]['kind'] = 'ready' if first else 'admitted'
    result = snapshot.authentication_events(include_admitted=second)
    assert result is snapshot.full and result[len(exposed) - 1] is exposed[-1]


def test_connect_projection_rechecks_current_bytes_and_current_mutations(tmp_path):
    path = tmp_path / '20.jsonl'
    rows = [ready(), {'kind': 'admitted', 'owner_pid': 20, 'token': 'child'}]
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    reader = journal.EventJournal()
    first = reader.snapshot(tmp_path)
    exposed = first.authentication_events(include_admitted=True)
    exposed[1]['token'] = 'mutated'
    assert first.authentication_events(include_admitted=True)[1] is exposed[1]
    assert first.materialize()[1]['token'] == 'mutated'
    assert reader.snapshot(tmp_path).authentication_events(include_admitted=True)[1]['token'] == 'child'
    rows[1]['token'] = 'replacement'
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    assert reader.snapshot(tmp_path).authentication_events(include_admitted=True)[1]['token'] == 'replacement'


def test_projection_selection_is_a_closed_boolean(tmp_path):
    snapshot = journal.EventJournal().snapshot(tmp_path)
    with pytest.raises(TypeError, match='closed authentication projection'):
        snapshot.authentication_events(include_admitted=1)


def test_connect_keeps_the_complete_original_policy_body():
    tree = ast.parse((ROOT / 'linux_supervisor.py').read_text())
    handle = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle')
    assert hashlib.sha256(ast.dump(handle, include_attributes=False).encode()).hexdigest() == '6fbeb95db17f96646b92c9ca1ae86e858f072e26084b6dd0fc38ea021b0f479e'


@pytest.mark.parametrize('connection', [False, True])
def test_projection_indices_follow_append_replacement_truncation_and_partial_tail(tmp_path, connection):
    path = tmp_path / '20.jsonl'
    reader = journal.EventJournal()
    bodies = [
        json.dumps(ready()) + '\n{"kind":"admitted","token":',
        json.dumps(ready()) + '\n{"kind":"admitted","token":"one"}',
        json.dumps(ready()) + '\n{"kind":"admitted","token":"two"}\n',
        '{"kind":"other"}\n' + json.dumps(ready()) + '\n',
        '{"kind":"ready","token":"replacement"}\n',
        '', json.dumps(ready()),
    ]
    for body in bodies:
        path.write_text(body)
        expected = []
        for line in body.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row['kind'] == 'ready' or connection and row['kind'] == 'admitted':
                expected.append(row)
        snapshot = reader.snapshot(tmp_path)
        assert snapshot.authentication_events(include_admitted=connection) == expected
        assert snapshot.full is None


@pytest.mark.parametrize('connection', [False, True])
def test_bad_prefix_and_replacement_never_retain_an_eligible_projection(tmp_path, connection):
    path = tmp_path / '20.jsonl'
    reader = journal.EventJournal()
    for body, valid in [(json.dumps(ready()) + '\n{}\n', False),
                        (json.dumps(ready()) + '\n', True),
                        ('null\n' + json.dumps(ready()) + '\n', False),
                        (json.dumps(ready()) + '\n', True)]:
        path.write_text(body)
        snapshot = reader.snapshot(tmp_path)
        rows = snapshot.authentication_events(include_admitted=connection)
        assert (snapshot.full is None) is valid
        if valid:
            assert rows == [ready()]
        else:
            assert rows is snapshot.full


def test_index_reuse_still_reads_every_file_and_returns_fresh_values(tmp_path, monkeypatch):
    for n in range(3):
        (tmp_path / f'{n}.jsonl').write_text(json.dumps({**ready(), 'token': str(n)}) + '\n')
    reader = journal.EventJournal()
    old = reader.snapshot(tmp_path).authentication_events()
    old[0]['token'] = 'mutated'
    calls = []
    read = Path.read_bytes
    def current(path):
        calls.append(path.name)
        return read(path)
    monkeypatch.setattr(Path, 'read_bytes', current)
    new = reader.snapshot(tmp_path).authentication_events()
    assert calls == ['0.jsonl', '1.jsonl', '2.jsonl']
    assert [row['token'] for row in new] == ['0', '1', '2']
    assert all(a is not b for a, b in zip(old, new))


def test_nonportable_decoder_result_does_not_gain_index_comparisons(tmp_path, monkeypatch):
    path = tmp_path / '20.jsonl'
    path.write_text('{"kind":"other"}\n')
    calls = []
    class Kind:
        def __hash__(self):
            calls.append('hash')
            return 13
        def __eq__(self, other):
            calls.append(('equal', other))
            return False
    journal.descriptor({'kind': Kind()})
    expected = list(calls)
    calls.clear()
    monkeypatch.setattr(json, 'loads', lambda body: {'kind': Kind()})
    snapshot = journal.EventJournal().snapshot(tmp_path)
    # Unknown decoder objects retain only the original descriptor's effects;
    # projection indexing must not compare them again.
    assert calls == expected
    assert snapshot.chunks[0][8] == ((), (), (0,))
