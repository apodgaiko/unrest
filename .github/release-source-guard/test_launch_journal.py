"""Fresh launch projection preserves original closed readers and error fallback."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import event_journal
from journal_supervisor import JournalSupervisor, launch_events
from linux_supervisor import Supervisor
from orders_git_custody import join_registration

KINDS = {'actual_launch_binding', 'admitted', 'orders_custody_launch_binding'}


def write(path, rows):
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))


def test_current_bytes_fresh_values_and_complete_generic_events(tmp_path):
    path = tmp_path / '1.jsonl'
    rows = [{'kind': 'inert', 'values': [0]}, {'kind': 'admitted', 'values': [1]},
            {'kind': 'actual_launch_binding', 'values': [2]},
            {'kind': 'orders_custody_launch_binding', 'values': [3]}]
    write(path, rows)
    supervisor = Supervisor.__new__(Supervisor)
    supervisor.manifest = {'events': str(tmp_path)}
    JournalSupervisor.adopt(supervisor)
    first = launch_events(supervisor)
    assert first == rows[1:]
    first[0]['values'].append('mutated')
    assert launch_events(supervisor) == rows[1:]
    assert supervisor.events() == rows
    rows[0] = {'kind': 'admitted', 'values': [4]}
    write(path, rows)
    assert launch_events(supervisor) == rows
    assert first[0] is not launch_events(supervisor)[1]


@pytest.mark.parametrize('row', [None, [], 42, {}, {'kind': []}, {'kind': 'ready', 'pid': float('nan')}])
def test_malformed_shapes_retain_complete_original_list(tmp_path, row):
    path = tmp_path / '1.jsonl'
    rows = [{'kind': 'inert'}, row, {'kind': 'admitted'}]
    write(path, rows)
    snapshot = event_journal.EventJournal().snapshot(tmp_path)
    assert snapshot.launch_events() is snapshot.materialize()


def test_decoder_changes_exposed_values_and_acquisition_errors_keep_full_path(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    write(path, [{'kind': 'inert'}, {'kind': 'admitted', 'values': [1]}])
    journal = event_journal.EventJournal()
    snapshot = journal.snapshot(tmp_path)
    snapshot[0]['kind'] = 'actual_launch_binding'
    assert snapshot.launch_events() is snapshot.materialize()
    snapshot = journal.snapshot(tmp_path)
    decode = event_journal.json.loads
    monkeypatch.setattr(event_journal.json, 'loads', lambda body: decode(body))
    assert snapshot.launch_events() is snapshot.materialize()
    def broken(path):
        raise OSError('current read failed')
    monkeypatch.setattr(Path, 'read_bytes', broken)
    with pytest.raises(OSError, match='current read failed'):
        journal.snapshot(tmp_path)


def test_plain_supervisor_retains_original_events_surface():
    rows = [{'kind': 'inert'}]
    plain = SimpleNamespace(events=lambda: rows)
    assert launch_events(plain) is rows


@pytest.mark.parametrize('change', ['none', 'duplicate-launch', 'duplicate-binding', 'reorder', 'foreign-token'])
def test_original_token_join_result_matches_complete_list(tmp_path, change):
    from test_orders_launch_token import selected, token_pair
    full, *_ = selected(tmp_path)
    value, concrete, actual = token_pair(full)
    rows = [{'kind': 'inert'}, concrete, {'kind': 'ready'}, actual]
    if change == 'duplicate-launch':
        rows.append(deepcopy(actual))
    elif change == 'duplicate-binding':
        rows.insert(0, deepcopy(concrete))
    elif change == 'reorder':
        rows.reverse()
    elif change == 'foreign-token':
        concrete['token'] = 'foreign'
    write(tmp_path / '1.jsonl', rows)
    snapshot = event_journal.EventJournal().snapshot(tmp_path)
    assert join_registration(value, snapshot.launch_events()) == join_registration(value, rows)


@pytest.mark.parametrize('change', ['none', 'duplicate-launch', 'duplicate-admission', 'missing-owner',
                                   'environment', 'cwd', 'source-pin', 'non-object', 'missing-kind'])
def test_original_source_resolver_result_error_and_consumed_state_match(tmp_path, change):
    import hashlib
    from primary_source_authority import SourceAuthority
    vector, environment, cwd = ['ps'], {'PATH': '/definitely-missing-guard-control'}, '/source'
    actual = {'kind': 'actual_launch_binding', 'owner_pid': 2, 'token': 't', 'cwd': cwd,
              'bootstrap_sha256': None,
              'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
              'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
    admitted = {'kind': 'admitted', 'owner_pid': 2, 'token': 't', 'class': 'source-control',
                'source_binding': {'path': '/source/unit-control.py', 'sha256': 'pinned'}}
    rows = [{'kind': 'inert', 'values': [1]}, actual, admitted]
    if change == 'duplicate-launch':
        rows.append(deepcopy(actual))
    elif change == 'duplicate-admission':
        rows.append(deepcopy(admitted))
    elif change == 'missing-owner':
        actual.pop('owner_pid')
    elif change == 'environment':
        actual['environment_sha256'] = 'foreign'
    elif change == 'cwd':
        actual['cwd'] = '/foreign'
    elif change == 'source-pin':
        admitted['source_binding']['sha256'] = 'foreign'
    elif change == 'non-object':
        rows.insert(0, None)
    elif change == 'missing-kind':
        rows.insert(0, {})
    write(tmp_path / '1.jsonl', rows)
    results = []
    for composed in (False, True):
        supervisor = Supervisor.__new__(Supervisor)
        supervisor.manifest = {'events': str(tmp_path)}
        supervisor.registered = {2: {}}
        if composed:
            JournalSupervisor.adopt(supervisor)
        authority = SourceAuthority.__new__(SourceAuthority)
        authority.supervisor = supervisor
        authority.contexts, authority.bound, authority.native_context = {}, {}, {}
        authority.maintenance, authority.consumed = set(), set()
        authority.manifest = {'product_pins': {'unit-control.py': 'pinned'}}
        authority.producers = SimpleNamespace(resolve_child=lambda *args: None)
        trace = SimpleNamespace(identities={4: {'ppid': 2}})
        try:
            result = authority.resolve(trace, 4, environment['PATH'] + '/ps', vector, environment, cwd)
            error = None
        except Exception as caught:
            result, error = None, (type(caught), caught.args)
        results.append((result, error, authority.bound, authority.consumed))
    assert results[0] == results[1]
    if change == 'none':
        assert results[0][0] is True and results[0][3] == {'t'}


def test_real_approval_install_composition_uses_projection_but_other_subclasses_do_not(tmp_path):
    from approval_orphan_custody import install, ApprovalSupervisor
    from linux_supervisor import receipts
    rows = [{'kind': 'inert'}, {'kind': 'admitted'}]
    write(tmp_path / '1.jsonl', rows)
    owner = Supervisor.__new__(Supervisor)
    owner.manifest, owner.registered = {'events': str(tmp_path)}, {}
    owner.ledger = receipts.ReceiptLedger.__new__(receipts.ReceiptLedger)
    JournalSupervisor.adopt(owner)
    install(owner)
    assert type(owner) is ApprovalSupervisor
    assert launch_events(owner) == [rows[1]]
    assert owner.events() == rows
    class Foreign(JournalSupervisor):
        pass
    foreign = Foreign.__new__(Foreign)
    foreign.manifest = owner.manifest
    assert launch_events(foreign) == rows
