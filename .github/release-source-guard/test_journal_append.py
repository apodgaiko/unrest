"""Closed-prefix validation reuse retains every current-byte and tail boundary."""
import json

import pytest

import event_journal


def original(path):
    result = []
    for line in path.read_text().splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result


@pytest.mark.parametrize('separator', ['\n', '\r', '\r\n', '\x85', '\u2028'])
def test_current_bytes_and_last_line_across_append_replace_and_truncate(tmp_path, separator):
    path = tmp_path / '1.jsonl'
    reader = event_journal.EventJournal()
    bodies = [
        '{"kind":"ready"}' + separator + '{"v":',
        '{"kind":"ready"}' + separator + '{"v":1}',
        '{"kind":"ready"}' + separator + '{"v":12}' + separator,
        '{"kind":"refused"}' + separator + '{"v":12}' + separator,
        '{"kind":"refused"}' + separator,
        '', '1', '12\n', '12\r', '12\r\n42\n',
    ]
    for body in bodies:
        path.write_bytes(body.encode())
        assert reader.events(tmp_path) == original(path)


def test_only_byte_identical_closed_prefix_reuses_validation(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text(''.join(json.dumps({'kind': 'ready', 'pid': n}) + '\n'
                            for n in range(100)))
    reader = event_journal.EventJournal()
    reader.snapshot(tmp_path)
    calls = []
    decode = event_journal.json.loads
    def loads(body):
        calls.append(body)
        return decode(body)
    monkeypatch.setattr(event_journal.json, 'loads', loads)
    with path.open('a') as stream:
        stream.write('{"kind":"forbidden","reason":"new"}\n')
    snapshot = reader.snapshot(tmp_path)
    assert len(calls) == 2 and len(snapshot) == 101
    assert snapshot[-1] == {'kind': 'forbidden', 'reason': 'new'}


def test_index_reuse_requires_current_chunks_and_complete_deduplication_state(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"registered","pid":2,"token":"child"}\n'
                    '{"kind":"launch_lifecycle_binding","token":"child"}\n'
                    '{"kind":"forbidden","reason":"repeat"}\n')
    journal = event_journal.EventJournal()
    calls = []
    original_build = event_journal.CensusIndex.build
    def build(*args):
        calls.append(True)
        return original_build(*args)
    monkeypatch.setattr(event_journal.CensusIndex, 'build', staticmethod(build))
    first = journal.snapshot(tmp_path).census({}, set())
    first[0]['pid'] = 999
    assert journal.snapshot(tmp_path).census({}, set())[0]['pid'] == 2
    assert len(calls) == 1
    assert journal.snapshot(tmp_path).census({2: {}}, set()) == [{'kind': 'forbidden', 'reason': 'repeat'}]
    assert len(calls) == 2
    journal.snapshot(tmp_path).census({3: {}}, set())
    assert len(calls) == 3  # Equal cardinality is not equal membership.
    with path.open('a') as stream:
        stream.write('{"kind":"ready","token":"new"}\n')
    rows = journal.snapshot(tmp_path).census({3: {}}, set())
    assert rows[-1]['kind'] == 'ready' and len(calls) == 4


def test_nonreflexive_metadata_uses_original_full_materialization(tmp_path):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","pid":NaN}\n')
    journal = event_journal.EventJournal()
    snapshot = journal.snapshot(tmp_path)
    assert snapshot.chunks[0][3] == (None,)
    rows = snapshot.census({}, set())
    assert rows is snapshot.materialize()
    assert str(rows[0]['pid']) == 'nan'


def test_candidate_positions_preserve_current_membership_and_inert_row_rewrites(tmp_path):
    path = tmp_path / '1.jsonl'
    rows = [{'kind': 'diagnostic_only', 'ordinal': n} for n in range(100)]
    rows += [{'kind': 'registered', 'pid': 2, 'token': 'child'},
             {'kind': 'launch_lifecycle_binding', 'token': 'child'},
             {'kind': 'ready', 'owner_pid': 2, 'token': 'child'}]
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    journal = event_journal.EventJournal()
    snapshot = journal.snapshot(tmp_path)
    assert snapshot.chunks[0][9] == ((100, 102), (101,), ())
    assert snapshot.census({}, set()) == rows[100:]
    marker = tuple(rows[-1].get(key) for key in event_journal.MARKER)
    assert journal.snapshot(tmp_path).census({2: {}}, {marker}) == []
    rows[0] = {'kind': 'forbidden', 'reason': 'changed current bytes'}
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    assert journal.snapshot(tmp_path).census({2: {}}, {marker}) == [rows[0]]
    rows[1] = {'kind': []}
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    snapshot = journal.snapshot(tmp_path)
    assert snapshot.chunks[0][9][2] == (1,)
    assert snapshot.census({2: {}}, {marker}) is snapshot.materialize()


def test_nonportable_decoder_rows_keep_full_census_across_policy_changes(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"diagnostic_only"}\n')
    decoder = event_journal.json.loads
    class Kind(str):
        pass
    def loads(body):
        value = decoder(body)
        if type(value) is dict and 'kind' in value:
            value['kind'] = Kind(value['kind'])
        return value
    monkeypatch.setattr(event_journal.json, 'loads', loads)
    journal = event_journal.EventJournal()
    snapshot = journal.snapshot(tmp_path)
    assert snapshot.chunks[0][9][2] == (0,)
    assert snapshot.census({}, set()) is snapshot.materialize()
    monkeypatch.setattr(event_journal.json, 'loads', decoder)
    snapshot = journal.snapshot(tmp_path)
    assert snapshot.census({}, set()) is snapshot.materialize()
