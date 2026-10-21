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
