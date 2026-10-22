"""Current-byte acquisition and fresh-object equivalence of journal reuse."""
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import event_journal as module


def original(directory):
    rows = []
    for path in sorted(directory.glob('*.jsonl')):
        for line in path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def test_sorted_records_invalid_lines_and_partial_append_match_original(tmp_path):
    (tmp_path / '20.jsonl').write_text('{"kind":"ready","nested":{"n":[1,2]}}\ninvalid\n{"partial":')
    (tmp_path / '1.jsonl').write_text('null\n42\n{"unicode":"é"}\r\n')
    reader = module.EventJournal()
    assert reader.events(tmp_path) == reader.events(tmp_path) == original(tmp_path)
    with (tmp_path / '20.jsonl').open('a') as f:
        f.write('true}\n')
    assert reader.events(tmp_path) == reader.events(tmp_path) == original(tmp_path)


@pytest.mark.parametrize('change', ['append', 'same-stat-overwrite', 'truncate', 'replace', 'remove', 'new-file'])
def test_every_current_read_detects_changes_without_stat_authority(tmp_path, change):
    path = tmp_path / '20.jsonl'
    path.write_text('{"kind":"allowed"}\n')
    reader = module.EventJournal()
    reader.events(tmp_path)
    before = path.stat()
    if change == 'append':
        with path.open('a') as f:
            f.write('{"kind":"forbidden"}\n')
    elif change == 'same-stat-overwrite':
        path.write_text('{"kind":"refused"}\n')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert path.stat().st_size == before.st_size
    elif change == 'truncate':
        path.write_text('')
    elif change == 'replace':
        path.unlink()
        path.write_text('{"kind":"forbidden"}\n')
    elif change == 'remove':
        path.unlink()
    else:
        (tmp_path / '1.jsonl').write_text('{"kind":"forbidden"}\n')
    assert reader.events(tmp_path) == reader.events(tmp_path) == original(tmp_path)


def test_mutating_public_nested_objects_never_changes_cached_or_future_events(tmp_path):
    (tmp_path / '1.jsonl').write_text('{"kind":"ready","value":{"items":[1,2]}}\n')
    reader = module.EventJournal()
    first = reader.events(tmp_path)
    first[0]['value']['items'].append(3)
    first[0]['kind'] = 'forged'
    assert reader.events(tmp_path) == reader.events(tmp_path) == original(tmp_path)
    assert reader.events(tmp_path)[0] is not reader.events(tmp_path)[0]


def test_unchanged_reads_reuse_line_validation_but_read_every_current_byte(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text(''.join(json.dumps({'i': n}) + '\n' for n in range(100)))
    calls, reads = [], []
    decode, read = module.json.loads, Path.read_bytes
    def loads(value):
        calls.append(value)
        return decode(value)
    def read_bytes(self, *a, **kw):
        reads.append(self)
        return read(self, *a, **kw)
    monkeypatch.setattr(module.json, 'loads', loads)
    monkeypatch.setattr(Path, 'read_bytes', read_bytes)
    reader = module.EventJournal()
    reader.events(tmp_path)
    assert len(calls) == 101 and reads == [path]
    calls.clear()
    assert len(reader.events(tmp_path)) == 100 and len(calls) == 1
    assert reads == [path, path]


def test_io_and_non_decode_errors_never_fall_back_to_cached_values(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready"}\n')
    reader = module.EventJournal()
    reader.events(tmp_path)
    def broken(*a, **k):
        raise OSError('current acquisition failed')
    monkeypatch.setattr(Path, 'read_bytes', broken)
    with pytest.raises(OSError, match='current acquisition failed'):
        reader.events(tmp_path)
    with pytest.raises(OSError, match='current acquisition failed'):
        reader.events(tmp_path)


def test_current_invalid_utf8_cannot_reuse_an_old_valid_snapshot(tmp_path):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready"}\n')
    reader = module.EventJournal()
    reader.events(tmp_path)
    path.write_bytes(b'\xff')
    with pytest.raises(UnicodeDecodeError):
        reader.events(tmp_path)


def test_composed_refresh_retains_original_poison_and_fresh_object_semantics(tmp_path):
    from journal_supervisor import JournalSupervisor
    from linux_supervisor import Supervisor
    value = Supervisor.__new__(Supervisor)
    value.manifest = {'events': str(tmp_path)}
    value.registered = {}
    value.timed_events, value.event_timings = set(), []
    value.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    effects = []
    value.poison = effects.append
    assert JournalSupervisor.adopt(value) is value
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","owner_pid":20,"token":"root","value":[1]}\n')
    value.refresh()
    value.event_timings[0]['event']['value'].append(2)
    assert value.events()[0]['value'] == [1]
    with path.open('a') as f:
        f.write('{"kind":"forbidden","reason":"retained"}\n')
    value.refresh()
    assert effects == ['finite_guard:retained']
    value.refresh()
    assert effects == ['finite_guard:retained', 'finite_guard:retained']


def test_array_envelope_keeps_original_deep_record_boundary(tmp_path):
    path = tmp_path / '1.jsonl'
    for depth in range(970, 1010):
        line = '[' * depth + '0' + ']' * depth
        try:
            json.loads(line)
        except RecursionError:
            continue
        path.write_text(line + '\n')
        reader = module.EventJournal()
        actual = reader.events(tmp_path)
        # Comparing deeply nested lists recursively can itself overflow.
        assert len(actual) == 1
        row = actual[0]
        for _ in range(depth):
            assert type(row) is list and len(row) == 1
            row = row[0]
        assert row == 0


def test_append_reuses_only_complete_matching_blocks_and_fresh_values(tmp_path):
    path = tmp_path / '1.jsonl'
    path.write_text(''.join(json.dumps({'kind': 'ready', 'n': n, 'nested': [n]}) + '\n'
                            for n in range(module.BLOCK * 3)))
    reader = module.EventJournal()
    first = reader.snapshot(tmp_path)
    rows = first.materialize()
    blocks = first.chunks[0][6].blocks
    assert len(blocks) == 3 and all(type(row[1]) is bytes for row in blocks)
    rows[0]['nested'].append('mutated')
    with path.open('a') as stream:
        stream.write('{"kind":"forbidden","reason":"new-current-row"}\n')
    second = reader.snapshot(tmp_path)
    assert second.materialize() == original(tmp_path)
    assert len(second.chunks[0][6].blocks) == 4
    assert all(a[1] is b[1] for a, b in zip(blocks, second.chunks[0][6].blocks))
    path.write_text('{"kind":"forbidden","reason":"rewrite"}\n')
    assert reader.events(tmp_path) == original(tmp_path)


def test_changed_integer_decoder_limit_still_raises_after_warm_read(tmp_path):
    path = tmp_path / '1.jsonl'
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(0)
        path.write_text('{"kind":"ready","value":' + '9' * 700 + '}\n')
        reader = module.EventJournal()
        assert reader.events(tmp_path) == original(tmp_path)
        sys.set_int_max_str_digits(640)
        with pytest.raises(ValueError):
            reader.events(tmp_path)
        with pytest.raises(ValueError):
            original(tmp_path)
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize('literal', ['NaN', 'Infinity', '-Infinity'])
def test_nonfinite_decoder_constants_never_cross_the_parse_cache(tmp_path, literal):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","value":' + literal + '}\n')
    reader = module.EventJournal()
    first, second = reader.events(tmp_path), reader.events(tmp_path)
    assert first == second == original(tmp_path)
    assert first[0]['value'] is second[0]['value']
    assert reader.snapshot(tmp_path).chunks[0][6].blocks == ()


def test_narrow_recursion_margin_uses_original_decoder(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","nested":[1]}\n')
    reader = module.EventJournal()
    assert reader.events(tmp_path) == original(tmp_path)
    def forbidden(*a):
        raise AssertionError('no parse-cache replay near recursion boundary')
    monkeypatch.setattr(module.marshal, 'loads', forbidden)
    monkeypatch.setattr(module.sys, 'getrecursionlimit', lambda: 100)
    assert reader.events(tmp_path) == original(tmp_path)


@pytest.mark.parametrize('change', ['decoder', 'policy'])
def test_changed_decoder_policy_uses_current_original_parser(tmp_path, monkeypatch, change):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","nested":[1]}\n')
    reader = module.EventJournal()
    assert reader.events(tmp_path) == original(tmp_path)
    def forbidden(*a):
        raise AssertionError('changed JSON policy must not replay an encoding')
    monkeypatch.setattr(module.marshal, 'loads', forbidden)
    if change == 'decoder':
        monkeypatch.setattr(module.json, '_default_decoder', json.JSONDecoder(
            object_hook=lambda value: {**value, 'decoder_marker': True}))
    else:
        monkeypatch.setattr(module.json._default_decoder, 'strict', False)
    assert reader.events(tmp_path) == original(tmp_path)
