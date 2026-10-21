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
    assert reader.events(tmp_path) == reader.for_refresh(tmp_path) == original(tmp_path)
    with (tmp_path / '20.jsonl').open('a') as f:
        f.write('true}\n')
    assert reader.events(tmp_path) == reader.for_refresh(tmp_path) == original(tmp_path)


@pytest.mark.parametrize('change', ['append', 'same-stat-overwrite', 'truncate', 'replace', 'remove', 'new-file'])
def test_every_current_read_detects_changes_without_stat_authority(tmp_path, change):
    path = tmp_path / '20.jsonl'
    path.write_text('{"kind":"allowed"}\n')
    reader = module.EventJournal()
    reader.for_refresh(tmp_path)
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
    assert reader.for_refresh(tmp_path) == reader.events(tmp_path) == original(tmp_path)


def test_mutating_public_nested_objects_never_changes_cached_or_future_events(tmp_path):
    (tmp_path / '1.jsonl').write_text('{"kind":"ready","value":{"items":[1,2]}}\n')
    reader = module.EventJournal()
    first = reader.events(tmp_path)
    first[0]['value']['items'].append(3)
    first[0]['kind'] = 'forged'
    assert reader.for_refresh(tmp_path) == reader.events(tmp_path) == original(tmp_path)
    assert reader.events(tmp_path)[0] is not reader.events(tmp_path)[0]


def test_unchanged_refresh_reuses_decoding_but_still_reads_complete_current_text(tmp_path, monkeypatch):
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
    reader.for_refresh(tmp_path)
    assert len(calls) == 100 and reads == [path]
    calls.clear()
    reader.for_refresh(tmp_path)
    assert calls == [] and reads == [path, path]
    assert len(reader.events(tmp_path)) == 100 and len(calls) == 1
    assert reads == [path, path, path]


def test_io_and_non_decode_errors_never_fall_back_to_cached_values(tmp_path, monkeypatch):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready"}\n')
    reader = module.EventJournal()
    reader.for_refresh(tmp_path)
    def broken(*a, **k):
        raise OSError('current acquisition failed')
    monkeypatch.setattr(Path, 'read_bytes', broken)
    with pytest.raises(OSError, match='current acquisition failed'):
        reader.for_refresh(tmp_path)
    with pytest.raises(OSError, match='current acquisition failed'):
        reader.events(tmp_path)


def test_current_invalid_utf8_cannot_reuse_an_old_valid_snapshot(tmp_path):
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready"}\n')
    reader = module.EventJournal()
    reader.for_refresh(tmp_path)
    path.write_bytes(b'\xff')
    with pytest.raises(UnicodeDecodeError):
        reader.for_refresh(tmp_path)


def test_real_refresh_retains_poison_and_does_not_expose_borrowed_rows(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('journal_refresh_control', Path(__file__).with_name('linux_supervisor.py'))
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    value = host.Supervisor.__new__(host.Supervisor)
    value.manifest = {'events': str(tmp_path)}
    value.registered = {}
    value.timed_events, value.event_timings = set(), []
    value.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    effects = []
    value.poison = effects.append
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready","owner_pid":20,"token":"root","value":[1]}\n')
    value._refresh_for_tick()
    value.event_timings[0]['event']['value'].append(2)
    assert value.events()[0]['value'] == [1]
    with path.open('a') as f:
        f.write('{"kind":"forbidden","reason":"retained"}\n')
    value._refresh_for_tick()
    assert effects == ['finite_guard:retained']
    value._refresh_for_tick()
    assert effects == ['finite_guard:retained', 'finite_guard:retained']
