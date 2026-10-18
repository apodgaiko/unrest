"""Dependency manifests derive from image bytes, never the observed target."""
import csv
import importlib.util
import io
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('dependency_outputs', Path(__file__).with_name('producer_outputs.py'))
assert SPEC is not None and SPEC.loader is not None
outputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(outputs)


def fixture_record():
    record = 'demo-1.dist-info/RECORD'
    members = {'demo.py': b'pass\n', 'demo-1.dist-info/INSTALLER': b'uv'}
    scripts = {'../../../bin/demo': b'#!/opt/primary-deps/bin/python\nimport demo\n',
               '../../../bin/native': b'\x7fELF\x00'}
    rows = [[name, *outputs.record_hash(body)] for name, body in {**members, **scripts}.items()]
    rows.append([record, '', ''])
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerows(sorted(rows))
    return stream.getvalue().encode(), record, members, scripts


def test_complete_uv_record_relocation():
    body, record, members, scripts = fixture_record()
    derived = outputs.relocate_record(body, record, members, scripts,
                                     '/opt/primary-deps/bin/python', '/source/.venv/bin/python')
    rows = outputs.record_rows(derived, record)
    assert rows['../../../bin/demo'] == outputs.record_hash(b'#!/source/.venv/bin/python\nimport demo\n')
    assert rows['../../../bin/native'] == outputs.record_hash(scripts['../../../bin/native'])
    assert rows['demo.py'] == outputs.record_hash(members['demo.py'])
    assert rows[record] == ['', '']
    assert set(rows) == {record, *members, *scripts}
    assert list(rows) == sorted(rows)


@pytest.mark.parametrize('change', ['member_bytes', 'script_bytes', 'missing_member',
                                     'missing_script', 'source_executable', 'target_executable',
                                     'foreign_shebang', 'duplicate', 'foreign_path',
                                     'unknown_row', 'self_hash', 'missing_self', 'bad_size'])
def test_record_derivation_denies_drift(change):
    body, record, members, scripts = fixture_record()
    source, target = '/opt/primary-deps/bin/python', '/source/.venv/bin/python'
    if change == 'member_bytes':
        members['demo.py'] += b'# drift'
    elif change == 'script_bytes':
        scripts['../../../bin/demo'] += b'# drift'
    elif change == 'missing_member':
        del members['demo.py']
    elif change == 'missing_script':
        del scripts['../../../bin/demo']
    elif change == 'source_executable':
        source = '/foreign/python'
    elif change == 'target_executable':
        target = '/foreign/python'
    elif change == 'foreign_shebang':
        old = scripts['../../../bin/demo']
        scripts['../../../bin/demo'] = b'#!/foreign/python\nimport demo\n'
        body = body.replace(','.join(outputs.record_hash(old)).encode(),
                            ','.join(outputs.record_hash(scripts['../../../bin/demo'])).encode())
    elif change == 'duplicate':
        body += body.splitlines(keepends=True)[0]
    elif change == 'foreign_path':
        body += b'../../outside,sha256=' + b'A' * 43 + b',1\n'
    elif change == 'unknown_row':
        body += b'unknown.py,sha256=' + b'A' * 43 + b',1\n'
    elif change == 'self_hash':
        body = body.replace((record + ',,').encode(), (record + ',sha256=' + 'A' * 43 + ',1').encode())
    elif change == 'missing_self':
        body = b''.join(row for row in body.splitlines(keepends=True) if not row.startswith(record.encode()))
    elif change == 'bad_size':
        body = body.replace(b',5\n', b',05\n')
    with pytest.raises(RuntimeError):
        outputs.relocate_record(body, record, members, scripts, source, target)
