"""Strict record equivalence with fresh bytes and fresh mutable observations."""
import json

import pytest

from journal_decode import JournalDecoder


@pytest.mark.parametrize('literal', [False, True])
@pytest.mark.parametrize('text', ['', '{"kind":"ready"}\n', 'null\n42\n',
                                  '{"nested":[1,{"x":2}]}\r\n',
                                  '{"a":1}\n{"a":2}\n',
                                  '{"a":1,"a":2}\n'])
def test_current_records_equal_original_and_return_fresh_values(literal, text):
    decoder = JournalDecoder()
    lines = text.split('\n')[:-1] if literal else text.splitlines()
    expected = [json.loads(line) for line in lines]
    for _ in range(2):
        actual = decoder.decode('owner', text, literal_newlines=literal)
        assert actual == expected
        if actual and isinstance(actual[0], dict):
            actual[0]['forged'] = True
    assert decoder.decode('owner', text, literal_newlines=literal) == expected


@pytest.mark.parametrize('text', ['\n', '{"partial":\n', '{} , {}\n', 'false trailing\n',
                                  '{}\ninvalid\n', '{"unicode":"\u2028"}\n'])
def test_invalid_original_lines_never_become_valid_array_input(text):
    decoder = JournalDecoder()
    with pytest.raises(json.JSONDecodeError):
        [json.loads(line) for line in text.splitlines()]
    with pytest.raises(json.JSONDecodeError):
        decoder.decode('owner', text)
    assert not decoder.frames


def test_append_replacement_and_truncation_revalidate_current_text(monkeypatch):
    decoder = JournalDecoder()
    original = json.loads
    calls = []
    def loads(text):
        calls.append(text)
        return original(text)
    monkeypatch.setattr(json, 'loads', loads)
    decoder.decode('owner', '{"a":1}\n')
    calls.clear()
    assert decoder.decode('owner', '{"a":1}\n') == [{'a': 1}]
    assert len(calls) == 1  # Fresh values; no repeated per-line decode.
    calls.clear()
    assert decoder.decode('owner', '{"a":1}\n{"b":2}\n') == [{'a': 1}, {'b': 2}]
    assert len(calls) == 2
    assert decoder.decode('owner', '{"a":9}\n') == [{'a': 9}]
    assert decoder.decode('owner', '') == []
    with pytest.raises(json.JSONDecodeError):
        decoder.decode('owner', 'broken\n')


def test_partial_record_is_revalidated_when_newline_arrives():
    decoder = JournalDecoder()
    assert decoder.decode('owner', '{"a":1}') == [{'a': 1}]
    assert decoder.decode('owner', '{"a":1}\n{"b":2}\n') == [{'a': 1}, {'b': 2}]


def test_array_envelope_does_not_reduce_original_recursion_limit():
    decoder = JournalDecoder()
    for depth in range(970, 1010):
        line = '[' * depth + '0' + ']' * depth
        try:
            json.loads(line)
        except RecursionError:
            continue
        actual = decoder.decode(str(depth), line + '\n')
        assert len(actual) == 1


def test_owner_and_literal_newline_modes_use_distinct_keys():
    decoder = JournalDecoder()
    assert decoder.decode(('a', False), '1\n') == [1]
    assert decoder.decode(('b', True), '2\n', literal_newlines=True) == [2]
    assert decoder.decode(('a', False), '1\n') == [1]


@pytest.mark.parametrize('body', [b'{"a":1}\n', b'\xef\xbb\xbf{"a":1}\n',
                                  '{"unicode":"\u2028"}\n'.encode(),
                                  '42'.encode('utf-16')])
def test_byte_lines_keep_original_encoding_and_split_semantics(body):
    decoder = JournalDecoder()
    expected = [json.loads(line) for line in body.splitlines()]
    assert decoder.decode('owner', body) == expected
    assert decoder.decode('owner', body) == expected


def operation_rows():
    import ast
    from pathlib import Path
    import types
    tree = ast.parse(Path(__file__).with_name('primary_operation_journal.py').read_bytes())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == 'rows')
    namespace = {'Path': Path, 'json': json}
    exec(compile(ast.Module(body=[method], type_ignores=[]), '<actual operation rows>', 'exec'), namespace)
    return namespace['rows'], types.SimpleNamespace


def test_actual_operation_rows_reacquire_bytes_and_exclude_only_uncommitted_tail(tmp_path):
    rows, owner = operation_rows()
    value = owner(state={'events': str(tmp_path)})
    journal = tmp_path / '1.jsonl'
    journal.write_bytes(b'{"kind":"registered","token":"original"}\n{"unfinished":')
    expected = [{'kind': 'registered', 'token': 'original'}]
    assert rows(value) == rows(value) == expected
    rows(value)[0]['token'] = 'forged'
    assert rows(value) == expected
    journal.write_bytes(b'{"kind":"registered","token":"replaced"}\n')
    assert rows(value)[0]['token'] == 'replaced'
    journal.write_bytes(b'{"invalid":}\n')
    with pytest.raises(json.JSONDecodeError):
        rows(value)


def test_actual_endpoint_wait_keeps_numeric_result_and_current_child_binding(tmp_path, monkeypatch):
    import importlib.util
    import os
    from pathlib import Path
    from types import SimpleNamespace
    path = Path(__file__).with_name('finite') / 'endpoint.py'
    spec = importlib.util.spec_from_file_location('wait_endpoint_control', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    events = []
    guard = SimpleNamespace(install=lambda: None, bootstrap=lambda: None, append=events.append,
                            _STATE={'events': str(tmp_path), 'token': 'owner'})
    module.STATE = {'spec': {'nonce': 'bound-nonce'}, 'identity': {'birth': 'bound'}}
    numeric = (123, 23 << 8)
    monkeypatch.setattr(os, 'waitpid', lambda pid, options: numeric)
    module.attach(guard)
    journal = tmp_path / (str(os.getpid()) + '.jsonl')
    def write(token):
        journal.write_text(json.dumps({'kind': 'registered', 'owner_pid': os.getpid(),
                                       'pid': 123, 'token': token}) + '\n')
    for token in ('original', 'replacement'):
        write(token)
        assert os.waitpid(123, 0) == numeric
        assert events[-1]['child_token'] == token
        assert events[-1]['numeric_returncode'] == 23
        assert events[-1]['raw_status'] == numeric[1]
        assert events[-1]['nonce'] == 'bound-nonce'
        assert events[-1]['owner_identity'] == {'birth': 'bound'}
    journal.write_text('malformed\n')
    with pytest.raises(json.JSONDecodeError):
        os.waitpid(123, 0)
    assert len(events) == 2
