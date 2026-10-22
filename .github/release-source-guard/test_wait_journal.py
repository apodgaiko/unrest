"""Current wait evidence retains full syntax checks and fresh registration choice."""
import json

import pytest

from finite.endpoint import latest_wait_registration


def baseline(data, owner=1, child=2):
    rows = [json.loads(line) for line in data.splitlines()]
    return next((e for e in reversed(rows) if e['kind'] == 'registered'
                 and e['owner_pid'] == owner and e['pid'] == child), None)


def row(token='old'):
    return json.dumps(dict(kind='registered', owner_pid=1, pid=2, token=token)).encode() + b'\n'


@pytest.mark.parametrize('data', [b'', row(), row()+row('new'), b'{"kind":"other"}\n',
                                      row()+b'{"kind":"other"}', row().rstrip(b'\n')])
def test_same_current_registration(data):
    result, prefix = latest_wait_registration(data, 1, 2)
    assert result == baseline(data)
    assert prefix == (data if data.endswith(b'\n') else b'')


@pytest.mark.parametrize('data', [b'broken\n'+row(), row()+b'broken\n',
                                      b'\xff\n'+row(), row()+b'\n'])
def test_invalid_syntax_is_not_hidden_by_match_or_cached_prefix(data):
    _, prefix = latest_wait_registration(row(), 1, 2)
    with pytest.raises((ValueError, UnicodeError)):
        baseline(data)
    with pytest.raises((ValueError, UnicodeError)):
        latest_wait_registration(data, 1, 2, prefix)


@pytest.mark.parametrize('data', [row('rewritten'), b'', row()+row('appended'),
                                      b'{"kind":"other"}\n', row()[:-1]+b' \n'])
def test_rewrite_truncation_and_append_use_current_bytes(data):
    _, prefix = latest_wait_registration(row(), 1, 2)
    assert latest_wait_registration(data, 1, 2, prefix)[0] == baseline(data)


def test_unterminated_prefix_cannot_hide_concatenated_invalid_json():
    data = row().rstrip(b'\n')
    _, prefix = latest_wait_registration(data, 1, 2)
    assert prefix == b''
    with pytest.raises(ValueError):
        latest_wait_registration(data+row('new'), 1, 2, prefix)


@pytest.mark.parametrize('data', [b'null\n', b'{}\n', b'3\n'])
def test_original_search_errors_preserved(data):
    with pytest.raises((TypeError, KeyError)) as original:
        baseline(data)
    with pytest.raises(type(original.value)):
        latest_wait_registration(data, 1, 2)


def test_actual_numeric_wait_and_fresh_child_token_retained(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from finite import endpoint

    journal = tmp_path / (str(os.getpid()) + '.jsonl')
    monkeypatch.setattr(endpoint, 'STATE', {'spec': {'nonce': 'exact-nonce'},
                                         'identity': {'pid': os.getpid()}})
    original_wait = os.waitpid
    monkeypatch.setattr(os, 'waitpid', original_wait)
    events = []
    guard = SimpleNamespace(install=lambda: None, bootstrap=lambda: None,
                            _STATE={'events': str(tmp_path), 'token': 'owner'}, append=events.append)
    endpoint.attach(guard)
    for status in (0, 7):
        pid = os.fork()
        if pid == 0:
            os._exit(status)
        try:
            record = dict(kind='registered', owner_pid=os.getpid(), pid=pid, token=str(status))
            with journal.open('ab') as stream:
                stream.write(json.dumps(record).encode()+b'\n')
            waited, raw_status = os.waitpid(pid, 0)
            assert waited == pid and os.waitstatus_to_exitcode(raw_status) == status
            assert events[-1] == dict(kind='raw_actual_parent_waitpid', pid=pid,
                requested_pid=pid, options=0, raw_status=raw_status, numeric_returncode=status,
                nonce='exact-nonce', owner_token='owner', owner_identity={'pid': os.getpid()},
                child_token=str(status), wait_event='actual_os_waitpid_return')
            with pytest.raises(ChildProcessError):
                original_wait(pid, os.WNOHANG)
        finally:
            try:
                original_wait(pid, 0)
            except ChildProcessError:
                pass
