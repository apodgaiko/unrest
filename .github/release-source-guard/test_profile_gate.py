"""Differential callback coverage for the identical profile skip predicate."""
import importlib.util
import sys
import threading
import types

import pytest

spec = importlib.util.spec_from_file_location('profile_gate', '/opt/source-guard/profile_gate.so')
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def function(name, filename, body):
    values = {}
    exec(compile('def ' + name + '():\n    ' + body, filename, 'exec'), values)
    return values[name]


@pytest.mark.parametrize('mode', ['sources', 'pytest', 'isolated', 'operation'])
def test_native_predicate_matches_original_callback_events(mode):
    selected = function('selected', '/proof/selected.py', 'return len((1, 2))')
    ignored = function('ignored', '/proof/ignored.py', 'return len((3,))')
    reporting = function('call_and_report', '/deps/_pytest/runner.py', 'return len(())')
    state = {'operations': object() if mode == 'operation' else None,
             'isolated_composition': types.SimpleNamespace(codes=ignored.__code__ if mode == 'isolated' else None)}
    sources = {'/proof/selected.py'} if mode == 'sources' else set()
    collected = []

    def record(frame, event, value):
        collected.append((frame.f_code, event, value))

    def original(frame, event, value):
        if (state.get('operations') is None and frame.f_code.co_filename not in sources
                and not (frame.f_code.co_name == 'call_and_report'
                         and frame.f_code.co_filename.endswith('/_pytest/runner.py'))
                and not (state['isolated_composition'].codes is not None
                         and frame.f_code == state['isolated_composition'].codes)):
            return
        record(frame, event, value)

    native = gate.make(record, state, sources)

    def exercise(callback):
        sys.setprofile(callback)
        try:
            selected()
            ignored()
            reporting()
        finally:
            sys.setprofile(None)

    exercise(original)
    expected = list(collected)
    collected.clear()
    exercise(native)
    assert collected == expected
    if mode != 'operation':
        assert all(row[0].co_filename in sources | {'/deps/_pytest/runner.py',
                   *({'/proof/ignored.py'} if mode == 'isolated' else set())} for row in collected)
    assert any(event == 'c_call' for _, event, _ in collected)
    assert any(event == 'return' for _, event, _ in collected)


def test_callback_exception_and_thread_profile_identity():
    chosen = function('chosen', '/proof/chosen.py', 'import sys; return sys.getprofile()')
    records = []
    state = {'isolated_composition': types.SimpleNamespace(codes=None)}
    native = gate.make(lambda *args: records.append(args[1]), state, {'/proof/chosen.py'})
    previous = threading.getprofile()
    try:
        sys.setprofile(native)
        assert chosen() is native
        sys.setprofile(None)
        threading.setprofile(native)
        results = []
        worker = threading.Thread(target=lambda: results.append(chosen()))
        worker.start()
        worker.join(5)
        assert not worker.is_alive() and results == [native]
    finally:
        sys.setprofile(None)
        threading.setprofile(previous)
    assert 'call' in records and 'return' in records

    def fail(*args):
        raise RuntimeError('selected observer refusal')

    rejected = gate.make(fail, state, {'/proof/chosen.py'})
    try:
        sys.setprofile(rejected)
        with pytest.raises(RuntimeError, match='selected observer refusal'):
            chosen()
    finally:
        sys.setprofile(None)
