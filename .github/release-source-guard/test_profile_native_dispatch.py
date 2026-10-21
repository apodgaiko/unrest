"""Native dispatch retains the observer, selected events, errors and threads."""
from __future__ import annotations

import importlib.util
import sys
import threading
from types import SimpleNamespace

import pytest


@pytest.fixture
def native_gate():
    if sys.platform != 'linux':
        pytest.skip('sealed Linux native profile module')
    spec = importlib.util.spec_from_file_location('profile_gate', '/opt/source-guard/profile_gate.so')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def chosen_function(body):
    values = {}
    exec(compile('def selected():\n' + body, '/proof/native-selected.py', 'exec'), values)
    return values['selected']


def test_native_dispatch_preserves_current_observer_and_selected_exception_events(native_gate):
    rows = []
    def record(frame, event, value):
        rows.append((frame.f_code, event, value))
    state = {'isolated_composition': SimpleNamespace(codes=None)}
    sources = {'/proof/native-selected.py'}
    gate = native_gate.make(record, state, sources)
    selected = chosen_function(' try:\n  len(1)\n except TypeError:\n  return 31\n')
    def original(frame, event, value):
        if frame.f_code.co_filename in sources:
            record(frame, event, value)
    before = sys.getprofile()
    try:
        sys.setprofile(original)
        assert selected() == 31
        sys.setprofile(None)
        expected = list(rows)
        rows.clear()
        sys.setprofile(gate)
        assert selected() == 31
        assert sys.getprofile() is gate and native_gate.uses_native_profile(gate)
        sys.setprofile(None)
        assert rows == expected
        assert any(event == 'c_exception' for _, event, _ in rows)
    finally:
        sys.setprofile(before)


def test_direct_gate_call_cannot_replace_an_unrelated_profile(native_gate):
    state = {'isolated_composition': SimpleNamespace(codes=None)}
    gate = native_gate.make(lambda *args: None, state, set())
    before = sys.getprofile()
    def unrelated(frame, event, value):
        pass
    try:
        sys.setprofile(unrelated)
        gate(sys._getframe(), 'return', None)
        assert sys.getprofile() is unrelated
        assert not native_gate.uses_native_profile(gate)
    finally:
        sys.setprofile(before)


def test_native_thread_dispatch_and_profile_restoration_keep_object_identity(native_gate):
    state = {'isolated_composition': SimpleNamespace(codes=None)}
    rows = []
    gate = native_gate.make(lambda frame, event, value: rows.append((threading.get_ident(), event)),
                            state, {'/proof/native-selected.py'})
    selected = chosen_function(' return 7\n')
    before, thread_before = sys.getprofile(), threading.getprofile()
    observed = []
    def child():
        assert selected() == 7
        observed.append((sys.getprofile() is gate, native_gate.uses_native_profile(gate)))
    try:
        threading.setprofile(gate)
        worker = threading.Thread(target=child)
        worker.start()
        worker.join(5)
        assert not worker.is_alive() and observed == [(True, True)]
        sys.setprofile(gate)
        assert selected() == 7
        assert native_gate.uses_native_profile(gate)
        sys.setprofile(before)
        assert sys.getprofile() is before
        assert any(tid == worker.ident and event == 'return' for tid, event in rows)
    finally:
        sys.setprofile(before)
        threading.setprofile(thread_before)


def test_native_selected_callback_failure_propagates_original_exception(native_gate):
    state = {'isolated_composition': SimpleNamespace(codes=None)}
    cause = RuntimeError('selected profile refused')
    def refuse(*args):
        raise cause
    gate = native_gate.make(refuse, state, {'/proof/native-selected.py'})
    selected = chosen_function(' return 7\n')
    before = sys.getprofile()
    try:
        sys.setprofile(gate)
        with pytest.raises(RuntimeError) as caught:
            selected()
        assert caught.value is cause
        assert sys.getprofile() is None  # Same single-error behavior as sys.setprofile.
    finally:
        sys.setprofile(before)
