"""Diagnostic attribution never replaces the installed guard or another tool."""
import sys

import pytest

from finite.guard_cost_profile import CostProfile, TOOL


def target(source, body):
    namespace = {}
    exec(compile(body, source, 'exec'), namespace)
    return namespace


def test_exact_guard_functions_are_counted_with_original_profile_preserved():
    functions = target('/guard-proof/metadata.py', 'def digest():\n    return 7\ndef admit():\n    return digest()\n')
    previous = sys.getprofile()
    events = []

    def profile(frame, event, value):
        if frame.f_code.co_filename == '/guard-proof/metadata.py':
            events.append((frame.f_code.co_name, event))

    try:
        sys.setprofile(profile)
        monitor = CostProfile('/guard-proof')
        assert monitor.start()
        assert functions['admit']() == 7
        assert functions['admit']() == 7
        report = monitor.stop()
        assert report['complete'] and report['existing_profile_identity_retained']
        assert sys.getprofile() is profile and sys.monitoring.get_tool(TOOL) is None
        assert {r['function']: r['calls'] for r in report['rows']} == {'admit': 2, 'digest': 2}
        assert all(0 <= r['exclusive_cpu_ns'] <= r['inclusive_cpu_ns'] for r in report['rows'])
        assert events == [('admit', 'call'), ('digest', 'call'), ('digest', 'return'), ('admit', 'return')] * 2
    finally:
        sys.setprofile(previous)
        if sys.monitoring.get_tool(TOOL) == 'unrest-private-guard-cost':
            monitor.stop()


def test_monitor_never_takes_an_existing_tool():
    sys.monitoring.use_tool_id(TOOL, 'original-tool')
    try:
        monitor = CostProfile('/guard-proof')
        assert monitor.start() is False
        assert monitor.stop()['complete'] is False
        assert sys.monitoring.get_tool(TOOL) == 'original-tool'
    finally:
        sys.monitoring.free_tool_id(TOOL)


def test_exception_unwind_and_non_guard_code_preserve_original_results():
    guard = target('/guard-proof/metadata.py', 'def read():\n    raise ValueError("original failure")\n')
    other = target('/ordinary/metadata.py', 'def digest():\n    return 9\n')
    monitor = CostProfile('/guard-proof')
    assert monitor.start()
    try:
        assert other['digest']() == 9
        with pytest.raises(ValueError, match='original failure'):
            guard['read']()
    finally:
        report = monitor.stop()
    assert report['complete'] and [r['function'] for r in report['rows']] == ['read']



def test_equal_but_distinct_code_objects_and_unrelated_unwinds():
    body = 'def read():\n    try:\n        unrelated()\n    except ValueError:\n        return 8\n'
    first = target('/guard-proof/metadata.py', body)
    second = target('/guard-proof/metadata.py', body)
    assert first['read'].__code__ == second['read'].__code__
    assert first['read'].__code__ is not second['read'].__code__

    def unrelated():
        raise ValueError('expected metadata probe')

    first['unrelated'] = second['unrelated'] = unrelated
    monitor = CostProfile('/guard-proof')
    assert monitor.start()
    try:
        assert first['read']() == second['read']() == 8
    finally:
        report = monitor.stop()
    assert report['complete'] and report['rows'][0]['calls'] == 2
    assert len(monitor.codes) == 2



def test_partial_registration_failure_releases_only_owned_tool(monkeypatch):
    register = sys.monitoring.register_callback
    failure = RuntimeError('original registration failure')

    def fail(tool, event, callback):
        if tool == TOOL and event == sys.monitoring.events.PY_RETURN and callback is not None:
            raise failure
        return register(tool, event, callback)

    monkeypatch.setattr(sys.monitoring, 'register_callback', fail)
    original = sys.getprofile()
    monitor = CostProfile('/guard-proof')
    with pytest.raises(RuntimeError) as observed:
        monitor.start()
    assert observed.value is failure
    assert sys.monitoring.get_tool(TOOL) is None and sys.getprofile() is original
