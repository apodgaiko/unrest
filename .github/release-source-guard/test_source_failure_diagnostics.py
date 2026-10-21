"""Failure reports survive a later hang without entering public event metadata."""
from io import StringIO
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_source_entry import Observer


def observer():
    events = []
    guard = SimpleNamespace(_STATE={}, append=events.append)
    return Observer(guard, None, {}, {}), events


@pytest.mark.parametrize('phase', ['setup', 'call', 'teardown'])
def test_original_failure_is_flushed_only_to_existing_private_capture(monkeypatch, phase):
    value, events = observer()
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    report = SimpleNamespace(failed=True, longreprtext='retained private failure body',
                             nodeid='original-case', when=phase, outcome='failed')
    before = vars(report).copy()
    value.pytest_runtest_logreport(report)
    assert vars(report) == before
    assert 'retained private failure body' in sink.getvalue()
    assert events == [{'kind': 'test_outcome', 'nodeid': 'original-case',
                       'phase': phase, 'outcome': 'failed'}]
    assert 'retained private failure body' not in repr(events)


@pytest.mark.parametrize('outcome', ['passed', 'skipped'])
def test_nonfailure_does_not_touch_report_body(monkeypatch, outcome):
    value, events = observer()
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    # Deliberately lacks longreprtext: nonfailure must not access it.
    report = SimpleNamespace(failed=False, nodeid='original-case', when='call', outcome=outcome)
    value.pytest_runtest_logreport(report)
    assert not sink.getvalue() and value.failure_reports == 0
    assert events[0]['outcome'] == outcome


def test_report_count_and_body_byte_bounds_do_not_change_results(monkeypatch):
    value, events = observer()
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    report = SimpleNamespace(failed=True, longreprtext='x' * 100000,
                             nodeid='original-case', when='call', outcome='failed')
    for _ in range(15):
        value.pytest_runtest_logreport(report)
    assert value.failure_reports == 12 and len(events) == 15
    assert sink.getvalue().count('x') == 12 * 65536
    assert report.longreprtext == 'x' * 100000
    assert all(event['outcome'] == 'failed' for event in events)


@pytest.mark.parametrize('fault', ['write', 'flush'])
def test_capture_failure_cannot_replace_test_verdict(monkeypatch, fault):
    value, events = observer()

    class Broken(StringIO):
        def write(self, text):
            if fault == 'write':
                raise OSError('capture unavailable')
            return super().write(text)

        def flush(self):
            raise OSError('capture unavailable')

    monkeypatch.setattr(sys, '__stderr__', Broken())
    report = SimpleNamespace(failed=True, longreprtext='private', nodeid='original-case',
                             when='call', outcome='failed')
    value.pytest_runtest_logreport(report)
    assert events == [{'kind': 'test_outcome', 'nodeid': 'original-case',
                       'phase': 'call', 'outcome': 'failed'}]


def test_utf8_truncation_retains_a_valid_bounded_prefix(monkeypatch):
    value, _ = observer()
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    report = SimpleNamespace(failed=True, longreprtext='€' * 50000)
    value.retain_failure(report)
    body = sink.getvalue().split(']\n', 1)[1].removesuffix('\n')
    assert len(body.encode()) <= 65536
    assert report.longreprtext.startswith(body)


def test_stall_snapshot_reads_live_tasks_without_resuming_or_cancelling(monkeypatch):
    import asyncio
    import json
    value, events = observer()
    case = 'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[cancel-validate]'
    value.guard._STATE['case'] = case
    token = value.startup_stall_token = object()
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    loop = asyncio.new_event_loop()
    async def suspended():
        await asyncio.Event().wait()
    task = loop.create_task(suspended(), name='do-not-save-private-task-name')
    try:
        before = (task.done(), task.cancelling(), task.get_coro().cr_frame.f_lineno)
        value.retain_stall_snapshot(token, case, loop)
        assert (task.done(), task.cancelling(), task.get_coro().cr_frame.f_lineno) == before
        body = sink.getvalue().split('[retained task snapshot]\n')[1]
        recorded = json.loads(body)
        assert recorded['case'] == case and len(recorded['tasks']) == 1
        assert recorded['tasks'][0]['done'] is False
        assert recorded['tasks'][0]['cancelling'] == 0
        assert len(recorded['threads']) <= 64
        assert 'do-not-save-private-task-name' not in body and events == []
    finally:
        task.cancel()
        loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
        loop.close()


def test_teardown_disarms_stale_timer_without_altering_original_result(monkeypatch):
    value, events = observer()
    value.guard._STATE['case'] = 'original-case'
    token = value.startup_stall_token = object()
    cancelled = []
    value.startup_stall_timer = SimpleNamespace(cancel=lambda: cancelled.append(True))
    sink = StringIO()
    monkeypatch.setattr(sys, '__stderr__', sink)
    report = SimpleNamespace(failed=False, nodeid='original-case', when='teardown', outcome='passed')
    value.pytest_runtest_logreport(report)
    value.retain_stall_snapshot(token, 'original-case', None)
    assert cancelled == [True] and value.startup_stall_timer is None
    assert not sink.getvalue() and events[0]['outcome'] == 'passed'


def test_diagnostic_timer_does_not_apply_to_unrelated_cases(monkeypatch):
    import primary_source_entry
    value, _ = observer()
    monkeypatch.setattr(primary_source_entry.threading, 'Timer', lambda *a: pytest.fail('unrelated timer'))
    value.pytest_runtest_call(SimpleNamespace(nodeid='other-case'))
    assert value.startup_stall_timer is None


@pytest.mark.parametrize('mode,captured,current,expected', [
    ('SOURCE', True, True, [89]),
    ('SOURCE', False, True, []),
    ('SOURCE', True, False, []),
    ('TEST-positive', True, True, []),
])
def test_only_flushed_current_full_stall_ends_as_failure(monkeypatch, mode, captured, current, expected):
    import primary_source_entry
    value, events = observer()
    value.profile['source_mode'] = mode
    token = object()
    value.startup_stall_token = token if current else object()
    value.guard._STATE['case'] = 'original-case'
    calls = []
    def capture(*args):
        calls.append('private-flush')
        return captured
    value.retain_stall_snapshot = capture
    exits = []
    monkeypatch.setattr(primary_source_entry.os, '_exit', lambda status: exits.append(status))
    value.finish_startup_stall(token, 'original-case', None)
    assert calls == ['private-flush'] and exits == expected and events == []


def test_pytest_asyncio_runner_loop_is_read_without_lazy_initialization(monkeypatch):
    import asyncio
    import primary_source_entry
    value, _ = observer()
    captured = []
    class Timer:
        def __init__(self, seconds, callback):
            assert seconds == 60
            self.callback = callback
        def start(self):
            self.callback()
    monkeypatch.setattr(primary_source_entry.threading, 'Timer', Timer)
    value.finish_startup_stall = lambda token, case, loop: captured.append(loop)
    runner = asyncio.Runner()
    case = 'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[cancel-work]'
    item = SimpleNamespace(nodeid=case, funcargs={'_function_scoped_runner': runner})
    value.pytest_runtest_call(item)
    assert captured == [None] and runner._loop is None
    with runner:
        actual = runner.get_loop()
        value.pytest_runtest_call(item)
        assert captured == [None, actual] and runner._loop is actual


def test_original_failure_sets_supported_session_stop_without_changing_report(monkeypatch):
    value, events = observer()
    session = SimpleNamespace(shouldfail=False)
    value.pytest_sessionstart(session)
    monkeypatch.setattr(sys, '__stderr__', StringIO())
    report = SimpleNamespace(failed=True, nodeid='original-case', when='call',
                             outcome='failed', longreprtext='original failure')
    before = vars(report).copy()
    value.pytest_runtest_logreport(report)
    assert session.shouldfail and vars(report) == before
    assert events == [{'kind': 'test_outcome', 'nodeid': 'original-case',
                       'phase': 'call', 'outcome': 'failed'}]
    session.shouldfail = 'earlier original failure'
    value.pytest_runtest_logreport(report)
    assert session.shouldfail == 'earlier original failure'


def test_pytest_failure_stops_after_actual_fixture_teardown(tmp_path, monkeypatch):
    value, _ = observer()
    monkeypatch.setattr(sys, '__stderr__', StringIO())
    source = tmp_path / 'test_stop.py'
    source.write_text('''from pathlib import Path
import pytest
ROOT = Path(__file__).parent
@pytest.fixture
def owned():
    yield
    (ROOT / 'closed').write_text('closed')
def test_failure(owned):
    assert False, 'retained original failure'
def test_later():
    (ROOT / 'later').write_text('must not execute')
''')
    class Forward:
        def pytest_sessionstart(self, session):
            value.pytest_sessionstart(session)
        def pytest_runtest_logreport(self, report):
            value.pytest_runtest_logreport(report)
    (tmp_path / 'empty.ini').write_text('[pytest]\n')
    result = pytest.main(['-q', '-c', str(tmp_path / 'empty.ini'), str(source)], plugins=[Forward()])
    assert result == pytest.ExitCode.TESTS_FAILED
    assert (tmp_path / 'closed').read_text() == 'closed'
    assert not (tmp_path / 'later').exists()


def test_cleanup_snapshot_is_passive_before_original_twenty_second_deadline(monkeypatch):
    import primary_source_entry
    value, _ = observer()
    calls = []
    class Timer:
        def __init__(self, seconds, callback):
            assert seconds == 10
            self.callback = callback
        def start(self):
            self.callback()
    monkeypatch.setattr(primary_source_entry.threading, 'Timer', Timer)
    value.retain_stall_snapshot = lambda *args: calls.append('private snapshot only')
    value.finish_startup_stall = lambda *args: pytest.fail('cleanup deadline changed')
    value.pytest_runtest_call(SimpleNamespace(
        nodeid='tests/test_acp_cleanup.py::test_recorded_transport_failures[success-work]', funcargs={}))
    assert calls == ['private snapshot only']


@pytest.mark.parametrize('change', ['none', 'case', 'name', 'pin', 'read', 'write'])
def test_candidate_metadata_diagnostic_cannot_replace_original_failure(monkeypatch, change):
    import hashlib
    source = Path('/source/src/unrest_harness/experimental_candidate.py')
    body = ("class CandidateInputError(ValueError): pass\n"
            "class _Observation:\n"
            " def metadata(self):\n"
            f"  name = {'../foreign' if change == 'name' else 'branches'!r}\n"
            "  raise CandidateInputError('unsupported_git_metadata')\n").encode()
    namespace = {}
    exec(compile(body, str(source), 'exec', dont_inherit=True), namespace)
    try:
        namespace['_Observation']().metadata()
    except ValueError as error:
        original = error
    traceback = original.__traceback__
    value, events = observer()
    value.manifest = {'product_pins': {'src/unrest_harness/experimental_candidate.py':
                      'foreign' if change == 'pin' else hashlib.sha256(body).hexdigest()}}
    original_read = Path.read_bytes
    def read(path):
        if path == source:
            if change == 'read':
                raise OSError('unavailable')
            return body
        return original_read(path)
    monkeypatch.setattr(Path, 'read_bytes', read)
    if change == 'write':
        def broken(event):
            raise OSError('unavailable')
        value.guard.append = broken
    item = SimpleNamespace(nodeid='foreign' if change == 'case' else
        'tests/test_experimental_candidate.py::test_literal_manifest_and_independent_oracle')
    call = SimpleNamespace(when='call', excinfo=SimpleNamespace(value=original))
    assert value.pytest_runtest_makereport(item, call) is None
    assert original.__traceback__ is traceback
    assert str(original) == 'unsupported_git_metadata'
    assert events == ([{'kind': 'candidate_metadata_refusal_entry', 'entry': 'branches',
                       'error_code': 'unsupported_git_metadata'}] if change == 'none' else [])
