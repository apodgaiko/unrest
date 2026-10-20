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
