"""A negative probe plan cannot intercept another original cleanup owner."""
from types import SimpleNamespace

import pytest
from finite import negative_startup as negative


@pytest.mark.parametrize('case', [
    'tests/test_acp_cleanup.py::test_client_cleanup_reaps_main_after_reader_failure',
    'tests/test_acp_cleanup.py::test_client_exhausts_terminals_pending_and_main[False]',
    'tests/test_acp_cleanup.py::test_client_exhausts_terminals_pending_and_main[True]',
    'foreign'])
def test_shared_inline_literal_receives_no_negative_probe_plan(case, monkeypatch):
    guard = SimpleNamespace(_STATE={'case': case, 'class': 'pytest-root',
                                   'token': 'root', 'checkout': '/source'})
    monkeypatch.setattr(negative, 'fixture_context', lambda *a: pytest.fail('foreign fixture context'))
    negative.plan(guard, {'class': 'inline:test_acp_cleanup.py:51'},
                  lambda *a, **kw: pytest.fail('foreign plan RPC'))
    assert 'negative_startup_plans' not in guard._STATE
