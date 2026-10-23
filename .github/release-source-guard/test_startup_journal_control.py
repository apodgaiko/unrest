"""Only one finite diagnostic selection receives inert, non-authority load."""
import json

import pytest

import startup_journal_control as control
from primary_source_inputs import test_plan as plan
from test_ci_commands import workflow


def selected():
    script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(control.TEST_JOURNAL_CONTEXT_CASES)).encode()
    return plan(script, workflow({}), 'TEST-positive')


def test_diagnostic_selection_retains_original_cases_budget_and_false_certificate():
    spec = selected()
    assert control.selected(spec)
    assert spec['timeout_seconds'] == 180
    assert spec['source_checkpoint_ready'] is False and spec['selected_carrier'] is None
    assert len(control.TEST_JOURNAL_CONTEXT_CASES) == 5
    assert control.FILES == 512 and control.ROWS_PER_FILE == 80


@pytest.mark.parametrize('change', ['full', 'poison', 'command', 'script', 'certificate', 'carrier'])
def test_drift_or_release_scope_never_seeds_a_journal(tmp_path, change):
    spec = selected()
    if change == 'full':
        spec['source_mode'] = 'FULL'
    elif change == 'poison':
        spec['source_mode'] = 'TEST-poison'
    elif change == 'command':
        spec['commands'][0].append('foreign')
    elif change == 'script':
        spec['script_sha256'] = '0' * 64
    elif change == 'certificate':
        spec['source_checkpoint_ready'] = True
    else:
        spec['selected_carrier'] = '0' * 64
    control.seed(spec, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_seed_is_inert_and_exclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'FILES', 2)
    monkeypatch.setattr(control, 'ROWS_PER_FILE', 3)
    control.seed(selected(), tmp_path)
    rows = [json.loads(row) for path in sorted(tmp_path.iterdir()) for row in path.read_text().splitlines()]
    assert [row['ordinal'] for row in rows] == list(range(6))
    assert all(row['kind'] == control.KIND and row['diagnostic_only'] is True
               and row['eligible_certificate'] is False and 'pid' not in row and 'token' not in row for row in rows)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(FileExistsError):
        control.seed(selected(), tmp_path)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_passive_registration_capture_is_bound_to_exact_context_selection():
    import hashlib
    from finite import approval_stall_diagnostic as diagnostic
    cases = list(control.TEST_JOURNAL_CONTEXT_CASES)
    profile = {'source_mode': 'TEST-positive', 'orig_argv': ['/python', '/pytest', '-q', *cases]}
    assert diagnostic.REGISTRATION_SELECTION_SHA256 == hashlib.sha256(json.dumps(['-q', *cases]).encode()).hexdigest()
    assert diagnostic.registration_seconds(profile, diagnostic.REGISTRATION_CASE) == 2.0
    for value in [dict(profile, source_mode='SOURCE'), dict(profile, source_mode='TEST-poison'),
                  dict(profile, orig_argv=None), dict(profile, orig_argv=profile['orig_argv'][:-1]),
                  dict(profile, orig_argv=[*profile['orig_argv'], '-k', 'foreign'])]:
        assert diagnostic.registration_seconds(value, diagnostic.REGISTRATION_CASE) is None
    assert diagnostic.registration_seconds(profile, cases[0]) is None


def test_passive_registration_timer_uses_existing_snapshot_without_exit_or_timeout_patch(monkeypatch):
    from types import SimpleNamespace
    import primary_source_entry as entry
    from finite import approval_stall_diagnostic as diagnostic
    timers, captured = [], []
    class Timer:
        def __init__(self, seconds, callback):
            self.seconds, self.callback = seconds, callback
            timers.append(self)
        def start(self):
            pass
    monkeypatch.setattr(entry.threading, 'Timer', Timer)
    path = '/guard/finite/approval_stall_diagnostic.py'
    owner = entry.Observer.__new__(entry.Observer)
    owner.profile = {'source_mode': 'TEST-positive', 'orig_argv': [
        '/python', '/pytest', '-q', *control.TEST_JOURNAL_CONTEXT_CASES]}
    owner.manifest = {'direct_support': {'files': {path: 'bound-pin', '/guard/finite/orders_git_data.py': 'roster-pin'}}}
    def load(name, actual, pin):
        assert (name, actual, pin) == ('approval_stall_diagnostic', path, 'bound-pin')
        return diagnostic
    monkeypatch.setattr(entry, 'load', load)
    owner.guard = SimpleNamespace(checked_source=lambda *args: {'CASES': {}})
    owner.retain_stall_snapshot = lambda *args: captured.append(args)
    owner.pytest_runtest_call(SimpleNamespace(nodeid=diagnostic.REGISTRATION_CASE, funcargs={}))
    assert len(timers) == 1 and timers[0].seconds == 2.0
    timers[0].callback()
    assert captured == [(owner.startup_stall_token, diagnostic.REGISTRATION_CASE, None)]
