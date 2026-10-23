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
