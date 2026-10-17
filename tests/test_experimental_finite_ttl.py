"""Exact scheduling TTL boundaries with a real retained controlled owner.

The scheduler clock alone is controlled: the distinct 1800-second pilot lifetime
remains live and unexpired. This isolates TTL from an earlier episode expiry;
it does not claim a real pilot may last 3600 seconds.
"""
import json
from types import SimpleNamespace

import pytest

from unrest_harness import experimental_cohort as cohort, experimental_model as model
from unrest_harness.experimental_lease import PilotLedger
from tests.test_experimental_finite_priority import NAMES, setup


@pytest.mark.parametrize('offset', [3599, 3600, 3601])
async def test_retained_owner_exact_parked_ttl(tmp_path, monkeypatch, offset):
    clock = [0.0]
    monkeypatch.setattr(cohort, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('P2')
    coordinator = setup(tmp_path / 'cohort', ledger, (NAMES[0],), reuse=True)
    worker = 'fixture:' + json.dumps({'writes': {'a': 'defective\n'}})
    validator = 'fixture:' + json.dumps({'expected': {'a': 'A\n'}})
    try:
        for instruction in (worker, validator):
            coordinator.state = model.reserve_next(coordinator.state)
            lane = coordinator.state.lanes[0]
            coordinator._event('reservation', NAMES[0], ordinal=lane.active,
                               phase=lane.phase, candidate=coordinator.lanes[NAMES[0]].manifest.digest)
            result = await coordinator._turn(lane, instruction)
            coordinator._consume(NAMES[0], result)
        owner = coordinator.owners[NAMES[0]]
        original_worker = coordinator.completions[0].identity
        assert not owner.stopped and not owner.quarantined
        assert len(owner.roles) == 2
        assert all(role.process.returncode is None for role in owner.roles.values())
        assert all(lease.parked_at == 0 for lease in coordinator.state.lanes[0].leases)
        clock[0] = float(offset)
        correction = 'fixture:' + json.dumps({'writes': {'a': 'A\n'}})
        result = await coordinator.run({NAMES[0]: (worker, validator, correction, validator)},
            'fixture:' + json.dumps({'expected': {'a': 'A\n', 'b': 'base\n'}}))
        rows = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
        if offset == 3599:
            assert result['outcome'] == 'passed'
            assert coordinator.completions[2].identity.session == original_worker.session
            assert coordinator.completions[2].identity.process_generation == original_worker.process_generation
            assert sum(row['event'] == 'send' for row in rows) == 6
        else:
            assert result['outcome'] == 'attention'
            assert coordinator.state.lanes[0].blocking == 'expired'
            assert len(coordinator.completions) == 2 and not coordinator.final
            assert coordinator.integrated is None
            assert sum(row['event'] == 'send' for row in rows) == 2
            assert coordinator.state.lanes[0].history == ('product_failure', 'expired')
        assert all(role.process.returncode is not None for role in owner.roles.values())
    finally:
        for owner in coordinator.all_owners:
            await owner.close()
        ledger.close()
