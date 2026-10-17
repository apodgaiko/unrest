"""Stopped-drain retirement through actual controlled ACP/private HTTP owners."""
import asyncio
import contextlib
import json

import pytest

from unrest_harness import experimental_cohort as cohort, experimental_model as model
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from unrest_harness.experimental_session import _SessionOwner
from tests.test_experimental_finite_priority import NAMES, setup
from tests.test_experimental_finite_stops import test_actual_stop_event_permutations as original_stop
from tests.test_experimental_finite_orders import CompletionBarriers


def handles(owner):
    return {'lane': owner.lane, 'stopped': owner.stopped, 'quarantined': owner.quarantined,
            'sent_active': owner.sent_active, 'drain_requested': owner.drain_requested,
            'roles': [r.process.returncode for r in owner.roles.values()],
            'backends': [b.process.returncode for b in owner.backends.values()],
            'close_done': owner._close_task is not None and owner._close_task.done()}


@pytest.mark.parametrize('delivery_barrier', [False, True], ids=['original-unchanged', 'retired-delivery'])
async def test_original_stop_and_retired_delivery(tmp_path, monkeypatch, record_property, delivery_barrier):
    original_turn, original_start = cohort.Coordinator._turn, _SessionOwner.start
    owners, observations = [], []

    async def start(self, *args, **kwargs):
        owners.append(self)
        return await original_start(self, *args, **kwargs)

    async def deliver(self, lane, instruction):
        result = await original_turn(self, lane, instruction)
        if delivery_barrier and lane.spec.id == NAMES[0] and self.ledger._halted:
            owner = self.owners[lane.spec.id]
            assert owner.stopped and not owner.sent_active and not owner.quarantined
            assert owner._close_task is not None and owner._watchdog is not None
            # Observe the real watchdog/cleanup finish before delivering the result.
            # wait is finite and non-cancelling; owned close remains the rescue.
            done, _ = await asyncio.wait({owner._close_task, owner._watchdog}, timeout=10)
            assert done == {owner._close_task, owner._watchdog}
            observations.append(handles(owner))
        return result

    monkeypatch.setattr(_SessionOwner, 'start', start)
    monkeypatch.setattr(cohort.Coordinator, '_turn', deliver)
    try:
        await original_stop(tmp_path, monkeypatch, ('expiry', 'stop', 'completion'))
    finally:
        for owner in owners:
            with contextlib.suppress(LeaseRefused):
                await owner.close()
        record_property('post_close', json.dumps([handles(o) for o in owners], sort_keys=True))
    assert all(o.stopped and not o.quarantined for o in owners)
    assert all(code is not None for o in owners for code in handles(o)['roles'] + handles(o)['backends'])
    assert bool(observations) == delivery_barrier


@pytest.mark.parametrize('boundary', ['clean', 'acknowledged-custody', 'uncertain-finish',
    'postprocessing', 'episode-expiry', 'campaign-expiry', 'ledger-closed', 'prior-owner-failure',
    'unrelated-halt', 'cancelled'])
async def test_retirement_boundaries(tmp_path, monkeypatch, record_property, boundary):
    clock = [0.0]
    ledger = PilotLedger(tmp_path / 'journal.jsonl', clock=lambda: clock[0])
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, (NAMES[0],), reuse=True)
    coordinator.state = model.reserve_next(coordinator.state)
    lane = coordinator.state.lanes[0]
    run_turn, finish = cohort.Coordinator._run_turn, ledger.finish
    observed = {}

    def finished(ticket, *, ambiguous=False):
        if boundary == 'uncertain-finish' and not ambiguous:
            clock[0] = ledger._turns[ticket][0]
        return finish(ticket, ambiguous=ambiguous)

    async def processed(self, lane, instruction):
        result = await run_turn(self, lane, instruction)
        owner = self.owners[lane.spec.id]
        observed['deadlines'] = dict(ledger._turns)
        if boundary == 'unrelated-halt':
            ledger.stop()
        elif boundary == 'prior-owner-failure':
            owner._revoke(quarantine=True)
        self._halt_owners()
        self._halt_owners()
        observed['drain_requested'] = owner.drain_requested
        if boundary == 'acknowledged-custody':
            clock[0] = next(iter(ledger._turns.values()))[0] + 1
        elif boundary == 'episode-expiry':
            clock[0] = 1800
        elif boundary == 'campaign-expiry':
            clock[0] = 5400
        elif boundary == 'ledger-closed':
            ledger.close()
        elif boundary == 'postprocessing':
            raise ValueError('controlled custody failure')
        elif boundary == 'cancelled':
            raise asyncio.CancelledError
        return result

    monkeypatch.setattr(ledger, 'finish', finished)
    monkeypatch.setattr(cohort.Coordinator, '_run_turn', processed)
    success = boundary in ('clean', 'acknowledged-custody')
    try:
        if success:
            await coordinator._turn(lane, 'fixture:' + json.dumps({'writes': {'a': 'A\n'}}))
        else:
            with pytest.raises((LeaseRefused, ValueError, asyncio.CancelledError)):
                await coordinator._turn(lane, 'fixture:' + json.dumps({'writes': {'a': 'A\n'}}))
        owner = coordinator.owners[NAMES[0]]
        assert owner.stopped and owner.quarantined == (not success)
        if 'deadlines' in observed:
            assert ledger._turns == observed['deadlines']
        if boundary in ('unrelated-halt', 'prior-owner-failure'):
            assert not observed['drain_requested']
        if boundary == 'uncertain-finish':
            assert [s for _, s in ledger._turns.values()] == ['uncertain']
        with pytest.raises(LeaseRefused):
            coordinator._assert_send_allowed()
    finally:
        for owner in coordinator.all_owners:
            with contextlib.suppress(LeaseRefused):
                await owner.close()
        ledger.close()
        record_property('post_close', json.dumps([handles(o) for o in coordinator.all_owners], sort_keys=True))
    assert all(code is not None for o in coordinator.all_owners
               for code in handles(o)['roles'] + handles(o)['backends'])


async def test_prior_failure_kept_while_unaffected_sent_sibling_drains(tmp_path, monkeypatch, record_property):
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=2)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare((1, 1))
    active = {}
    try:
        for name, filename in zip(NAMES, ('a', 'b'), strict=True):
            coordinator.state = model.reserve_next(coordinator.state)
            lane = next(lane for lane in coordinator.state.lanes if lane.spec.id == name)
            active[name] = asyncio.create_task(coordinator._turn(lane,
                'fixture:' + json.dumps({'writes': {filename: filename.upper() + '\n'}})))
        for name in NAMES:
            await asyncio.wait_for(barriers.receipts[name, 0].wait(), 45)
        first, sibling = (coordinator.owners[name] for name in NAMES)
        deadlines = {t: d for t, (d, _) in ledger._turns.items()}
        first._revoke(quarantine=True)
        assert first.quarantined and not first.drain_requested
        assert sibling.drain_requested and sibling.sent_active and not sibling.stopped
        coordinator._halt_owners()
        barriers.rescue()
        await coordinator._drain(active)
        assert coordinator.outcome == 'attention' and coordinator.state.halted
        assert first.quarantined and not sibling.quarantined and sibling.stopped
        assert sibling.last_completion in coordinator.completions
        assert {t: d for t, (d, _) in ledger._turns.items()} == deadlines
        assert not coordinator.final and coordinator.integrated is None
        with pytest.raises(LeaseRefused):
            coordinator._assert_send_allowed()
    finally:
        barriers.rescue()
        done, pending = await asyncio.wait(active.values(), timeout=15)
        for task in pending:
            task.cancel()
        await asyncio.gather(*active.values(), return_exceptions=True)
        for owner in coordinator.all_owners:
            with contextlib.suppress(LeaseRefused):
                await owner.close()
        ledger.close()
        record_property('post_close', json.dumps([handles(o) for o in coordinator.all_owners], sort_keys=True))
    assert all(code is not None for o in coordinator.all_owners
               for code in handles(o)['roles'] + handles(o)['backends'])
