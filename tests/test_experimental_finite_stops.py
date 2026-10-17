"""All twelve named event orders with actual sent, receipt-blocked siblings."""
import asyncio
import itertools
import json
from types import SimpleNamespace

import pytest

from unrest_harness import experimental_cohort as cohort, experimental_model as model
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from tests.test_experimental_finite_priority import NAMES, setup, step
from tests.test_experimental_finite_orders import CompletionBarriers


ORDERS = [*itertools.permutations(('sibling-pass', 'sibling-fail', 'stop')),
          *itertools.permutations(('completion', 'expiry', 'stop'))]


@pytest.mark.parametrize('order', ORDERS, ids=['-'.join(row) for row in ORDERS])
async def test_actual_stop_event_permutations(tmp_path, monkeypatch, order):
    clock = [0.0]
    monkeypatch.setattr(cohort, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 14)
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    expiry = 'expiry' in order
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=2, reuse=expiry)
    config, base = coordinator.state.config, coordinator.state.base
    specs = tuple(lane.spec for lane in coordinator.state.lanes)
    active = {}
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    try:
        if expiry:
            # A real retained worker parks at scheduler time zero. The sibling
            # is sent at3501, so its original model deadline3801 survives TTL3600.
            coordinator.state = model.reserve_next(coordinator.state)
            lane = coordinator.state.lanes[0]
            result = await coordinator._turn(lane, 'fixture:' + json.dumps(
                {'writes': {'a': 'defective\n'}}))
            coordinator._consume(NAMES[0], result)
            assert coordinator.owners[NAMES[0]].roles['worker'].process.returncode is None
            clock[0] = 3501.0
            coordinator.state = model.advance(coordinator.state, 3501)
        else:
            histories = []
            for specification, length in zip(specs, (1, 5), strict=True):
                admission = model.admit((specification,), base=base, clean=True,
                    isolated_dispatch=True, config=config)
                assert admission.state is not None
                coordinator.state = admission.state
                for _ in range(length):
                    await step(coordinator, specification.id)
                histories.append(coordinator.state.lanes[0])
            coordinator.state = model.State(config=config, base=base, lanes=tuple(histories))
        barriers.prepare((2, 1) if expiry else (2, 6))
        for _ in range(2):
            before = coordinator.state
            coordinator.state = model.reserve_next(before)
            assert before != coordinator.state
            lane = next(lane for lane in coordinator.state.lanes
                        if lane.active is not None and lane.spec.id not in active)
            name = lane.spec.id
            script = ({'expected': {'a': 'defective\n'}} if name == NAMES[0]
                      else {'writes': {'b': 'B\n'}} if expiry
                      else {'expected': {'b': 'correct\n'}})
            coordinator._event('reservation', name, ordinal=lane.active, phase=lane.phase,
                               candidate=coordinator.lanes[name].manifest.digest)
            active[name] = asyncio.create_task(coordinator._turn(lane, 'fixture:' + json.dumps(script)))
        ordinals = {lane.spec.id: lane.active for lane in coordinator.state.lanes}
        for name in NAMES:
            await asyncio.wait_for(barriers.receipts[name, ordinals[name]].wait(), 45)
            assert coordinator.owners[name].sent_active
        deadlines = {lane.spec.id: lane.turns[-1].deadline for lane in coordinator.state.lanes}
        receipts_before = sum(len(path.read_text().splitlines()) for path in coordinator.root.rglob('received.jsonl'))
        count_before = coordinator.state.turn_count
        observed = []
        for event in order:
            if event in ('sibling-pass', 'sibling-fail', 'completion'):
                name = NAMES[0] if event == 'sibling-pass' else NAMES[1]
                await barriers.release(name, ordinals[name])
                result = await asyncio.wait_for(asyncio.shield(active.pop(name)), 45)
                coordinator._consume(name, result)
            elif event == 'expiry':
                clock[0] = 3600.0
                coordinator.state = model.advance(coordinator.state, 3600)
                if 'stop' not in observed:
                    assert coordinator.state.lanes[0].blocking == 'expired'
                else:
                    assert coordinator.state.halt == 'stopped'
                    assert not coordinator.state.lanes[0].leases
                assert coordinator.state.lanes[1].turns[-1].deadline == deadlines[NAMES[1]] == 3801
                coordinator._halt_owners()
            else:
                (coordinator.root / 'stop-request').write_text('')
                with pytest.raises(LeaseRefused, match='cohort_dispatch_stopped'):
                    coordinator._assert_send_allowed()
            observed.append(event)
            if coordinator.state.halted:
                assert model.reserve_next(coordinator.state) == coordinator.state
                with pytest.raises(LeaseRefused, match='cohort_dispatch_stopped'):
                    coordinator._assert_send_allowed()
        barriers.rescue()
        await coordinator._drain(active)
        assert observed == list(order)
        assert coordinator.state.halted and coordinator.integrated is None and not coordinator.final
        assert coordinator.state.turn_count == count_before
        assert sum(len(path.read_text().splitlines()) for path in coordinator.root.rglob('received.jsonl')) == receipts_before
        if expiry:
            assert coordinator.state.lanes[1].candidate == 0
            assert coordinator.state.lanes[1].turns[-1].outcome == 'sealed'
        else:
            assert coordinator.state.lanes[0].phase == 'passed'
            assert coordinator.state.lanes[1].history == ('product_failure',) * 3
        assert all(all(turn.targets == lane.spec.targets for turn in lane.turns)
                   for lane in coordinator.state.lanes)
        coordinator._persist()
    finally:
        if barriers is not None:
            barriers.rescue()
        if active:
            await asyncio.gather(*active.values(), return_exceptions=True)
        for owner in coordinator.all_owners:
            await owner.close()
        ledger.close()
