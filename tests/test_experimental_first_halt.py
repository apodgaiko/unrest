"""First owned journal halt with an actual already-sent ACP/HTTP sibling."""
import asyncio
import contextlib
import json
import os

import pytest

from unrest_harness import experimental_model as model
from unrest_harness.acp_runner import ACPError
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from tests.test_experimental_drain_retirement import handles
from tests.test_experimental_finite_orders import CompletionBarriers
from tests.test_experimental_finite_priority import NAMES, setup


@pytest.mark.parametrize('boundary', ['cutoff', 'write', 'fsync', 'persistent-write', 'persistent-fsync',
    'unrelated-halt', 'closed', 'episode-expiry', 'campaign-expiry'])
async def test_first_owned_halt(tmp_path, monkeypatch, record_property, boundary):
    clock = [0.0]
    ledger = PilotLedger(tmp_path / 'journal.jsonl', clock=lambda: clock[0])
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=2)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare((1, 1))
    active = {}
    finish = ledger.finish
    write, fsync = os.write, os.fsync
    armed = [False]
    failures = []

    def broken_write(fd, data):
        if fd == ledger._fd and armed[0] and boundary.endswith('write'):
            failures.append('write')
            if not boundary.startswith('persistent'):
                armed[0] = False
            raise OSError('controlled journal write failure')
        return write(fd, data)

    def broken_fsync(fd):
        if fd == ledger._fd and armed[0] and boundary.endswith('fsync'):
            failures.append('fsync')
            if not boundary.startswith('persistent'):
                armed[0] = False
            raise OSError('controlled journal fsync failure')
        return fsync(fd)

    def finishing(ticket, *, ambiguous=False):
        if not ambiguous and ticket == first_ticket:
            assert not coordinator.state.halted and not ledger._halted
            assert not any(o.drain_requested for o in coordinator.all_owners)
            assert first.last_completion is not None
            if boundary == 'unrelated-halt':
                ledger.stop()
                clock[0] = deadlines[ticket]
            elif boundary == 'closed':
                ledger.close()
            elif boundary in ('episode-expiry', 'campaign-expiry'):
                clock[0] = 1800 if boundary == 'episode-expiry' else 5400
            elif boundary == 'cutoff':
                clock[0] = deadlines[ticket]
            else:
                armed[0] = True
        return finish(ticket, ambiguous=ambiguous)

    monkeypatch.setattr(os, 'write', broken_write)
    monkeypatch.setattr(os, 'fsync', broken_fsync)
    try:
        # Receipt barriers, not timing, establish two sent turns with distinct
        # original cutoffs. The injected clock only moves at a known boundary.
        for index, (name, filename) in enumerate(zip(NAMES, ('a', 'b'), strict=True)):
            clock[0] = index * 100.0
            coordinator.state = model.reserve_next(coordinator.state)
            lane = next(lane for lane in coordinator.state.lanes if lane.spec.id == name)
            active[name] = asyncio.create_task(coordinator._turn(lane,
                'fixture:' + json.dumps({'writes': {filename: filename.upper() + '\n'}})))
            await asyncio.wait_for(barriers.receipts[name, 0].wait(), 45)
        first, sibling = (coordinator.owners[name] for name in NAMES)
        deadlines = {t: d for t, (d, _) in ledger._turns.items()}
        first_ticket, sibling_ticket = deadlines
        assert deadlines[first_ticket] == 300 and deadlines[sibling_ticket] == 400
        monkeypatch.setattr(ledger, 'finish', finishing)
        barriers.paths[NAMES[0], 0].with_suffix('.release').write_text('release')
        done, pending = await asyncio.wait({active[NAMES[0]]}, timeout=15)
        assert not pending, 'first owned failure did not settle'
        assert isinstance(active[NAMES[0]].exception(), LeaseRefused)
        assert first.quarantined and first.last_completion is not None
        assert not first._acknowledged and first.last_completion not in coordinator.completions
        denied = boundary in ('unrelated-halt', 'closed', 'episode-expiry', 'campaign-expiry')
        expected_reason = ('journal_unavailable' if boundary == 'closed' or 'write' in boundary
                           or 'fsync' in boundary else 'turn_not_acknowledged')
        assert str(first.failure) == expected_reason
        assert coordinator.reason == expected_reason
        if denied:
            assert not sibling.drain_requested
        else:
            assert sibling.sent_active and sibling.drain_requested and not sibling.stopped
        coordinator._halt_owners()  # Repeated stop retains the original permission.
        barriers.paths[NAMES[1], 0].with_suffix('.release').write_text('release')
        done, pending = await asyncio.wait(set(active.values()), timeout=15)
        assert not pending, 'sibling drain did not settle'
        await coordinator._drain(active)
        if not denied:
            assert sibling.last_completion is not None
        if denied:
            # Revocation can close the actual ACP pipe before a late response
            # reaches the ledger. Both are refusals, never successful seals.
            assert isinstance(active[NAMES[1]].exception(), (LeaseRefused, ACPError))
            assert not sibling._acknowledged and sibling.quarantined
            assert sibling.last_completion not in coordinator.completions
        elif boundary.startswith('persistent'):
            assert isinstance(active[NAMES[1]].exception(), LeaseRefused)
            assert not sibling._acknowledged and sibling.quarantined
            assert sibling.last_completion not in coordinator.completions
            assert ledger._turns[sibling_ticket][1] == 'sent'
            assert any(e['stage'] == 'journal_stop' for e in coordinator.cleanup_errors)
        else:
            assert active[NAMES[1]].exception() is None
            assert sibling._acknowledged and not sibling.quarantined and sibling.stopped
            assert sibling.last_completion in coordinator.completions
            assert ledger._turns[sibling_ticket][1] == 'acked'
        assert bool(failures) == ('write' in boundary or 'fsync' in boundary)
        assert {t: d for t, (d, _) in ledger._turns.items()} == deadlines
        assert ledger.accounting()['campaign'] == 2
        assert not coordinator.final and coordinator.integrated is None
        with pytest.raises(LeaseRefused):
            coordinator._assert_send_allowed()
    finally:
        armed[0] = False
        barriers.rescue()
        if active:
            _, pending = await asyncio.wait(set(active.values()), timeout=15)
            for task in pending:
                task.cancel()
            for owner in coordinator.all_owners:
                with contextlib.suppress(LeaseRefused):
                    await owner.close()
            await asyncio.gather(*active.values(), return_exceptions=True)
        ledger.close()
        record_property('post_close', json.dumps([handles(o) for o in coordinator.all_owners], sort_keys=True))
    assert all(code is not None for o in coordinator.all_owners
               for code in handles(o)['roles'] + handles(o)['backends'])


@pytest.mark.parametrize('event', ['session_identity', 'reserve', 'send'])
@pytest.mark.parametrize('failure', ['write', 'fsync'])
async def test_other_owned_journal_halts(tmp_path, monkeypatch, record_property, event, failure):
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=2)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare((1, 1))
    active = {}
    append, write, fsync = ledger._append, os.write, os.fsync
    armed = [False]
    failed = []

    def appending(name, fields):
        if name == event and not failed:
            assert not coordinator.state.halted and not ledger._halted
            armed[0] = True
        return append(name, fields)

    def writing(fd, data):
        if fd == ledger._fd and armed[0] and failure == 'write':
            armed[0] = False
            failed.append(event)
            raise OSError('controlled owned journal write')
        return write(fd, data)

    def syncing(fd):
        if fd == ledger._fd and armed[0] and failure == 'fsync':
            armed[0] = False
            failed.append(event)
            raise OSError('controlled owned journal fsync')
        return fsync(fd)

    try:
        for index, (name, filename) in enumerate(zip(NAMES, ('a', 'b'), strict=True)):
            coordinator.state = model.reserve_next(coordinator.state)
            lane = next(lane for lane in coordinator.state.lanes if lane.spec.id == name)
            active[name] = asyncio.create_task(coordinator._turn(lane,
                'fixture:' + json.dumps({'writes': {filename: filename.upper() + '\n'}})))
            if index == 0:
                await asyncio.wait_for(barriers.receipts[name, 0].wait(), 45)
                sibling = coordinator.owners[name]
                deadlines = dict(ledger._turns)
                monkeypatch.setattr(ledger, '_append', appending)
                monkeypatch.setattr(os, 'write', writing)
                monkeypatch.setattr(os, 'fsync', syncing)
        _, pending = await asyncio.wait({active[NAMES[1]]}, timeout=15)
        assert not pending
        assert str(active[NAMES[1]].exception()) == 'journal_unavailable'
        assert failed == [event] and coordinator.reason == 'journal_unavailable'
        assert sibling.sent_active and sibling.drain_requested and not sibling.stopped
        barriers.rescue()
        _, pending = await asyncio.wait(set(active.values()), timeout=15)
        assert not pending
        await coordinator._drain(active)
        assert active[NAMES[0]].exception() is None
        assert sibling.last_completion in coordinator.completions
        assert sibling.stopped and not sibling.quarantined and sibling._acknowledged
        assert all(ledger._turns[t][0] == d for t, (d, _) in deadlines.items())
        assert coordinator.owners[NAMES[1]].quarantined
        with pytest.raises(LeaseRefused):
            coordinator._assert_send_allowed()
    finally:
        armed[0] = False
        barriers.rescue()
        if active:
            _, pending = await asyncio.wait(set(active.values()), timeout=15)
            for task in pending:
                task.cancel()
            for owner in coordinator.all_owners:
                with contextlib.suppress(LeaseRefused):
                    await owner.close()
            await asyncio.gather(*active.values(), return_exceptions=True)
        ledger.close()
        record_property('post_close', json.dumps([handles(o) for o in coordinator.all_owners], sort_keys=True))
    assert all(code is not None for o in coordinator.all_owners
               for code in handles(o)['roles'] + handles(o)['backends'])
