"""Actual acknowledgement I/O, preauthorized drain and later-cutoff sibling."""
import asyncio
import contextlib
import json
import os

import pytest

from unrest_harness import experimental_model as model
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from tests.test_experimental_drain_retirement import handles
from tests.test_experimental_finite_orders import CompletionBarriers
from tests.test_experimental_finite_priority import NAMES, setup


@pytest.mark.parametrize('boundary', ['write', 'fsync'])
@pytest.mark.parametrize('offset,correction_failure', [(-1, None), (0, None), (1, None),
                                                       (0, 'write'), (0, 'fsync')])
@pytest.mark.parametrize('preauthorized', [False, True])
async def test_ack_durability(tmp_path, monkeypatch, record_property, boundary, offset,
                              correction_failure, preauthorized):
    clock = [0.0]
    ledger = PilotLedger(tmp_path / 'journal.jsonl', clock=lambda: clock[0])
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=2)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare((1, 1))
    active, events = {}, []
    append, write, fsync = ledger._append, os.write, os.fsync
    current = [None]
    injected = []

    def appending(event, fields):
        current[0] = (event, fields.get('ticket'))
        try:
            if current[0] == ('uncertain', first_ticket):
                assert ledger._turns[first_ticket] == (300.0, 'uncertain')
                assert ledger._halted and not first._acknowledged
                assert ledger.halted_by(first) is (not preauthorized)
            return append(event, fields)
        finally:
            current[0] = None

    def transition(stage, fd):
        if fd != ledger._fd or current[0] is None:
            return
        event, ticket = current[0]
        if ticket != first_ticket:
            return
        if event == 'ack' and stage == boundary:
            assert first.last_completion is not None and not first._acknowledged
            assert first.drain_requested is preauthorized
            assert ledger._turns[ticket] == (300.0, 'sent')
            clock[0] = 300.0 + offset
            events.append({'stage': stage, 'clock': clock[0], 'event': event})
        if event == 'uncertain' and stage == correction_failure:
            injected.append(stage)
            raise OSError('controlled corrective journal failure')

    def writing(fd, data):
        transition('write', fd)
        result = write(fd, data)
        if fd == ledger._fd and current[0] == ('ack', first_ticket):
            events.append({'stage': 'real-write-return', 'clock': clock[0]})
        return result

    def syncing(fd):
        transition('fsync', fd)
        result = fsync(fd)
        if fd == ledger._fd and current[0] == ('ack', first_ticket):
            events.append({'stage': 'real-fsync-return', 'clock': clock[0]})
        return result

    try:
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
        assert list(deadlines.values()) == [300.0, 400.0]
        monkeypatch.setattr(ledger, '_append', appending)
        monkeypatch.setattr(os, 'write', writing)
        monkeypatch.setattr(os, 'fsync', syncing)
        if preauthorized:
            coordinator._halt_owners()
            assert all(o.drain_requested and o.sent_active for o in (first, sibling))
        barriers.paths[NAMES[0], 0].with_suffix('.release').write_text('release')
        _, pending = await asyncio.wait({active[NAMES[0]]}, timeout=15)
        assert not pending, 'acknowledgement did not settle'
        failure = active[NAMES[0]].exception()
        if offset >= 0:
            assert isinstance(failure, LeaseRefused) and str(failure) == 'turn_not_acknowledged'
            assert first.failure is failure
            assert first.quarantined and not first._acknowledged
            assert first.last_completion is not None
            assert first.last_completion not in coordinator.completions
            assert ledger._turns[first_ticket][1] == 'uncertain'
            assert ledger.halted_by(first) is (not preauthorized)
            if correction_failure:
                assert isinstance(failure.__cause__, LeaseRefused)
                assert str(failure.__cause__) == 'journal_unavailable'
            assert sibling.drain_requested and sibling.sent_active and not sibling.stopped
        else:
            assert failure is None and first._acknowledged and not first.quarantined
            assert ledger._turns[first_ticket][1] == 'acked'
        assert injected == ([correction_failure] if correction_failure else [])
        # Later original cutoff stays valid; no fresh turn or deadline is granted.
        barriers.paths[NAMES[1], 0].with_suffix('.release').write_text('release')
        _, pending = await asyncio.wait(set(active.values()), timeout=15)
        assert not pending, 'unaffected sibling did not settle'
        await coordinator._drain(active)
        assert active[NAMES[1]].exception() is None
        assert sibling._acknowledged and not sibling.quarantined
        assert sibling.last_completion in coordinator.completions
        assert ledger._turns[sibling_ticket][1] == 'acked'
        assert {t: d for t, (d, _) in ledger._turns.items()} == deadlines
        assert ledger.accounting()['campaign'] == 2
        journal = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
        assert sum(row['event'] == 'send' for row in journal) == 2
        history = [row['event'] for row in journal if row.get('ticket') == first_ticket]
        expected = ['reserve', 'send', 'ack']
        if offset >= 0 and correction_failure != 'write':
            expected.append('uncertain')
        assert history == expected  # A failed fsync may leave bytes; it is not a durable correction.
        if preauthorized or offset >= 0:
            with pytest.raises(LeaseRefused):
                coordinator._assert_send_allowed()
        assert not coordinator.final and coordinator.integrated is None
    finally:
        monkeypatch.setattr(ledger, '_append', append)
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
        record_property('io_events', json.dumps(events, sort_keys=True))
        record_property('post_close', json.dumps([handles(o) for o in coordinator.all_owners], sort_keys=True))
    assert any(e['stage'] == 'real-fsync-return' for e in events)
    assert all(handles(o)['close_done'] and o.stopped for o in coordinator.all_owners)
    assert all(code is not None for o in coordinator.all_owners
               for code in handles(o)['roles'] + handles(o)['backends'])
