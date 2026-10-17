"""Coordinator fault paths through actual controlled adapter/backend/private MCP."""
import asyncio
import json
from pathlib import Path
import shutil
import time

import pytest

from unrest_harness import experimental_cohort as cohort
from unrest_harness.experimental_lease import LeaseRefused

from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'


@pytest.mark.parametrize('failure', ['journal', 'state', 'completion', 'consume', 'combined', 'cancel', 'timeout', 'refusal'])
async def test_persistent_fault_after_backend_receipt_drains(tmp_path, monkeypatch, failure, record_property):
    original_event = cohort.Coordinator._event
    original_write = cohort.os.write
    original_record = cohort.write_record
    original_consume = cohort.Coordinator._consume
    original_close = cohort._SessionOwner.close
    task = asyncio.current_task()
    captured = {}
    attempts = {'journal': 0, 'state': 0, 'consume': 0}
    armed = False

    def write(fd, data):
        if armed and fd == captured['coordinator'].ledger._fd:
            attempts['journal'] += 1
            raise OSError('persistent controlled journal fault')
        return original_write(fd, data)

    def record(path, data):
        if (armed and path.name == 'state.json' and (failure in ('state', 'combined')
                or failure == 'completion' and any(e['event'] == 'completion' and e['lane'] == 'a-second'
                    for e in captured['coordinator'].events))):
            attempts['state'] += 1
            raise OSError('persistent controlled state fault')
        if armed and failure == 'state' and path.name == 'campaign-status.json':
            raise OSError('persistent campaign status fault')
        return original_record(path, data)

    def consume(self, name, result):
        if armed and failure == 'consume':
            attempts['consume'] += 1
            raise OSError('persistent controlled consumption fault')
        original_consume(self, name, result)
        if armed and failure == 'combined':
            attempts['consume'] += 1
            raise OSError('persistent controlled consumption fault')

    async def close(self):
        if armed and self.lane == 'a-second' and 'before_close' not in captured:
            # This executes before owned termination, not after controller return.
            captured['before_close'] = {
                'completed': bool(list(self.root.rglob('broker-observations.jsonl'))),
                'result': self.last_completion,
                'returncodes': [b.process.returncode for b in self.backends.values()],
                'deadlines': {k: d for k, (d, _) in self.ledger._turns.items()},
            }
        return await original_close(self)

    def event(self, name, lane, **fields):
        nonlocal armed
        original_event(self, name, lane, **fields)
        if not armed and name == 'consumed' and lane == 'z-first':
            sibling = self.owners['a-second']
            receipt = list(sibling.root.rglob('received.jsonl'))
            assert receipt and json.loads(receipt[0].read_text().splitlines()[0])['method'] == 'turn/start'
            assert sibling.sent_active
            assert not list(sibling.root.rglob('broker-observations.jsonl'))
            captured.update(coordinator=self, sibling=sibling, started=time.monotonic(),
                            deadlines={k: d for k, (d, _) in self.ledger._turns.items()},
                            seal=(self.root / 'seal-1.json').read_bytes())
            armed = True
            if failure != 'cancel':
                (self.root / 'stop-request').touch()
            if failure == 'cancel':
                assert task is not None
                task.cancel()
            elif failure == 'timeout':
                raise TimeoutError('controlled deadline failure')
            elif failure == 'refusal':
                raise LeaseRefused('controlled_original_refusal')

    async def cancel_again():
        while not armed:
            await asyncio.sleep(.01)
        if failure == 'cancel':
            for _ in range(3):
                await asyncio.sleep(.1)
                assert task is not None
                task.cancel()
        # Stop is synchronous; give the outer handler one loop iteration.
        await asyncio.sleep(.1)
        coordinator = captured['coordinator']
        assert coordinator.state.halted
        first = coordinator.owners['z-first']
        assert first.stopped and first.broker._active is None
        with pytest.raises(LeaseRefused):
            coordinator.ledger.available()
        with pytest.raises(LeaseRefused):
            coordinator._assert_send_allowed()

    monkeypatch.setattr(cohort.Coordinator, '_event', event)
    monkeypatch.setattr(cohort.Coordinator, '_consume', consume)
    monkeypatch.setattr(cohort._SessionOwner, 'close', close)
    monkeypatch.setattr(cohort, 'write_record', record)
    # Fault every append for journal; other variants still fail repeated stop
    # logging, except consume which needs a successfully returned sibling result.
    if failure not in ('state', 'completion', 'consume'):
        monkeypatch.setattr(cohort.os, 'write', write)
    observer = asyncio.create_task(cancel_again())
    try:
        result = await cohort.campaign(tmp_path / 'campaign', trusted_process=True,
            adapter=ADAPTER, fixture=FIXTURE, package=None, episodes=('C1',),
            controlled_timing=((2, 10), (0, 0)), transport=controlled_transport())
        await asyncio.wait_for(observer, 1)
    finally:
        if not observer.done():
            observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)
    assert armed
    coordinator = captured['coordinator']
    status = result['episodes']['C1']
    assert status['outcome'] == 'attention'
    assert status['reason'] == ('lease_refused' if failure == 'refusal'
        else 'cohort_failed' if failure in ('timeout', 'state', 'combined')
        else 'cohort_cancelled' if failure == 'cancel' else 'cohort_dispatch_stopped')
    assert status['turns_consumed'] == 2 and status['final_turns_consumed'] == 0
    assert coordinator.integrated is None and not coordinator.final
    assert [e['phase'] for e in coordinator.events if e['event'] == 'dispatch'] == ['work', 'work']
    before = captured['before_close']
    assert before['completed'] and before['result'] is not None
    assert before['returncodes'] and all(code is None for code in before['returncodes'])
    assert before['deadlines'] == captured['deadlines']
    assert time.monotonic() - captured['started'] < 20
    assert all(owner.stopped and owner.broker._active is None for owner in coordinator.all_owners)
    assert all(b.process.returncode is not None for o in coordinator.all_owners for b in o.backends.values())
    assert all(r.process.returncode is not None for o in coordinator.all_owners for r in o.roles.values())
    assert not any(lane['reuse_eligible'] for lane in status['lanes'])
    if failure not in ('state', 'completion', 'consume'):
        assert 2 <= attempts['journal'] < 20
    if failure not in ('completion', 'consume'):
        assert (coordinator.root / 'seal-1.json').read_bytes() == captured['seal']
    else:
        assert attempts['consume'] == (1 if failure == 'consume' else 0)
        assert len(coordinator.completions) == 2
    if failure in ('state', 'completion', 'combined'):
        assert 2 <= attempts['state'] < 10
        assert status['persistence_failed']
    if failure == 'combined':
        assert attempts['consume'] == 1
    if failure == 'state':
        assert result['persistence_failed']
    saved = cohort.recovered_status(coordinator.root / 'state.json')
    assert saved['resumable'] is False and saved['accounting'] == 'last_persisted_snapshot'
    record_property('drain_observations', json.dumps({
        'boundary': failure, 'attempts': attempts, 'status': status,
        'post_fault_seconds': time.monotonic() - captured['started'],
        'deadlines_unchanged': before['deadlines'] == captured['deadlines'],
        'completion_before_close': before['completed'],
        'live_backend_before_close': before['returncodes'],
        'owned_returncodes': [b.process.returncode for o in coordinator.all_owners
                             for b in o.backends.values()],
        'unconsumed_completions': sum(o.last_completion is not None
            and o.last_completion not in coordinator.completions for o in coordinator.all_owners),
    }, sort_keys=True))


@pytest.mark.parametrize('boundary', ['timeout', 'refusal', 'unsent'])
async def test_failed_or_unsent_owner_revokes_while_received_sibling_drains(tmp_path, monkeypatch, boundary, record_property):
    from unrest_harness import experimental_session as session
    from unrest_harness.experimental_lease import PilotLedger

    original_run = cohort.Coordinator._run_turn
    original_turn = session._SessionOwner.turn
    original_request = session._TurnClient.send_request
    original_reserve = PilotLedger.reserve
    original_halt = cohort.Coordinator._halt_owners
    original_write = cohort.os.write
    captured = {}
    armed = False
    failures = []

    async def run_turn(self, lane, instruction):
        captured['coordinator'] = self
        if lane.spec.id == 'z-first':
            # Arrange receipt through the real sibling backend, before allowing
            # the failed/unsent lane to reach its independent boundary.
            async with asyncio.timeout(20):
                while not list(self.root.glob('a-second/**/received.jsonl')):
                    await asyncio.sleep(.01)
        return await original_run(self, lane, instruction)

    async def turn(self, name, **kwargs):
        if self.lane == 'z-first' and boundary != 'unsent':
            kwargs['scenario'] = 'stall' if boundary == 'timeout' else 'missing_completion'
        return await original_turn(self, name, **kwargs)

    def reserve(self, identity, **kwargs):
        ticket = original_reserve(self, identity, **kwargs)
        if identity.lane == 'z-first' and boundary == 'timeout':
            # Establish a short original deadline before grant/send; never extend
            # or replace it at halt. Only this controlled test changes the clock.
            _, status = self._turns[ticket]
            self._turns[ticket] = (self._clock() + .5, status)
        captured.setdefault('deadlines', {})[ticket] = self._turns[ticket][0]
        return ticket

    async def request(self, method, params, **kwargs):
        coordinator = captured.get('coordinator')
        first = None if coordinator is None else coordinator.owners.get('z-first')
        if (boundary == 'unsent' and method == 'session/prompt' and first is not None
                and any(role.client is self for role in first.roles.values())):
            assert first.broker._active is not None
            captured['unsent_granted'] = True
            (coordinator.root / 'stop-request').touch()
            await asyncio.Event().wait()  # Must be cancelled, never released to send.
        return await original_request(self, method, params, **kwargs)

    def write(fd, data):
        if armed and fd == captured['coordinator'].ledger._fd:
            failures.append(time.monotonic())
            raise OSError('persistent stop/ack fault')
        return original_write(fd, data)

    def halt(self):
        nonlocal armed
        if not armed:
            sibling = self.owners['a-second']
            assert sibling.sent_active and list(sibling.root.rglob('received.jsonl'))
            assert not list(sibling.root.rglob('broker-observations.jsonl'))
            armed = True
            captured['halt'] = time.monotonic()
        original_halt(self)
        first = self.owners['z-first']
        assert first.stopped and first.broker._active is None

    monkeypatch.setattr(cohort.Coordinator, '_run_turn', run_turn)
    monkeypatch.setattr(cohort.Coordinator, '_halt_owners', halt)
    monkeypatch.setattr(session._SessionOwner, 'turn', turn)
    monkeypatch.setattr(session._TurnClient, 'send_request', request)
    monkeypatch.setattr(PilotLedger, 'reserve', reserve)
    monkeypatch.setattr(cohort.os, 'write', write)
    result = await cohort.campaign(tmp_path / 'campaign', trusted_process=True,
        adapter=ADAPTER, fixture=FIXTURE, package=None, episodes=('C1',),
        controlled_timing=((0, 10), (0, 0)), transport=controlled_transport())
    assert armed
    coordinator = captured['coordinator']
    status = result['episodes']['C1']
    assert status['outcome'] == 'attention'
    assert status['reason'] == ('cohort_dispatch_stopped' if boundary == 'unsent'
        else 'completion_missing_or_stale' if boundary == 'refusal' else 'cohort_failed')
    assert status['turns_consumed'] == 2 and status['final_turns_consumed'] == 0
    assert not coordinator.final and coordinator.integrated is None
    assert {k: d for k, (d, _) in coordinator.ledger._turns.items()} == captured['deadlines']
    first, sibling = coordinator.owners['z-first'], coordinator.owners['a-second']
    assert sibling.last_completion is not None
    assert list(sibling.root.rglob('broker-observations.jsonl'))
    assert first.last_completion is None
    if boundary == 'unsent':
        assert captured['unsent_granted'] and not list(first.root.rglob('received.jsonl'))
    else:
        assert list(first.root.rglob('received.jsonl'))
    assert 1 < len(failures) < 20 and time.monotonic() - captured['halt'] < 20
    assert all(owner.stopped and owner.broker._active is None for owner in coordinator.all_owners)
    assert all(b.process.returncode is not None for o in coordinator.all_owners for b in o.backends.values())

    record_property('drain_observations', json.dumps({
        'boundary': boundary, 'journal_failures': len(failures), 'status': status,
        'post_halt_seconds': time.monotonic() - captured['halt'],
        'deadlines': sorted(captured['deadlines'].values()),
        'received_lanes': [o.lane for o in coordinator.all_owners if list(o.root.rglob('received.jsonl'))],
        'completed_lanes': [o.lane for o in coordinator.all_owners if o.last_completion is not None],
        'owned_returncodes': [b.process.returncode for o in coordinator.all_owners
                             for b in o.backends.values()],
    }, sort_keys=True))


async def test_campaign_status_write_failure_cannot_report_success(tmp_path, monkeypatch):
    original = cohort.write_record

    def record(path, data):
        if path.name == 'campaign-status.json':
            raise OSError('persistent final status fault')
        return original(path, data)

    monkeypatch.setattr(cohort, 'write_record', record)
    result = await cohort.campaign(tmp_path / 'campaign', trusted_process=True,
        adapter=ADAPTER, fixture=FIXTURE, package=None, episodes=('P1',), transport=controlled_transport())
    assert result['persistence_failed']
    assert result['episodes']['P1']['outcome'] == 'attention'
    assert result['episodes']['P1']['reason'] == 'campaign_status_unavailable'
    assert result['episodes']['P1']['turns_consumed'] == 4
