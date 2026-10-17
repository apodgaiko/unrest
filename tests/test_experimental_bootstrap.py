"""Independent controlled schedules for bounded backend bootstrap compatibility."""
import asyncio
import json
from pathlib import Path
import time

import pytest

from unrest_harness import experimental_session as session
from unrest_harness.experimental_diagnostics import StartupTimeout, startup_timeout
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from tests.test_experimental_startup_diagnostics import ADAPTER, FIXTURE, PROBE, config


from tests.controlled_transport import controlled_transport


@pytest.fixture
def delayed_backend(monkeypatch):
    launch = asyncio.create_subprocess_exec
    environment = session._SessionOwner._environment
    observed = []

    def controlled_environment(self, home):
        value = environment(self, home)
        if self.provider_config is not None:
            value['CODEX_HOME'] = str(self.provider_config.codex_home)
        return value

    def install(delay):
        async def delayed(*args, **kwargs):
            if len(args) > 1 and Path(args[1]).name == 'fake-app-server':
                assert Path(args[1]).read_bytes() == FIXTURE.read_bytes()
                # Actual child readiness delay; no provider/auth/network bootstrap.
                script = ('import runpy,sys,time; p=sys.argv.pop(1); '
                          f'time.sleep({delay!r}); runpy.run_path(p,run_name="__main__")')
                args = (args[0], '-c', script, *args[1:])
            child = await launch(*args, **kwargs)
            observed.append(child)
            return child
        monkeypatch.setattr(asyncio, 'create_subprocess_exec', delayed)
        return observed

    monkeypatch.setattr(session._SessionOwner, '_environment', controlled_environment)
    return install


async def test_actual_thirty_two_second_readiness(tmp_path, monkeypatch, delayed_backend):
    children = delayed_backend(32)
    requests = []
    send = session._TurnClient.send_request
    started = time.monotonic()

    async def observed(self, method, *args, **kwargs):
        requests.append((method, time.monotonic() - started))
        assert method not in ('session/prompt', 'turn/start')
        return await send(self, method, *args, **kwargs)

    monkeypatch.setattr(session._TurnClient, 'send_request', observed)
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    assert children and all(p.returncode is not None for p in children)
    assert result['reservations'] == result['sends'] == 0
    assert not list((tmp_path / 'probe').rglob('trace.jsonl'))
    assert result['outcome'] == 'initialized', result
    assert result['closed'] and result['effective_config_sha256']
    assert 32 <= time.monotonic() - started < 45
    assert next(t for m, t in requests if m == 'session/new') >= 32
    before = result['owner_diagnostics']['pre_cleanup']
    assert before['backends']['worker']['exit_status'] is None
    assert before['adapters']['worker']['exit_status'] is None
    journal = [json.loads(s)['event'] for s in
               (tmp_path / 'probe/initialization-only.jsonl').read_text().splitlines()]
    assert not set(journal) & {'reserve', 'send', 'ack', 'uncertain'}


@pytest.mark.parametrize('boundary', ['near', 'exhausted', 'cancel', 'stop'])
async def test_actual_launch_lifetime_and_interruptions(tmp_path, monkeypatch, delayed_backend, boundary):
    children = delayed_backend(60)
    original = session._SessionOwner.initialize_only
    owners = []

    async def initialize(self, **kwargs):
        owners.append(self)
        if boundary in ('near', 'exhausted'):
            self.ledger._episode_started = self.ledger._clock() - (1799.7 if boundary == 'near' else 1801)
            await original(self, **kwargs)
        else:
            task = asyncio.create_task(original(self, **kwargs))
            while not self.roles:
                await asyncio.sleep(.01)
            if boundary == 'cancel':
                task.cancel()
            else:
                self._revoke(quarantine=True)
            await task

    monkeypatch.setattr(session._SessionOwner, 'initialize_only', initialize)
    started = time.monotonic()
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    assert result['outcome'] == 'attention'
    assert time.monotonic() - started < 15
    assert all(p.returncode is not None for p in children)
    assert result['reservations'] == result['sends'] == 0
    assert owners[0].broker._active is None
    if boundary == 'exhausted':
        assert not children and not owners[0]._launches
    assert not list((tmp_path / 'probe').rglob('trace.jsonl'))


async def test_phases_share_one_deadline_across_tasks():
    started = time.monotonic()
    child = None
    async def phases():
        async with startup_timeout(.3, 'provider_preflight'):
            await asyncio.sleep(.08)
        async with startup_timeout(.3, 'acp_initialize_session'):
            await asyncio.sleep(.08)
    with pytest.raises(StartupTimeout) as caught:
        async with startup_timeout(.12, 'owner_launch'):
            child = asyncio.create_task(phases())
            await asyncio.shield(child)
    assert caught.value.scope == 'owner_launch'
    await asyncio.gather(child, return_exceptions=True)
    assert isinstance(child.exception(), StartupTimeout)
    assert child.exception().scope == 'owner_launch'
    assert .12 <= time.monotonic() - started < .25


def test_absolute_ledger_includes_setup_and_cleanup(tmp_path):
    now = [100.0]
    ledger = PilotLedger(tmp_path / 'ledger', clock=lambda: now[0])
    try:
        ledger.admit('P1')
        now[0] += 21
        assert ledger.lifetime_remaining() == 1779
        now[0] += 7  # Cleanup is elapsed time too; no reset before next admission.
        assert ledger._started == ledger._episode_started == 100
        assert ledger.lifetime_remaining() == 1772
        now[0] = 5500
        with pytest.raises(LeaseRefused):
            ledger.lifetime_remaining()
    finally:
        ledger.close()


async def test_capped_body_free_observation_is_pre_cleanup(tmp_path):
    from types import SimpleNamespace
    owner = object.__new__(session._SessionOwner)
    owner._pre_cleanup = None
    reader = asyncio.StreamReader()
    reader.feed_data(b'PRIVATE_CANARY' * 10000)
    reader.feed_eof()
    process = SimpleNamespace(stderr=reader, stdout=asyncio.StreamReader(), returncode=17)
    backend = SimpleNamespace(process=process, diagnostic_bytes=0, diagnostic_truncated=False)
    owner.backends, owner.roles = {'worker': backend}, {}
    await owner._drain_backend_stderr(backend)
    owner._observe_before_cleanup()
    process.returncode = -15
    owner._observe_before_cleanup()
    value = owner._pre_cleanup['backends']['worker']
    assert value == {'exit_status': 17, 'stdout_eof': False, 'stderr_eof': True,
                     'stderr_bytes': 65536, 'stderr_truncated': True}
    assert 'PRIVATE_CANARY' not in json.dumps(owner._pre_cleanup)


def test_turn_reservation_does_not_restart_clock_after_bootstrap(tmp_path):
    from unrest_harness.experimental_lease import TurnIdentity
    now = [100.0]
    ledger = PilotLedger(tmp_path / 'ledger', clock=lambda: now[0])
    try:
        ledger.admit('P1')
        bound = ledger.turn_deadline()
        now[0] += 21
        identity = TurnIdentity('lane', 'worker', 'node', 'handoff', 'session', 'generation',
                                1, ('a',), '0' * 64)
        ticket = ledger.reserve(identity, deadline=bound)
        assert ledger.remaining(ticket) == 279
        now[0] = 400
        with pytest.raises(LeaseRefused, match='turn_expired'):
            ledger.remaining(ticket)
        # Neither startup nor cleanup grants a fresh 300 seconds.
        assert ledger._turns[ticket][0] == 400
    finally:
        ledger.close()


# This fixture uses the real pinned adapter, owned controlled child and HTTP broker.
from tests.test_experimental_session import session as _owner_fixture  # noqa: E402


@pytest.fixture
def owned_session(tmp_path):
    return _owner_fixture.__wrapped__(tmp_path, None)


async def test_delayed_turn_uses_only_original_remaining_time(owned_session, delayed_backend):
    owner = owned_session
    children = delayed_backend(32)
    await owner.start()
    started = time.monotonic()
    observed = []
    grant = owner.broker.grant
    def ready_grant(*args, **kwargs):
        assert time.monotonic() - started >= 32
        return grant(*args, **kwargs)
    owner.broker.grant = ready_grant
    def before_send():
        ticket = next(k for k, (_, status) in owner.ledger._turns.items() if status == 'reserved')
        remaining = owner.ledger.remaining(ticket)
        observed.append(remaining)
        assert 250 < remaining < 268
    try:
        await owner.turn('worker', on_send=before_send)
        assert observed and time.monotonic() - started >= 32
        events = [json.loads(line) for line in (owner.root / 'journal.jsonl').read_text().splitlines()]
        assert [e['event'] for e in events].count('send') == 1
    finally:
        await owner.close()
    assert children and all(p.returncode is not None for p in children)


@pytest.mark.parametrize('limit', ['turn', 'episode', 'campaign'])
@pytest.mark.parametrize('exhausted', [False, True])
async def test_original_limits_refuse_before_grant_or_send(
        owned_session, delayed_backend, monkeypatch, limit, exhausted):
    owner = owned_session
    children = delayed_backend(60)
    await owner.start()
    now = owner.ledger._clock()
    remaining = -.1 if exhausted else .25
    if limit == 'turn':
        monkeypatch.setattr(owner.ledger, 'turn_deadline', lambda: now + remaining)
    elif limit == 'episode':
        owner.ledger._episode_started = now - 1800 + remaining
    else:
        owner.ledger._started = now - 5400 + remaining
    grants = []
    monkeypatch.setattr(owner.broker, 'grant', lambda *a, **kw: grants.append(True))
    started = time.monotonic()
    with pytest.raises((LeaseRefused, TimeoutError)):
        await owner.turn('worker')
    assert time.monotonic() - started < 15
    assert not grants and owner.ledger.accounting()['campaign'] == 0
    assert all(p.returncode is not None for p in children)
    assert not list(owner.root.rglob('trace.jsonl'))
    if exhausted:
        assert not children and not owner._launches


@pytest.mark.parametrize('point', ['reserve', 'grant', 'send', 'serialize'])
@pytest.mark.parametrize('cause', ['expire', 'stop'])
async def test_boundary_recheck_blocks_expired_or_stopped_send(
        owned_session, monkeypatch, point, cause):
    owner = owned_session
    await owner.start()
    await owner.initialize_only()
    grants = []
    original_grant = owner.broker.grant
    def grant(*args, **kwargs):
        grants.append(True)
        return original_grant(*args, **kwargs)
    monkeypatch.setattr(owner.broker, 'grant', grant)
    def interrupt():
        if cause == 'stop':
            owner._revoke(quarantine=True)
        else:
            clock = owner.ledger._clock
            captured = clock()
            monkeypatch.setattr(owner.ledger, '_clock', lambda: captured + 301)
    if point == 'reserve':
        original = owner.broker.digest
        def digest(*args):
            value = original(*args)
            interrupt()
            return value
        monkeypatch.setattr(owner.broker, 'digest', digest)
    elif point == 'grant':
        original = owner.ledger.reserve
        def reserve(*args, **kwargs):
            ticket = original(*args, **kwargs)
            interrupt()
            return ticket
        monkeypatch.setattr(owner.ledger, 'reserve', reserve)
    elif point == 'serialize':
        dumps = json.dumps
        def serialize(value, *args, **kwargs):
            result = dumps(value, *args, **kwargs)
            if isinstance(value, dict) and value.get('method') == 'session/prompt':
                interrupt()
            return result
        monkeypatch.setattr(json, 'dumps', serialize)
    with pytest.raises(LeaseRefused):
        await owner.turn('worker', on_send=interrupt if point == 'send' else None)
    assert grants == ([True] if point in ('send', 'serialize') else [])
    assert owner.broker._active is None
    assert not list(owner.root.rglob('trace.jsonl'))
    assert all(r.process.returncode is not None for r in owner.roles.values())
    assert all(b.process.returncode is not None for b in owner.backends.values())


async def test_actual_sequential_initialize_and_session_share_cutoff(
        owned_session, monkeypatch):
    owner = owned_session
    await owner.start()
    original = session._TurnClient.send_request
    phases = []
    async def delayed(self, method, *args, **kwargs):
        if method in ('initialize', 'session/new'):
            phases.append(method)
            await asyncio.sleep(.3)
        assert method != 'session/prompt'
        return await original(self, method, *args, **kwargs)
    monkeypatch.setattr(session._TurnClient, 'send_request', delayed)
    monkeypatch.setattr(owner.ledger, 'turn_deadline', lambda: time.monotonic() + .55)
    with pytest.raises(LeaseRefused, match='synthetic_session_quarantined'):
        await owner.turn('worker')
    assert owner.startup_diagnostics['worker'].failure['timer_scope'] == 'owner_launch'
    assert phases == ['initialize', 'session/new']
    assert owner.ledger.accounting()['campaign'] == 0
    assert all(r.process.returncode is not None for r in owner.roles.values())
    assert all(b.process.returncode is not None for b in owner.backends.values())


async def test_startup_subtracts_from_actual_inference_timeout(
        owned_session, delayed_backend, monkeypatch):
    owner = owned_session
    children = delayed_backend(.5)
    await owner.start()
    deadline = time.monotonic() + 2
    monkeypatch.setattr(owner.ledger, 'turn_deadline', lambda: deadline)
    sent = []
    with pytest.raises(LeaseRefused, match='synthetic_session_quarantined'):
        await owner.turn('worker', scenario='stall', on_send=lambda: sent.append(time.monotonic()))
    assert len(sent) == 1
    assert .5 < deadline - sent[0] < 1.5
    assert deadline <= time.monotonic() < deadline + 10
    events = [json.loads(s)['event'] for s in (owner.root / 'journal.jsonl').read_text().splitlines()]
    assert events.count('reserve') == events.count('send') == events.count('uncertain') == 1
    assert all(p.returncode is not None for p in children)
    assert owner.broker._active is None



async def test_expiry_during_seal_cannot_publish_grant(owned_session, monkeypatch):
    from unrest_harness.experimental_lease import TurnIdentity
    owner = owned_session
    identity = TurnIdentity('lane', 'worker', 'node', 'handoff', 'session', 'generation',
                            1, ('a',), owner.broker.digest(('a',)))
    original = owner.broker.seal
    def slow_seal(*args):
        value = original(*args)
        time.sleep(.04)
        return value
    monkeypatch.setattr(owner.broker, 'seal', slow_seal)
    try:
        with pytest.raises(LeaseRefused, match='turn_not_admissible'):
            owner.broker.grant(identity, deadline=time.monotonic() + .02)
        assert owner.broker._active is None and not owner.broker._seen
    finally:
        await owner.close()
