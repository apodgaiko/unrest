"""Controlled real-process/MCP proof of the public retained lane API."""
import hashlib
import json
from pathlib import Path
import shutil
import time

from fastmcp import Client
import pytest

from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_broker import broker_server
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger, TurnBroker, TurnIdentity, require_provider
from unrest_harness.experimental_session import LeaseLane
from unrest_harness.providers import PROVIDERS

from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing-codex-acp').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'


@pytest.fixture
def setup(tmp_path):
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    (candidate / 'b').write_text('unchanged\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(__file__).parents[1] / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    expected = hashlib.sha256(json.dumps([
        (p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(candidate.iterdir())
    ], separators=(',', ':')).encode()).hexdigest()
    ledger = PilotLedger(tmp_path / 'campaign.jsonl')
    ledger.admit('P3')
    def lane(name='lane', **kwargs):
        return LeaseLane(tmp_path / name, candidate, ('a', 'b'), expected_candidate=expected,
            lane=name, adapter=ADAPTER, policy=policy, ledger=ledger,
            trusted_process=True, fixture=FIXTURE, **kwargs, transport=controlled_transport())
    yield candidate, ledger, lane
    ledger.close()


async def test_retained_correction_rotation_then_one_shot(setup):
    candidate, ledger, factory = setup
    lane = factory()
    results = []
    try:
        for generation in range(3):
            results.append(await lane.turn('worker', 'produce_corrected'))
            results.append(await lane.turn('validator', 'Validate full scope',
                controlled_disposition='reproducible_product_defect' if generation < 2 else 'pass'))
        assert lane.phase == 'passed'
        for offset in (0, 1):
            assert results[offset].identity.session == results[offset + 2].identity.session
            assert results[offset].identity.process_generation == results[offset + 2].identity.process_generation
            assert (results[offset].identity.ordinal, results[offset + 2].identity.ordinal) == (1, 2)
            assert results[offset + 4].identity.process_generation != results[offset].identity.process_generation
            assert results[offset + 4].identity.ordinal == 1
        assert (candidate / 'a').read_text() == 'corrected\n'
        assert (candidate / 'b').read_text() == 'unchanged\n'
        assert all(not owner.quarantined for owner in lane.owners)
        assert not ledger._leases
        assert lane.status()['os_write_isolation'] == 'unverified'
        assert lane.status()['native_approval'] == 'unverified'
        assert lane.status()['final_candidate_timing'] == 'unverified'
        assert lane.status()['enabled_by_default'] is False
        for owner in lane.owners:
            assert all(role.process.returncode is not None for role in owner.roles.values())
            assert all(b.process.returncode is not None for b in owner.backends.values())
    finally:
        await lane.close()


@pytest.mark.parametrize('disposition', ['conflict', 'missing_authority', 'scope_expansion',
                                        'unknown', 'malformed_handoff'])
async def test_noncorrectable_real_mcp_never_correction(setup, disposition):
    _, ledger, factory = setup
    lane = factory()
    await lane.turn('worker', 'fixture')
    with pytest.raises(LeaseRefused, match='noncorrectable'):
        await lane.turn('validator', 'Validate everything', controlled_disposition=disposition)
    assert lane.phase == 'attention'
    with pytest.raises(LeaseRefused):
        await lane.turn('worker', 'try correction')
    assert ledger._counts == {'P3': 2}
    await lane.close()


async def test_second_generation_failure_cannot_correct(setup):
    _, ledger, factory = setup
    lane = factory()
    try:
        for _ in range(2):
            await lane.turn('worker', 'fixture')
            await lane.turn('validator', 'full scope', controlled_disposition='reproducible_product_defect')
        await lane.turn('worker', 'fixture')
        with pytest.raises(LeaseRefused, match='fresh_generation_failed'):
            await lane.turn('validator', 'full scope', controlled_disposition='reproducible_product_defect')
        assert lane.generation == 1 and lane.phase == 'attention'
        assert ledger._counts == {'P3': 6}
    finally:
        await lane.close()


@pytest.mark.parametrize('when', ['before-first', 'parked'])
async def test_retained_expected_never_resnapshots(setup, when):
    candidate, ledger, factory = setup
    lane = factory()
    if when == 'parked':
        await lane.turn('worker', 'fixture')
    (candidate / 'a').write_text('unauthorized\n')
    with pytest.raises(LeaseRefused):
        await lane.turn('worker' if when == 'before-first' else 'validator', 'full scope')
    assert lane.phase == 'attention'
    assert ledger._counts['P3'] == (0 if when == 'before-first' else 1)
    with pytest.raises(LeaseRefused):
        await lane.close()


@pytest.mark.parametrize('operation', ['replace_file', 'complete_turn'])
async def test_active_direct_write_not_blessed_by_mcp(tmp_path, operation):
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base')
    broker = TurnBroker(candidate, tmp_path / 'records')
    identity = TurnIdentity('lane', 'worker', 'child', 'handoff', 'session', 'process',
                            1, ('a',), broker.digest(('a',)))
    token = broker.grant(identity, deadline=time.monotonic() + 30)
    (candidate / 'a').write_text('direct-write')
    from dataclasses import asdict
    wire = {**asdict(identity), 'scope': list(identity.scope)}
    args = {'capability': token, 'turn': wire}
    args.update({'name': 'a', 'content': 'attempt-to-hide'} if operation == 'replace_file' else
                {'candidate': broker.digest(('a',)), 'disposition': 'sealed'})
    async with Client(broker_server(broker, 'connection-' * 8)) as client:
        with pytest.raises(Exception, match='unexpected_candidate_mutation'):
            await client.call_tool(operation, args)
    assert broker.quarantined and broker._active is None
    assert not list((tmp_path / 'records').iterdir())
    assert (candidate / 'a').read_text() == 'direct-write'
    broker.close()


def identity(ordinal):
    return TurnIdentity('lane', 'worker', 'child', 'handoff', 'session', 'process',
                        ordinal, ('a',), '0' * 64)


def test_shared_24_turn_clock_concurrency_and_final_reservation(tmp_path):
    now = [0.0]
    ledger = PilotLedger(tmp_path / 'campaign', clock=lambda: now[0], capacity=9)
    try:
        ordinal = 0
        for episode, maximum in ledger.maxima.items():
            ledger.admit(episode)
            tickets = []
            for _ in range(min(4, maximum - 2)):
                ordinal += 1
                tickets.append(ledger.reserve(identity(ordinal)))
            with pytest.raises(LeaseRefused):
                ledger.reserve(identity(ordinal + 1))
            for ticket in tickets:
                ledger.sent(ticket)
                ledger.finish(ticket)
            for _ in range(maximum - 2 - len(tickets)):
                ordinal += 1
                ticket = ledger.reserve(identity(ordinal))
                ledger.sent(ticket)
                ledger.finish(ticket)
            with pytest.raises(LeaseRefused, match='budget'):
                ledger.reserve(identity(ordinal + 1))
            for _ in range(2):
                ordinal += 1
                ticket = ledger.reserve(identity(ordinal), final=True)
                ledger.sent(ticket)
                ledger.finish(ticket)
            ledger.close_episode()
            now[0] += 1000
        assert ordinal == 24 and sum(ledger._counts.values()) == 24
        assert ledger._started == 0
        now[0] = 5400
        with pytest.raises(LeaseRefused, match='campaign_stopped'):
            ledger.available()
    finally:
        ledger.close()
    with pytest.raises(FileExistsError):
        PilotLedger(tmp_path / 'campaign')


def test_ambiguous_concurrent_send_stops_other_reservations(tmp_path):
    ledger = PilotLedger(tmp_path / 'campaign')
    ledger.admit('C1')
    one, two = ledger.reserve(identity(1)), ledger.reserve(identity(2))
    ledger.sent(one)
    ledger.finish(one, ambiguous=True)
    with pytest.raises(LeaseRefused):
        ledger.sent(two)
    ledger.finish(two, ambiguous=True)
    assert ledger._counts['C1'] == 2
    ledger.close()


def test_missing_controls_and_budget_rejected_before_admission(tmp_path):
    for provider in ('claude', 'other'):
        with pytest.raises(LeaseRefused, match='unsupported_provider'):
            require_provider(provider, trusted_process=True, controls=True)
    with pytest.raises(LeaseRefused, match='opt_in_required'):
        require_provider('codex')
    with pytest.raises(LeaseRefused, match='retained_controls'):
        require_provider('codex', trusted_process=True)
    ledger = PilotLedger(tmp_path / 'journal')
    with pytest.raises(LeaseRefused, match='turn_not_admissible'):
        require_provider('codex', trusted_process=True, controls=True, ledger=ledger)
    ledger.admit('P1')
    ledger.stop()
    with pytest.raises(LeaseRefused, match='campaign_stopped'):
        require_provider('codex', trusted_process=True, controls=True, ledger=ledger)
    ledger.close()


async def test_missing_completion_consumes_campaign_and_reaps(setup):
    _, ledger, factory = setup
    lane = factory()
    with pytest.raises(LeaseRefused):
        await lane.turn('worker', 'fixture', controlled_scenario='missing_completion')
    assert ledger._counts['P3'] == 1
    assert ledger._halted
    assert all(p.process.returncode is not None for owner in lane.owners for p in owner.backends.values())
    with pytest.raises(LeaseRefused):
        await lane.close()


def test_retained_session_capacity_does_not_reset_on_episode(tmp_path):
    ledger = PilotLedger(tmp_path / 'journal')
    ledger.admit('C1')
    claims = [ledger.claim_session() for _ in range(4)]
    with pytest.raises(LeaseRefused, match='retained_session_capacity'):
        ledger.claim_session()
    for claim in claims:
        ledger.release_session(claim)
    ledger.close()


async def test_two_independent_controlled_lanes_share_campaign_capacity(tmp_path):
    import asyncio
    ledger = PilotLedger(tmp_path / 'campaign')
    ledger.admit('C1')
    lanes = []
    for name in ('a', 'b'):
        candidate = tmp_path / f'candidate-{name}'
        candidate.mkdir()
        (candidate / 'a').write_text('base\n')
        expected = hashlib.sha256(json.dumps([
            ('a', hashlib.sha256(b'base\n').hexdigest())], separators=(',', ':')).encode()).hexdigest()
        policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
            policy=load_capability_policy(Path(__file__).parents[1] / 'src/unrest_harness/bundled'),
            profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
        lanes.append(LeaseLane(tmp_path / name, candidate, ('a',), expected_candidate=expected,
            lane=name, adapter=ADAPTER, policy=policy, ledger=ledger,
            trusted_process=True, fixture=FIXTURE, transport=controlled_transport()))
    try:
        await asyncio.gather(*(lane.turn('worker', 'produce_corrected') for lane in lanes))
        assert len(ledger._leases) == 2
        await asyncio.gather(*(lane.turn('validator', 'full scope') for lane in lanes))
        assert ledger._counts == {'C1': 4}
        assert all(lane.phase == 'passed' for lane in lanes)
        assert not ledger._leases
        with pytest.raises(LeaseRefused, match='budget'):
            ledger.available()
        ledger.available(final=True)
    finally:
        for lane in lanes:
            await lane.close()
        ledger.close()


async def test_real_construction_uses_supported_subscription_environment_without_launch(setup, monkeypatch):
    _, _, factory = setup
    lane = factory()
    # Only environment construction: never launch real Codex or read auth files.
    monkeypatch.setenv('HOME', '/private/tmp/subscription-home-fixture')
    monkeypatch.setenv('CODEX_CONFIG', '{"model":"unwanted", "features":{}}')
    owner = await lane._start()
    owner.controlled = False
    role_home = owner.root / 'worker'
    env = owner._environment(role_home)
    assert env['HOME'] == '/private/tmp/subscription-home-fixture'
    assert env['CODEX_PATH'] == str(owner.launcher)
    config = json.loads(env['CODEX_CONFIG'])
    assert config['model'] == 'gpt-6-astra'
    assert config['model_reasoning_effort'] == 'medium'
    assert config['forced_login_method'] == 'chatgpt'
    assert config['sandbox_mode'] == 'read-only'
    assert config['sqlite_home'] == str(role_home / 'sqlite')
    assert config['log_dir'] == str(role_home / 'logs')
    assert env['TMPDIR'] == str(role_home / 'tmp')
    assert not config['features']['shell_tool']
    assert env['INITIAL_AGENT_MODE'] == 'read-only'
    assert not owner.roles and not owner.backends
    await lane.close()


async def test_signal_failure_requires_actual_wait_confirmation(setup, monkeypatch):
    import unrest_harness.experimental_session as module
    _, _, factory = setup
    lane = factory()
    owner = await lane._start()
    class Process:
        pid = 424242
        returncode = None
        waits = 0
        async def wait(self):
            self.waits += 1
            self.returncode = 0
            return 0
    process = Process()
    def failed_signal(*args):
        raise PermissionError('exited group race')
    monkeypatch.setattr(module.os, 'killpg', failed_signal)
    await owner._reap(process)
    assert process.waits == 1 and process.returncode == 0
    assert not owner.quarantined
    await lane.close()


@pytest.mark.parametrize('selection', [False, 'false', 'true', 1, None])
def test_opt_in_requires_actual_boolean(selection):
    with pytest.raises(LeaseRefused, match='opt_in_required'):
        require_provider('codex', trusted_process=selection, controls=True)
