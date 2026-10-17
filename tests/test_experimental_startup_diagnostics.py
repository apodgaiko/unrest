"""Controlled-only diagnostics; never launch a real backend or call a model."""
import asyncio
import json
from pathlib import Path
import runpy
import shutil
import time

import pytest

from unrest_harness.experimental_diagnostics import StartupDiagnostics, category
from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_provider_config import ProviderConfig
from unrest_harness.experimental_session import _SessionOwner

from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'
PROBE = runpy.run_path(str(Path(__file__).parents[1] / 'tools/probe_v046_startup.py'))['probe']


@pytest.fixture(autouse=True)
def controlled_config_home(monkeypatch):
    original = _SessionOwner._environment

    def environment(self, home):
        value = original(self, home)
        if self.controlled and self.provider_config is not None:
            # Match the declared synthetic layer; never use subscription files.
            value['CODEX_HOME'] = str(self.provider_config.codex_home)
        return value

    monkeypatch.setattr(_SessionOwner, '_environment', environment)


def config(tmp_path):
    return ProviderConfig(codex_home=tmp_path / 'subscription', user_home=tmp_path / 'user',
                          cwd=tmp_path / 'probe', ambient={}, system=tmp_path / 'system')


@pytest.mark.parametrize('error,expected', [
    (TimeoutError('PRIVATE_CANARY'), 'timeout'),
    (PermissionError('PRIVATE_CANARY'), 'permission_denied'),
    (LeaseRefused('PRIVATE_CANARY'), 'lease_refused'),
    (LeaseRefused('provider_protocol_invalid'), 'provider_protocol_invalid'),
    (RuntimeError('PRIVATE_CANARY'), 'exception'),
])
def test_fixed_vocabulary_first_failure_cleanup_separation(error, expected):
    diagnostic = StartupDiagnostics()
    diagnostic.phase('config_read')
    diagnostic.fail(error)
    diagnostic.phase('owner_cleanup')
    diagnostic.fail(OSError('PRIVATE_CANARY'), cleanup=True)
    diagnostic.fail(RuntimeError('PRIVATE_CANARY'))
    for _ in range(100):
        diagnostic.phase('PRIVATE_CANARY')
        diagnostic.fail(LeaseRefused('PRIVATE_CANARY'), cleanup=True)
    assert diagnostic.failure == {'stage': 'config_read', 'category': expected}
    assert len(diagnostic.events) == 32
    assert len(diagnostic.cleanup) <= 16
    assert 'PRIVATE_CANARY' not in json.dumps(diagnostic.snapshot())
    assert category(type('PRIVATE_CANARY', (Exception,), {})()) == 'exception'


async def test_initialization_probe_real_controlled_path_no_prompt(tmp_path, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError('prompt path entered')
    monkeypatch.setattr(_SessionOwner, 'turn', forbidden)
    launch = asyncio.create_subprocess_exec
    methods = []

    class ObservedWriter:
        def __init__(self, writer):
            self.writer = writer
            self.pending = b''

        def __getattr__(self, name):
            return getattr(self.writer, name)

        def write(self, raw):
            self.pending += raw
            while b'\n' in self.pending:
                line, self.pending = self.pending.split(b'\n', 1)
                method = json.loads(line).get('method')
                if method is not None:
                    methods.append(method)
                    assert method not in ('turn/start', 'session/prompt', 'thread/resume', 'thread/fork')
            self.writer.write(raw)

    async def observed_launch(*args, **kwargs):
        child = await launch(*args, **kwargs)
        if len(args) > 1 and Path(args[1]).name == 'fake-app-server':
            assert Path(args[1]).read_bytes() == FIXTURE.read_bytes()
            child.stdin = ObservedWriter(child.stdin)
        return child

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observed_launch)
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    (tmp_path / 'startup-result.json').write_text(json.dumps(result, sort_keys=True))
    assert result['outcome'] == 'initialized', json.dumps(result, sort_keys=True)
    assert result['effective_config_sha256']
    assert methods[:4] == ['initialize', 'config/read', 'configRequirements/read', 'account/read']
    assert set(methods) <= {'initialize', 'initialized', 'config/read', 'configRequirements/read',
                            'account/read', 'skills/list', 'thread/start', 'thread/unsubscribe', 'model/list'}
    phases = result['owner_diagnostics']['roles']['worker']['events']
    assert phases[phases.index('preflight_initialize'):phases.index('config_read')] == [
        'preflight_initialize', 'initialize_frame_wait', 'initialize_frame_received',
        'initialize_write_wait', 'initialize_write_complete', 'initialize_response_wait',
        'initialize_response_received']
    assert result['served_identity'] == {'model': 'gpt-6-astra', 'modelProvider': 'openai',
                                         'reasoningEffort': 'medium'}
    assert result['closed'] and result['owned_reaped']
    assert result['reservations'] == result['sends'] == result['provider_turns'] == 0
    events = [json.loads(line)['event'] for line in
              (tmp_path / 'probe/initialization-only.jsonl').read_text().splitlines()]
    assert not set(events) & {'reserve', 'send', 'ack', 'uncertain'}
    assert not list((tmp_path / 'probe').rglob('trace.jsonl'))
    repeated = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                           fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    assert repeated['outcome'] == 'attention' and 'owner_diagnostics' not in repeated


@pytest.mark.parametrize('mode', ['refusal', 'timeout', 'permission'])
async def test_bridge_failure_preserved_through_owned_close(tmp_path, monkeypatch, mode):
    configuration = config(tmp_path)
    if mode == 'timeout':
        from unrest_harness.experimental_lease import PilotLedger
        monkeypatch.setattr(PilotLedger, 'turn_deadline', lambda self: self._clock() + 3)
    if mode == 'refusal':
        def refuse(*args):
            raise LeaseRefused('PRIVATE_CANARY')
        monkeypatch.setattr(configuration, 'verify_effective', refuse)
    else:
        original = configuration.admit_bridge
        async def fail(*args):
            if mode == 'permission':
                args[-1]('config_read')
                raise PermissionError('PRIVATE_CANARY')
            # Stall the actual read until the shortened original cutoff expires.
            reader = asyncio.StreamReader()
            await original(args[0], args[1], reader, args[3], args[4], args[5])
        monkeypatch.setattr(configuration, 'admit_bridge', fail)
    started = time.monotonic()
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=configuration, transport=controlled_transport())
    elapsed = time.monotonic() - started
    assert elapsed < 12
    if mode == 'timeout':
        assert elapsed >= 3
    assert result['outcome'] == 'attention' and result['owned_reaped']
    diagnostic = result['owner_diagnostics']['roles']['worker']
    assert diagnostic['failure']['category'] == {
        'refusal': 'lease_refused', 'timeout': 'timeout', 'permission': 'permission_denied'}[mode]
    if mode != 'timeout':
        assert diagnostic['failure']['stage'] == {
            'refusal': 'effective_verify', 'permission': 'config_read'}[mode]
    if mode == 'timeout':
        # Owner, ACP and bridge timers share the exact absolute cutoff. The
        # first expired observer retains its task-local phase, including bridge
        # response wait; all three timers still carry owner_launch provenance.
        assert diagnostic['failure']['stage'] in (
            'owner_launch', 'acp_initialize', 'initialize_response_wait')
        assert diagnostic['failure']['timer_scope'] == 'owner_launch'
        assert 'initialize_response_wait' in diagnostic['events']
    assert result['effective_config_sha256'] is None
    assert result['reservations'] == result['sends'] == 0
    assert 'PRIVATE_CANARY' not in json.dumps(result)
    assert result['deadlines_seconds']['setup_total'] == 300


async def test_broker_start_preserves_primary_over_cleanup(tmp_path, monkeypatch):
    from unrest_harness import experimental_session as session

    def refused(*args, **kwargs):
        raise PermissionError('PRIVATE_CANARY')

    monkeypatch.setattr(session, 'broker_server', refused)
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    assert result['diagnostics']['failure']['category'] == 'permission_denied'
    owner = result['owner_diagnostics']['owner']
    assert owner['failure'] == {'stage': 'broker_start', 'category': 'permission_denied'}
    assert owner['cleanup_errors']
    assert result['owner_diagnostics']['roles'] == {}
    assert result['outcome'] == 'attention' and result['owned_reaped']
    assert 'PRIVATE_CANARY' not in json.dumps(result)


async def test_initialized_owner_has_no_http_mutation_authority(tmp_path, monkeypatch):
    from dataclasses import asdict
    from fastmcp import Client
    from unrest_harness.experimental_lease import TurnIdentity
    from unrest_harness.experimental_session import _TurnClient

    initialize = _SessionOwner.initialize_only
    request = _TurnClient.send_request
    methods = []

    async def observed_request(self, method, *args, **kwargs):
        methods.append(method)
        assert method not in ('session/prompt', 'turn/start')
        return await request(self, method, *args, **kwargs)

    async def check(self, **kwargs):
        await initialize(self, **kwargs)
        assert self.broker._active is None
        async with Client(self.url, auth=self._connection) as client:
            identity = TurnIdentity('initialization-only', 'worker', 'child', 'handoff',
                                    'ungranted', 'ungranted', 1, ('a',), '0' * 64)
            reply = await client.call_tool('replace_file', {
                'turn': asdict(identity), 'capability': 'PRIVATE_CANARY',
                'name': 'a', 'content': 'PRIVATE_CANARY'}, raise_on_error=False)
            assert reply.is_error
        with pytest.raises(Exception):
            async with Client(self.url, auth='invalid-connection-token') as client:
                await client.list_tools()
        assert (self.broker._root / 'a').read_bytes() == b'base\n'
        assert not self.ledger._turns

    monkeypatch.setattr(_TurnClient, 'send_request', observed_request)
    monkeypatch.setattr(_SessionOwner, 'initialize_only', check)
    result = await PROBE(tmp_path / 'probe', ADAPTER, None, trusted_process=True,
                         fixture=FIXTURE, configuration=config(tmp_path), transport=controlled_transport())
    assert 'session/new' in methods and 'initialize' in methods
    assert result['outcome'] == 'initialized', json.dumps(result)
    assert result['owned_reaped'] and result['closed']
    assert 'PRIVATE_CANARY' not in json.dumps(result)


async def test_coordinator_persists_startup_and_separate_cleanup_failure(tmp_path, monkeypatch):
    from unrest_harness import experimental_cohort as cohort
    from unrest_harness.experimental_relay import Bridge

    async def denied(self):
        raise PermissionError('PRIVATE_CANARY')

    monkeypatch.setattr(Bridge, 'start', denied)
    result = await cohort.campaign(tmp_path / 'campaign', trusted_process=True,
        adapter=ADAPTER, fixture=FIXTURE, package=None, episodes=('P1',), transport=controlled_transport())
    status = result['episodes']['P1']
    assert status['outcome'] == 'attention'
    assert status['turns_consumed'] == 1 and status['final_turns_consumed'] == 0
    states = list((tmp_path / 'campaign').rglob('state.json'))
    assert len(states) == 1
    saved = json.loads(states[0].read_text())
    diagnostic = saved['diagnostics']
    assert diagnostic['coordinator']['failure']['category'] == 'permission_denied'
    owner = diagnostic['owners'][0]
    assert owner['roles']['worker']['failure'] == {
        'stage': 'bridge_listen', 'category': 'permission_denied'}
    assert owner['owner']['cleanup_errors'] and saved['cleanup_errors']
    assert not list((tmp_path / 'campaign').rglob('received.jsonl'))
    assert not list((tmp_path / 'campaign').rglob('broker-observations.jsonl'))
    assert not any(e['event'] == 'completion' for e in saved['events'])
    assert 'PRIVATE_CANARY' not in json.dumps(result) + json.dumps(saved)
