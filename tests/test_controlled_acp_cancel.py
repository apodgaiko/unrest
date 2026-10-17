"""Cancellation on actual controlled ACP/Bridge/backend pipes, never native proof."""
import asyncio
import contextlib
import hashlib
import json
from pathlib import Path

import pytest

from unrest_harness.experimental_lease import LeaseRefused
from tests.test_controlled_python_acp import local_session as local_session, transport as transport


@pytest.fixture
def methods(monkeypatch):
    launch = asyncio.create_subprocess_exec
    observed_methods = []
    class Writer:
        def __init__(self, writer):
            self.writer, self.pending = writer, b''
        def __getattr__(self, name):
            return getattr(self.writer, name)
        def write(self, raw):
            self.pending += raw
            while b'\n' in self.pending:
                line, self.pending = self.pending.split(b'\n', 1)
                frame = json.loads(line)
                if 'method' in frame:
                    observed_methods.append(frame['method'])
            self.writer.write(raw)
    async def observed(*args, **kwargs):
        child = await launch(*args, **kwargs)
        if Path(args[1]).name == 'fake-app-server':
            child.stdin = Writer(child.stdin)
        return child
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observed)
    return observed_methods


@pytest.mark.parametrize('state', ['idle', 'completed', 'active', 'pending'])
async def test_owned_cancel_wire_and_cleanup(local_session, monkeypatch, state, tmp_path, methods):
    from unrest_harness import experimental_session as session
    if state == 'pending':
        source = Path('tests/fixtures/experimental_session_app_server.py').read_text()
        source = source.replace('def emit(value):', "def emit(value):\n    if 'turn' in value.get('result', {}):\n        return")
        fixture = tmp_path / 'pending_backend.py'
        fixture.write_text(source)
        monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(fixture.read_bytes()).hexdigest())
        local_session.ledger.close()
        local_session.broker.close()
        local_session = session.SyntheticSession(tmp_path / 'pending-owner',
            local_session.broker._root, ('a',), adapter=local_session.adapter,
            fixture=fixture, policy=local_session.policy, transport=local_session.transport)
    started = asyncio.Event()
    bridge_start = session.Bridge.start
    async def observed_start(bridge):
        observe = bridge.observe_backend
        buffer = b''
        def observed_backend(raw):
            nonlocal buffer
            if observe:
                observe(raw)
            buffer += raw
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if json.loads(line).get('method') == 'turn/started':
                    started.set()
        bridge.observe_backend = observed_backend
        return await bridge_start(bridge)
    monkeypatch.setattr(session.Bridge, 'start', observed_start)
    turn = None
    await local_session.start()
    await local_session.initialize_only()
    role, backend = local_session.roles['worker'], local_session.backends['worker']
    try:
        if state == 'completed':
            await local_session.turn('worker')
        elif state != 'idle':
            turn = asyncio.create_task(local_session.turn('worker', scenario='stall'))
            async with asyncio.timeout(3):
                await started.wait()
        async with asyncio.timeout(2):
            assert await role.client.send_request('session/cancel', {'sessionId': role.session}) == {}
        assert methods.count('turn/interrupt') == (1 if state in ('active', 'pending') else 0)
        assert methods.count('turn/start') == (0 if state == 'idle' else 1)
        assert (local_session.last_completion is not None) == (state == 'completed')
        assert backend.process.returncode is None
        assert role.process.returncode is None and backend.bridge.connected.is_set()
    finally:
        if turn:
            turn.cancel()
            with contextlib.suppress(asyncio.CancelledError, LeaseRefused):
                await turn
        with contextlib.suppress(LeaseRefused):
            await local_session.close()
    assert backend.process.returncode is not None and role.process.returncode is not None
    assert local_session.broker._active is None
    events = [json.loads(line)['event'] for line in (local_session.root / 'journal.jsonl').read_text().splitlines()]
    assert ('ack' in events) == (state == 'completed')
    if state == 'idle':
        assert not {'reserve', 'send', 'uncertain'} & set(events)
    elif state != 'completed':
        assert 'send' in events and 'uncertain' in events and local_session.quarantined


@pytest.mark.parametrize('identity', ['wrong', 'stale'])
async def test_owned_cancel_wrong_identity_refuses(local_session, identity, tmp_path, methods):
    invalid = 'wrong-session'
    if identity == 'stale':
        from unrest_harness.experimental_session import SyntheticSession
        retired = SyntheticSession(tmp_path / 'retired-owner', local_session.broker._root,
            ('a',), adapter=local_session.adapter,
            fixture=Path('tests/fixtures/experimental_session_app_server.py'),
            policy=local_session.policy, transport=local_session.transport)
        await retired.start()
        try:
            await retired.initialize_only()
            invalid = retired.roles['worker'].session
        finally:
            await retired.close()
        assert all(child.returncode is not None for child in (
            retired.roles['worker'].process, retired.backends['worker'].process))
    await local_session.start()
    await local_session.initialize_only()
    role = local_session.roles['worker']
    assert invalid != role.session
    try:
        with pytest.raises(Exception):
            async with asyncio.timeout(3):
                await role.client.send_request('session/cancel', {
                    'sessionId': invalid})
        async with asyncio.timeout(3):
            await local_session._fault.wait()
        assert local_session.quarantined and local_session.broker._active is None
        assert local_session.last_completion is None
    finally:
        with contextlib.suppress(LeaseRefused):
            await local_session.close()
    assert all(child.returncode is not None for child in (
        role.process, local_session.backends['worker'].process))
    assert not {'turn/start', 'turn/interrupt', 'thread/resume', 'thread/fork'} & set(methods)
    events = [json.loads(line)['event'] for line in (local_session.root / 'journal.jsonl').read_text().splitlines()]
    assert not {'reserve', 'send', 'ack', 'uncertain'} & set(events)
