"""Controlled initial-exchange boundaries with independently bounded phase schedules."""
import asyncio
import json
import time

import pytest

from unrest_harness.experimental_diagnostics import (
    StartupDiagnostics, StartupTimeout, startup_timeout,
)
from unrest_harness.experimental_provider_config import ProviderConfig
from unrest_harness.experimental_session import _SessionOwner


class Writer:
    def __init__(self, *, stall=False, fail=False):
        self.frames = []
        self.stall = stall
        self.fail = fail

    def write(self, raw):
        self.frames.append(raw)
        if self.fail:
            raise BrokenPipeError('PRIVATE_CANARY')

    async def drain(self):
        if self.stall:
            await asyncio.Event().wait()


@pytest.mark.parametrize('boundary', ['frame', 'write', 'response'])
@pytest.mark.parametrize('outcome', ['timeout', 'failure', 'cancel'])
async def test_initial_exchange_boundaries(tmp_path, monkeypatch, boundary, outcome):
    config = ProviderConfig(codex_home=tmp_path / 'home', user_home=tmp_path / 'user',
                            cwd=tmp_path, ambient={}, system=tmp_path / 'system')
    diagnostic = StartupDiagnostics()
    adapter, backend = asyncio.StreamReader(), asyncio.StreamReader()
    incoming = b'{"id":"PRIVATE_CANARY","method":"initialize","params":{}}\n'
    if boundary != 'frame':
        adapter.feed_data(incoming)
    writer = Writer(stall=boundary == 'write' and outcome != 'failure',
                    fail=boundary == 'write' and outcome == 'failure')
    if outcome == 'failure':
        if boundary == 'frame':
            adapter.feed_data(b'{"id":"PRIVATE_CANARY","method":"wrong"}\n')
        elif boundary == 'response':
            backend.feed_data(b'{"id":"wrong_PRIVATE_CANARY","result":{}}\n')

    async def run():
        try:
            async with startup_timeout(.1, 'owner_launch'):
                await config.admit_bridge(adapter, Writer(), backend, writer, tmp_path, diagnostic.phase)
        except BaseException as error:
            diagnostic.fail(error)
            raise

    started = time.monotonic()
    task = asyncio.create_task(run())
    if outcome == 'cancel':
        while f'initialize_{boundary}_wait' not in diagnostic.events:
            await asyncio.sleep(0)
        task.cancel()
    with pytest.raises(BaseException) as caught:
        await task
    if outcome == 'timeout':
        assert isinstance(caught.value, StartupTimeout)
        assert caught.value.scope == 'owner_launch'
        assert .1 <= time.monotonic() - started < 2
    elif outcome == 'cancel':
        assert isinstance(caught.value, asyncio.CancelledError)
        assert 'timer_scope' not in diagnostic.failure
    else:
        assert not isinstance(caught.value, (TimeoutError, asyncio.CancelledError))
    expected = f'initialize_{boundary}_wait'
    assert diagnostic.failure['stage'] == expected
    assert ('initialize_frame_received' in diagnostic.events) == (boundary != 'frame')
    assert ('initialize_write_complete' in diagnostic.events) == (boundary == 'response')
    assert 'initialize_response_received' not in diagnostic.events
    assert writer.frames == ([] if boundary == 'frame' else [incoming])
    assert not config.effective_digests
    assert 'PRIVATE_CANARY' not in json.dumps(diagnostic.snapshot())


async def test_matching_response_marker_precedes_config_request(tmp_path):
    config = ProviderConfig(codex_home=tmp_path / 'home', user_home=tmp_path / 'user',
                            cwd=tmp_path, ambient={}, system=tmp_path / 'system')
    d = StartupDiagnostics()
    adapter, backend = asyncio.StreamReader(), asyncio.StreamReader()
    adapter.feed_data(b'{"id":7,"method":"initialize"}\n')
    backend.feed_data(b'{"id":7,"result":{}}\n')
    backend.feed_eof()
    writer = Writer()
    with pytest.raises(Exception):
        async with startup_timeout(.1, 'owner_launch'):
            await config.admit_bridge(adapter, Writer(), backend, writer, tmp_path, d.phase)
    assert d.events == ['preflight_initialize', 'initialize_frame_wait',
        'initialize_frame_received', 'initialize_write_wait', 'initialize_write_complete',
        'initialize_response_wait', 'initialize_response_received', 'config_read']
    assert [json.loads(raw)['method'] for raw in writer.frames] == ['initialize', 'config/read']


@pytest.mark.parametrize('mode', ['nested', 'foreign', 'cancel'])
async def test_timer_ownership_not_inferred_from_exception_or_shared_stage(mode):
    d = StartupDiagnostics()
    d.phase('acp_initialize')

    async def sibling():
        d.phase('initialize_response_wait')

    await asyncio.create_task(sibling())
    try:
        async with startup_timeout(5, 'acp_initialize_session'):
            if mode == 'nested':
                async with startup_timeout(0, 'provider_preflight'):
                    await asyncio.sleep(1)
            elif mode == 'foreign':
                raise TimeoutError('PRIVATE_CANARY')
            else:
                raise asyncio.CancelledError('PRIVATE_CANARY')
    except BaseException as error:
        d.fail(error)
    assert d.failure['stage'] == 'acp_initialize'
    if mode == 'nested':
        assert d.failure['timer_scope'] == 'provider_preflight'
    else:
        assert 'timer_scope' not in d.failure
    assert d.failure['category'] == ('cancelled' if mode == 'cancel' else 'timeout')
    assert 'PRIVATE_CANARY' not in json.dumps(d.snapshot())


@pytest.mark.parametrize('cancel', [False, True])
async def test_actual_enclosing_launch_scope_preserves_shielded_owner(cancel):
    class Ledger:
        def remaining_until(self, deadline):
            return .1

    owner = object.__new__(_SessionOwner)
    owner.startup_diagnostics = {}
    owner._launches = set()
    owner.ledger = Ledger()
    owner._fault = asyncio.Event()
    owner.stopped = False
    entered = asyncio.Event()
    release = asyncio.Event()

    async def open_role(name):
        owner.startup_diagnostics[name].phase('initialize_response_wait')
        entered.set()
        await release.wait()

    owner._open_role = open_role
    owner._launch_finished = lambda task: None
    task = asyncio.create_task(owner._launch_role('worker', time.monotonic() + .1))
    await entered.wait()
    if cancel:
        task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError if cancel else StartupTimeout):
            await task
        d = owner.startup_diagnostics['worker'].snapshot()
        assert d['failure']['stage'] == 'owner_launch'
        if cancel:
            assert 'timer_scope' not in d['failure']
        else:
            assert d['failure']['timer_scope'] == 'owner_launch'
        assert all(not t.done() for t in owner._launches)
    finally:
        release.set()
        await asyncio.gather(*owner._launches)


@pytest.mark.parametrize('failure', ['drain', 'eof', 'malformed'])
async def test_failed_drain_or_response_never_claims_completion(tmp_path, failure):
    config = ProviderConfig(codex_home=tmp_path / 'home', user_home=tmp_path / 'user',
                            cwd=tmp_path, ambient={}, system=tmp_path / 'system')
    d = StartupDiagnostics()
    adapter, backend = asyncio.StreamReader(), asyncio.StreamReader()
    adapter.feed_data(b'{"id":7,"method":"initialize"}\n')
    writer = Writer()
    if failure == 'drain':
        async def failed_drain():
            raise ConnectionResetError('PRIVATE_CANARY')
        writer.drain = failed_drain
    elif failure == 'eof':
        backend.feed_eof()
    else:
        backend.feed_data(b'PRIVATE_CANARY\n')
    try:
        async with startup_timeout(.1, 'owner_launch'):
            await config.admit_bridge(adapter, Writer(), backend, writer, tmp_path, d.phase)
    except Exception as error:
        d.fail(error)
    assert d.failure['stage'] == ('initialize_write_wait' if failure == 'drain'
                                  else 'initialize_response_wait')
    assert 'timer_scope' not in d.failure
    assert 'initialize_response_received' not in d.events
    assert ('initialize_write_complete' in d.events) == (failure != 'drain')
    assert 'PRIVATE_CANARY' not in json.dumps(d.snapshot())
