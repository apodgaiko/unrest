"""Actual StreamReader boundaries and controlled owner diagnostic privacy."""
import asyncio
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from unrest_harness.experimental_diagnostics import StartupDiagnostics, startup_timeout
from unrest_harness.experimental_lease import LeaseRefused
from tests.test_experimental_provider_config import configuration, effective_fixture

from tests.controlled_transport import controlled_transport

CANARY = 'PRIVATE_ADMISSION_BOUND_CANARY'


def wire(value):
    return (json.dumps(value) + '\n').encode()


def padded(raw, length):
    assert len(raw) <= length
    return raw[:-1] + b' ' * (length - len(raw)) + b'\n'


def warning(length=None):
    raw = wire({'method': 'configWarning', 'params': {'summary': CANARY}})
    return padded(raw, length) if length else raw


class Writer:
    def __init__(self):
        self.frames = []

    def write(self, raw):
        self.frames.append(raw)

    async def drain(self):
        await asyncio.sleep(0)


@pytest.mark.parametrize('side', ['adapter', 'backend'])
@pytest.mark.parametrize('length,newline,limit,category', [
    (65535, True, 65536, None),
    (65536, True, 65536, None),
    (65537, True, 65536, 'frame_bound'),
    (65538, True, 65536, 'reader_limit'),
    (65537, True, 131072, 'frame_bound'),
    (0, False, 65536, 'eof'),
    (1, False, 65536, 'unterminated_frame'),
    (65536, False, 65536, 'unterminated_frame'),
    (65537, False, 65536, 'reader_limit'),
    (65537, False, 131072, 'unterminated_frame'),
])
async def test_actual_reader_newline_eof_and_fragment(tmp_path, side, length, newline, limit, category):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    results = effective_fixture(config, role)
    initial = wire({'id': 1, 'method': 'initialize', 'params': {}})
    reply = wire({'id': 1, 'result': {}})
    raw = padded(initial if side == 'adapter' else reply, length) if newline else b'x' * length
    ar, br = asyncio.StreamReader(limit=limit), asyncio.StreamReader(limit=limit)
    aw, bw = Writer(), Writer()
    if side == 'backend':
        ar.feed_data(initial)
    async def admit():
        async with startup_timeout(2, 'owner_launch'):
            await config.admit_bridge(ar, aw, br, bw, role)
    task = asyncio.create_task(admit())
    # Deliver a fragment without a newline: readline must remain pending.
    reader = ar if side == 'adapter' else br
    reader.feed_data(raw[:min(7, len(raw))])
    await asyncio.sleep(0)
    assert not task.done() and not aw.frames
    reader.feed_data(raw[min(7, len(raw)):])
    if not newline:
        reader.feed_eof()
    if category is None:
        if side == 'adapter':
            br.feed_data(reply)
        for method, result in zip(('config/read', 'configRequirements/read', 'account/read'), results):
            br.feed_data(wire({'id': 'unrest-preflight-' + method, 'result': result}))
    try:
        async with startup_timeout(2, 'owner_launch'):
            if category:
                with pytest.raises(LeaseRefused) as caught:
                    await task
                assert str(caught.value) == 'provider_configuration_' + category
                assert not aw.frames and not config.effective_digests
            else:
                await task
                assert aw.frames == [raw if side == 'backend' else reply]
                assert len(bw.frames) == 4
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('count,total,tail,expected', [
    (31, None, 'normal', None), (32, None, 'normal', None),
    (33, None, 'normal', 'frame_count_bound'),
    (10, 262143, 'normal', None), (10, 262144, 'normal', None),
    (10, 262145, 'normal', 'aggregate_bound'),
    (33, 262145, 'normal', 'frame_count_bound'),
    (33, 262145, 'frame', 'frame_count_bound'),
    (33, 262145, 'fragment', 'unterminated_frame'),
    (33, 262145, 'reader', 'reader_limit'),
    (33, None, 'eof', 'eof'),
])
async def test_shared_counters_across_replies_notifications_and_priority(tmp_path, count, total, tail, expected):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    results = effective_fixture(config, role)
    initial = wire({'id': 1, 'method': 'initialize', 'params': {}})
    replies = [wire({'id': 1, 'result': {}})] + [
        wire({'id': 'unrest-preflight-' + m, 'result': r})
        for m, r in zip(('config/read', 'configRequirements/read', 'account/read'), results)]
    # Five mandatory frames include the adapter request. Spread the rest across
    # all reply phases so per-request or per-direction counter resets would pass.
    chunks = [[reply] for reply in replies]
    for i in range(count - 5):
        chunks[i % 4].insert(0, warning())
    frames = [initial] + [raw for chunk in chunks for raw in chunk]
    if tail in ('frame', 'fragment', 'reader'):
        frames[-1] = padded(frames[-1], 65538 if tail == 'reader' else 65537)
        if tail == 'fragment':
            frames[-1] = frames[-1][:-1] + b' '
    elif tail == 'eof':
        frames[-1] = b''
    if total:
        extra = total - sum(map(len, frames))
        # Pad only notification JSON whitespace, never weaken schema validation.
        for i in range(1, len(frames) - 1):
            if b'configWarning' in frames[i]:
                addition = min(extra, 65536 - len(frames[i]))
                frames[i] = padded(frames[i], len(frames[i]) + addition)
                extra -= addition
        assert extra == 0 and sum(map(len, frames)) == total
    ar = asyncio.StreamReader()
    br = asyncio.StreamReader(limit=131072 if tail == 'fragment' else 65536)
    aw, bw = Writer(), Writer()
    ar.feed_data(frames[0])
    br.feed_data(b''.join(frames[1:]))
    br.feed_eof()
    async with startup_timeout(2, 'owner_launch'):
        if expected:
            with pytest.raises(LeaseRefused) as caught:
                await config.admit_bridge(ar, aw, br, bw, role)
            assert str(caught.value) == 'provider_configuration_' + expected
            assert not aw.frames and not config.effective_digests
        else:
            await config.admit_bridge(ar, aw, br, bw, role)
            assert len(bw.frames) == 4
            assert aw.frames == [b''.join(raw for raw in frames[1:]
                                          if b'configWarning' in raw or raw == replies[0])]


@pytest.mark.parametrize('category', ['reader_limit', 'eof', 'unterminated_frame',
                                     'frame_bound', 'frame_count_bound', 'aggregate_bound'])
async def test_owner_adapter_bound_privacy_first_failure_cleanup_no_send(tmp_path, monkeypatch, category, capfd):
    from unrest_harness import experimental_session as session
    from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
    from unrest_harness.providers import PROVIDERS

    root = Path(__file__).resolve().parents[1]
    frames = {
        'reader_limit': warning(262145), 'eof': b'',
        'unterminated_frame': warning()[:-1], 'frame_bound': warning(65537),
        'frame_count_bound': warning() * 32, 'aggregate_bound': warning(65536) * 4,
    }
    source = (root / 'tests/fixtures/experimental_session_app_server.py').read_text()
    # Replace only the config/read response on a pinned controlled backend.
    injection = ("        if method == 'config/read':\n"
                 "            sys.stderr.write(" + repr(CANARY) + ")\n"
                 "            sys.stderr.flush()\n"
                 "            sys.stdout.buffer.write(" + repr(frames[category]) + ")\n"
                 "            sys.stdout.buffer.flush()\n"
                 "            return\n")
    source = source.replace("        emit({'id': request['id'], 'result': result})",
                            injection + "        emit({'id': request['id'], 'result': result})")
    fixture = tmp_path / 'backend.py'
    fixture.write_text(source)
    monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(fixture.read_bytes()).hexdigest())
    config = configuration(tmp_path)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(root / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    owner = session._SessionOwner(tmp_path / 'campaign/owner', candidate, ('a',),
        adapter=Path(shutil.which('codex-acp')).resolve(), fixture=fixture,
        policy=policy, provider_config=config, transport=controlled_transport())
    environment = owner._environment
    monkeypatch.setattr(owner, '_environment', lambda home: {
        **environment(home), 'CODEX_HOME': str(config.codex_home)})
    writes = []
    # Observe the real adapter/backend pipe write methods, forwarding unchanged.
    pipe_methods = []
    spawn = asyncio.create_subprocess_exec
    async def observed_spawn(*args, **kwargs):
        process = await spawn(*args, **kwargs)
        if process.stdin is not None:
            original_pipe_write = process.stdin.write
            def pipe_write(raw):
                for line in raw.splitlines():
                    try:
                        value = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue  # Bridge nonce, never protocol metadata.
                    if isinstance(value, dict) and 'method' in value:
                        pipe_methods.append(value['method'])
                return original_pipe_write(raw)
            process.stdin.write = pipe_write
        return process
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observed_spawn)
    original_write = session._TurnClient._write
    async def write(self, message):
        writes.append(message.get('method'))
        return await original_write(self, message)
    monkeypatch.setattr(session._TurnClient, '_write', write)
    grants = []
    grant = owner.broker.grant
    def observed_grant(*args, **kwargs):
        grants.append(True)
        return grant(*args, **kwargs)
    monkeypatch.setattr(owner.broker, 'grant', observed_grant)
    try:
        await owner.start('P2')
        with pytest.raises(LeaseRefused):
            await owner.initialize_only()
        assert owner.stopped and owner.quarantined and owner.broker._active is None
        diagnostic = owner.startup_diagnostics['worker']
        first = copy.deepcopy(diagnostic.snapshot()['failure'])
        assert first['category'] == 'provider_configuration_' + category
        assert first['stage'] == 'config_read'
        diagnostic.fail(RuntimeError(CANARY))
        diagnostic.fail(LeaseRefused(CANARY), cleanup=True)
        assert diagnostic.snapshot()['failure'] == first
        assert any(d['category'] == 'lease_refused' for d in diagnostic.snapshot()['cleanup_errors'])
        with pytest.raises(LeaseRefused):
            await owner.turn('worker')
    finally:
        with contextlib.suppress(LeaseRefused):
            await owner.close()
    assert not grants and 'session/prompt' not in writes
    assert 'initialize' in pipe_methods and 'config/read' in pipe_methods
    assert not {'session/prompt', 'turn/start', 'thread/resume', 'thread/fork'} & set(pipe_methods)
    assert all(x.process.returncode is not None for x in [*owner.backends.values(), *owner.roles.values()])
    snapshot = owner.diagnostics()
    (owner.root / 'complete-diagnostics.json').write_text(json.dumps(snapshot))
    for path in owner.root.rglob('*'):
        if path.is_file() and path != owner.backend_launcher:
            assert not any(c.encode() in path.read_bytes() for c in
                           (CANARY, 'CANARY_PRIVATE', 'COMMON_INSTRUCTION_CANARY')), path.relative_to(owner.root)
    events = [json.loads(line)['event'] for line in (owner.root / 'journal.jsonl').read_text().splitlines()]
    assert not {'reserve', 'send', 'ack', 'uncertain', 'session_identity'} & set(events)
    assert (candidate / 'a').read_text() == 'base\n'
    captured = capfd.readouterr()
    assert CANARY not in captured.out + captured.err


def test_historical_category_remains_body_free():
    diagnostic = StartupDiagnostics()
    diagnostic.fail(LeaseRefused('provider_configuration_protocol_bound'))
    assert diagnostic.snapshot()['failure']['category'] == 'provider_configuration_protocol_bound'
