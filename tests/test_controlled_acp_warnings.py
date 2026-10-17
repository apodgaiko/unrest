"""Local warning conversion through the pinned fixture; native execution unverified."""
import asyncio
import copy
import contextlib
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import signal
import sys

import pytest

from unrest_harness.experimental_session import ControlledTransport, _SessionOwner
from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_provider_config import ThreadObservation
from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.providers import PROVIDERS
from tests import test_experimental_notifications as notifications
from tests import test_experimental_provider_config as configuration
from tests import test_experimental_config_frames as config_frames

LOCAL = Path(__file__).parent / 'fixtures/controlled_python_acp.py'
Adapter = runpy.run_path(str(LOCAL), run_name='controlled_warning_tests')['Adapter']


@pytest.fixture
def selected_owner():
    # The migrated original entry points now select at their production boundary.
    # Do not substitute constructors or launchers to choose the transport.
    transport = ControlledTransport(LOCAL, Path(sys.executable))
    transport.verify(controlled=True, package=None)
    return transport


@pytest.mark.parametrize('status', ['disabled', 'connecting', 'connected', 'errored', 'unknown'])
@pytest.mark.parametrize('when', ['startup', 'parked', 'before-send'])
async def test_original_owner_warning_state_and_phase(tmp_path, monkeypatch, selected_owner, status, when):
    # Execute the original body, including callback, HTTP, journal and privacy oracles.
    await notifications.test_controlled_process_http_revocation_and_warning_privacy(
        tmp_path, monkeypatch, status, when)


@pytest.mark.parametrize('inject_context', [False, True])
@pytest.mark.parametrize('with_skills', [False, True])
async def test_original_private_configuration(tmp_path, monkeypatch, selected_owner,
                                              inject_context, with_skills):
    await configuration.test_startup_and_thread_controls_through_actual_owned_adapter(
        tmp_path, inject_context, with_skills, monkeypatch)


@pytest.mark.parametrize('mode', ['ready', 'drift', 'error', 'eof'])
async def test_original_private_large_config(tmp_path, monkeypatch, capfd, selected_owner, mode):
    await config_frames.test_pinned_adapter_large_private_and_adapter_replies(
        tmp_path, monkeypatch, capfd, mode)


async def converted(raw, session='owned-session', closed=False):
    adapter = Adapter()
    adapter.session = session
    adapter.warnings_closed = closed
    adapter.reader = asyncio.StreamReader(limit=16 * 1024 * 1024)
    emitted = []
    adapter.emit = emitted.append
    adapter.reader.feed_data(raw[:7])
    task = asyncio.create_task(adapter.backend())
    await asyncio.sleep(0)
    assert not emitted
    adapter.reader.feed_data(raw[7:])
    adapter.reader.feed_eof()
    try:
        await task
    except EOFError:
        return emitted
    except Exception:
        assert not emitted
        raise


@pytest.mark.parametrize('details', [None, '', 'details-from-wire'])
@pytest.mark.parametrize('session', [None, 'owned-session'])
async def test_warning_wire_content_and_startup_routing(details, session):
    frame = copy.deepcopy(notifications.WARNING)
    frame['params']['summary'] = 'summary-from-wire'
    frame['params']['details'] = details
    emitted = await converted(notifications.wire(frame), session)
    if session is None:
        assert emitted == []
    else:
        text = 'Config warning: summary-from-wire' + ('\n\n' + details if details else '') + '\n\n'
        assert emitted == [{'jsonrpc': '2.0', 'method': 'session/update', 'params': {
            'sessionId': session, 'update': {'sessionUpdate': 'agent_message_chunk',
                                          'content': {'type': 'text', 'text': text}}}}]
        assert notifications.CANARY not in json.dumps(emitted)  # path/range stay inert


@pytest.mark.parametrize('frame,expected', [
    (frame, expected) for frame, expected in notifications.variants()
    if expected and (isinstance(frame, bytes) or frame.get('method') in
                     ('configWarning', 'remoteControl/status/changed'))
])
async def test_malformed_or_unsupported_warning_wire_refuses(frame, expected):
    raw = frame if isinstance(frame, bytes) else notifications.wire(frame)
    with pytest.raises((ValueError, KeyError, TypeError)):
        await converted(raw)


@pytest.mark.parametrize('session', ['', False, 1, [], {}])
async def test_warning_wrong_session_refuses(session):
    with pytest.raises(ValueError, match='warning session'):
        await converted(notifications.wire(notifications.WARNING), session)


async def test_warning_after_cancel_refuses():
    adapter = Adapter()
    adapter.session = 'owned-session'
    adapter.prompt = asyncio.get_running_loop().create_future()
    requests = []
    async def rpc(method, params):
        requests.append((method, params))
        return {}
    adapter.rpc = rpc
    assert await adapter.handle({'method': 'session/cancel',
                                 'params': {'sessionId': 'owned-session'}}) == {}
    assert requests == [('turn/interrupt', {'threadId': 'owned-session'})]
    with pytest.raises(ValueError, match='late local warning'):
        adapter.notification(notifications.wire(notifications.WARNING))


async def test_warning_size_bound_refuses():
    with pytest.raises(ValueError, match='notification envelope'):
        await converted(notifications.wire({'method': 'configWarning',
                                            'params': {'summary': 'w' * 65536}}))


def warning_backend(attack):
    frame = copy.deepcopy(notifications.WARNING)
    if attack == 'malformed':
        frame['params']['summary'] = None
    elif attack == 'unsupported':
        frame['method'] = 'unsupportedLocalWarning'
    source = (LOCAL.parent / 'experimental_session_app_server.py').read_text()
    return source.replace('def main():', 'def main():\n    signal.signal(signal.SIGUSR1, '
                          'lambda *_: emit(' + repr(frame) + '))')


@pytest.mark.parametrize('attack', ['malformed', 'unsupported', 'wrong-callback', 'late-cancel'])
async def test_owned_warning_refusal_and_cleanup(tmp_path, monkeypatch, attack):
    from unrest_harness import experimental_session as session
    fixture = tmp_path / 'warning_backend.py'
    fixture.write_text(warning_backend(attack))
    monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(fixture.read_bytes()).hexdigest())
    config = configuration.configuration(tmp_path)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(LOCAL.parents[2] / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    owner = _SessionOwner(tmp_path / 'campaign/owner', candidate, ('a',),
        adapter=Path(shutil.which('codex-acp') or '/missing').resolve(), fixture=fixture,
        policy=policy, provider_config=config,
        transport=ControlledTransport(LOCAL, Path(sys.executable)))
    environment = owner._environment
    monkeypatch.setattr(owner, '_environment', lambda home: {
        **environment(home), 'CODEX_HOME': str(config.codex_home)})
    observed, callbacks = [], []
    original_backend = ThreadObservation.backend
    def backend(self, raw):
        original_backend(self, raw)
        if b'configWarning' in raw or b'unsupportedLocalWarning' in raw:
            observed.append(True)
    monkeypatch.setattr(ThreadObservation, 'backend', backend)
    original_callback = owner._callback
    def callback(role, method, params):
        assert observed  # The production Bridge accepted the complete backend frame first.
        callbacks.append(params['sessionId'])
        assert params['update']['content']['text'].startswith(
            'Config warning: ' + notifications.WARNING['params']['summary'])
        if attack == 'wrong-callback':
            params = {**params, 'sessionId': role.session + '-wrong'}
        return original_callback(role, method, params)
    monkeypatch.setattr(owner, '_callback', callback)
    try:
        await owner.start()
        await owner.initialize_only()
        if attack == 'late-cancel':
            role = owner.roles['worker']
            await role.client.send_request('session/cancel', {'sessionId': role.session})
        owner.backends['worker'].process.send_signal(signal.SIGUSR1)
        async with asyncio.timeout(3):
            while not owner.stopped:
                await asyncio.sleep(.01)
        assert owner.quarantined and owner.broker._active is None
        assert bool(callbacks) == (attack == 'wrong-callback')
        assert bool(observed) == (attack != 'malformed')
        with pytest.raises(LeaseRefused):
            await owner.turn('worker')
        assert owner.last_completion is None and (candidate / 'a').read_text() == 'base\n'
    finally:
        with contextlib.suppress(LeaseRefused):
            await owner.close()
    assert len(owner.roles) == len(owner.backends) == 1
    assert all(child.returncode is not None for child in (
        *(role.process for role in owner.roles.values()),
        *(backend.process for backend in owner.backends.values())))
    assert not owner.broker._active
    for path in owner.root.rglob('*'):
        if path.is_file() and path != owner.backend_launcher:
            assert notifications.CANARY.encode() not in path.read_bytes()
    journal = [json.loads(line)['event'] for line in (owner.root / 'journal.jsonl').read_text().splitlines()]
    assert not {'reserve', 'send', 'ack', 'uncertain'} & set(journal)
