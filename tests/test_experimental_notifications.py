"""Pinned notification wire schemas, controlled adapter privacy and revocation."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path

import pytest

from unrest_harness.experimental_diagnostics import StartupDiagnostics, startup_timeout
from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_provider_config import ThreadObservation, _frame, _notification
from unrest_harness.experimental_relay import pump
from tests.test_experimental_provider_config import configuration, effective_fixture, stream_pair, close_streams

from tests.controlled_transport import controlled_transport

CANARY = 'PRIVATE_NOTIFICATION_CANARY'
WARNING = {'method': 'configWarning', 'params': {'summary': CANARY, 'details': CANARY,
    'path': '/never/open/' + CANARY, 'range': {'start': {'line': 2**64 - 1, 'column': 0},
                                          'end': {'line': 0, 'column': 0}}}, 'emittedAtMs': -2**63}
REMOTE = {'method': 'remoteControl/status/changed', 'params': {
    'status': 'disabled', 'serverName': CANARY, 'installationId': CANARY}}
ACCOUNT = {'method': 'account/updated', 'params': {'authMode': 'chatgpt', 'planType': 'plus'}}


def wire(value):
    return (json.dumps(value, ensure_ascii=True, indent=None) + ' \n').encode()


def variants():
    result = []
    def add(value, expected=None):
        result.append((value, expected))
    for base in (WARNING, REMOTE, ACCOUNT):
        for stamp in ('absent', None, -2**63, 0, 2**63 - 1):
            value = copy.deepcopy(base)
            value.pop('emittedAtMs', None)
            if stamp != 'absent':
                value['emittedAtMs'] = stamp
            add(value)
        for stamp in (True, 0.5, '0', -2**63 - 1, 2**63):
            add({**base, 'emittedAtMs': stamp}, 'provider_protocol_envelope_fields')
        add({**base, 'privateUnknown': CANARY}, 'provider_protocol_envelope_fields')
        add({**base, 'params': {**base['params'], 'unknown': CANARY}}, 'provider_notification_invalid')
        add({**base, 'id': 1, 'emittedAtMs': None}, 'provider_protocol_envelope_fields')
    for status in ('connecting', 'connected', 'errored', 'unknown', None, False, [], {}):
        add({**REMOTE, 'params': {**REMOTE['params'], 'status': status}}, 'provider_notification_invalid')
    for key in ('serverName', 'installationId', 'status'):
        value = copy.deepcopy(REMOTE)
        del value['params'][key]
        add(value, 'provider_notification_invalid')
    for env in (None, '', CANARY):
        add({**REMOTE, 'params': {**REMOTE['params'], 'environmentId': env}})
    add({**REMOTE, 'params': {**REMOTE['params'], 'environmentId': 3}}, 'provider_notification_invalid')
    for params in ({'summary': ''}, {'summary': CANARY, 'details': None, 'path': None, 'range': None}):
        add({'method': 'configWarning', 'params': params})
    for params in ({}, {'summary': None}, {'summary': 0}, {'summary': CANARY, 'path': []},
                   {'summary': CANARY, 'details': False}, {'summary': CANARY, 'range': {}},
                   {'summary': CANARY, 'range': {'start': {}, 'end': {}}}):
        add({'method': 'configWarning', 'params': params}, 'provider_notification_invalid')
    for value in (True, -1, 2**64, 0.0, '1', None):
        frame = copy.deepcopy(WARNING)
        frame['params']['range']['start']['line'] = value
        add(frame, 'provider_notification_invalid')
    for params in ({'authMode': 'chatgpt'}, {'authMode': 'chatgpt', 'planType': None}):
        add({'method': 'account/updated', 'params': params})
    for params in ({}, {'authMode': None}, {'authMode': 'apikey'}, {'authMode': 'headers'}):
        add({'method': 'account/updated', 'params': params}, 'provider_managed_auth_required')
    for params in ({'authMode': 'apiKey'}, {'authMode': 'chatgpt', 'planType': 'bogus'},
                   {'authMode': 'chatgpt', 'planType': []}):
        add({'method': 'account/updated', 'params': params}, 'provider_notification_invalid')
    add({'method': CANARY, 'params': {}}, 'provider_notification_unsupported')
    add({'method': 'turn/started', 'params': {}}, 'provider_notification_unsupported')
    add({'method': 'configWarning', 'params': {'summary': CANARY}, 'id': 8},
        'provider_configuration_protocol_invalid')
    add({'id': 'wrong-' + CANARY, 'result': {}}, 'provider_configuration_response_id_mismatch')
    add({'id': 1, 'error': {'code': -1, 'message': CANARY, 'data': CANARY}},
        'provider_configuration_error_response')
    add(b'{"method":"configWarning","method":"configWarning"}\n', 'provider_protocol_json_invalid')
    add(b'not-json-' + CANARY.encode() + b'\n', 'provider_protocol_json_invalid')
    return result


@pytest.mark.parametrize('notification,expected', variants(), ids=lambda _: None)
async def test_actual_admission_wire_schema_and_private_single_flush(tmp_path, notification, expected):
    config = configuration(tmp_path)
    role = tmp_path / 'campaign/role'
    effective, requirements, account = effective_fixture(config, role)
    (ar, aw), (cr, cw) = await stream_pair()
    (br, bw), (sr, sw) = await stream_pair()
    sent = []
    class Writer:
        def write(self, raw):
            sent.append(raw)
            aw.write(raw)
        async def drain(self):
            await aw.drain()
    raw = notification if isinstance(notification, bytes) else wire(notification)
    initial = wire({'id': 1, 'result': {'userAgent': 'controlled'}})
    async def backend():
        await sr.readline()
        # Fragment, then coalesce notification and reply across a write boundary.
        sw.write(raw[:7])
        await sw.drain()
        await asyncio.sleep(0)
        sw.write(raw[7:] + initial)
        await sw.drain()
        for result in (effective, requirements, account):
            request = json.loads(await sr.readline())
            assert not sent  # Nothing escapes before the final effective checks.
            sw.write(wire({'id': request['id'], 'result': result}))
            await sw.drain()
    task = asyncio.create_task(backend())
    cw.write(wire({'id': 1, 'method': 'initialize', 'params': {}}))
    diagnostic = StartupDiagnostics()
    try:
        async with startup_timeout(3, 'owner_launch'):
            if expected:
                with pytest.raises(LeaseRefused) as caught:
                    await config.admit_bridge(ar, Writer(), br, bw, role)
                assert str(caught.value) == expected
                diagnostic.fail(caught.value)
                diagnostic.fail(LeaseRefused(CANARY))
                assert diagnostic.failure['category'] == expected
                assert not sent
            else:
                await config.admit_bridge(ar, Writer(), br, bw, role)
                assert sent == [raw + initial]
                assert await cr.readexactly(len(raw + initial)) == raw + initial
        assert CANARY not in json.dumps(diagnostic.snapshot())
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await close_streams(aw, cw, bw, sw)


@pytest.mark.parametrize('base', [REMOTE, {'id': 1, 'result': {}},
                                {'id': 1, 'method': 'initialize', 'params': {}}])
@pytest.mark.parametrize('backend', [False, True])
def test_timestamp_direction(base, backend):
    value = {**base, 'emittedAtMs': None}
    if backend and 'id' not in base:
        assert _frame(wire(value), backend=backend) == value
    else:
        with pytest.raises(LeaseRefused, match='provider_protocol_envelope_fields'):
            _frame(wire(value), backend=backend)


@pytest.mark.parametrize('params', [{}, {'authMode': None, 'planType': None},
                                  {'authMode': 'apikey', 'planType': 'unknown'}])
def test_account_schema_optionality_is_distinct_from_policy(params):
    assert _notification({'method': 'account/updated', 'params': params}) == params


@pytest.mark.parametrize('status', ['disabled', 'connecting', 'connected', 'errored', 'unknown'])
async def test_runtime_fragment_never_forwarded_before_observation(status):
    observer = ThreadObservation()
    (reader, iw), (_, writer) = await stream_pair()
    (out, peer), (_, ow) = await stream_pair()
    eof = asyncio.Event()
    task = asyncio.create_task(pump(reader, ow, eof.set, observer.backend, observer.restrict_backend))
    raw = wire({**REMOTE, 'params': {**REMOTE['params'], 'status': status}})
    normal = wire({'method': 'turn/completed', 'params': {'threadId': 'controlled'}, 'emittedAtMs': 0})
    try:
        writer.write(raw[:-2])
        await writer.drain()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(out.read(1), .02)
        writer.write(raw[-2:] + normal)
        await writer.drain()
        if status == 'disabled':
            assert await asyncio.wait_for(out.readexactly(len(raw + normal)), 1) == raw + normal
        else:
            with pytest.raises(LeaseRefused, match='provider_notification_invalid'):
                await task
            ow.close()
            assert await out.read() == b''
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await close_streams(iw, writer, peer, ow)


@pytest.mark.parametrize('status', ['disabled', 'connecting', 'connected', 'errored', 'unknown'])
@pytest.mark.parametrize('when', ['startup', 'parked', 'before-send'])
async def test_controlled_process_http_revocation_and_warning_privacy(tmp_path, monkeypatch, status, when):
    import contextlib
    import signal
    import shutil
    from dataclasses import asdict
    from fastmcp import Client
    from unrest_harness import experimental_session as session
    from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
    from unrest_harness.providers import PROVIDERS

    fixture_source = (Path(__file__).parent / 'fixtures/experimental_session_app_server.py').read_text()
    notification = {**REMOTE, 'params': {**REMOTE['params'], 'status': status}, 'emittedAtMs': 2**63 - 1}
    # A test-local pinned executable emits on an owned signal, without any real
    # provider, environment override, network destination or security fallback.
    fixture_source = fixture_source.replace("    print(json.dumps(value), flush=True)",
        "    if 'method' in value and 'id' not in value:\n        value['emittedAtMs'] = -1\n"
        "    print(json.dumps(value), flush=True)")
    fixture_source = fixture_source.replace('controlled@example.invalid', CANARY)
    fixture_source = fixture_source.replace('def main():',
        'def main():\n    signal.signal(signal.SIGUSR1, lambda *_: emit(' + repr(notification) + '))')
    fixture_source = fixture_source.replace("        emit({'id': request['id'], 'result': result})",
        "        emit({'id': request['id'], 'result': result})\n"
        "        if method == 'initialize':\n            emit(" + repr(WARNING) + ")\n"
        + ("            emit(" + repr(notification) + ")\n" if when == 'startup' else '')
        + "        if method == 'thread/start':\n            emit(" + repr(WARNING) + ")")
    fixture_source = fixture_source.replace("            emit({'method': 'turn/started'",
        "            emit(" + repr(WARNING) + ")\n            emit({'method': 'turn/started'")
    fixture = tmp_path / 'controlled-notifications.py'
    fixture.write_text(fixture_source)
    monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(fixture.read_bytes()).hexdigest())
    config = configuration(tmp_path)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(__file__).resolve().parents[1] / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    owner = session._SessionOwner(tmp_path / 'campaign/owner', candidate, ('a',),
        adapter=Path(shutil.which('codex-acp')).resolve(), fixture=fixture,
        policy=policy, provider_config=config, transport=controlled_transport())
    environment = owner._environment
    monkeypatch.setattr(owner, '_environment', lambda home: {
        **environment(home), 'CODEX_HOME': str(config.codex_home)})
    callbacks = []
    original_callback = owner._callback
    def callback(role, method, params):
        if CANARY in json.dumps(params):
            callbacks.append('warning-converted-to-acp')
        return original_callback(role, method, params)
    monkeypatch.setattr(owner, '_callback', callback)
    requests = []
    original_write = session._TurnClient._write
    saw_remote = asyncio.Event()
    rejection_slots = []
    def record_rejection_slot():
        rejection_slots.append((owner.stopped, owner.broker._active is None))
    original_backend = ThreadObservation.backend
    def observed_backend(self, data):
        try:
            return original_backend(self, data)
        finally:
            if b'remoteControl/status/changed' in data:
                saw_remote.set()
                if status != 'disabled':
                    asyncio.get_running_loop().call_soon(record_rejection_slot)
    monkeypatch.setattr(ThreadObservation, 'backend', observed_backend)
    async def transition():
        owner.backends['worker'].process.send_signal(signal.SIGUSR1)
        await asyncio.wait_for(saw_remote.wait(), 3)
    async def write(self, msg):
        if msg.get('method') == 'session/prompt' and when == 'before-send':
            assert owner.broker._active is not None
            await transition()
        requests.append(msg.get('method'))
        return await original_write(self, msg)
    monkeypatch.setattr(session._TurnClient, '_write', write)
    grants = []
    grant = owner.broker.grant
    def observed_grant(identity, **kwargs):
        token = grant(identity, **kwargs)
        grants.append((identity, token))
        return token
    monkeypatch.setattr(owner.broker, 'grant', observed_grant)
    try:
        await owner.start('P2')
        if when == 'startup' and status != 'disabled':
            with pytest.raises(LeaseRefused):
                await owner.initialize_only()
        else:
            await owner.initialize_only()
            if when == 'parked':
                await transition()
            if status == 'disabled':
                completion = await owner.turn('worker')
                assert completion.disposition == 'sealed'
                assert callbacks  # The real pinned adapter converted warning text.
                assert (candidate / 'a').read_text() == 'defective\n'
                identity, token = grants[-1]
                # Actual HTTP stale capability cannot overwrite immutable completion.
                async with Client(owner.url, auth=owner._connection) as client:
                    refused = await client.call_tool('replace_file', {
                        'turn': asdict(identity), 'capability': token, 'name': 'a',
                        'content': CANARY}, raise_on_error=False)
                    assert refused.is_error
            else:
                with pytest.raises(LeaseRefused):
                    await owner.turn('worker')
        if status != 'disabled':
            if when != 'startup':
                assert rejection_slots and all(slot == (True, True) for slot in rejection_slots)
            assert owner.stopped and owner.quarantined and owner.broker._active is None
            assert (candidate / 'a').read_text() == 'base\n'
            assert not list(owner.root.rglob('received.jsonl'))
            count = len(grants)
            with pytest.raises(LeaseRefused):
                await owner.turn('worker')
            assert len(grants) == count == (1 if when == 'before-send' else 0)
            d = owner.startup_diagnostics['worker'].snapshot()
            assert d['failure']['category'] == 'provider_notification_invalid'
            owner.startup_diagnostics['worker'].fail(LeaseRefused(CANARY))
            assert d['failure'] == owner.startup_diagnostics['worker'].snapshot()['failure']
            if grants:
                identity, token = grants[-1]
                try:
                    async with asyncio.timeout(2):
                        async with Client(owner.url, auth=owner._connection) as client:
                            response = await client.call_tool('replace_file', {
                                'turn': asdict(identity), 'capability': token,
                                'name': 'a', 'content': CANARY}, raise_on_error=False)
                            assert response.is_error
                except (OSError, RuntimeError, TimeoutError):
                    pass  # Closed owned HTTP transport is also a concrete refusal.
                assert (candidate / 'a').read_text() == 'base\n'
    finally:
        with contextlib.suppress(LeaseRefused):
            await owner.close()
    assert all(b.process.returncode is not None for b in owner.backends.values())
    assert all(r.process.returncode is not None for r in owner.roles.values())
    snapshot = owner.diagnostics()
    (owner.root / 'complete-diagnostics.json').write_text(json.dumps(snapshot))
    # Scan complete persisted artifacts, including logs and journals, not just
    # selected metadata fields. The sole exclusion is the pinned test executable.
    for path in owner.root.rglob('*'):
        if path.is_file() and path != owner.backend_launcher:
            assert not any(v.encode() in path.read_bytes() for v in
                           (CANARY, 'CANARY_PRIVATE', 'COMMON_INSTRUCTION_CANARY')), path.relative_to(owner.root)
    journal = [json.loads(line)['event'] for line in (owner.root / 'journal.jsonl').read_text().splitlines()]
    if status != 'disabled':
        assert 'send' not in journal and 'ack' not in journal
