"""Synthetic evidence only; no live provider admission claims."""
from pathlib import Path
import json
import shutil

import pytest

from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_lease import LeaseRefused
from unrest_harness.experimental_session import SyntheticSession
from unrest_harness.providers import PROVIDERS

from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing-codex-acp').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'


@pytest.fixture
def session(tmp_path, request):
    # This refusal exercises the original native runtime pin, before any spawn.
    native = request is not None and request.node.originalname == 'test_runtime_pin_rechecked_before_launch'
    root = Path(__file__).resolve().parents[1]
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('synthetic\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
                                    policy=load_capability_policy(root / 'src/unrest_harness/bundled'),
                                    profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    return SyntheticSession(tmp_path / 'owner', candidate, ('a',), adapter=ADAPTER,
                            fixture=FIXTURE, policy=policy,
                            transport=None if native else controlled_transport())


async def test_installed_adapter_two_prompts_and_http_completion(session):
    await session.start()
    try:
        first = await session.turn('worker')
        second = await session.turn('worker')
        assert first.identity.session == second.identity.session
        assert first.identity.process_generation == second.identity.process_generation
        assert (first.identity.ordinal, second.identity.ordinal) == (1, 2)
        assert first.sealed_candidate == second.identity.candidate
        assert first.sealed_candidate != second.sealed_candidate
        trace = [json.loads(s) for s in (session.root / 'worker/trace.jsonl').read_text().splitlines()]
        assert [r['ordinal'] for r in trace] == [1, 2]
        assert all(r['synthetic'] for r in trace)
    finally:
        await session.close()
    assert all(r.process.returncode is not None for r in session.roles.values())


async def test_missing_completion_stops(session):
    await session.start()
    with pytest.raises(LeaseRefused):
        await session.turn('worker', scenario='missing_completion')
    assert session.stopped and session.quarantined
    with pytest.raises(LeaseRefused):
        await session.turn('worker')


async def test_roles_correction_and_independent_candidate_scope(session):
    import hashlib
    from unrest_harness.experimental_lease import correction_allowed
    (session.broker._root / 'b').write_bytes(b'unchanged\n')
    session.scope = ('a', 'b')
    await session.start()
    try:
        first = await session.turn('worker')
        failure = await session.turn('validator', disposition='reproducible_product_defect')
        backends = {name: owned.process for name, owned in session.backends.items()}
        adapters = {name: role.process for name, role in session.roles.items()}
        assert correction_allowed(failure, failure.identity)
        # Independent controller oracle: actual full directory bytes, not broker digest.
        candidate = session.broker._root
        assert (candidate / 'a').read_bytes() == b'defective\n'
        expected = hashlib.sha256(json.dumps([
            ('a', hashlib.sha256(b'corrected\n').hexdigest()),
            ('b', hashlib.sha256(b'unchanged\n').hexdigest())], separators=(',', ':')).encode()).hexdigest()
        corrected = await session.turn('worker')
        recheck = await session.turn('validator')
        assert corrected.identity.candidate == first.sealed_candidate
        assert corrected.identity.candidate != corrected.sealed_candidate
        assert corrected.sealed_candidate == recheck.identity.candidate == recheck.sealed_candidate == expected
        assert tuple(sorted(p.name for p in candidate.iterdir())) == recheck.identity.scope
        assert (candidate / 'a').read_bytes() == b'corrected\n'
        assert first.identity.process_generation == corrected.identity.process_generation
        assert failure.identity.process_generation == recheck.identity.process_generation
        assert first.identity.process_generation != failure.identity.process_generation
        assert recheck.identity.session == failure.identity.session
        assert recheck.identity.ordinal == corrected.identity.ordinal == 2
        assert recheck.disposition == 'pass'
        assert all(session.backends[name].process is handle for name, handle in backends.items())
        assert all(session.roles[name].process is handle for name, handle in adapters.items())
        assert (candidate / 'b').read_bytes() == b'unchanged\n'
        assert first.identity.candidate != first.sealed_candidate
        assert failure.identity.candidate == failure.sealed_candidate == first.sealed_candidate
        assert first.identity.session == corrected.identity.session
        worker = [json.loads(line) for line in
                  (session.root / 'worker/broker-observations.jsonl').read_text().splitlines()]
        validator = [json.loads(line) for line in
                     (session.root / 'validator/broker-observations.jsonl').read_text().splitlines()]
        assert [row['replaced'] for row in worker] == [True, True]
        assert worker[1]['stale_write_refused']
        assert all(row['validator_write_refused'] and not row['replaced'] for row in validator)
    finally:
        await session.close()


@pytest.mark.parametrize('method,params', [
    ('fs/read_text_file', {'path': '/anything'}),
    ('fs/write_text_file', {'path': '/anything', 'content': 'x'}),
    ('terminal/create', {'command': 'anything'}),
    ('session/request_permission', {}),
    ('session/update', {'sessionId': 'wrong', 'update': {}}),
    ('session/update', {'sessionId': True, 'update': {}}),
    ('session/update', {'sessionId': 'synthetic-session', 'update': []}),
])
async def test_exclusive_policy_revokes_and_never_calls_ordinary(session, method, params, monkeypatch):
    await session.start()
    await session.turn('worker')
    role = session.roles['worker']
    def forbidden(*args):
        pytest.fail('ordinary callback was called')
    monkeypatch.setattr(role.client, '_handle_fs_read', forbidden)
    monkeypatch.setattr(role.client, '_handle_fs_write', forbidden)
    monkeypatch.setattr(role.client, '_handle_permission_request', forbidden)
    monkeypatch.setattr(role.client, '_handle_terminal_create', forbidden)
    with pytest.raises(LeaseRefused):
        await role.client._dispatch(method, params)
    assert session.stopped
    assert session.broker._active is None
    with pytest.raises(LeaseRefused):
        await session.close()
    assert (session.root / 'quarantine').exists()


async def test_parked_transport_eof_stops(session):
    import asyncio
    await session.start()
    await session.turn('worker')
    session.roles['worker'].process.kill()
    async with asyncio.timeout(3):
        await session._fault.wait()
    with pytest.raises(LeaseRefused):
        await session.close()
    assert session.broker._active is None
    assert session.stopped


async def test_broker_loss_stops_parked_session(session):
    import asyncio
    await session.start()
    await session.turn('worker')
    session._server.should_exit = True
    async with asyncio.timeout(3):
        await session._fault.wait()
    with pytest.raises(LeaseRefused):
        await session.close()
    assert session.roles['worker'].process.returncode is not None


async def test_budget_expiry_while_parked(session):
    import asyncio
    await session.start()
    await session.turn('worker')
    session.ledger._clock = lambda: session.ledger._started + 5401
    async with asyncio.timeout(2):
        await session._fault.wait()
    with pytest.raises(LeaseRefused):
        await session.close()
    assert session.stopped


async def test_final_reservations_not_consumed_by_early_turns(session):
    await session.start('P1')
    await session.turn('worker')
    await session.turn('validator')
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    journal = [json.loads(s) for s in (session.root / 'journal.jsonl').read_text().splitlines()]
    assert len([r for r in journal if r['event'] == 'send']) == 2
    assert next(r for r in journal if r['event'] == 'admit')['final_reserved'] == 2


async def test_ambient_env_not_imported_and_launcher_pin(session, monkeypatch):
    for name in ('OPENAI_API_KEY', 'AUTH_REQUEST', 'APP_SERVER_LOGS', 'CODEX_PATH',
                 'INITIAL_AGENT_MODE', 'NODE_OPTIONS', 'HTTPS_PROXY'):
        monkeypatch.setenv(name, 'forbidden')
    env = session._environment(session.root)
    assert env['INITIAL_AGENT_MODE'] == 'read-only'
    assert env['CODEX_PATH'] == str(session.launcher)
    assert set(env) == {'HOME', 'CODEX_HOME', 'TMPDIR', 'PATH', 'INITIAL_AGENT_MODE', 'CODEX_PATH'}
    await session.start()
    session.launcher.chmod(0o700)
    session.launcher.write_text('#!/bin/sh\nexit 77\n')
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert not session.roles


async def test_journal_failure_revokes_without_sending(session, monkeypatch):
    await session.start()
    def fail(*args, **kwargs):
        raise OSError('injected journal failure')
    monkeypatch.setattr(session.ledger, '_append', fail)
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert session.quarantined
    assert session.broker._active is None
    assert not (session.root / 'worker/trace.jsonl').exists()
    assert (session.root / 'quarantine').exists()


async def test_stop_record_failure_is_not_success(session, monkeypatch):
    await session.start()
    await session.turn('worker')
    def fail(*args):
        raise OSError('injected durable stop failure')
    monkeypatch.setattr(session, '_record_stop', fail)
    with pytest.raises(LeaseRefused):
        await session.close()
    assert session.stopped and session.quarantined
    assert all(role.process.returncode is not None for role in session.roles.values())


async def test_wait_failure_still_kills_owned_process(session, monkeypatch):
    await session.start()
    await session.turn('worker')
    role = session.roles['worker']
    wait = role.process.wait
    async def fail():
        raise OSError('injected wait failure')
    monkeypatch.setattr(role.process, 'wait', fail)
    with pytest.raises(LeaseRefused):
        await session.close()
    await wait()
    assert role.process.returncode is not None


@pytest.mark.parametrize("launch_number", [1, 2])
async def test_cancel_during_registration_retains_handle(session, monkeypatch, launch_number):
    import asyncio
    import unrest_harness.experimental_session as module
    await session.start()
    original = asyncio.create_subprocess_exec
    spawned, release = asyncio.Event(), asyncio.Event()
    handles = []
    async def delayed(*args, **kwargs):
        process = await original(*args, **kwargs)
        handles.append(process)
        if len(handles) == launch_number:
            spawned.set()
            await release.wait()
        return process
    monkeypatch.setattr(module.asyncio, 'create_subprocess_exec', delayed)
    turn = asyncio.create_task(session.turn('worker'))
    await spawned.wait()
    turn.cancel()
    await asyncio.sleep(.02)
    turn.cancel()  # repeated cancellation must not abandon the retained close task
    release.set()
    with pytest.raises((LeaseRefused, asyncio.CancelledError)):
        await turn
    with pytest.raises(LeaseRefused):
        await session.close()
    assert handles and all(p.returncode is not None for p in handles)
    assert session.backends['worker'].process is handles[0]
    if launch_number == 2:
        assert session.roles['worker'].process is handles[1]


async def test_restart_rejected_and_ordinary_files_untouched(session):
    await session.start()
    await session.turn('worker')
    await session.close()
    with pytest.raises(FileExistsError):
        SyntheticSession(session.root, session.broker._root, session.scope, adapter=ADAPTER,
                         fixture=FIXTURE, policy=session.policy, transport=controlled_transport())
    assert not (session.root / '.unrest-runtime').exists()
    assert not (session.root / '.unrest').exists()


@pytest.mark.parametrize('scenario', ['stall', 'ignore_term'])
async def test_real_active_deadline_cancellation_and_kill(session, monkeypatch, scenario):
    import asyncio
    await session.start()
    await session.turn('worker')
    original = session.ledger.remaining
    monkeypatch.setattr(session.ledger, 'remaining', lambda ticket: min(.15, original(ticket)))
    with pytest.raises(LeaseRefused):
        async with asyncio.timeout(4):
            await session.turn('worker', scenario=scenario)
    assert session.stopped and session.quarantined
    assert session.broker._active is None
    assert session.roles['worker'].process.returncode is not None
    journal = (session.root / 'journal.jsonl').read_text()
    assert 'uncertain' in journal


async def test_rotated_tokens_stale_identity_candidate_and_duplicates(session, monkeypatch):
    from dataclasses import asdict, replace
    from fastmcp import Client
    captured = []
    original = session.broker.grant
    def capture(identity, *, deadline):
        token = original(identity, deadline=deadline)
        captured.append((identity, token))
        return token
    monkeypatch.setattr(session.broker, 'grant', capture)
    await session.start()
    try:
        await session.turn('worker')
        await session.turn('worker')
        assert captured[0][1] != captured[1][1]
        async with Client(session.url, auth=session._connection) as client:
            for identity, token in captured:
                for candidate in (identity.candidate, '0' * 64):
                    reply = await client.call_tool('complete_turn', {
                        'turn': asdict(identity), 'capability': token,
                        'candidate': candidate, 'disposition': 'sealed'}, raise_on_error=False)
                    assert reply.is_error
            identity, token = captured[-1]
            reply = await client.call_tool('complete_turn', {
                'turn': asdict(replace(identity, session='wrong')), 'capability': token,
                'candidate': identity.candidate, 'disposition': 'sealed'}, raise_on_error=False)
            assert reply.is_error
        # Tokens crossed the real adapter unchanged, but never reached durable logs.
        for file in session.root.rglob('*'):
            if file.is_file():
                data = file.read_bytes()
                assert all(token.encode() not in data for _, token in captured)
                assert session._connection.encode() not in data
    finally:
        await session.close()


async def test_late_response_after_cancel_does_not_break_reader(session):
    import asyncio
    import sys
    from unrest_harness.acp_runner import ACPClient
    code = '''import json,sys,time
for line in sys.stdin:
 r=json.loads(line); time.sleep(.08)
 print(json.dumps({'id':r['id'],'result':{'ok':True}}),flush=True)
'''
    process = await asyncio.create_subprocess_exec(sys.executable, '-c', code,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
    client = ACPClient(process, str(session.root), session.policy, {})
    await client.start()
    try:
        request = asyncio.create_task(client.send_request('first', {}))
        await asyncio.sleep(.02)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        async with asyncio.timeout(2):
            assert await client.send_request('second', {}) == {'ok': True}
        assert not client._pending
    finally:
        await client.cleanup()
        await session.close()


async def test_callback_tasks_are_awaited_during_cleanup(session):
    import asyncio
    import sys
    from unrest_harness.acp_runner import ACPClient
    started, cleaned = asyncio.Event(), asyncio.Event()
    async def handler(params):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(.01)
            cleaned.set()
    code = '''import json,time
print(json.dumps({'method':'session/update','params':{}}),flush=True)
time.sleep(20)
'''
    process = await asyncio.create_subprocess_exec(sys.executable, '-c', code,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
    client = ACPClient(process, str(session.root), session.policy, {}, handler)
    await client.start()
    async with asyncio.timeout(2):
        await started.wait()
    process.terminate()
    await client.cleanup()
    assert cleaned.is_set()
    assert not client._request_tasks
    await session.close()


async def test_transport_lost_after_durable_completion_is_not_success(session, monkeypatch):
    import asyncio
    import time
    await session.start()
    loop = asyncio.get_running_loop()
    remaining = session.ledger.remaining
    monkeypatch.setattr(session.ledger, 'remaining', lambda ticket: min(3, remaining(ticket)))
    original = session.broker.complete
    def complete_then_lose(*args):
        result = original(*args)
        loop.call_soon_threadsafe(session.roles['worker'].process.kill)
        return result
    monkeypatch.setattr(session.broker, 'complete', complete_then_lose)
    started = time.monotonic()
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert time.monotonic() - started < 2
    assert list((session.root / 'completions').glob('*.json'))
    assert session.stopped and session.quarantined
    journal = (session.root / 'journal.jsonl').read_text()
    assert 'uncertain' in journal
    assert '"event": "ack"' not in journal


@pytest.mark.parametrize('session_id', [None, '', True, 4, [], {}])
async def test_malformed_open_session_rejected(session, monkeypatch, session_id):
    from unrest_harness.acp_runner import ACPClient
    original = ACPClient.send_request
    async def corrupt(client, method, params):
        result = await original(client, method, params)
        if method == 'session/new':
            result['sessionId'] = session_id
        return result
    monkeypatch.setattr(ACPClient, 'send_request', corrupt)
    await session.start()
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert session.stopped
    assert not (session.root / 'worker/trace.jsonl').exists()


async def test_reservation_precedes_transmission_and_send_requires_pipe_write(session, monkeypatch):
    from unrest_harness.acp_runner import ACPClient
    original = ACPClient.send_request
    observed = []
    async def check(client, method, params):
        if method == 'session/prompt':
            events = [json.loads(s)['event'] for s in
                      (session.root / 'journal.jsonl').read_text().splitlines()]
            assert events[-1] == 'reserve' and 'send' not in events
            observed.append(method)
        result = await original(client, method, params)
        if method == 'session/prompt':
            events = [json.loads(s)['event'] for s in
                      (session.root / 'journal.jsonl').read_text().splitlines()]
            assert events[-2:] == ['reserve', 'send']
        return result
    monkeypatch.setattr(ACPClient, 'send_request', check)
    await session.start()
    await session.turn('worker')
    await session.close()
    assert observed == ['session/prompt']


async def test_broker_completion_failure_consumes_send(session, monkeypatch):
    await session.start()
    remaining = session.ledger.remaining
    monkeypatch.setattr(session.ledger, 'remaining', lambda ticket: min(.2, remaining(ticket)))
    def fail(*args):
        raise OSError('injected broker publication failure')
    monkeypatch.setattr(session.broker, 'complete', fail)
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert session.stopped
    events = [json.loads(s)['event'] for s in (session.root / 'journal.jsonl').read_text().splitlines()]
    assert events.count('send') == 1 and events.count('uncertain') == 1


async def test_fixture_substitution_is_rejected_before_root_creation(session, tmp_path):
    fake = tmp_path / 'substitution.py'
    fake.write_text('raise AssertionError("must not execute")\n')
    root = tmp_path / 'forbidden-owner'
    with pytest.raises(LeaseRefused, match='pin_mismatch'):
        SyntheticSession(root, session.broker._root, session.scope, adapter=ADAPTER,
                         fixture=fake, policy=session.policy, transport=controlled_transport())
    assert not root.exists()
    await session.close()


async def test_sigterm_ignoring_owned_process_is_killed_and_reaped(session, monkeypatch):
    import asyncio
    import signal
    import sys
    from unrest_harness.acp_runner import ACPClient
    from unrest_harness.experimental_session import _Role
    code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)"
    process = await asyncio.create_subprocess_exec(sys.executable, '-c', code,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        start_new_session=True)
    assert await process.stdout.readline() == b'ready\n'
    client = ACPClient(process, str(session.root), session.policy, {})
    await client.start()
    session.roles['worker'] = _Role(process, client, 'controlled-fixture')
    import unrest_harness.experimental_session as module
    signals = []
    killpg = module.os.killpg
    def record(pid, sig):
        assert process.returncode is None
        signals.append(sig)
        killpg(pid, sig)
    monkeypatch.setattr(module.os, 'killpg', record)
    await session.close()
    await session._stop_role(session.roles['worker'])
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.returncode == -signal.SIGKILL


async def test_cleanup_failure_quarantines_but_still_reaps(session, monkeypatch):
    await session.start()
    await session.turn('worker')
    role = session.roles['worker']
    cleanup = role.client.cleanup
    async def fail(**kwargs):
        raise OSError('injected client cleanup failure')
    monkeypatch.setattr(role.client, 'cleanup', fail)
    with pytest.raises(LeaseRefused):
        await session.close()
    await cleanup(close_main_process=False)
    assert role.process.returncode is not None
    assert (session.root / 'quarantine').exists()


async def test_eof_finalizer_cleanup_repeated_cancellation_drains_pending(session):
    import asyncio
    from types import SimpleNamespace
    from unrest_harness.acp_runner import ACPClient, ACPError
    started, entered, release, settled = (asyncio.Event() for _ in range(4))
    written = asyncio.Event()
    class Input:
        def write(self, data):
            written.set()
        async def drain(self):
            pass
    async def handler(params):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            entered.set()
            await release.wait()
            settled.set()
    stdout = asyncio.StreamReader()
    client = ACPClient(SimpleNamespace(stdin=Input(), stdout=stdout),
                       str(session.root), session.policy, {}, handler)
    await client.start()
    request = asyncio.create_task(client.send_request('pending', {}))
    await written.wait()
    stdout.feed_data(b'{"method":"session/update","params":{}}\n')
    await started.wait()
    stdout.feed_eof()
    await entered.wait()  # EOF already cancelled the callback; finalizer now owns cleanup.
    cleanup = asyncio.create_task(client.cleanup(close_main_process=False))
    await asyncio.sleep(0)
    cleanup.cancel()
    await asyncio.sleep(0)
    cleanup.cancel()
    release.set()
    try:
        await cleanup
    except asyncio.CancelledError:
        pass
    try:
        assert settled.is_set()
        assert client._reader_task.done()
        assert client._cleanup_task.done()
        assert not client._request_tasks
        assert request.done()
        with pytest.raises(ACPError):
            await request
        assert not client._pending
    finally:
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)
        await session.close()


async def test_genuine_adapter_beside_substituted_node_rejected(session, tmp_path):
    prefix = tmp_path / 'untrusted'
    adapter = prefix / 'lib/node_modules/@agentclientprotocol/codex-acp/dist/index.js'
    adapter.parent.mkdir(parents=True)
    adapter.write_bytes(ADAPTER.read_bytes())
    node = prefix / 'bin/node'
    node.parent.mkdir()
    node.write_text('#!/bin/sh\nexit 77\n')
    node.chmod(0o755)
    root = tmp_path / 'substituted-owner'
    try:
        with pytest.raises(LeaseRefused, match='pin_mismatch'):
            SyntheticSession(root, session.broker._root, session.scope, adapter=adapter,
                             fixture=FIXTURE, policy=session.policy)
        assert not root.exists()
    finally:
        await session.close()


async def test_stop_role_no_signal_after_reap_or_duplicate_registration(session, monkeypatch):
    import asyncio
    import signal
    from types import SimpleNamespace
    import unrest_harness.experimental_session as module
    signals = []
    term_sent, release_wait = asyncio.Event(), asyncio.Event()
    class Process:
        pid = 424242
        stdin = None
        returncode = None
        async def wait(self):
            await release_wait.wait()
            self.returncode = 0
            return 0
    async def cleanup(**kwargs):
        pass
    process = Process()
    role = module._Role(process, SimpleNamespace(cleanup=cleanup), 'recorder')
    def record(pid, sig):
        assert process.returncode is None, 'signal through stale process group after reap'
        signals.append((pid, sig))
        term_sent.set()
    monkeypatch.setattr(module.os, 'killpg', record)
    stopping = asyncio.create_task(session._stop_role(role))
    await term_sent.wait()
    duplicate = asyncio.create_task(session._stop_role(role))
    await asyncio.sleep(0)
    release_wait.set()
    try:
        await asyncio.gather(stopping, duplicate)
        await session._stop_role(role)
        assert signals == [(process.pid, signal.SIGTERM)]
    finally:
        await session.close()


async def test_reaped_leader_unconfirmed_descendant_quarantines_without_signal(session, monkeypatch):
    from types import SimpleNamespace
    import unrest_harness.experimental_session as module
    closed = []
    async def cleanup(**kwargs):
        pass
    class Unconfirmed:
        async def wait(self):
            raise TimeoutError
    async def close():
        closed.append(True)
    def forbidden(*args):
        pytest.fail('reaped group must never be signaled')
    monkeypatch.setattr(module.os, 'killpg', forbidden)
    process = SimpleNamespace(pid=424242, stdin=None, stdout=None, returncode=0)
    lifetime = SimpleNamespace(exited=Unconfirmed(), close=close)
    role = module._Role(process, SimpleNamespace(cleanup=cleanup), 'reaped', lifetime=lifetime)
    session.roles['worker'] = role
    with pytest.raises(LeaseRefused, match='quarantined'):
        await session.close()
    await session._stop_role(role)
    assert closed == [True]
    assert (session.root / 'quarantine').is_file()


async def test_runtime_pin_rechecked_before_launch(session, monkeypatch, tmp_path):
    node = tmp_path / 'node'
    node.write_text('#!/bin/sh\nexit 77\n')
    node.chmod(0o755)
    session.node = node
    await session.start()
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert not session.roles
    assert not (session.root / 'worker').exists()


async def test_lifetime_connection_missing_exit_drains_observer_and_quarantines(session, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import unrest_harness.experimental_session as module
    lifetime = module._FixtureLifetime()
    lifetime.server = await asyncio.start_server(lifetime.accept, '127.0.0.1', 0)
    port = lifetime.server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write((lifetime.nonce + '\n').encode())
    await writer.drain()
    await lifetime.connected.wait()
    async def cleanup(**kwargs):
        pass
    def forbidden(*args):
        pytest.fail('unconfirmed fixture exit cannot authorize a stale group signal')
    monkeypatch.setattr(module.os, 'killpg', forbidden)
    role = module._Role(SimpleNamespace(pid=424242, stdin=None, stdout=None, returncode=0),
                        SimpleNamespace(cleanup=cleanup), 'reaped', lifetime=lifetime)
    session.roles['worker'] = role
    try:
        async with asyncio.timeout(5):
            with pytest.raises(LeaseRefused, match='quarantined'):
                await session.close()
        assert not lifetime.exited.is_set()
        assert all(task.done() for task in lifetime.tasks)
        assert await reader.read() == b''
    finally:
        writer.close()
        await writer.wait_closed()


async def test_stop_owner_survives_repeated_cancel_and_escalates_only_live_leader(session, monkeypatch):
    import asyncio
    import signal
    from types import SimpleNamespace
    import unrest_harness.experimental_session as module
    term_waiting, allow_timeout = asyncio.Event(), asyncio.Event()
    signals = []
    class Process:
        pid = 424242
        stdin = None
        returncode = None
        async def wait(self):
            if signals == [signal.SIGTERM]:
                term_waiting.set()
                await allow_timeout.wait()
                raise TimeoutError
            self.returncode = -signal.SIGKILL
            return self.returncode
    async def cleanup(**kwargs):
        pass
    process = Process()
    role = module._Role(process, SimpleNamespace(cleanup=cleanup), 'barrier')
    def record(pid, sig):
        assert process.returncode is None
        signals.append(sig)
    monkeypatch.setattr(module.os, 'killpg', record)
    stopping = asyncio.create_task(session._stop_role(role))
    await term_waiting.wait()
    stopping.cancel()
    await asyncio.sleep(0)
    stopping.cancel()
    duplicate = asyncio.create_task(session._stop_role(role))
    allow_timeout.set()
    with pytest.raises(asyncio.CancelledError):
        await stopping
    await duplicate
    await session._stop_role(role)
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert role.stop_task.done()
    assert process.returncode == -signal.SIGKILL
    await session.close()


async def test_private_json_broker_unaffected_by_other_sse_server_shutdown(session, monkeypatch):
    from sse_starlette.sse import AppStatus
    monkeypatch.setattr(AppStatus, 'should_exit', True)
    await session.start()
    try:
        completion = await session.turn('worker')
        assert completion.identity.candidate != completion.sealed_candidate
    finally:
        await session.close()
    assert all(role.lifetime.exited.is_set() for role in session.roles.values())
    assert all(task.done() for role in session.roles.values() for task in role.lifetime.tasks)


async def test_second_launch_failure_reaps_registered_backend(session, monkeypatch):
    import asyncio
    original = asyncio.create_subprocess_exec
    calls = []
    async def launch(*args, **kwargs):
        calls.append(kwargs['env'])
        if len(calls) == 2:
            assert session.backends['worker'].process.returncode is None
            raise OSError('synthetic second launch failure')
        return await original(*args, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    await session.start()
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert session.backends['worker'].process.returncode is not None
    assert not session.roles
    assert 'SYNTHETIC_RELAY' not in calls[0] and 'CODEX_PATH' not in calls[0]
    assert 'SYNTHETIC_RELAY' in calls[1]
    assert (session.root / 'quarantine').exists()


@pytest.mark.parametrize('component', ['backend', 'adapter', 'bridge'])
@pytest.mark.parametrize('active', [False, True])
async def test_independent_component_loss_revokes_and_retains_reservations(
        session, monkeypatch, component, active):
    import asyncio
    await session.start()
    await session.turn('worker')
    role, backend = session.roles['worker'], session.backends['worker']
    entered = asyncio.Event()
    original = role.client.send_request
    async def observe(method, params):
        if method == 'session/prompt':
            entered.set()
        return await original(method, params)
    monkeypatch.setattr(role.client, 'send_request', observe)
    turn = None
    if active:
        turn = asyncio.create_task(session.turn('worker', scenario='stall'))
        await entered.wait()
    before = (session.root / 'journal.jsonl').read_bytes().count(b'"event": "reserve"')
    observations = []
    revoke = session._revoke
    def observe_revoke(*, quarantine):
        if not session.stopped:
            observations.append((role.process.returncode, backend.lifetime.exited.is_set()))
        revoke(quarantine=quarantine)
        assert session.broker._active is None
    monkeypatch.setattr(session, '_revoke', observe_revoke)
    if component == 'backend':
        backend.process.kill()
    elif component == 'adapter':
        role.process.kill()
    else:
        backend.bridge.writer.close()
    async with asyncio.timeout(6):
        await session._fault.wait()
        if turn:
            with pytest.raises(Exception):
                await turn
        with pytest.raises(LeaseRefused):
            await session.close()
    assert observations
    if component == 'backend':
        assert observations[0][0] is None  # backend loss independent of adapter EOF
    assert session.broker._active is None
    assert backend.process.returncode is not None and role.process.returncode is not None
    after = (session.root / 'journal.jsonl').read_bytes().count(b'"event": "reserve"')
    assert after == before == (2 if active else 1)
    with pytest.raises(LeaseRefused):
        await session.turn('worker')
    assert (session.root / 'quarantine').exists()


async def test_structural_stderr_drain_bounded(session):
    import asyncio
    from types import SimpleNamespace
    reader = asyncio.StreamReader()
    backend = SimpleNamespace(process=SimpleNamespace(stderr=reader), diagnostic_bytes=0,
                              diagnostic_truncated=False)
    task = asyncio.create_task(session._drain_backend_stderr(backend))
    for _ in range(100):
        reader.feed_data(b'credential-and-protocol-must-never-be-retained' * 1000)
        await asyncio.sleep(0)
    reader.feed_eof()
    await task
    assert backend.diagnostic_bytes == 65536
    assert backend.diagnostic_truncated is True
    assert set(vars(backend)) == {'process', 'diagnostic_bytes', 'diagnostic_truncated'}
    await session.close()


@pytest.mark.parametrize('stage', ['backend_registered', 'adapter_registered', 'auth', 'forwarding'])
async def test_cancel_after_registration_or_during_bridge_keeps_cleanup_owner(
        session, monkeypatch, stage):
    import asyncio
    from unrest_harness.acp_runner import ACPClient
    from unrest_harness.experimental_relay import Bridge
    entered, release = asyncio.Event(), asyncio.Event()
    if stage == 'backend_registered':
        original = Bridge.start
        async def gated(bridge):
            assert session.backends['worker'].bridge is bridge
            entered.set()
            await release.wait()
            return await original(bridge)
        monkeypatch.setattr(Bridge, 'start', gated)
    elif stage == 'adapter_registered':
        original = ACPClient.start
        async def gated(client):
            assert session.roles['worker'].client is client
            entered.set()
            await release.wait()
            return await original(client)
        monkeypatch.setattr(ACPClient, 'start', gated)
    elif stage == 'auth':
        original = Bridge.attach
        async def gated(bridge, reader, writer):
            entered.set()
            await release.wait()
            return await original(bridge, reader, writer)
        monkeypatch.setattr(Bridge, 'attach', gated)
    else:
        original = ACPClient.send_request
        async def gated(client, method, params):
            if method == 'session/prompt':
                entered.set()
                await release.wait()
            return await original(client, method, params)
        monkeypatch.setattr(ACPClient, 'send_request', gated)
    await session.start()
    turn = asyncio.create_task(session.turn('worker'))
    async with asyncio.timeout(8):
        await entered.wait()
        turn.cancel()
        await session._fault.wait()
        turn.cancel()
        release.set()
        with pytest.raises((LeaseRefused, asyncio.CancelledError)):
            await turn
        with pytest.raises(LeaseRefused):
            await session.close()
    assert all(b.process.returncode is not None for b in session.backends.values())
    assert all(r.process.returncode is not None for r in session.roles.values())
    assert session.broker._active is None
    assert (session.root / 'quarantine').exists()


@pytest.mark.parametrize('launch_number', [1, 2])
async def test_registration_after_close_deadline_bounded(session, monkeypatch, launch_number):
    import asyncio
    original = asyncio.create_subprocess_exec
    entered, release = asyncio.Event(), asyncio.Event()
    handles, waits = [], []
    async def delayed(*args, **kwargs):
        process = await original(*args, **kwargs)
        handles.append(process)
        wait = process.wait
        async def observed_wait():
            result = await wait()
            waits.append(process)
            return result
        monkeypatch.setattr(process, 'wait', observed_wait)
        if len(handles) == launch_number:
            entered.set()
            await release.wait()
        return process
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', delayed)
    await session.start()
    turn = asyncio.create_task(session.turn('worker'))
    rescued = False
    try:
        await asyncio.wait_for(entered.wait(), 5)
        turn.cancel()
        await asyncio.wait_for(session._fault.wait(), 1)
        assert session.stopped and session.broker._active is None
        turn.cancel()
        done, _ = await asyncio.wait({turn}, timeout=10)
        assert done, 'cleanup must return without waiting for delayed registration'
        with pytest.raises((LeaseRefused, asyncio.CancelledError)):
            turn.result()
        assert session.quarantined and (session.root / 'quarantine').exists()
        assert not release.is_set()
        # No prompt was sent before registration: no fabricated turn reservation.
        assert b'"event": "reserve"' not in (session.root / 'journal.jsonl').read_bytes()
    finally:
        release.set()
        done, pending = await asyncio.wait(session._launches, timeout=8)
        if pending or not turn.done():
            rescued = True
            for process in handles:
                if process.returncode is None:
                    process.kill()  # Only exact owned test handles; never guessed PIDs.
            for backend in session.backends.values():
                for owner in (backend.bridge, backend.lifetime):
                    if owner.writer is not None:
                        owner.writer.transport.abort()
            await asyncio.wait({turn, *session._launches}, timeout=4)
        waiting = {asyncio.create_task(process.wait()) for process in handles}
        _, pending = await asyncio.wait(waiting, timeout=3)
        assert not pending, "owned test process did not reap after rescue"
        with pytest.raises(LeaseRefused):
            await session.close()
    assert not rescued
    assert len(handles) == launch_number
    assert all(process.returncode is not None and process in waits for process in handles)


async def test_transport_uncertainty_persists_quarantine_without_cancelling_waiter(session, monkeypatch):
    import asyncio
    from unrest_harness import experimental_relay
    await session.start()
    await session.turn('worker')
    backend = session.backends['worker']
    writer = backend.bridge.writer
    original = writer.wait_closed
    release = asyncio.Event()
    async def delayed_close():
        await release.wait()
        await original()
    monkeypatch.setattr(writer, 'wait_closed', delayed_close)
    monkeypatch.setattr(experimental_relay, 'WRITE_SECONDS', .03)
    closing = asyncio.create_task(session.close())
    try:
        done, _ = await asyncio.wait({closing}, timeout=5)
        assert done
        with pytest.raises(LeaseRefused):
            closing.result()
        assert session.broker._active is None
        assert session.quarantined and (session.root / 'quarantine').exists()
        waiter = backend.bridge.cleanup.writers[writer]
        assert not waiter.done() and not waiter.cancelled()
        assert backend.process.returncode is not None
        assert session.roles['worker'].process.returncode is not None
        assert (session.root / 'journal.jsonl').read_bytes().count(b'"event": "reserve"') == 1
        with pytest.raises(LeaseRefused):
            await session.turn('worker')
    finally:
        release.set()
        await asyncio.gather(*backend.bridge.cleanup.writers.values(), return_exceptions=True)


async def test_duplicate_pump_failures_keep_first_cause_and_one_owned_cleanup(session):
    import asyncio
    from tests.test_experimental_relay import Writer
    await session.start()
    try:
        await session.turn('worker')
        bridge = session.backends['worker'].bridge
        diagnostic = session.startup_diagnostics['worker']
        before = (session.broker._root / 'a').read_bytes()
        first = LeaseRefused('provider_notification_invalid')
        second = RuntimeError('PRIVATE_SECOND_PUMP_FAILURE')
        cleanup_owners = []
        lost = bridge.lost
        def observed_loss():
            lost()
            cleanup_owners.append(session._close_task)
            assert session.stopped and session.broker._active is None
        bridge.lost = observed_loss
        def reject(error):
            def observe(data):
                raise error
            return observe
        readers = [asyncio.StreamReader(), asyncio.StreamReader()]
        for reader in readers:
            reader.feed_data(b'PRIVATE_FRAME_BODY')
        # Both pumps are ready before either runs; cleanup is only scheduled by loss.
        failures = [asyncio.create_task(bridge._pump(reader, Writer(), reject(error), None))
                    for reader, error in zip(readers, (first, second), strict=True)]
        results = await asyncio.gather(*failures, return_exceptions=True)
        assert results[0] is first and results[1] is second
        assert len(cleanup_owners) == 2 and cleanup_owners[0] is cleanup_owners[1]
        assert diagnostic.snapshot()['failure']['category'] == 'provider_notification_invalid'
        assert 'PRIVATE' not in json.dumps(diagnostic.snapshot())
        with pytest.raises(LeaseRefused):
            await session.turn('worker')
        with pytest.raises(LeaseRefused):
            await session.close()
        retained = session._close_task
        with pytest.raises(LeaseRefused):
            await session.close()
        assert retained is cleanup_owners[0] and retained.done()
        assert (session.broker._root / 'a').read_bytes() == before
        assert all(b.process.returncode is not None for b in session.backends.values())
        assert all(r.process.returncode is not None for r in session.roles.values())
    finally:
        try:
            await session.close()
        except LeaseRefused:
            pass
