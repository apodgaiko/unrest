from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from dataclasses import asdict, replace

import pytest
from fastmcp import Client

from unrest_harness.experimental_broker import broker_server
from unrest_harness.experimental_confinement import OwnedProcesses, acp_envelope, deny_callback
from unrest_harness.experimental_lease import (
    Completion, LeaseRefused, PilotLedger, TurnBroker, TurnIdentity,
    correction_allowed, require_provider,
)


@pytest.fixture
def broker(tmp_path):
    root = tmp_path / 'candidate'
    root.mkdir()
    (root / 'a').write_text('base\n')
    instance = TurnBroker(root, tmp_path / 'records')
    yield instance
    instance.close()


def turn(broker, **kwargs):
    identity = TurnIdentity('lane', 'worker', 'child', 'handoff', 'session', 'process',
                            1, ('a',), broker.digest(('a',)))
    return replace(identity, **kwargs)


def grant(broker, identity):
    return broker.grant(identity, deadline=time.monotonic() + 30)


def test_completion_replay_and_correction(broker, tmp_path):
    identity = turn(broker)
    token = grant(broker, identity)
    digest = broker.replace(token, identity, 'a', 'fixed\n')
    completion = broker.complete(token, identity, digest, 'sealed')
    assert completion.sealed_candidate == digest
    records = list((tmp_path / 'records').glob('*.json'))
    assert len(records) == 1
    original = records[0].read_bytes()
    with pytest.raises(LeaseRefused):
        broker.complete(token, identity, digest, 'sealed')
    correction = replace(identity, ordinal=2, candidate=digest)
    new_token = grant(broker, correction)
    assert token != new_token
    with pytest.raises(LeaseRefused):
        broker.replace(token, correction, 'a', 'stale')
    broker.complete(new_token, correction, digest, 'sealed')
    assert records[0].read_bytes() == original
    assert len(list((tmp_path / 'records').glob('*.json'))) == 2
    assert token.encode() not in original
    assert not (tmp_path / '.unrest').exists()


@pytest.mark.parametrize('field,value', [
    ('lane', 'other'), ('role', 'validator'), ('child', 'other'), ('handoff', 'other'),
    ('session', 'other'), ('process_generation', 'other'), ('ordinal', 2),
    ('scope', ('b',)), ('candidate', 'f' * 64),
])
def test_every_binding_rejects(broker, field, value):
    identity = turn(broker)
    token = grant(broker, identity)
    with pytest.raises(LeaseRefused, match='authority'):
        broker.replace(token, replace(identity, **{field: value}), 'a', 'bad')
    assert broker.digest(('a',)) == identity.candidate


@pytest.mark.parametrize('name', ['../escape', '/tmp/escape', '.', 'a/b'])
def test_path_traversal_rejects(broker, name):
    identity = turn(broker)
    token = grant(broker, identity)
    with pytest.raises(LeaseRefused):
        broker.replace(token, identity, name, 'bad')


def test_validator_cannot_write_and_failure_classification(broker):
    identity = turn(broker, role='validator')
    token = grant(broker, identity)
    with pytest.raises(LeaseRefused, match='scope'):
        broker.replace(token, identity, 'a', 'bad')
    for disposition in ['conflict', 'missing_authority', 'scope_expansion', 'unknown',
                        'malformed_handoff', 'pass', 'defect', '']:
        assert not correction_allowed(Completion(identity, identity.candidate, disposition), identity)
    assert correction_allowed(Completion(identity, identity.candidate,
                                          'reproducible_product_defect'), identity)
    assert not correction_allowed(Completion(identity, '0' * 64,
                                              'reproducible_product_defect'), identity)


@pytest.mark.parametrize('attack', ['symlink', 'hardlink', 'extra', 'root'])
def test_candidate_substitution(broker, tmp_path, attack):
    identity = turn(broker)
    token = grant(broker, identity)
    root = tmp_path / 'candidate'
    outside = tmp_path / 'outside'
    outside.write_text('private')
    if attack in ('symlink', 'hardlink'):
        (root / 'a').unlink()
        if attack == 'symlink':
            (root / 'a').symlink_to(outside)
        else:
            os.link(outside, root / 'a')
    elif attack == 'extra':
        (root / 'extra').write_text('extra')
    else:
        root.rename(tmp_path / 'moved')
        root.mkdir()
    with pytest.raises(LeaseRefused):
        broker.replace(token, identity, 'a', 'bad')
    assert outside.read_text() == 'private'


def test_park_drains_commit_before_ack(broker, monkeypatch):
    identity = turn(broker)
    token = grant(broker, identity)
    entered, release, parked = threading.Event(), threading.Event(), threading.Event()
    rename = os.rename

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return rename(*args, **kwargs)

    monkeypatch.setattr(os, 'rename', paused)
    writer = threading.Thread(target=broker.replace, args=(token, identity, 'a', 'changed'))
    writer.start()
    assert entered.wait(3)
    parker = threading.Thread(target=lambda: (broker.park(), parked.set()))
    parker.start()
    assert not parked.wait(.05)
    release.set()
    writer.join(3)
    parker.join(3)
    assert parked.is_set()
    sealed = broker.digest(('a',))
    with pytest.raises(LeaseRefused):
        broker.replace(token, identity, 'a', 'after-ack')
    assert broker.digest(('a',)) == sealed


def test_restart_and_continuity_fail_closed(broker, tmp_path):
    identity = turn(broker)
    grant(broker, identity)
    broker.park()
    with pytest.raises(LeaseRefused):
        grant(broker, replace(identity, ordinal=2, session='replacement'))
    with pytest.raises(FileExistsError):
        TurnBroker(tmp_path / 'candidate', tmp_path / 'records')


@pytest.mark.parametrize('episode,maximum', [('P1', 4), ('P2', 6), ('P3', 8), ('C1', 6)])
def test_pilot_final_reservation(tmp_path, broker, episode, maximum):
    path = tmp_path / 'ledger.jsonl'
    ledger = PilotLedger(path)
    try:
        ledger.admit(episode)
        for ordinal in range(1, maximum - 1):
            ticket = ledger.reserve(turn(broker, ordinal=ordinal))
            ledger.sent(ticket)
            ledger.finish(ticket)
        with pytest.raises(LeaseRefused, match='budget'):
            ledger.reserve(turn(broker, ordinal=maximum - 1))
        for ordinal in range(maximum - 1, maximum + 1):
            ticket = ledger.reserve(turn(broker, ordinal=ordinal), final=True)
            ledger.sent(ticket)
            ledger.finish(ticket)
        with pytest.raises(LeaseRefused):
            ledger.reserve(turn(broker), final=True)
        ledger.close_episode()
    finally:
        ledger.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert sum(row['event'] == 'reserve' for row in rows) == maximum
    with pytest.raises(FileExistsError):
        PilotLedger(path)


@pytest.mark.parametrize('elapsed', [300, 1800, 5400])
def test_deadline_before_send(tmp_path, broker, elapsed):
    now = [0.0]
    ledger = PilotLedger(tmp_path / 'ledger', clock=lambda: now[0])
    try:
        ledger.admit('P1')
        ticket = ledger.reserve(turn(broker))
        now[0] = elapsed
        with pytest.raises(LeaseRefused):
            ledger.sent(ticket)
    finally:
        ledger.close()


def test_ambiguous_send_never_retries(tmp_path, broker):
    ledger = PilotLedger(tmp_path / 'ledger')
    try:
        ledger.admit('P2')
        ticket = ledger.reserve(turn(broker))
        ledger.finish(ticket, ambiguous=True)
        with pytest.raises(LeaseRefused):
            ledger.sent(ticket)
        with pytest.raises(LeaseRefused):
            ledger.reserve(turn(broker))
    finally:
        ledger.close()


def test_owned_ignoring_child_and_unknown_quarantine(broker, tmp_path):
    owner = OwnedProcesses(broker)
    child = owner.launch_local([sys.executable, '-c',
        'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);'
        'time.sleep(30)'], cwd=tmp_path, env={})
    assert child.stdout.readline() == b'ready\n'
    assert owner.close(.05)
    assert child.poll() == -signal.SIGKILL
    with pytest.raises(LeaseRefused):
        owner.launch_local(['false'], cwd=tmp_path, env={})
    other = OwnedProcesses(broker)
    other.unknown_child()
    assert not other.close()
    with pytest.raises(LeaseRefused):
        grant(broker, turn(broker))


@pytest.mark.parametrize('provider', ['claude', 'codex', 'unknown'])
def test_unsupported_provider(provider):
    with pytest.raises(LeaseRefused, match='unsupported|opt_in_required'):
        require_provider(provider)


@pytest.mark.parametrize('method', ['fs/write_text_file', 'terminal/create', 'session/request_permission'])
def test_callbacks_never_delegate(method):
    with pytest.raises(LeaseRefused):
        deny_callback(method)


def test_owned_acp_envelope():
    for command in ['/review', ' /goal', '\n/compact']:
        with pytest.raises(LeaseRefused):
            acp_envelope('session/prompt', 'id', command)
    with pytest.raises(LeaseRefused):
        acp_envelope('session/set_mode', 'id', 'agent')
    assert acp_envelope('session/prompt', 'id', 'work')['sessionId'] == 'id'


async def test_real_mcp_completion_and_replay(broker):
    identity = turn(broker)
    token = grant(broker, identity)
    async with Client(broker_server(broker, "local-connection-" * 3)) as client:
        assert {tool.name for tool in await client.list_tools()} == {'replace_file', 'complete_turn'}
        result = await client.call_tool('complete_turn', {'capability': token, 'turn': asdict(identity),
            'candidate': identity.candidate, 'disposition': 'sealed'})
        assert not result.is_error
        replay = await client.call_tool('complete_turn', {'capability': token, 'turn': asdict(identity),
            'candidate': identity.candidate, 'disposition': 'sealed'}, raise_on_error=False)
        assert replay.is_error


async def test_http_mcp_static_header_never_becomes_turn_authority(broker):
    import asyncio
    import socket

    import httpx
    import uvicorn

    connection = 'local-connection-' * 3
    server = broker_server(broker, connection)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    app = server.http_app(stateless_http=True)
    runner = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False))
    task = asyncio.create_task(runner.serve(sockets=[listener]))
    try:
        for _ in range(100):
            if runner.started:
                break
            await asyncio.sleep(.01)
        assert runner.started
        url = f'http://127.0.0.1:{port}/mcp'
        async with httpx.AsyncClient() as http:
            response = await http.post(url, json={'jsonrpc': '2.0', 'id': 1,
                                                 'method': 'tools/list'})
            assert response.status_code == 401
        identity = turn(broker)
        token = grant(broker, identity)
        async with Client(url, auth=connection) as client:
            for field, value in [('ordinal', True), ('ordinal', 1.0),
                                 ('scope', 'a'), ('scope', [1]), ('scope', [['a']])]:
                for tool, fields in [
                    ('replace_file', {'name': 'a', 'content': 'bad'}),
                    ('complete_turn', {'candidate': identity.candidate,
                                       'disposition': 'sealed'}),
                ]:
                    rejected = await client.call_tool(tool, {
                        'capability': token, 'turn': {**asdict(identity), field: value},
                        **fields}, raise_on_error=False)
                    assert rejected.is_error
                    assert 'invalid_identity' in str(rejected)
            assert broker.digest(identity.scope) == identity.candidate
            arguments = {'capability': connection, 'turn': asdict(identity),
                         'name': 'a', 'content': 'changed'}
            rejected = await client.call_tool('replace_file', arguments, raise_on_error=False)
            assert rejected.is_error
            arguments['capability'] = token
            result = await client.call_tool('replace_file', arguments)
            assert not result.is_error
            broker.park()
            replay = await client.call_tool('replace_file', arguments, raise_on_error=False)
            assert replay.is_error
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()


async def test_http_mcp_target_verdicts_are_strict_booleans(broker):
    import asyncio
    import socket

    import httpx
    import uvicorn

    connection = 'local-connection-' * 3
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    app = broker_server(broker, connection).http_app(stateless_http=True, json_response=True)
    runner = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False))
    task = asyncio.create_task(runner.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not runner.started:
                await asyncio.sleep(.01)
        identity = TurnIdentity(**{**asdict(turn(broker)), 'role': 'validator',
                                   'targets': ('VAL-A',)})
        token = grant(broker, identity)
        url = f'http://127.0.0.1:{listener.getsockname()[1]}/mcp'
        async with httpx.AsyncClient() as client:
            for value in (0, 1, 'true', 'false', '1', None, [], {}):
                response = await client.post(url, headers={
                    'Authorization': 'Bearer ' + connection,
                    'Accept': 'application/json, text/event-stream',
                }, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                    'name': 'complete_turn', 'arguments': {'capability': token,
                        'turn': asdict(identity), 'candidate': identity.candidate,
                        'disposition': 'pass', 'verdicts': {'VAL-A': value}}}})
                response.raise_for_status()
                assert response.json()['result']['isError'] is True
                assert broker._active is not None
        async with Client(url, auth=connection) as client:
            result = await client.call_tool('complete_turn', {'capability': token,
                'turn': asdict(identity), 'candidate': identity.candidate,
                'disposition': 'pass', 'verdicts': {'VAL-A': True}})
            assert not result.is_error
        assert broker.completion(identity).verdicts == (('VAL-A', True),)
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()


def test_budget_repeated_identity_consumes_no_new_send(tmp_path, broker):
    ledger = PilotLedger(tmp_path / 'ledger')
    try:
        ledger.admit('P1')
        identity = turn(broker)
        ticket = ledger.reserve(identity)
        ledger.sent(ticket)
        ledger.finish(ticket)
        with pytest.raises(LeaseRefused, match='already_reserved'):
            ledger.reserve(identity)
    finally:
        ledger.close()


def test_revoked_token_never_revives(broker, monkeypatch):
    identity = turn(broker)
    token = grant(broker, identity)
    broker.park()
    monkeypatch.setattr('unrest_harness.experimental_lease.secrets.token_urlsafe', lambda _: token)
    with pytest.raises(LeaseRefused, match='collision'):
        grant(broker, replace(identity, ordinal=2))


def test_cleanup_failure_revokes_and_quarantines(broker, tmp_path, monkeypatch):
    owner = OwnedProcesses(broker)
    identity = turn(broker)
    token = grant(broker, identity)
    child = owner.launch_local([sys.executable, '-c', 'import time;time.sleep(30)'],
                              cwd=tmp_path, env={})
    terminate = child.terminate
    try:
        monkeypatch.setattr(child, 'terminate', lambda: (_ for _ in ()).throw(OSError('injected')))
        assert not owner.close(.05)
        assert broker.quarantined
        with pytest.raises(LeaseRefused):
            broker.replace(token, identity, 'a', 'bad')
    finally:
        terminate()
        child.wait(timeout=3)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_completion_publish_drains_before_park(broker, monkeypatch):
    identity = turn(broker)
    token = grant(broker, identity)
    entered, release, parked = threading.Event(), threading.Event(), threading.Event()
    link = os.link

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return link(*args, **kwargs)

    monkeypatch.setattr(os, 'link', paused)
    writer = threading.Thread(target=broker.complete,
                              args=(token, identity, identity.candidate, 'sealed'))
    writer.start()
    assert entered.wait(3)
    parker = threading.Thread(target=lambda: (broker.park(), parked.set()))
    parker.start()
    assert not parked.wait(.05)
    release.set()
    writer.join(3)
    parker.join(3)
    assert parked.is_set()
    with pytest.raises(LeaseRefused):
        broker.complete(token, identity, identity.candidate, 'sealed')


@pytest.mark.parametrize('field,value', [
    ('ordinal', True), ('ordinal', 1.0), ('ordinal', '1'),
    ('scope', 'a'), ('scope', ['a']), ('scope', (1,)), ('scope', (['a'],)),
    ('scope', ('a\x00',)), ('lane', 1), ('child', True), ('handoff', []),
    ('session', {}), ('process_generation', 2), ('candidate', None), ('role', []),
])
def test_identity_types_are_strict(broker, field, value):
    with pytest.raises(LeaseRefused, match='invalid_identity'):
        turn(broker, **{field: value})


@pytest.mark.parametrize('operation', ['replace', 'complete'])
@pytest.mark.parametrize('field,value', [
    ('ordinal', True), ('ordinal', 1.0), ('ordinal', '1'), ('scope', 'a'),
    ('scope', None), ('scope', [1]), ('scope', [['a']]), ('lane', 1),
])
async def test_mcp_rejects_malformed_identity(broker, tmp_path, operation, field, value):
    identity = turn(broker)
    token = grant(broker, identity)
    malformed = {**asdict(identity), field: value}
    arguments = {'capability': token, 'turn': malformed}
    if operation == 'replace':
        name = 'replace_file'
        arguments.update(name='a', content='bad')
    else:
        name = 'complete_turn'
        arguments.update(candidate=identity.candidate, disposition='sealed')
    async with Client(broker_server(broker, 'local-connection-' * 3)) as client:
        result = await client.call_tool(name, arguments, raise_on_error=False)
        assert result.is_error
        assert 'invalid_identity' in str(result)
    assert (tmp_path / 'candidate' / 'a').read_text() == 'base\n'
    assert not list((tmp_path / 'records').iterdir())
    assert broker.complete(token, identity, identity.candidate, 'sealed').identity is identity


@pytest.mark.parametrize('operation,fail_at', [('replace', 1), ('replace', 2), ('complete', 1)])
def test_digest_failure_revokes_and_quarantines(broker, tmp_path, monkeypatch, operation, fail_at):
    identity = turn(broker)
    token = grant(broker, identity)
    digest = broker.digest
    calls = 0

    def failing(scope):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError('injected digest read failure')
        return digest(scope)

    monkeypatch.setattr(broker, 'digest', failing)
    with pytest.raises(OSError, match='injected'):
        if operation == 'replace':
            broker.replace(token, identity, 'a', 'committed')
        else:
            broker.complete(token, identity, identity.candidate, 'sealed')
    assert broker.quarantined
    assert broker._active is None
    assert (tmp_path / 'candidate' / 'a').read_text() == (
        'committed' if operation == 'replace' and fail_at == 2 else 'base\n')
    assert not list((tmp_path / 'records').iterdir())
    with pytest.raises(LeaseRefused):
        broker.replace(token, identity, 'a', 'after failure')
    with pytest.raises(LeaseRefused):
        grant(broker, replace(identity, ordinal=2))


def test_completion_uses_granted_identity(broker):
    identity = turn(broker)
    token = grant(broker, identity)
    caller = replace(identity)
    assert caller is not identity
    result = broker.complete(token, caller, identity.candidate, 'sealed')
    assert result.identity is identity


@pytest.mark.parametrize('barrier', ['spawn', 'registration', 'spawn_failure'])
def test_close_waits_for_launch_registration(broker, tmp_path, monkeypatch, barrier):
    import subprocess
    from concurrent.futures import ThreadPoolExecutor

    owner = OwnedProcesses(broker)
    entered, release, closing, closed = (threading.Event() for _ in range(4))
    children = []
    popen = subprocess.Popen

    def paused_spawn(*args, **kwargs):
        if barrier == 'spawn_failure':
            entered.set()
            assert release.wait(5)
            raise OSError('injected spawn failure')
        child = popen(*args, **kwargs)
        children.append(child)
        assert child.stdout.readline() == b'ready\n'
        if barrier == 'spawn':
            entered.set()
            assert release.wait(5)
        return child

    class RegistrationBarrier(list):
        def append(self, child):
            entered.set()
            assert release.wait(5)
            super().append(child)

    monkeypatch.setattr(subprocess, 'Popen', paused_spawn)
    if barrier == 'registration':
        owner._processes = RegistrationBarrier()

    def close():
        closing.set()
        result = owner.close(.1)
        closed.set()
        return result

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            launch = pool.submit(owner.launch_local, [sys.executable, '-c',
                'import time;print("ready",flush=True);time.sleep(30)'], cwd=tmp_path, env={})
            assert entered.wait(5)
            cleanup = pool.submit(close)
            assert closing.wait(5)
            try:
                assert not closed.wait(.1)
            finally:
                release.set()
            if barrier == 'spawn_failure':
                with pytest.raises(OSError, match='spawn failure'):
                    launch.result(timeout=5)
            else:
                assert launch.result(timeout=5) is children[0]
            assert cleanup.result(timeout=5)
            for child in children:
                assert child.poll() is not None
                assert all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))
            with pytest.raises(LeaseRefused):
                owner.launch_local(['unused'], cwd=tmp_path, env={})
    finally:
        release.set()
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


@pytest.mark.parametrize('operation', ['replace', 'complete'])
@pytest.mark.parametrize('failure', ['directory_fsync', 'temporary_cleanup'])
def test_committed_failure_preserves_bytes_and_revokes(
        broker, tmp_path, monkeypatch, operation, failure):
    identity = turn(broker)
    token = grant(broker, identity)
    fsync, unlink = os.fsync, os.unlink
    directory_fd = broker._root_fd if operation == 'replace' else broker._record_fd

    def fail_fsync(fd):
        if fd == directory_fd:
            raise OSError('injected directory fsync')
        return fsync(fd)

    def fail_unlink(*args, **kwargs):
        raise OSError('injected cleanup')

    if failure == 'directory_fsync':
        monkeypatch.setattr(os, 'fsync', fail_fsync)
    else:
        monkeypatch.setattr(os, 'unlink', fail_unlink)
    with pytest.raises(OSError, match='injected'):
        if operation == 'replace':
            broker.replace(token, identity, 'a', 'committed')
        else:
            broker.complete(token, identity, identity.candidate, 'sealed')
    assert broker.quarantined
    assert broker._active is None
    if operation == 'replace':
        assert (tmp_path / 'candidate' / 'a').read_text() == 'committed'
    else:
        records = list((tmp_path / 'records').glob('*.json'))
        assert len(records) == 1
        assert json.loads(records[0].read_text())['identity']['ordinal'] == 1
    with pytest.raises(LeaseRefused):
        broker.complete(token, identity, identity.candidate, 'sealed')
    monkeypatch.setattr(os, 'unlink', unlink)
