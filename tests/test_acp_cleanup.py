"""Bounded ordinary cleanup regressions with retained child handles."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

import pytest

from unrest_harness import acp_runner as a
from unrest_harness.assets import AssetLoader
from unrest_harness.models import Task, TaskList
from unrest_harness.storage import ProjectStore
from tests.test_acp_runner import _safe_policy
from tests.test_provider_review import controller_fixture

FIXTURE = Path(__file__).parent / 'fixtures' / 'cleanup_acp_process.py'


def malformed(case):
    if case == 'deep_json':
        return '[' * 10000 + '0' + ']' * 10000
    if case == 'success':
        return None
    return json.dumps({'jsonrpc': '2.0', 'id': [] if case == 'array_id' else {}, 'result': {}})


async def rescue(children):
    for child in children:
        if child.returncode is None:
            child.kill()
            await asyncio.wait_for(child.wait(), 5)


@pytest.mark.parametrize('role', ['work', 'validate', 'terminal_reviewer'])
@pytest.mark.parametrize('failure', ['exit', 'deadline', 'cancel'])
async def test_startup_failure_attribution_and_owned_cleanup(tmp_path, monkeypatch, role, failure, caplog):
    _, store, _ = controller_fixture(tmp_path)
    runner = a.ACPNodeRunner(store.config, AssetLoader(store.config))
    children = []
    entered = asyncio.Event()
    original_wait = runner._wait_for_server_ready
    original_close = runner._close_mcp_process

    async def start(**kwargs):
        body = (
            "import sys; print('private-startup-body',file=sys.stderr); sys.exit(23)"
            if failure == 'exit' else "import time; time.sleep(30)"
        )
        child = await asyncio.create_subprocess_exec(
            sys.executable, '-c', body,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        children.append(child)
        runner._start_mcp_drains(child)
        return child

    async def ready(host, port, *, process):
        entered.set()
        return await original_wait(host, port, timeout=.5, process=process)

    async def close(*args, **kwargs):
        await original_close(*args, **kwargs)
        if failure == 'cancel':
            raise RuntimeError('secondary cleanup fault')

    async def forbidden(*args, **kwargs):
        raise AssertionError('ACP launch must not follow startup failure')

    monkeypatch.setattr(runner, '_start_worker_mcp_server', start)
    monkeypatch.setattr(runner, '_start_terminal_reviewer_mcp', start)
    monkeypatch.setattr(runner, '_wait_for_server_ready', ready)
    monkeypatch.setattr(runner, '_close_mcp_process', close)
    monkeypatch.setattr(a, 'spawn_launch', forbidden)
    try:
        if role == 'terminal_reviewer':
            pending = runner.run_terminal_review('project', 'mission-001', 'startup', store)
        else:
            pending = runner.run_node('project', 'mission-001', Task(
                id='startup', type=role, body='local startup', targets=[], skill='s'), 'startup', store)
        task = asyncio.create_task(pending)
        if failure == 'cancel':
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            if role == 'terminal_reviewer':
                with pytest.raises(RuntimeError) as caught:
                    await task
                report = str(caught.value)
                assert isinstance(caught.value.__cause__, TimeoutError)
            else:
                handoff = await task
                assert not handoff.done and handoff.request_attention is False
                report = handoff.report
            assert 'stage=tcp_readiness' in report
            assert f'pid={children[0].pid}' in report
            assert ('reason=child_exit' if failure == 'exit' else 'reason=deadline') in report
            assert ('exit_code=23' if failure == 'exit' else 'exit_code=None') in report
            assert 'private-startup-body' not in report
        assert len(children) == 1 and children[0].returncode is not None
        assert not runner._mcp_drains
        assert 'private-startup-body' not in caplog.text
    finally:
        await rescue(children)


@pytest.mark.parametrize('role', ['work', 'validate', 'terminal_reviewer'])
@pytest.mark.parametrize('case', ['deep_json', 'array_id', 'object_id', 'success'])
async def test_recorded_transport_failures(tmp_path, monkeypatch, role, case):
    _, store, _ = controller_fixture(tmp_path)
    targets = ['VAL-CLEANUP'] if role == 'validate' else []
    if role == 'validate':
        (store.ensure_contract_dir('project', 'mission-001') / 'VAL-CLEANUP.md').write_text(
            '# Local cleanup fixture\nControlled target.\n')
        store.save_task_list('project', 'mission-001', TaskList(tasks=[Task(
            id='w1', type='validate', body='controlled', targets=targets, skill='s')]))
    ws = store.workspace_dir('project')
    subprocess.run(['git', 'init', '-q', str(ws)], check=True)
    subprocess.run(['git', '-c', 'user.name=Controlled', '-c',
                    'user.email=controlled@example.invalid', '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '--allow-empty',
                    '-qm', 'Controlled'], cwd=ws, check=True)
    scenario = tmp_path / 'scenario.json'
    scenario.write_text(json.dumps({'raw': malformed(case), 'role': role,
                                    'receipt': str(tmp_path / 'receipt')}))
    command = f'{sys.executable} {FIXTURE} {scenario}'
    config = replace(store.config, worker_acp_command=command,
                     validator_acp_command=command, terminal_reviewer_acp_command=command)
    runner = a.ACPNodeRunner(config, AssetLoader(config))
    children = []
    spawn = asyncio.create_subprocess_exec

    async def tracked(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', tracked)
    error = None
    result = None
    try:
        try:
            if role == 'terminal_reviewer':
                result = await asyncio.wait_for(runner.run_terminal_review(
                    'project', 'mission-001', 'attempt-1', store), 20)
            else:
                result = await asyncio.wait_for(runner.run_node(
                    'project', 'mission-001', Task(id='w1', type=role, body='controlled',
                    targets=targets, skill='s'), 'attempt-1', store), 20)
        except Exception as exc:
            error = exc
        assert (tmp_path / 'receipt').exists(), repr(error)
        assert (tmp_path / 'receipt').read_text() == 'recorded'
        assert len(children) == 2
        assert all(child.returncode is not None for child in children), [
            child.returncode for child in children]
        assert error is None or isinstance(error, a.ACPError)
        if case == 'success':
            assert error is None and result.done
        else:
            assert error is not None or (not result.done and result.request_attention)
            if role != 'terminal_reviewer':
                block = ProjectStore(config).read_provider_review(
                    'project', 'mission-001', 'attempt-1', 'w1')
                assert block is not None and block.review is None
    finally:
        await rescue(children)


@pytest.mark.parametrize('role', ['work', 'validate', 'terminal_reviewer'])
@pytest.mark.parametrize('fault', ['reader', 'client', 'progress', 'cancel', 'primary'])
async def test_cleanup_faults_and_repeated_cancellation(tmp_path, monkeypatch, role, fault):
    _, store, _ = controller_fixture(tmp_path)
    scenario = tmp_path / 'scenario.json'
    scenario.write_text(json.dumps({'role': role, 'no_handoff': True}))
    command = f'{sys.executable} {FIXTURE} {scenario}'
    config = replace(store.config, worker_acp_command=command,
                     validator_acp_command=command, terminal_reviewer_acp_command=command)
    runner = a.ACPNodeRunner(config, AssetLoader(config))
    children = []
    spawn = asyncio.create_subprocess_exec
    entered, release = asyncio.Event(), asyncio.Event()
    original_cleanup = a.ACPClient.cleanup
    failure = RuntimeError('controlled cleanup fault')
    primary = RuntimeError('controlled session failure')
    original_request = a.ACPClient.send_request

    async def request(client, method, params):
        result = await original_request(client, method, params)
        if method == 'session/prompt':
            raise primary
        return result

    async def tracked(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        return child

    async def cleanup(client, **kwargs):
        await original_cleanup(client, **kwargs)
        if fault == 'client':
            raise failure
        if fault == 'cancel':
            entered.set()
            await release.wait()
            raise failure

    async def flush(tracker):
        raise failure

    async def finish_reader(client):
        await original_finish(client)
        raise failure

    original_finish = a.ACPClient._finish_reader
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', tracked)
    monkeypatch.setattr(a.ACPClient, 'cleanup', cleanup)
    if fault == 'primary':
        monkeypatch.setattr(a.ACPClient, 'send_request', request)
    if fault in ('progress', 'primary'):
        monkeypatch.setattr(a.ACPProgressTracker, 'flush', flush)
    if fault == 'reader':
        monkeypatch.setattr(a.ACPClient, '_finish_reader', finish_reader)
    if role == 'terminal_reviewer':
        coro = runner.run_terminal_review('project', 'mission-001', 'attempt-1', store)
    else:
        coro = runner.run_node('project', 'mission-001', Task(id='w1', type=role,
            body='controlled', targets=[], skill='s'), 'attempt-1', store)
    task = asyncio.create_task(coro)
    try:
        if fault == 'cancel':
            await asyncio.wait_for(entered.wait(), 15)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
        done, _ = await asyncio.wait([task], timeout=20)
        assert done, 'cleanup did not finish within bounded observation'
        with pytest.raises(asyncio.CancelledError if fault == 'cancel' else RuntimeError) as caught:
            task.result()
        if role == 'terminal_reviewer' and fault == 'progress':
            assert 'without calling submit_terminal_review' in str(caught.value)
        elif fault != 'cancel':
            assert caught.value is (primary if fault == 'primary' else failure)
        assert len(children) == 2 and all(p.returncode is not None for p in children)
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await rescue(children)
        await asyncio.gather(task, return_exceptions=True)


async def test_client_cleanup_reaps_main_after_reader_failure(tmp_path, monkeypatch):
    child = await asyncio.create_subprocess_exec(sys.executable, '-c',
        'import time; time.sleep(30)', stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE)
    client = a.ACPClient(child, str(tmp_path), policy=_safe_policy('codex'),
                         terminal_environment={})
    error = RuntimeError('controlled reader fault')

    async def fail():
        raise error

    finish = client._finish_reader

    async def fail_settlement():
        await finish()
        raise OSError('secondary settlement failure')

    monkeypatch.setattr(client, '_finish_reader', fail_settlement)
    client._reader_task = asyncio.create_task(fail())
    await asyncio.sleep(0)
    try:
        with pytest.raises(RuntimeError) as caught:
            await client.cleanup()
        assert caught.value is error and child.returncode is not None
        assert not client._pending
    finally:
        await rescue([child])


@pytest.mark.parametrize('cancel', [False, True])
async def test_client_exhausts_terminals_pending_and_main(tmp_path, monkeypatch, cancel):
    children = [await asyncio.create_subprocess_exec(sys.executable, '-c',
        'import time; time.sleep(30)', stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE) for _ in range(3)]
    client = a.ACPClient(children[0], str(tmp_path), policy=_safe_policy('codex'),
                         terminal_environment={})
    for i, child in enumerate(children[1:]):
        client._terminals[str(i)] = a.ManagedTerminal(str(i), child)
    pending = asyncio.get_running_loop().create_future()
    client._pending[1] = pending
    entered, release = asyncio.Event(), asyncio.Event()
    close = a._close_subprocess
    failure = RuntimeError('controlled terminal cleanup fault')

    async def faulty_close(process, **kwargs):
        await close(process, **kwargs)
        if process is children[1]:
            if cancel:
                entered.set()
                await release.wait()
            raise failure

    monkeypatch.setattr(a, '_close_subprocess', faulty_close)
    task = asyncio.create_task(client.cleanup())
    try:
        if cancel:
            await asyncio.wait_for(entered.wait(), 10)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
        done, _ = await asyncio.wait([task], timeout=15)
        assert done
        with pytest.raises(asyncio.CancelledError if cancel else RuntimeError) as caught:
            task.result()
        if not cancel:
            assert caught.value is failure
        assert all(child.returncode is not None for child in children)
        assert not client._pending and not client._terminals
        assert isinstance(pending.exception(), a.ACPError)
    finally:
        release.set()
        await rescue(children)
        await asyncio.gather(task, return_exceptions=True)
        if pending.done() and not pending.cancelled():
            pending.exception()


@pytest.mark.parametrize('rid', [1, '1', None, True, 1.0, [], {}])
async def test_response_correlation_keeps_numeric_identity(tmp_path, rid):
    # No child is needed for the pure correlation boundary.
    client = a.ACPClient(None, str(tmp_path), policy=_safe_policy('codex'),
                         terminal_environment={})
    pending = asyncio.get_running_loop().create_future()
    client._pending[1] = pending
    try:
        if rid is not None and type(rid) not in (str, int, float):
            with pytest.raises(a.ACPError, match='Invalid ACP response ID'):
                client._handle_response({'id': rid, 'result': 'ok'})
        else:
            client._handle_response({'id': rid, 'result': 'ok'})
        assert pending.done() == (type(rid) in (int, float))
        if pending.done():
            assert pending.result() == 'ok'
    finally:
        pending.cancel()


@pytest.mark.parametrize('fault', ['observer', 'cancel', 'transport'])
async def test_saved_review_observer_compatibility(tmp_path, monkeypatch, caplog, fault):
    _, store, _ = controller_fixture(tmp_path)
    scenario = tmp_path / 'scenario.json'
    scenario.write_text(json.dumps({'role': 'terminal_reviewer', 'progress': True,
        'receipt': str(tmp_path / 'receipt'),
        'raw': malformed('array_id') if fault == 'transport' else None}))
    command = f'{sys.executable} {FIXTURE} {scenario}'
    config = replace(store.config, terminal_reviewer_acp_command=command)
    runner = a.ACPNodeRunner(config, AssetLoader(config))
    secret = 'controlled-secret-observer-value'
    monkeypatch.setenv('OPENAI_API_KEY', secret)
    children, observed, saved = [], [], []
    spawn = asyncio.create_subprocess_exec
    report_path = store.terminal_review_path('project', 'mission-001', 'attempt-1')

    async def tracked(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        return child

    def observer(message):
        observed.append(message)
        saved.append(report_path.read_bytes())
        if fault == 'cancel':
            raise asyncio.CancelledError()
        raise RuntimeError('observer failed ' + secret)

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', tracked)
    result, error = None, None
    try:
        try:
            result = await asyncio.wait_for(runner.run_terminal_review(
                'project', 'mission-001', 'attempt-1', store, progress_callback=observer), 20)
        except BaseException as exc:
            error = exc
        assert (tmp_path / 'receipt').exists(), repr(error)
        assert (tmp_path / 'receipt').read_text() == 'recorded'
        assert len(children) == 2 and all(p.returncode is not None for p in children)
        assert observed == ['Agent: controlled progress']
        assert saved == [report_path.read_bytes()]
        original = json.loads(saved[0])
        assert original['done'] and original['report'] == 'controlled completion'
        if fault == 'cancel':
            assert isinstance(error, asyncio.CancelledError)
        elif fault == 'transport':
            assert isinstance(error, a.ACPError)
        else:
            assert error is None, repr(error)
            assert result.done and result.report == original['report']
        if fault != 'cancel':
            assert 'Terminal-review progress callback failed' in caplog.text
            assert 'observer failed' in caplog.text and secret not in caplog.text
    finally:
        await rescue(children)


@pytest.mark.parametrize('settlement_fault', [False, True])
async def test_inflight_terminal_registration_before_inventory(tmp_path, monkeypatch,
                                                             settlement_fault):
    spawn = asyncio.create_subprocess_exec
    children = [await spawn(sys.executable, '-c', 'import time; time.sleep(30)',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE) for _ in range(2)]
    # Policy is irrelevant to this scheduling proof, but terminal/create still
    # traverses the real spawn, registration, output and close implementations.
    policy = _safe_policy('codex')
    monkeypatch.setattr(type(policy), 'authorize_command', lambda *args: None)
    monkeypatch.setattr(type(policy), 'authorize_path', lambda *args, **kwargs: tmp_path)
    client = a.ACPClient(children[0], str(tmp_path), policy=policy, terminal_environment={})
    client._terminals['existing'] = a.ManagedTerminal('existing', children[1])
    spawned, release, registered = asyncio.Event(), asyncio.Event(), asyncio.Event()
    events = []
    failure = RuntimeError('controlled post-settlement failure')
    finish = client._finish_reader
    close = a._close_subprocess

    async def paused_spawn(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        spawned.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            # Controlled producer completion during cancellation: this is a
            # registration-order fixture, not a claim about stdlib spawn races.
            events.append('producer-cancelled')
        return child

    async def create():
        await client._handle_terminal_create({'command': sys.executable,
                                             'args': ['-c', 'import time; time.sleep(30)']})
        events.append('registered')
        registered.set()

    async def settle():
        await finish()
        events.append('settled')
        if settlement_fault:
            raise failure

    async def close_barrier(process, **kwargs):
        if process is children[1]:
            events.append('existing-close')
            release.set()
            await asyncio.wait_for(registered.wait(), 5)
        await close(process, **kwargs)

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', paused_spawn)
    monkeypatch.setattr(client, '_finish_reader', settle)
    monkeypatch.setattr(a, '_close_subprocess', close_barrier)
    producer = asyncio.create_task(create())
    client._request_tasks.add(producer)
    producer.add_done_callback(client._request_tasks.discard)
    cleanup = None
    try:
        await asyncio.wait_for(spawned.wait(), 5)
        cleanup = asyncio.create_task(client.cleanup())
        done, _ = await asyncio.wait([cleanup], timeout=15)
        assert done, 'cleanup exceeded observation bound'
        if settlement_fault:
            with pytest.raises(RuntimeError) as caught:
                cleanup.result()
            assert caught.value is failure
        else:
            cleanup.result()
        observation = {'events': events, 'returncodes': [p.returncode for p in children],
                       'inventory': list(client._terminals), 'producer_done': producer.done()}
        print(json.dumps(observation))
        assert len(children) == 3 and all(p.returncode is not None for p in children), observation
        assert events.index('registered') < events.index('settled') < events.index('existing-close')
        assert producer.done() and not client._terminals and not client._request_tasks
    finally:
        release.set()
        await rescue(children)
        await asyncio.gather(producer, *([cleanup] if cleanup else []), return_exceptions=True)
