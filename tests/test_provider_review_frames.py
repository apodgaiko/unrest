"""Controlled transport boundary checks; no external reviewer or model calls."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import sys
import subprocess

import pytest

from tests.test_provider_review import FIXTURE, controller_fixture, event, wire
from unrest_harness.acp_runner import ACPNodeRunner
from unrest_harness.assets import AssetLoader
from unrest_harness.models import Task
from unrest_harness.provider_review import ProviderReviewCapture
from unrest_harness.storage import ProjectStore


MUTATIONS = [
    *(('id', value) for value in (None, 0, 2, '2', True, {}, [])),
    ('result', {}), ('error', {}), ('both', None),
    ('jsonrpc', None), ('jsonrpc', '1.0'), ('method', None), ('method', 'other'),
    ('sessionUpdate', None), ('sessionUpdate', []), ('sessionUpdate', 'other'),
    ('params_position', None), ('update_position', None),
    ('wrapper_conflict', None), ('output_conflict', None),
]


def malformed(field, value):
    frame = {'jsonrpc': '2.0', 'method': 'session/update', 'params': event()}
    if field == 'both':
        frame.update(id=2, result={}, error={})
    elif field == 'sessionUpdate':
        if value is None:
            frame['params']['update'].pop(field)
        else:
            frame['params']['update'][field] = value
    elif field == 'params_position':
        frame['update'] = frame.pop('params')['update']
    elif field == 'update_position':
        frame['params'] = frame['params']['update']
    elif field == 'wrapper_conflict':
        frame['params']['update']['rawInput'] = {'server': 's', 'tool': 't', 'arguments': {}}
    elif field == 'output_conflict':
        frame['params']['update']['rawOutput'] = {'result': {}, 'error': None}
    elif value is None and field in ('jsonrpc', 'method'):
        frame.pop(field)
    else:
        frame[field] = value
    return frame


@pytest.mark.parametrize(('field', 'value'), MUTATIONS)
async def test_malformed_frame_cannot_correlate_or_escape_capture(tmp_path, field, value):
    records = []
    capture = ProviderReviewCapture('thread-1', records.append)
    # wire sends session/new as ID 1 and session/prompt as ID 2.
    result = await wire(tmp_path, [], capture, raw_frame=json.dumps(malformed(field, value)))
    assert result is None
    assert capture.blocked.reason == 'invalid_context'
    assert len(records) == 1


@pytest.mark.parametrize('ordering', ['before', 'after', 'batch_before', 'batch_after', 'eof'])
async def test_actual_runner_matching_id_order_and_owned_cleanup(tmp_path, monkeypatch, ordering):
    controller, store, _ = controller_fixture(tmp_path)
    workspace = store.workspace_dir('project')
    subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
    subprocess.run(['git', '-c', 'user.name=Controlled Test', '-c',
                    'user.email=controlled@example.invalid', 'commit', '--allow-empty',
                    '-qm', 'Controlled completion identity'], cwd=workspace, check=True)
    scenario = tmp_path / 'scenario.json'
    config = replace(store.config, worker_acp_command=f'{sys.executable} {FIXTURE} {scenario}')
    runner = ACPNodeRunner(config, AssetLoader(config))
    frame = malformed('result', {})
    frame['id'] = '$prompt_id'
    path = store.attempt_path('project', 'mission-001', 'attempt-1', 'w1')
    scenario.write_text(json.dumps({'events': [], 'frames': [frame], 'ordering': ordering,
                                    'handoff': str(path), 'mcp_receipt': str(tmp_path / 'mcp-receipt')}))
    children = []
    spawn = asyncio.create_subprocess_exec

    async def record(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', record)
    handoff = await asyncio.wait_for(runner.run_node(
        'project', 'mission-001', Task(id='w1', type='work', body='controlled', targets=[], skill='s'),
        'attempt-1', store,
    ), 15)
    assert (tmp_path / 'mcp-receipt').read_text() == 'recorded'
    assert len(children) == 2 and all(child.returncode is not None for child in children)
    assert not handoff.done and handoff.request_attention
    controller.advance_project('project', max_steps=1)
    assert store.load_task_state('project', 'mission-001').status_of('w1') == 'failed'
    assert ProjectStore(config).read_provider_review(
        'project', 'mission-001', 'attempt-1', 'w1',
    ).reason == 'invalid_context'


async def test_ordinary_response_with_nested_review_is_not_captured(tmp_path):
    capture = ProviderReviewCapture('thread-1', lambda _: pytest.fail('unexpected block'))
    result = {'nested': event()}
    assert await wire(tmp_path, [], capture, raw_frame=json.dumps({
        'jsonrpc': '2.0', 'id': 2, 'result': result,
    })) == result
    assert capture.blocked is None


def test_first_block_survives_conflicting_frame_and_publication_failure():
    records = []
    capture = ProviderReviewCapture('thread-1', records.append)
    capture.consume(event())
    capture.consume_frame(malformed('id', []))
    assert capture.blocked.reason == 'denied' and len(records) == 1

    def unavailable(_):
        raise OSError('controlled')

    capture = ProviderReviewCapture('thread-1', unavailable)
    assert capture.consume_frame(malformed('id', 2))
    capture.consume(event('approved'))
    assert capture.blocked.reason == 'persistence_unavailable'


@pytest.mark.parametrize('payload', [None, {}, {'unexpected': 'controlled'}, []])
@pytest.mark.parametrize('registered', [False, True])
async def test_prefixed_update_with_malformed_content_blocks(tmp_path, payload, registered):
    update = event(update=True)
    update['update']['rawOutput'] = payload
    records = []
    capture = ProviderReviewCapture('thread-1', records.append)
    events = [event('inProgress')] if registered else []
    assert await wire(tmp_path, [*events, update], capture) is None
    assert capture.blocked.reason == 'invalid_context' and len(records) == 1
