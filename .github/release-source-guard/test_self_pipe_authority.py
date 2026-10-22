"""Preserve every original per-payload process/READY authentication predicate."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

SUPPORT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('pipe_authority_control', SUPPORT / 'finite/self_pipe_authority.py')
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)


@pytest.fixture
def context(tmp_path):
    saved = {'pid': os.getpid(), 'ppid': os.getppid(), 'pgid': os.getpgid(0),
             'sid': os.getsid(0), 'uid': os.getuid(), 'start_ticks': 17,
             'clock_ticks_per_second': 100, 'boot_id': 'control-boot'}
    ready = {'kind': 'ready', 'owner_pid': os.getpid(), 'token': 'current-token',
             'manifest_sha256': '1' * 64, 'guard_sha256': '2' * 64,
             'registry_sha256': '3' * 64, 'runtime_sha256': '4' * 64}
    reader = SUPPORT / 'finite/linux_identity.py'
    state = {'setup_mode': 'source', 'phase': 'READY', 'token': ready['token'],
             'ready_record': ready, 'events': str(tmp_path),
             'direct_support': {'files': {str(reader): hashlib.sha256(reader.read_bytes()).hexdigest()}}}
    path = tmp_path / (str(os.getpid()) + '.jsonl')
    path.write_text(json.dumps({'kind': 'before'}) + '\n' + json.dumps(ready) + '\n')
    path.chmod(0o600)
    current = deepcopy(saved)
    calls = []
    def identify(pid):
        assert pid == os.getpid()
        calls.append('fresh identity')
        return dict(current)
    def load(path, pin):
        assert path == reader and pin == state['direct_support']['files'][str(reader)]
        return {'identity': identify}
    def refuse(reason):
        raise RuntimeError(reason)
    guard = SimpleNamespace(__file__=str(SUPPORT / 'finite/runtime_guard.py'), _STATE=state,
                            checked_source=load, require_ready=lambda token: calls.append(token),
                            refuse=refuse)
    endpoint = SimpleNamespace(STATE={'identity': deepcopy(saved), 'token': ready['token']})
    return guard, endpoint, current, path, calls


def test_fresh_process_and_exact_durable_ready_are_joined_every_time(context):
    guard, endpoint, _, path, calls = context
    check = authority.prepare(guard, endpoint)
    for _ in range(3):
        result = check()
        assert result['process_identity'] == endpoint.STATE['identity']
        assert result['token'] == endpoint.STATE['token']
        assert len(result['ready_sha256']) == 64
        with path.open('a') as stream:
            stream.write(json.dumps({'kind': 'later append'}) + '\n')
    assert calls == ['current-token', 'fresh identity', 'fresh identity', 'fresh identity']


@pytest.mark.parametrize('field', ['pid', 'ppid', 'pgid', 'sid', 'uid', 'start_ticks',
                                   'clock_ticks_per_second', 'boot_id'])
def test_every_original_fresh_process_identity_field_refuses_drift(context, field):
    guard, endpoint, current, _, _ = context
    check = authority.prepare(guard, endpoint)
    current[field] = 'changed'
    assert check() is None  # Original observer owns refusal or exact adoption proof.


@pytest.mark.parametrize('field', ['phase', 'state-token', 'ready', 'endpoint-token', 'endpoint-identity'])
def test_live_ready_claim_drift_refuses(context, field):
    guard, endpoint, _, _, _ = context
    check = authority.prepare(guard, endpoint)
    if field == 'phase':
        guard._STATE['phase'] = 'pending'
    elif field == 'state-token':
        guard._STATE['token'] = 'changed'
    elif field == 'ready':
        guard._STATE['ready_record']['guard_sha256'] = '0' * 64
    elif field == 'endpoint-token':
        endpoint.STATE['token'] = 'changed'
    else:
        endpoint.STATE['identity']['ppid'] += 1
    assert check() is None


@pytest.mark.parametrize('drift', ['removed-ready', 'replacement', 'symlink', 'mode'])
def test_ready_journal_remains_real_current_and_owned(context, drift):
    guard, endpoint, _, path, _ = context
    check = authority.prepare(guard, endpoint)
    if drift == 'removed-ready':
        path.write_text('{"kind":"unrelated"}\n')
    elif drift in ('replacement', 'symlink'):
        original = path.with_suffix('.saved')
        path.rename(original)
        if drift == 'replacement':
            path.write_bytes(original.read_bytes())
            path.chmod(0o600)
        else:
            path.symlink_to(original)
    else:
        path.chmod(0o644)
    assert check() is None


def test_non_source_mode_never_selects_local_enforcement():
    guard = SimpleNamespace(_STATE={'setup_mode': 'non-source'})
    assert authority.prepare(guard, None) is None
