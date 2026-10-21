"""Closed candidate Git and malformed-fixture joins preserve native no-launch negatives."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import candidate_git_custody as git
from finite.candidate_git import CLASS, SOURCE, environment
import invalid_format_custody as invalid
import owned_multiprocess_authority as owned


def selection():
    vector = ['/usr/bin/git', 'rev-parse', 'HEAD']
    cwd = '/work/owned/pytest/case/repository'
    env = environment(cwd)
    registration = {'class': CLASS, 'python': False, 'case': SOURCE + '::test_literal_manifest_and_independent_oracle',
                    'owner_pid': 20, 'token': 'actual',
                    'source_binding': {'path': '/source/' + SOURCE, 'line': 21, 'sha256': 'pin', 'function': 'git'}}
    selected = {'registration': registration, 'owner_pid': 20, 'token': 'actual',
                'bootstrap_sha256': None, 'cwd': cwd,
                'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()}
    return selected, vector, env, cwd, '/source', '/work/owned', {SOURCE: 'pin'}


def test_native_git_consumes_exact_source_registration():
    assert git.eligible(*selection())


@pytest.mark.parametrize('key', ['class', 'python', 'case', 'token', 'owner_pid', 'source_binding',
                                'cwd', 'bootstrap_sha256', 'transformed_argv_sha256', 'environment_sha256',
                                'vector', 'environment', 'owned', 'pin'])
def test_native_git_rejects_each_broken_binding(key):
    selected, vector, env, cwd, checkout, owned_root, pins = selection()
    if key in {'class', 'python', 'case', 'token', 'owner_pid', 'source_binding'}:
        selected['registration'][key] = 'foreign'
    elif key == 'vector':
        vector[0] = '/bin/sh'
    elif key == 'environment':
        env['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif key == 'owned':
        owned_root = '/other'
    elif key == 'pin':
        pins[SOURCE] = 'foreign'
    else:
        selected[key] = 'foreign'
    assert not git.eligible(selected, vector, env, cwd, checkout, owned_root, pins)


def malformed(tmp_path, monkeypatch):
    root = tmp_path / 'pytest/case/workspace'
    root.mkdir(parents=True)
    case, name = next(iter(invalid.CASES.items()))
    launcher = root / name
    launcher.write_bytes(invalid.BODY)
    launcher.chmod(0o700)
    env, vector = {'PATH': '/usr/bin:/bin'}, ['./' + name]
    ident = {'pid': 20, 'uid': os.getuid(), 'start_ticks': 12}
    monkeypatch.setattr(invalid, 'identity', lambda pid: ident)
    original = Path.resolve
    def resolve(path, *args, **kwargs):
        return root if str(path) == '/proc/21/cwd' else original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'resolve', resolve)
    registration = {'class': 'source-cohort2:invalid-format', 'case': case, 'owner_pid': 20, 'token': 'actual',
                    'source_binding': {'path': '/source/' + invalid.PRODUCT, 'line': 409,
                                       'sha256': 'product-pin', 'function': 'spawn_launch'}}
    selected = {'bootstrap_sha256': None, 'registration': registration, 'cwd': str(root),
                'token': 'actual', 'owner_pid': 20,
                'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()}
    authority = SimpleNamespace(bound={21: selected}, manifest={'owned_root': str(tmp_path),
                                'product_pins': {invalid.PRODUCT: 'product-pin'}},
                                supervisor=SimpleNamespace(registered={20: {'identity': ident}}),
                                contexts={}, pipe_records=[])
    trace = SimpleNamespace(identities={21: {'ppid': 20}})
    return authority, trace, vector, env, root, launcher


def test_only_original_malformed_bytes_reach_kernel(tmp_path, monkeypatch):
    authority, trace, vector, env, root, _ = malformed(tmp_path, monkeypatch)
    assert invalid.resolve(authority, trace, 21, vector[0], vector, env, str(root))
    assert authority.pipe_records[0]['expected_exec_return'] == -8
    assert authority.pipe_records[0]['successful_exec_permitted'] is False


@pytest.mark.parametrize('change', ['body', 'script', 'mode', 'symlink', 'case', 'token', 'cwd', 'vector'])
def test_malformed_fixture_does_not_grant_real_execution(tmp_path, monkeypatch, change):
    authority, trace, vector, env, root, launcher = malformed(tmp_path, monkeypatch)
    if change in {'body', 'script'}:
        launcher.write_bytes(b'\x7fELF' if change == 'body' else b'#!/bin/sh\nexit 0\n')
    elif change == 'mode':
        launcher.chmod(0o755)
    elif change == 'symlink':
        other = root / 'other'
        other.write_bytes(invalid.BODY)
        other.chmod(0o700)
        launcher.unlink()
        launcher.symlink_to(other)
    elif change in {'case', 'token'}:
        authority.bound[21]['registration'][change] = 'foreign'
    elif change == 'cwd':
        authority.bound[21]['cwd'] = '/foreign'
    else:
        vector.append('foreign')
    assert not invalid.resolve(authority, trace, 21, vector[0], vector, env, str(root))


def test_successful_exec_of_malformed_fixture_stops_before_body():
    errors = []
    authority = SimpleNamespace(bound={21: {'registration': {'class': 'source-cohort2:invalid-format'}}},
                                supervisor=SimpleNamespace(poison=errors.append))
    trace = SimpleNamespace(poison=[])
    with pytest.raises(RuntimeError, match='unexpected_successful_exec'):
        owned.OwnedMultiprocessCustody.exec_descriptors(authority, trace, 21, [], {}, '/source')
    assert trace.poison == errors == ['invalid_format_unexpected_successful_exec']
