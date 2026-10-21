"""Exact original LaunchPlan fixtures and refusal of changed custody links."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from finite import launch_preflight_routes as routes
from finite.launch_image import resolve as image
from launch_preflight_custody import join


@pytest.mark.parametrize('name', list(routes.SITES))
def test_only_nine_original_spawn_sites_have_finite_specs(name, tmp_path):
    case = routes.SOURCE + '::' + name
    spec = routes.specification(case, str(tmp_path))
    assert spec['line'] == routes.SITES[name]
    assert spec['owner'] == name.split('[')[0]
    assert not routes.specification(case + '-foreign', str(tmp_path))
    assert not routes.specification(case, '../foreign')


@pytest.mark.parametrize('name', [n for n in routes.SITES if n != routes.ALIAS_OWNER and 'legal_empty' not in n])
def test_fixed_script_bytes_modes_and_file_kind(name, tmp_path):
    spec = routes.specification(routes.SOURCE + '::' + name, str(tmp_path))
    launcher = spec['launcher']
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_bytes(spec['body'])
    launcher.chmod(0o700)
    assert routes.fixture(spec, {})
    launcher.write_bytes(spec['body'] + b'foreign')
    assert not routes.fixture(spec, {})
    launcher.write_bytes(spec['body'])
    launcher.chmod(0o600)
    assert not routes.fixture(spec, {})
    launcher.unlink()
    launcher.mkdir()
    assert not routes.fixture(spec, {})


def test_alias_is_actual_symlink_to_byte_pinned_runtime(tmp_path):
    spec = routes.specification(routes.SOURCE + '::' + routes.ALIAS_OWNER, str(tmp_path))
    runtime = {'realpath': str(Path(sys.executable).resolve()), 'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}
    spec['launcher'].symlink_to(sys.executable)
    assert routes.fixture(spec, runtime)
    assert not routes.fixture(spec, {**runtime, 'sha256': '0' * 64})
    assert not routes.fixture(spec, {**runtime, 'realpath': '/foreign'})


def context(name):
    cwd = '/work/owned/pytest/test_real_spawn_preserves_exac0' if name == routes.ALIAS_OWNER else '/work/owned/pytest/original0'
    case = routes.SOURCE + '::' + name
    spec = routes.specification(case, cwd)
    vector = ['adapter', '-c', 'exact bootstrap'] if spec['kind'] == 'python-alias' else spec['argv']
    env = spec['environment']
    registration = {'class': routes.ALIAS_CLASS if spec['kind'] == 'python-alias' else routes.NATIVE_CLASS,
                    'case': case, 'owner_pid': 20, 'token': 'one-original-launch',
                    'source_binding': {'path': '/source/' + routes.SOURCE, 'line': spec['line'], 'sha256': routes.PIN}}
    selected = {'registration': registration, 'owner_pid': 20, 'token': registration['token'], 'cwd': cwd,
                'bootstrap_sha256': hashlib.sha256(vector[2].encode()).hexdigest() if spec['kind'] == 'python-alias' else None,
                'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()}
    manifest = {'product_pins': {routes.SOURCE: routes.PIN}, 'owned_root': '/work/owned',
                'runtime': {'paths': [routes.ALIAS_PATH]}}
    return selected, vector, env, cwd, manifest


@pytest.mark.parametrize('name', list(routes.SITES))
def test_each_exact_registration_joins_stopped_vector(name):
    assert join(*context(name)) is not None


@pytest.mark.parametrize('field', ['class', 'case', 'source_binding', 'owner_pid', 'token',
                                   'cwd', 'bootstrap_sha256', 'transformed_argv_sha256',
                                   'environment_sha256', 'vector', 'environment', 'source_pin'])
@pytest.mark.parametrize('name', [routes.ALIAS_OWNER, 'test_real_direct_launch_preserves_original_argv0[relative]'])
def test_any_changed_custody_link_refuses(field, name):
    selected, vector, env, cwd, manifest = deepcopy(context(name))
    if field in {'class', 'case', 'source_binding', 'owner_pid', 'token'}:
        selected['registration'][field] = 'foreign'
    elif field == 'vector':
        vector.append('--foreign')
    elif field == 'environment':
        env['LD_PRELOAD'] = '/foreign'
    elif field == 'source_pin':
        manifest['product_pins'][routes.SOURCE] = 'foreign'
    else:
        selected[field] = 'foreign'
    assert join(selected, vector, env, cwd, manifest) is None


@pytest.mark.parametrize('entry', ['', 'tools'])
def test_lifecycle_image_uses_child_cwd_for_relative_path(tmp_path, monkeypatch, entry):
    parent = tmp_path / 'parent'
    child = tmp_path / 'child'
    parent.mkdir()
    child.mkdir()
    target = child / entry / 'adapter'
    target.parent.mkdir(exist_ok=True)
    target.write_text('#!/bin/sh\nexit 0\n')
    target.chmod(0o700)
    monkeypatch.chdir(parent)
    # Synthetic controls deliberately mount /work noexec. A real access probe
    # must respect that mount even when mode bits contain execute permission.
    if getattr(os, 'ST_NOEXEC', 0) & os.statvfs(child).f_flag:
        with pytest.raises(FileNotFoundError):
            image('adapter', child, {'PATH': entry})
    else:
        assert Path(image('adapter', child, {'PATH': entry})) == target
    assert image('./' + str(Path(entry) / 'adapter'), child, {}) == str(child / entry / 'adapter')


def test_image_skips_directory_and_non_executable_without_host_fallback(tmp_path):
    for name in ('blocked', 'selected'):
        (tmp_path / name).mkdir()
    (tmp_path / 'blocked/adapter').mkdir()
    selected = tmp_path / 'selected/adapter'
    selected.write_bytes(b'fixed')
    selected.chmod(0o700)
    if getattr(os, 'ST_NOEXEC', 0) & os.statvfs(tmp_path).f_flag:
        with pytest.raises(FileNotFoundError):
            image('adapter', tmp_path, {'PATH': 'blocked:selected'})
    else:
        assert image('adapter', tmp_path, {'PATH': 'blocked:selected'}) == str(selected)
    selected.chmod(0o600)
    with pytest.raises(FileNotFoundError):
        image('adapter', tmp_path, {'PATH': 'blocked:selected'})
