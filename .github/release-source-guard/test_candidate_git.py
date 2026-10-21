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


def test_original_fixture_callable_frame_registers_without_running_git(tmp_path, monkeypatch):
    import importlib.util
    import sys
    from finite import candidate_git
    from finite.isolated_refusal import named
    source = Path(__file__).parent.parent.parent / 'tests/test_experimental_candidate.py'
    if not source.is_file():
        pytest.skip('original source is absent from the isolated control capsule')
    spec = importlib.util.spec_from_file_location('_candidate_original_control', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    root = tmp_path / 'pytest/case'
    root.mkdir(parents=True)
    pin = hashlib.sha256(source.read_bytes()).hexdigest()
    state = {'checkout': str(source.parents[1]), 'owned_root': str(tmp_path),
             'case': SOURCE + '::test_literal_manifest_and_independent_oracle',
             'product_pins': {SOURCE: pin}, 'copy_git': {'/usr/bin/git': 'image-pin'},
             'isolated_named': named,
             'isolated_source_code': lambda p: compile(p.read_bytes(), str(p), 'exec', dont_inherit=True)}
    records = []
    class Observed(Exception):
        pass
    def refuse(reason):
        raise AssertionError(reason)
    def capture(argv, **kwargs):
        selected = candidate_git.admit(argv, kwargs['cwd'], kwargs['env'], state, records.append, refuse)
        assert selected['class'] == CLASS
        assert selected['source_binding']['caller'] == 'repo'
        assert selected['source_binding']['caller_line'] == 35
        raise Observed
    monkeypatch.setattr(module.subprocess, 'check_output', capture)
    original = module.repo.__wrapped__
    with pytest.raises(Observed):
        original(root)
    assert len(records) == 1


def test_product_object_reader_is_bound_to_plain_import_code():
    from finite.isolated_refusal import named
    path = Path(__file__).parent.parent.parent / 'src/unrest_harness/experimental_candidate.py'
    if not path.is_file():
        pytest.skip('product source is absent from the isolated control capsule')
    from unrest_harness.experimental_candidate import _Observation
    path = Path(_Observation.git.__code__.co_filename)
    if not path.is_file():
        pytest.skip('product source is absent from the isolated control capsule')
    compiled = compile(path.read_bytes(), str(path), 'exec', dont_inherit=True)
    assert named(named(compiled, '_Observation'), 'git') == _Observation.git.__code__


def test_admitted_journal_omits_template_python_field_but_bootstrap_is_native():
    selected, *arguments = selection()
    del selected['registration']['python']
    assert git.eligible(selected, *arguments)
    selected['bootstrap_sha256'] = 'python-body'
    assert not git.eligible(selected, *arguments)


def maintenance_fixture(tmp_path):
    import zlib
    from candidate_git_maintenance import SITES
    root = tmp_path / 'pytest/case/repository'
    git_dir = root / '.git'
    (git_dir / 'refs/heads').mkdir(parents=True)
    (git_dir / 'config').write_text('[core]\nrepositoryformatversion=0\nfilemode=true\nbare=false\nlogallrefupdates=true\n[user]\nname=Fixture\nemail=fixture@example.invalid\n')
    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    body = b'tree ' + b'0' * 40 + b'\nauthor Fixture <fixture@example.invalid> 946684800 +0000\ncommitter Fixture <fixture@example.invalid> 946684800 +0000\n\nbase\n'
    raw = b'commit ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.sha1(raw).hexdigest()
    objects = git_dir / 'objects' / oid[:2]
    objects.mkdir(parents=True)
    (objects / oid[2:]).write_bytes(zlib.compress(raw))
    (git_dir / 'refs/heads/main').write_text(oid + '\n')
    parent = {'argv': ['/usr/bin/git', 'commit', '-m', 'base'], 'cwd': str(root),
              'environment': environment(root), 'candidate_registration': {'case': SOURCE + '::test_literal_manifest_and_independent_oracle',
              'source_binding': {'caller': 'repo', 'caller_line': 41}}}
    env = {**parent['environment'], 'PATH': '/usr/lib/git-core:/usr/bin:/bin',
           'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '', 'GIT_AUTHOR_NAME': 'Fixture',
           'GIT_AUTHOR_EMAIL': 'fixture@example.invalid', 'GIT_AUTHOR_DATE': '@946684800 +0000'}
    assert SITES[('repo', 41)] == 'base'
    return parent, env, str(root), str(tmp_path)


def test_exact_stock_maintenance_metadata(tmp_path):
    from candidate_git_maintenance import metadata
    assert metadata(*maintenance_fixture(tmp_path))


@pytest.mark.parametrize('change', ['caller', 'line', 'argv', 'cwd', 'parent_env', 'env', 'config',
                                   'head', 'ref', 'object', 'git_symlink'])
def test_stock_maintenance_refuses_changed_source_or_repository(tmp_path, change):
    from candidate_git_maintenance import metadata
    parent, env, cwd, owned_root = maintenance_fixture(tmp_path)
    root = Path(cwd)
    if change in {'caller', 'line'}:
        parent['candidate_registration']['source_binding'][{'line': 'caller_line'}.get(change, change)] = 'foreign'
    elif change == 'argv':
        parent['argv'][-1] = 'foreign'
    elif change == 'cwd':
        parent['cwd'] = '/foreign'
    elif change == 'parent_env':
        parent['environment']['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif change == 'env':
        env['GIT_AUTHOR_DATE'] = '@1 +0000'
    elif change == 'config':
        with (root / '.git/config').open('a') as stream:
            stream.write('[core]\nhooksPath=/foreign\n')
    elif change == 'head':
        (root / '.git/HEAD').write_text('ref: refs/heads/other\n')
    elif change == 'ref':
        (root / '.git/refs/heads/main').write_text('not-an-oid\n')
    elif change == 'object':
        oid = (root / '.git/refs/heads/main').read_text().strip()
        (root / '.git/objects' / oid[:2] / oid[2:]).write_bytes(b'not-zlib')
    else:
        (root / '.git').rename(root / 'elsewhere')
        (root / '.git').symlink_to(root / 'elsewhere', target_is_directory=True)
    try:
        accepted = metadata(parent, env, cwd, owned_root)
    except (ValueError, OSError, __import__('configparser').Error, __import__('zlib').error):
        accepted = False
    assert not accepted


@pytest.mark.parametrize('caller,line,message', [('repo', 41, 'base'), ('repo', 46, 'candidate'),
    ('test_unsupported_tree_entries', 402, 'unsupported'),
    ('test_executable_tracked_file_and_nested_extra', 454, 'executable')])
def test_four_original_commit_sites_keep_their_own_metadata(tmp_path, caller, line, message):
    import zlib
    from candidate_git_maintenance import metadata
    parent, env, cwd, owned_root = maintenance_fixture(tmp_path)
    git_dir = Path(cwd) / '.git'
    old_oid = (git_dir / 'refs/heads/main').read_text().strip()
    old = zlib.decompress((git_dir / 'objects' / old_oid[:2] / old_oid[2:]).read_bytes()).split(b'\0', 1)[1]
    body = old.removesuffix(b'base\n') + message.encode() + b'\n'
    raw = b'commit ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.sha1(raw).hexdigest()
    directory = git_dir / 'objects' / oid[:2]
    directory.mkdir(exist_ok=True)
    (directory / oid[2:]).write_bytes(zlib.compress(raw))
    (git_dir / 'refs/heads/main').write_text(oid + '\n')
    parent['argv'][-1] = message
    parent['candidate_registration']['source_binding'].update(caller=caller, caller_line=line)
    if caller != 'repo':
        parent['candidate_registration']['case'] = SOURCE + '::' + caller + ('[100644]' if line == 402 else '')
    assert metadata(parent, env, cwd, owned_root)
    parent['candidate_registration']['source_binding']['caller_line'] += 1
    assert not metadata(parent, env, cwd, owned_root)
