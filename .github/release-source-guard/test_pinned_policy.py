"""Pure derivation reuse never substitutes for fresh policy or byte admission."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_linux_supervisor import host


def sha(body):
    return hashlib.sha256(body).hexdigest()


@pytest.fixture
def policy(tmp_path, monkeypatch):
    finite = tmp_path / 'finite'
    finite.mkdir()
    path = finite / 'custody_host.py'
    path.write_bytes((host.ROOT / path.name).read_bytes())
    monkeypatch.setattr(host, 'ROOT', finite)
    supervisor = host.Supervisor.__new__(host.Supervisor)
    supervisor.spec = {'pins': {str(path): sha(path.read_bytes())}}
    supervisor.root = {'uid': os.getuid()}
    source = tmp_path / 'checkout/src/unrest_harness/run_control.py'
    source.parent.mkdir(parents=True)
    source.write_bytes(b'\n' * 1146 + b'launch_worker(project, request)\n')
    root = tmp_path / 'owned/project'
    request = root / '.unrest/runs/one/request.json'
    request.parent.mkdir(parents=True)
    run = {'run_id': 'run:one', 'generation': 1}
    request.write_text(json.dumps(run))
    supervisor.manifest = {'owned_root': str(tmp_path / 'owned'),
                           'checkout': str(tmp_path / 'checkout'),
                           'product_pins': {'src/unrest_harness/run_control.py': sha(source.read_bytes())},
                           'runtime': {'paths': [sys.executable]}, 'source_case': 'case'}
    call = next(n for n in ast.walk(ast.parse(source.read_bytes())) if isinstance(n, ast.Call))
    snapshot = {'cwd': str(root), 'request': run, 'request_path': str(request),
                'request_sha256': sha(request.read_bytes()),
                'source_sha256': sha(source.read_bytes()),
                'AST_sha256': sha(ast.dump(call, include_attributes=False).encode()),
                'argv': [sys.executable, '-m', 'unrest_harness.run_worker', '--project-root',
                         str(root), '--run-id', 'run:one', '--executor', 'executor_fixture:execute',
                         '--custody-root-id', 'custody', '--generation', '1'],
                'executor': 'executor_fixture:execute', 'custody_root_id': 'custody',
                'worker_environment': {}, 'env': {'LANG': 'C.UTF-8', 'PATH': os.defpath,
                                                  'PYTHONPATH': str(source.parent.parent)},
                'owner_id': 'owner', 'requesting_case': 'case', 'requesting_class': 'role'}
    return supervisor, snapshot, path, source, request


def check(supervisor, snapshot):
    supervisor.custody_support()['check_snapshot'](supervisor, snapshot)


def test_repeat_reads_current_bytes_but_derives_once_and_keeps_fresh_globals(policy):
    supervisor, snapshot, _, _, _ = policy
    first = supervisor.custody_support()
    first['FIELDS'].clear()
    first['private_state'] = object()
    for _ in range(20):
        check(supervisor, snapshot)
    second = supervisor.custody_support()
    assert 'private_state' not in second and second['FIELDS']
    assert first['check_snapshot'].__globals__ is not second['check_snapshot'].__globals__
    assert supervisor.pure_phases['support_reads'] == 22
    assert supervisor.pure_phases['source_reads'] == 20
    assert supervisor.pure_phases['support_compiles'] == 1
    assert supervisor.pure_phases['source_derivations'] == 1
    # A new observer derives independently; there is no module/persistent cache.
    other = host.Supervisor.__new__(host.Supervisor)
    other.spec, other.root, other.manifest = supervisor.spec, supervisor.root, supervisor.manifest
    check(other, snapshot)
    assert other.pure_phases['support_compiles'] == other.pure_phases['source_derivations'] == 1
    assert other._custody_code is not supervisor._custody_code


@pytest.mark.parametrize('target', ['support', 'source'])
@pytest.mark.parametrize('drift', ['bytes', 'unreadable', 'symlink', 'replacement', 'mode', 'hardlink'])
def test_current_carrier_drift_refuses_after_population(policy, target, drift):
    supervisor, snapshot, support, source, _ = policy
    check(supervisor, snapshot)
    path = support if target == 'support' else source
    if drift == 'bytes':
        # Same size and restored mtime cannot bypass the fresh hash.
        info = path.stat()
        body = path.read_bytes()
        path.write_bytes(body.replace(b'\n', b' ', 1))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    elif drift == 'unreadable':
        path.unlink()
    elif drift == 'mode':
        path.chmod(0o600 if path.stat().st_mode & 0o077 else 0o644)
    else:
        original = path.with_suffix('.original')
        path.rename(original)
        if drift == 'symlink':
            path.symlink_to(original)
        elif drift == 'replacement':
            path.write_bytes(original.read_bytes())
        else:
            os.link(original, path)
    with pytest.raises((RuntimeError, OSError)):
        check(supervisor, snapshot)
    assert supervisor.pure_phases['support_compiles'] == 1
    assert supervisor.pure_phases['source_derivations'] == 1


@pytest.mark.parametrize('field', ['AST_sha256', 'source_sha256', 'request_sha256', 'requesting_case',
                                  'executor', 'env', 'argv', 'request', 'schema'])
def test_dynamic_snapshot_checks_still_execute_after_population(policy, field):
    supervisor, snapshot, _, _, request = policy
    check(supervisor, snapshot)
    changed = copy.deepcopy(snapshot)
    if field == 'schema':
        changed['extra'] = True
    elif field == 'request':
        changed['request']['generation'] = 2
    elif field == 'env':
        changed['env']['EXTRA'] = 'changed'
    elif field == 'argv':
        changed['argv'].append('--extra')
    else:
        changed[field] = 'changed'
    with pytest.raises(RuntimeError):
        check(supervisor, changed)
    check(supervisor, snapshot)
    request.write_text(json.dumps({'run_id': 'run:one', 'generation': 2}))
    with pytest.raises(RuntimeError, match='custody_stale_request_refused'):
        check(supervisor, snapshot)
    assert supervisor.pure_phases['source_derivations'] == 1


def test_compilation_retains_filename_future_flags_and_no_shared_policy_globals(policy):
    supervisor, _, path, _, _ = policy
    namespace = supervisor.custody_support()
    expected = {}
    exec(compile(path.read_bytes(), str(path), 'exec',
                 flags=host.__future__.annotations.compiler_flag, dont_inherit=True), expected)
    assert namespace['FIELDS'] == expected['FIELDS'] and namespace['COMMON'] == expected['COMMON']
    actual = namespace['check_snapshot'].__code__
    original = expected['check_snapshot'].__code__
    assert actual.co_filename == original.co_filename == str(path)
    assert actual.co_flags == original.co_flags and actual.co_code == original.co_code
    with pytest.raises(RuntimeError, match='custody_frame_schema_refused'):
        namespace['handle'](supervisor, {'kind': 'custody_submit'}, [])
    assert not hasattr(supervisor, 'custody')


def test_cached_descriptor_does_not_cache_role_or_ready_outcomes(policy):
    supervisor, _, _, _, _ = policy
    request = {'kind': 'custody_owner', 'id': 'id', 'nonce': 'nonce',
               'pid': 1, 'token': 'token', 'identity': {}}
    for _ in range(3):
        with pytest.raises(RuntimeError, match='custody_READY_refused'):
            supervisor.custody_support()['handle'](supervisor, request, [])
    assert supervisor.pure_phases['support_compiles'] == 1
    assert supervisor.pure_phases['support_reads'] == 3

