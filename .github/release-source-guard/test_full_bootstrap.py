"""Physical acquisition and exact preparation routing negatives."""
import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import full_bootstrap as full
from primary_custody import exclusive, read_regular
from structured_evidence import EvidenceRefused, identity_check


@pytest.mark.parametrize('entry', ['full_bootstrap.py', 'full_input_controls.py'])
def test_host_cli_refusal_never_exports_traceback_or_private_paths(tmp_path, entry):
    result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name(entry))],
                            env={'RUNNER_TEMP': str(tmp_path)}, capture_output=True, check=False)
    assert result.returncode == 125 and result.stderr == b''
    value = json.loads(result.stdout)
    assert value == {'schema': ('unrest.v046.full-input-produced.v1' if entry == 'full_bootstrap.py'
                                else 'unrest.v046.full-host-controls.v1'),
                     'status': 'refused', 'source_testcase_executed': False,
                     'eligible_certificate': False}
    assert str(tmp_path).encode() not in result.stdout


@pytest.mark.parametrize('tail', ['01', '02', '03', '04', '05', '06', '00', '07',
                                 '1', '01-extra', '', '-01', 'x-01'])
@pytest.mark.parametrize('workflow', ['v046-source-readiness.yml', 'ci.yml', 'other.yml'])
def test_full_family_evidence_default_denies(tail, workflow):
    row = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
           'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
           'artifact_name': 'v046-source-primary-source-1-1',
           'workflow_ref': 'apodgaiko/unrest/.github/workflows/' + workflow + '@' + full.PREFIX + tail}
    if tail in {'01', '02', '03', '04', '05', '06'} and workflow == 'v046-source-readiness.yml':
        identity_check(row)
    else:
        with pytest.raises(EvidenceRefused):
            identity_check(row)


@pytest.mark.parametrize('tail', ['01', '02', '03', '04', '05', '06', '00', '07', '1', '', 'x-01'])
def test_every_family_member_is_reserved(tail):
    assert full.reserved(full.PREFIX + tail)
    assert not full.reserved('refs/heads/codex/release-v046-normal')


@pytest.mark.parametrize('mutation', ['symlink', 'hardlink', 'mode', 'directory', 'oversize'])
def test_physical_input_rejects_aliases_and_wrong_metadata(tmp_path, mutation):
    target = tmp_path / 'primary-source-input.json'
    exclusive(target, b'{}')
    if mutation == 'symlink':
        target.rename(tmp_path / 'original')
        target.symlink_to(tmp_path / 'original')
    elif mutation == 'hardlink':
        os.link(target, tmp_path / 'alias')
    elif mutation == 'mode':
        target.chmod(0o644)
    elif mutation == 'directory':
        target.unlink()
        target.mkdir()
    else:
        target.write_bytes(b'x' * 65537)
    with pytest.raises((EvidenceRefused, OSError)):
        read_regular(target, 65536, 0o600)


def test_exclusive_input_never_overwrites_stale_or_link(tmp_path):
    target = tmp_path / 'primary-source-input.json'
    exclusive(target, b'original')
    with pytest.raises(FileExistsError):
        exclusive(target, b'changed')
    assert read_regular(target, 65536, 0o600) == b'original'
    target.unlink()
    target.symlink_to(tmp_path / 'missing')
    with pytest.raises(FileExistsError):
        exclusive(target, b'changed')
    assert not (tmp_path / 'missing').exists()


def test_payload_or_nonlinux_role_cannot_issue_host_input():
    if sys.platform == 'linux' and os.getuid() not in {0, 20000, 20001}:
        pytest.skip('payload-role control runs inside the source-free Ubuntu capsule')
    with pytest.raises(EvidenceRefused, match='full_host_role'):
        full.context('PREPAREONLY')


def test_physical_replacement_during_real_read_refuses(tmp_path, monkeypatch):
    import primary_custody as custody
    target = tmp_path / 'primary-source-input.json'
    exclusive(target, b'original input')
    original_fdopen = custody.os.fdopen

    @contextmanager
    def replacing_stream(descriptor, mode, closefd):
        with original_fdopen(descriptor, mode, closefd=closefd) as stream:
            class Reader:
                def read(self, count):
                    body = stream.read(count)
                    target.rename(tmp_path / 'original')
                    target.write_bytes(body)
                    target.chmod(0o600)
                    return body
            yield Reader()

    monkeypatch.setattr(custody.os, 'fdopen', replacing_stream)
    with pytest.raises(EvidenceRefused, match='custody_file_changed'):
        read_regular(target, 65536, 0o600)


def test_owned_private_root_refuses_alias_or_changed_mode(tmp_path):
    root, identity = full.private_root(tmp_path, create=True)
    assert full.private_root(tmp_path)[1] == identity
    root.chmod(0o755)
    with pytest.raises(EvidenceRefused):
        full.private_root(tmp_path)
    root.rmdir()
    (tmp_path / 'alias').mkdir(mode=0o700)
    root.symlink_to(tmp_path / 'alias')
    with pytest.raises(EvidenceRefused):
        full.private_root(tmp_path)


def test_moving_custody_preserves_child_inode_but_changes_runner_identity(tmp_path):
    root, identity = full.private_root(tmp_path, create=True)
    original_runner = full.file_identity(tmp_path.lstat())[:5]
    moved = tmp_path / 'new-runner'
    moved.mkdir(mode=0o700)
    root.rename(moved / root.name)
    assert full.private_root(moved)[1] == identity
    assert full.file_identity(moved.lstat())[:5] != original_runner


def test_nonrecursive_scope_exempts_only_exact_carrier(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    support = tmp_path / '.github/release-source-guard'
    support.mkdir(parents=True)
    (support / 'policy.json').write_text('{}')
    (support / 'guard.py').write_text('original guard')
    (support / 'runtime.py').write_text('original runtime')
    (tmp_path / 'source.py').write_text('original')
    (tmp_path / 'doc.md').write_text('original')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    before = full.scope(tmp_path)
    (tmp_path / full.CARRIER).write_text('{}')
    subprocess.run(['git', '-C', str(tmp_path), 'add', full.CARRIER], check=True)
    assert full.scope(tmp_path) == before
    (tmp_path / full.CARRIER).write_text('{"changed":true}')
    assert full.scope(tmp_path) == before
    for name in ('source.py', 'doc.md', '.github/release-source-guard/policy.json',
                 '.github/release-source-guard/guard.py', '.github/release-source-guard/runtime.py'):
        target = tmp_path / name
        original = target.read_bytes()
        target.write_bytes(original + b' ')
        assert full.scope(tmp_path) != before
        target.write_bytes(original)
    (support / 'unknown.json').write_text('{}')
    with pytest.raises(EvidenceRefused, match='full_unknown_support'):
        full.scope(tmp_path)
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    assert full.scope(tmp_path) != before


def test_preparation_is_common_and_dispatch_free():
    tree = ast.parse(Path(__file__).with_name('ci_shell.py').read_bytes())
    prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'create_capsule')
    text = ast.unparse(prepare)
    build = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare_capsule')
    text += ast.unparse(build)
    assert "'create'" in text and "'inspect'" in text
    assert "'start'" not in text and 'capture_raw_source' not in text
    wrapper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'retained_main')
    assert sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == 'main' for n in ast.walk(wrapper)) == 1
    assert 'primary_encryption_failed' in ast.unparse(wrapper)
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    assert sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == 'prepare_capsule' for n in ast.walk(main)) == 1
    branch = next(n for n in main.body if isinstance(n, ast.If)
                  and isinstance(n.test, ast.Name) and n.test.id == 'prepare_only')
    assert any(isinstance(n, ast.Return) and n.value.value == 0 for n in branch.body)
    assert 'source_testcase_executed' in ast.unparse(branch)
    assert 'eligible_certificate' in ast.unparse(branch)
    capture = next(n for n in main.body if isinstance(n, ast.Try)
                   and 'capture_raw_source' in ast.unparse(n))
    assert 'create_capsule(prepared)' in ast.unparse(capture)
    assert 'create_capsule(prepared)' in ast.unparse(branch)
    # Creation/inspect failures retain the same closed status, cleanup and
    # encryption path as transport failures; preparation never starts payload.
    assert 'status = 125' in ast.unparse(capture)
    assert "'--force'" in ast.unparse(capture)
    assert 'primary_encryption_failed' in ast.unparse(main)
    assert full.sha(full.SCRIPT) == '83130e7c9c358fe2461d918192481beb7d97b5d88f02b695481052b28a931310'


def test_workflow_preserves_original_scripts_and_routes_only_preparation():
    root = Path(__file__).resolve().parent.parent.parent
    path = root / '.github/workflows/v046-source-readiness.yml'
    if not path.is_file():
        path = Path('/metadata/source-readiness-workflow.yml')
    workflow = path.read_text()
    assert 'full_bootstrap.py PREPAREONLY' in workflow
    assert 'ci_shell.py --prepare-full {0}' in workflow
    assert workflow.count("if: ${{ !contains(github.ref, 'source-guard-structured-20261018-full-bootstrap') }}") == 4
    commands = json.loads(Path(__file__).with_name('ci_commands.json').read_bytes())
    assert commands['v0.4.7 source suite'].encode() == full.SCRIPT + b'\n'
