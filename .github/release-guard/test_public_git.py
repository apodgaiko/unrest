"""Real Git consumes the public projection without runner configuration/history trees."""
import io
import tarfile
from pathlib import Path

import pytest

from git_policy import PUBLIC_FM000 as FM000, PUBLIC_TAGS as TAGS, public_git as git, public_prepare as prepare

SUPPORT = Path(__file__).resolve().parent
ROOT = next(p for p in SUPPORT.parents if (p/'pyproject.toml').is_file())


@pytest.fixture(scope='module')
def copied(tmp_path_factory):
    destination = tmp_path_factory.mktemp('public-history') / 'source'
    destination.mkdir()
    head = git(ROOT, 'rev-parse', 'HEAD').decode().strip()
    with tarfile.open(fileobj=io.BytesIO(git(ROOT, 'archive', '--format=tar', head))) as archive:
        members = archive.getmembers()
        assert len(members) <= 20000 and sum(member.size for member in members) <= 512 * 1024 * 1024
        assert all(member.isfile() or member.isdir() for member in members)
        archive.extractall(destination, filter='data')
    proof = prepare(ROOT, destination, head)
    return destination, head, proof


def test_real_status_index_and_historical_queries_are_faithful(copied):
    destination, head, proof = copied
    assert git(destination, 'status', '--short') == b''
    expected_index=b''
    for row in git(ROOT, 'ls-tree', '-r', '-z', head).split(b'\0'):
        if row:
            header,path=row.split(b'\t',1)
            mode,kind,oid=header.split(b' ')
            assert kind==b'blob'
            expected_index+=mode+b' '+oid+b' 0\t'+path+b'\0'
    assert git(destination, 'ls-files', '-z', '--stage') == expected_index
    assert git(destination, 'rev-parse', 'HEAD').decode().strip() == head
    git(destination, 'merge-base', '--is-ancestor', FM000, 'HEAD')
    for tag in TAGS:
        assert git(destination, 'ls-tree', '-r', tag) == git(ROOT, 'ls-tree', '-r', tag)
    assert git(destination, 'show', 'v0.4.0:docs/release/lean-core-v0.4.0.md') == git(
        ROOT, 'show', 'v0.4.0:docs/release/lean-core-v0.4.0.md')
    assert git(destination, 'diff', '--name-only', FM000, 'v0.2.1') == git(
        ROOT, 'diff', '--name-only', FM000, 'v0.2.1')
    assert git(destination, 'archive', '5a3d568aa881c746432b7034597bbb8a1ffe025f') == git(
        ROOT, 'archive', '5a3d568aa881c746432b7034597bbb8a1ffe025f')
    assert proof['commits']>0 and 'complete reachable history' in proof['scope']


def test_closed_refs_and_clean_generated_metadata_are_acquired(copied):
    destination,head,proof=copied
    metadata=destination/'.git'
    assert not (metadata/'hooks').exists() and not (metadata/'objects/info/alternates').exists()
    assert {p.name for p in (metadata/'refs/tags').iterdir()}==set(TAGS)
    assert all(not p.is_symlink() and p.stat().st_nlink==1 for p in metadata.rglob('*') if p.is_file())
    assert 'remote' not in (metadata/'config').read_text() and 'credential' not in (metadata/'config').read_text()
    assert git(destination,'for-each-ref','--format=%(refname)').decode().splitlines()==['refs/tags/'+name for name in sorted(TAGS)]


def test_wrong_head_cannot_create_a_projection(tmp_path):
    destination = tmp_path / 'source'
    destination.mkdir()
    with pytest.raises(RuntimeError, match='head_drift'):
        prepare(ROOT, destination, '0' * 40)
    assert not (destination / '.git').exists()


def test_historical_tag_drift_fails_before_writing(tmp_path, monkeypatch):
    import git_policy as module
    destination = tmp_path / 'source'
    destination.mkdir()
    monkeypatch.setitem(module.PUBLIC_TAGS, 'v0.2.0', '0' * 40)
    with pytest.raises(RuntimeError, match='historical_tag_drift'):
        prepare(ROOT, destination, git(ROOT, 'rev-parse', 'HEAD').decode().strip())
    assert not (destination / '.git').exists()


def test_existing_metadata_is_not_overwritten(tmp_path):
    destination = tmp_path / 'source'
    (destination / '.git').mkdir(parents=True)
    marker = destination / '.git/USER-data'
    marker.write_bytes(b'preserve')
    with pytest.raises(RuntimeError, match='destination'):
        prepare(ROOT, destination, git(ROOT, 'rev-parse', 'HEAD').decode().strip())
    assert marker.read_bytes() == b'preserve'


def test_aliased_destination_cannot_acquire_metadata(tmp_path):
    destination = tmp_path / 'source'
    destination.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(destination, target_is_directory=True)
    with pytest.raises(RuntimeError, match='destination_alias'):
        prepare(ROOT, alias, git(ROOT, 'rev-parse', 'HEAD').decode().strip())
    assert not (destination / '.git').exists()


def test_unrelated_private_branch_and_blob_are_not_acquired(tmp_path):
    import subprocess
    source=tmp_path/'local-public-input'
    source.mkdir()
    git(source,'init','--bare','--template=','--object-format=sha1')
    head=git(ROOT,'rev-parse','HEAD').decode().strip()
    git(source,'fetch','--no-tags','--no-auto-maintenance',str(ROOT),head,*('refs/tags/'+name+':refs/tags/'+name for name in TAGS))
    (source/'HEAD').write_text(head+'\n')
    blob=git(source,'hash-object','-w','--stdin',data=b'unrelated-private-branch-marker').decode().strip()
    tree=git(source,'mktree',data=('100644 blob '+blob+'\tprivate.txt\n').encode()).decode().strip()
    commit=git(source,'-c','user.name=Test','-c','user.email=test@invalid','commit-tree',tree,'-m','unrelated').decode().strip()
    git(source,'update-ref','refs/heads/private-unrelated',commit)
    destination=tmp_path/'target'
    destination.mkdir()
    prepare(source,destination,head)
    with pytest.raises(subprocess.CalledProcessError):
        git(destination,'cat-file','-e',blob)
    assert git(destination,'for-each-ref','refs/heads')==b''


def test_status_handles_readonly_metadata_without_rewriting_index(copied):
    destination, _, _ = copied
    metadata = destination / '.git'
    paths = [metadata, *metadata.rglob('*')]
    modes = {path: path.stat().st_mode & 0o777 for path in paths}
    try:
        for path in paths:
            path.chmod(0o555 if path.is_dir() else 0o444)
        before = {str(path.relative_to(metadata)): (path.read_bytes(), path.stat().st_mtime_ns,
                                                     path.stat().st_ctime_ns)
                  for path in paths if path.is_file()}
        assert git(destination, 'status', '--short') == b''
        after = {str(path.relative_to(metadata)): (path.read_bytes(), path.stat().st_mtime_ns,
                                                    path.stat().st_ctime_ns)
                 for path in metadata.rglob('*') if path.is_file()}
        assert after == before
    finally:
        for path, mode in modes.items():
            path.chmod(mode)


def test_all_required_release_binding_revisions_are_in_the_closed_projection():
    assert set(TAGS) == {'v0.2.0', 'v0.2.1', 'v0.3.0', 'v0.3.1', 'v0.4.0', 'v0.4.5'}
    assert git(ROOT, 'rev-parse', 'v0.4.5^{commit}').decode().strip() == (
        '5a3d568aa881c746432b7034597bbb8a1ffe025f')



def test_git_owner_exception_is_one_exact_path_without_ambient_configuration(monkeypatch):
    import git_policy as module
    monkeypatch.setenv('GIT_CONFIG_COUNT','1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0','unsafe-host-setting')
    seen = []
    def run(argv, **kwargs):
        seen.append((argv,kwargs))
        return type('Result',(),dict(stdout=b'closed'))()
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.public_git(ROOT,'rev-parse','HEAD') == b'closed'
    argv, options = seen[0]
    assert argv[:6] == ['git','--no-replace-objects','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    assert options['env']['GIT_CONFIG_GLOBAL'] == module.os.devnull and options['env']['GIT_CONFIG_NOSYSTEM'] == '1'
    assert 'GIT_CONFIG_COUNT' not in options['env'] and 'GIT_CONFIG_KEY_0' not in options['env']
