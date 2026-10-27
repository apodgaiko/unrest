"""Closed public Git projection for unchanged source inventory/history tests."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess

TAGS = {
    'v0.2.0': '687ad97c3d4622d3a793a3363bc154ba5e6aa9cf',
    'v0.2.1': '2652e657ea69e7ed65b2e5cf19278a45260989c4',
    'v0.3.0': 'c0e7a4faae8863b935c5cd8a0f37a8408860b2e4',
    'v0.3.1': 'fb52910a3d2499375d9283791ba35b31fc620943',
    'v0.4.0': '111396f755a82d8194ee3ad649ba3d0519504158',
    'v0.4.5': 'a77a8be304b736f54acfa6b7181661560aa8433d',
}
FM000 = '2b17a613b99ef182c9bae18b8171efc17e8fe8d2'
OID = re.compile(r'[0-9a-f]{40}')


def git(repository: Path, *arguments: str, data: bytes | None = None) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    return subprocess.run(['git', '--no-replace-objects', '-C', str(repository), *arguments],
                          input=data, capture_output=True, check=True, env=environment).stdout


def oid(value: bytes) -> str:
    result = value.decode('ascii').strip()
    if OID.fullmatch(result) is None:
        raise RuntimeError('public_git_object_id')
    return result


def projection(repository: Path, head: str) -> tuple[dict[str, str], dict[str, str]]:
    if OID.fullmatch(head) is None or oid(git(repository, 'rev-parse', '--verify', 'HEAD')) != head:
        raise RuntimeError('public_git_head_drift')
    commits = git(repository, 'rev-list', head).decode('ascii').splitlines()
    if not commits or len(commits) > 20000 or any(OID.fullmatch(item) is None for item in commits):
        raise RuntimeError('public_git_commit_graph')
    objects = dict.fromkeys(commits, 'commit')
    roots = {head, FM000}
    if FM000 not in objects:
        raise RuntimeError('public_git_required_ancestor')
    for name, expected in TAGS.items():
        if oid(git(repository, 'rev-parse', '--verify', 'refs/tags/' + name)) != expected:
            raise RuntimeError('public_git_historical_tag_drift')
        if git(repository, 'cat-file', '-t', expected).strip() != b'tag':
            raise RuntimeError('public_git_historical_tag_type')
        objects[expected] = 'tag'
        commit = oid(git(repository, 'rev-parse', '--verify', name + '^{commit}'))
        if commit not in objects or objects[commit] != 'commit':
            raise RuntimeError('public_git_historical_ancestry')
        roots.add(commit)
    for commit in sorted(roots):
        tree = oid(git(repository, 'rev-parse', '--verify', commit + '^{tree}'))
        objects[tree] = 'tree'
        for row in git(repository, 'ls-tree', '-r', '-t', '-z', '--full-tree', commit).split(b'\0'):
            if not row:
                continue
            header, _ = row.split(b'\t', 1)
            _, kind, object_id = header.decode('ascii').split(' ')
            if kind not in {'tree', 'blob'} or OID.fullmatch(object_id) is None:
                raise RuntimeError('public_git_tree_member')
            if objects.setdefault(object_id, kind) != kind:
                raise RuntimeError('public_git_object_type_conflict')
    if len(objects) > 50000:
        raise RuntimeError('public_git_projection_bound')
    return objects, dict(TAGS)


def prepare(repository: Path, destination: Path, head: str) -> dict[str, object]:
    if destination.resolve(strict=True) != destination:
        raise RuntimeError('public_git_destination_alias')
    repository, destination = repository.resolve(strict=True), destination.resolve(strict=True)
    if (not destination.is_dir() or destination.is_relative_to(repository)
            or repository.is_relative_to(destination) or (destination / '.git').exists()
            or (destination / '.git').is_symlink()):
        raise RuntimeError('public_git_destination')
    objects, tags = projection(repository, head)
    # Explicit IDs, no revision traversal or delta reuse: no other trees,
    # branches, hooks, runner config, credentials or alternate path is copied.
    pack = git(repository, 'pack-objects', '--stdout', '--no-reuse-delta',
               '--no-reuse-object', '--window=0', data=''.join(k + '\n' for k in sorted(objects)).encode())
    if len(pack) > 256 * 1024 * 1024 or not pack.startswith(b'PACK'):
        raise RuntimeError('public_git_pack_bound')
    metadata = destination / '.git'
    packed = metadata / 'objects/pack'
    packed.mkdir(parents=True)
    (metadata / 'refs/tags').mkdir(parents=True)
    (metadata / 'config').write_bytes(b'[core]\nrepositoryformatversion = 0\nbare = false\n')
    (metadata / 'HEAD').write_text(head + '\n')
    name = hashlib.sha1(pack[:-20]).hexdigest()
    if bytes.fromhex(name) != pack[-20:]:
        raise RuntimeError('public_git_pack_checksum')
    path = packed / ('pack-' + name + '.pack')
    path.write_bytes(pack)
    if oid(git(destination, 'index-pack', '--index-version=2', str(path))) != name:
        raise RuntimeError('public_git_index_identity')
    index = path.with_suffix('.idx')
    observed = {}
    for line in git(destination, 'verify-pack', '-v', str(index)).decode('ascii').splitlines():
        fields = line.split()
        if fields and OID.fullmatch(fields[0]):
            if len(fields) != 5 or fields[0] in observed or fields[1] not in {'commit', 'tree', 'blob', 'tag'}:
                raise RuntimeError('public_git_pack_member')
            observed[fields[0]] = fields[1]
        elif not (line.startswith('non delta: ') or line == str(path) + ': ok'):
            raise RuntimeError('public_git_pack_verification')
    if observed != objects:
        raise RuntimeError('public_git_object_set')
    for name, object_id in tags.items():
        (metadata / 'refs/tags' / name).write_text(object_id + '\n')
    git(destination, 'read-tree', head)
    if oid(git(destination, 'rev-parse', '--verify', 'HEAD^{commit}')) != head:
        raise RuntimeError('public_git_head_consumption')
    git(destination, 'merge-base', '--is-ancestor', FM000, head)
    return {'head': head, 'historical_tags': tags, 'objects': len(objects),
            'pack_sha256': hashlib.sha256(pack).hexdigest(), 'external_deltas': False,
            'scope': 'public HEAD commit graph; HEAD/FM000/six historical trees; exact tag objects'}
