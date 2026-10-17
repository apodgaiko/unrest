"""Finite native ancestry admits the genuine vector and rejects changed bindings."""
import hashlib
import importlib.util
from pathlib import Path
import zlib

import pytest

spec = importlib.util.spec_from_file_location('linux_git', Path(__file__).with_name('linux_git.py'))
assert spec is not None and spec.loader is not None
git = importlib.util.module_from_spec(spec)
spec.loader.exec_module(git)


@pytest.mark.parametrize('mutation', ['none', 'image', 'parent', 'argv', 'environment', 'object'])
def test_exact_commit_maintenance_binding(tmp_path, mutation):
    root = tmp_path / 'workspace'
    metadata = root / '.git'
    (metadata / 'refs/heads').mkdir(parents=True)
    body = b'tree ' + b'0' * 40 + b'\nauthor Test <test@example.invalid> 1700000000 +0000\ncommitter Test <test@example.invalid> 1700000000 +0000\n\nbase\n'
    content = b'commit ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.sha1(content).hexdigest()
    objects = metadata / 'objects' / oid[:2]
    objects.mkdir(parents=True)
    object_path = objects / oid[2:]
    object_path.write_bytes(zlib.compress(content))
    (metadata / 'HEAD').write_text('ref: refs/heads/main\n')
    (metadata / 'refs/heads/main').write_text(oid + '\n')
    parent = {'argv': list(git.COMMIT), 'cwd': str(root), 'environment': {'PATH': '/usr/bin'}}
    environment = {'PATH': '/usr/lib/git-core:/usr/bin', 'GIT_EXEC_PATH': '/usr/lib/git-core',
                   'GIT_PREFIX': '',
                   'GIT_CONFIG_PARAMETERS': "'user.name'='Test' 'user.email'='test@example.invalid'",
                   'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                   'GIT_AUTHOR_DATE': '@1700000000 +0000'}
    vector = list(git.MAINTENANCE)
    pin = hashlib.sha256(Path(vector[0]).read_bytes()).hexdigest()
    if mutation == 'image':
        pin = '0' * 64
    if mutation == 'parent':
        parent['argv'][-1] = 'other'
    if mutation == 'argv':
        vector[-1] = '--force'
    if mutation == 'environment':
        environment['GIT_AUTHOR_DATE'] = '@1700000001 +0000'
    if mutation == 'object':
        object_path.write_bytes(zlib.compress(content + b'changed'))
    assert git.admit(parent, vector[0], vector, environment, str(root), pin, '/work') is (mutation == 'none')
