"""Finite stock-Git maintenance child of the unchanged empty-commit source call."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import stat
import zlib

COMMIT = ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
          'commit', '--allow-empty', '-qm', 'base']
MAINTENANCE = ['/usr/lib/git-core/git', 'maintenance', 'run', '--auto', '--quiet']


def regular(path: Path, limit: int) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > limit:
        raise RuntimeError('finite Git metadata carrier refused')
    return path.read_bytes()


def admit(parent: dict, path: str, vector: list[str], environment: dict[str, str],
          cwd: str, image_pin: str) -> bool:
    if (parent['argv'] != COMMIT or parent['cwd'] != cwd
            or path != MAINTENANCE[0] or vector != MAINTENANCE
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != image_pin):
        return False
    root = Path(cwd)
    if not root.is_relative_to('/work/pytest') or root.resolve() != root:
        return False
    git = root / '.git'
    head = regular(git / 'HEAD', 256).decode().strip()
    if not re.fullmatch(r'ref: refs/heads/[A-Za-z0-9._/-]+', head):
        return False
    ref = git / head.removeprefix('ref: ')
    if not ref.resolve().is_relative_to(git.resolve()):
        return False
    oid = regular(ref, 64).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', oid):
        return False
    compressed = regular(git / 'objects' / oid[:2] / oid[2:], 16384)
    decoder = zlib.decompressobj()
    content = decoder.decompress(compressed, 16385)
    if len(content) > 16384 or not decoder.eof or decoder.unused_data:
        return False
    if hashlib.sha1(content).hexdigest() != oid:
        return False
    header, separator, commit = content.partition(b'\0')
    if not separator or header != b'commit ' + str(len(commit)).encode():
        return False
    author = re.search(rb'^author Test <test@example.invalid> ([0-9]+ [+-][0-9]{4})$',
                       commit, re.MULTILINE)
    if author is None or not commit.endswith(b'\n\nbase\n'):
        return False
    expected = {**parent['environment'],
                'PATH': '/usr/lib/git-core:' + parent['environment']['PATH'],
                'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                'GIT_CONFIG_PARAMETERS': "'user.name'='Test' 'user.email'='test@example.invalid'",
                'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                'GIT_AUTHOR_DATE': '@' + author.group(1).decode()}
    return environment == expected
