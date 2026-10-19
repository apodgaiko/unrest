"""SOURCE startup custody for the exact owned temporary directory generation."""
from __future__ import annotations

import os
from pathlib import Path
import stat


def directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError('source_environment_aliased_root')
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
    finally:
        os.close(fd)
    def key(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if (key(before) != key(opened) or key(before) != key(path.lstat())
            or not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid()):
        raise RuntimeError('source_environment_directory_custody')
    return key(before)


def capture(state):
    if (state['source_selection'] != 'primary-source' or state['class'] != 'pytest-root'
            or state['token'] != 'root' or state['checkout'] != '/source'
            or state['owned_root'] != '/work/owned'
            or os.environ.get('TMPDIR') != '/work/owned/tmp'):
        raise RuntimeError('source_environment_context')
    return {'directories': {path: directory(path) for path in ('/work/owned', '/work/owned/tmp')},
            'environment': dict(os.environ)}


def matches(state):
    activation = state.get('operation_activation')
    saved = getattr(activation, 'owned_environment', None)
    if saved is None:
        return False
    if (state.get('source_selection') != 'primary-source' or state.get('class') != 'pytest-root'
            or state.get('token') != 'root' or state['checkout'] != '/source'
            or state['owned_root'] != '/work/owned'):
        return False
    current = dict(os.environ)
    # pytest supplies this exact current call marker after pre-body acquisition.
    if current.pop('PYTEST_CURRENT_TEST', None) != state['case'] + ' (call)':
        return False
    import pytest
    baseline = dict(saved['environment'])
    if 'PYTEST_VERSION' not in baseline:
        if current.pop('PYTEST_VERSION', None) != pytest.__version__:
            return False
    try:
        return (current == baseline and
                saved['directories'] == {path: directory(path)
                                        for path in ('/work/owned', '/work/owned/tmp')})
    except (OSError, RuntimeError):
        return False
