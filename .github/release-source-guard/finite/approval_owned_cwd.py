"""Exact inherited owned-directory binding for two controlled approval children."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

KINDS = {
    'source-approval-relay': ('tests/fixtures/approval_recovery_acp.py', 17,
        '1813512c5ad2177af6738fbfb99e9d43f6884394878e1034d3956ca5f0f31d46', 'source-approval-adapter'),
    'source-approval-python-backend': ('src/unrest_harness/approval_relay.py', 131,
        'efaba9521aa12d6fbdb228f05da210a4027675c79830d1a5ca93627faa80da44', 'source-approval-relay'),
}


def directory(cwd, owned):
    path, root = Path(cwd), Path(owned) / 'pytest'
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not path.is_relative_to(root) or path == root or path.name != 'workspace'):
        raise RuntimeError('approval_owned_cwd_path')
    for parent in [path, *path.parents]:
        if parent == Path(owned):
            break
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or info.st_uid != 20000:
            raise RuntimeError('approval_owned_cwd_owner')
    info = path.stat()
    return {'cwd': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid}


def prepare(launch, options, state, mode, emit):
    selected = launch['registration']
    site = KINDS.get(selected['class'])
    if site is None or mode is None:
        return False
    name, line, pin, parent = site
    source = Path(state['checkout']) / name
    if (state['class'] != parent or selected['source_binding'] != {
            'path': str(source), 'line': line, 'sha256': pin}
            or state['product_pins'].get(name) != pin
            or hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or options.get('cwd') is not None or not selected['python']):
        raise RuntimeError('approval_owned_cwd_source')
    first = directory(os.getcwd(), state['owned_root'])
    if first != directory(os.getcwd(), state['owned_root']):
        raise RuntimeError('approval_owned_cwd_changed')
    emit({'kind': 'approval_owned_cwd_constructor', 'token': launch['launch_token'],
          'class': selected['class'], 'source_binding': selected['source_binding'],
          'original_cwd': None, 'constructor_cwd': '.', 'parent_view': first,
          'argv_sha256': hashlib.sha256(json.dumps(launch['child_argv']).encode()).hexdigest()})
    return True
