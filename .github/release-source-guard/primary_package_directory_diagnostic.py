"""Finite observer metadata for the original directory refusal; no admission.

Snapshots bracket actual child dispatch and authenticated original module return.
They preserve inode identity and emptiness, rather than treating a familiar leaf
name as evidence of which operation created it. No cache file body is opened.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

LIMIT = 128


def sha(body):
    return hashlib.sha256(body).hexdigest()


def metadata(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        def identity(info):
            return [getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                    'st_gid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')]
        leaves = sorted(os.listdir(descriptor))
        if len(leaves) > 4096:
            raise RuntimeError('package_directory_diagnostic_leaf_bound')
        if (path.resolve(strict=True) != path or identity(before) != identity(path.lstat())
                or identity(before) != identity(os.fstat(descriptor))
                or leaves != sorted(os.listdir(descriptor))):
            raise RuntimeError('package_directory_diagnostic_race')
        return {'identity': identity(before), 'type': stat.S_IFMT(before.st_mode),
                'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
                'gid': before.st_gid, 'inode': before.st_ino, 'links': before.st_nlink,
                'empty': not leaves, 'leaf_count': len(leaves),
                'leaf_names_sha256': sha(json.dumps(leaves, separators=(',', ':')).encode())}
    finally:
        os.close(descriptor)


def capture(producers, child, phase):
    """Observer-only snapshot; callers never use it to change guard outcomes."""
    try:
        root = Path(producers.common['cache'])
        if root != Path('/work/cache') or child['parent'] not in producers.uv:
            raise RuntimeError('package_directory_diagnostic_context')
        context = producers.uv[child['parent']]
        parent = producers.kernel.identity(child['parent'])
        peer = producers.kernel.identity(child['pid'])
        if parent != context['identity'] or peer['ppid'] != child['parent'] or peer['uid'] != 20000:
            raise RuntimeError('package_directory_diagnostic_birth')
        paths = sorted(p for p in root.rglob('*') if p.is_dir() and not p.is_symlink())
        rows = {}
        for path in paths:
            relative = path.relative_to(root).as_posix()
            key = sha(relative.encode())
            if key not in producers.cache_current:
                if len(rows) >= LIMIT:
                    raise RuntimeError('package_directory_diagnostic_bound')
                rows[key] = {'relative': relative, **metadata(path)}
        record = {'phase': phase, 'pid': child['pid'], 'helper': child['helper'],
                  'peer': peer, 'writer': parent, 'cwd_sha256': sha(child['cwd'].encode()),
                  'operation_sha256': sha(context['token'].encode()), 'directories': rows}
        if phase == 'original-module-return':
            events = producers.supervisor.events()
            record['ready'] = [row for row in events if row['kind'] == 'ready'
                               and row['owner_pid'] == child['pid'] and row['token'] == child['token']]
            record['callbacks'] = [{'kind': row['kind'], 'sha256': sha(json.dumps(row, sort_keys=True).encode())}
                                   for row in events if row.get('owner_pid') == child['pid']
                                   and row['kind'] in {'isolated_actual_backend_call', 'isolated_backend_output'}]
        history = getattr(producers, 'package_directory_history', [])
        if len(history) >= 16:
            raise RuntimeError('package_directory_diagnostic_history_bound')
        producers.package_directory_history = [*history, record]
    except BaseException as error:
        producers.package_directory_diagnostic_error = type(error).__name__


def refusal(producers, context, error, trace):
    if str(error) != 'primary_cache_output_extra_directory':
        raise RuntimeError('package_directory_diagnostic_wrong_refusal')
    frames = []
    cursor = error.__traceback__
    while cursor is not None:
        if cursor.tb_frame.f_code.co_name == 'completed_cache' and cursor.tb_frame.f_locals.get('self') is producers:
            frames.append(cursor.tb_frame)
        cursor = cursor.tb_next
    frames = [frame for frame in frames if {'current', 'names', 'permitted', 'allowed_dirs'} <= frame.f_locals.keys()]
    if len(frames) != 1:
        raise RuntimeError('package_directory_diagnostic_original_frame')
    values = frames[0].f_locals
    current, names = values['current'], values['names']
    rejected = sorted(key for key, entry in current.items() if entry['type'] == 'directory'
                      and key not in values['permitted'] and names[key] not in values['allowed_dirs'])
    if not 0 < len(rejected) <= 16:
        raise RuntimeError('package_directory_diagnostic_rejected_bound')
    result = {'schema': 'unrest.v046.primary-package-directory-diagnostic.v1',
              'status': 'original-directory-refusal-preserved',
              'authority_granted': False, 'eligible_certificate': False,
              'source_checkpoint_ready': False, 'selected_carrier': None,
              'pid': context['pid'], 'identity': context['identity'],
              'operation_sha256': sha(context['token'].encode()),
              'kernel_exit': [row for row in trace.records if row['kind'] == 'kernel_exit'
                              and row['pid'] == context['pid']],
              'diagnostic_error': getattr(producers, 'package_directory_diagnostic_error', None),
              'directories': []}
    for key in rejected:
        relative = names[key]
        result['directories'].append({'path': relative, 'path_sha256': key,
            'leaf_sha256': sha(Path(relative).name.encode()),
            'preexisting': key in producers.cache_current,
            'final': metadata(Path(producers.common['cache']) / relative),
            'observations': [{**{k: v for k, v in row.items() if k != 'directories'},
                              'directory': row['directories'].get(key)}
                             for row in getattr(producers, 'package_directory_history', [])]})
    if len(json.dumps(result).encode()) > 65536:
        raise RuntimeError('package_directory_diagnostic_projection_bound')
    return result
