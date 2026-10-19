"""Retain names of current native outputs after UV retires their tempdirs.

UV0.11.0 Cache::venv_dir creates the Builds bucket (builds-v0) before its
TempDir. The original helpers consume that TempDir, then UV drops it while
leaving its empty parent. The original directory census already admits output
ancestors, but cannot derive them from a retired name missing in both maps.
This package-only ledger supplies those exact current consumed names; it never
adds cache entries or changes the original directory predicate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat

from primary_package_directory_diagnostic import metadata

PARENT = Path('/work/cache/builds-v0')
HELPERS = {'get_requires_for_build_sdist', 'build_sdist',
           'get_requires_for_build_wheel', 'build_wheel'}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def consumed(producers, request):
    child = producers.children[request['pid']]
    context = producers.uv[child['parent']]
    header = Path('/receipts/native-startup') / (str(child['pid']) + '.json')
    if sha(header.read_bytes()) != child['profile_sha256']:
        raise RuntimeError('package_retired_build_profile')
    profile = json.loads(header.read_bytes())
    spec = producers.interface.protected_json(profile['spec'], profile['spec_sha256'])
    root = Path(spec['primary_runtime_output']['root'])
    if (root.parent != PARENT or not root.name.startswith('.tmp')
            or spec['parent_operation']['identity'] != context['identity']
            or producers.kernel.identity(child['pid']) != child['identity']
            or producers.kernel.identity(context['pid']) != context['identity']
            or child['pid'] not in producers.response_staged):
        raise RuntimeError('package_retired_build_current_consumer')
    rows = producers.supervisor.events()
    ready = [row for row in rows if row['kind'] == 'ready' and row['owner_pid'] == child['pid']
             and row['token'] == child['token']]
    calls = [row for row in rows if row['kind'] == 'isolated_actual_backend_call'
             and row['owner_pid'] == child['pid'] and row['helper'] == child['helper']]
    if len(ready) != 1 or len(calls) != 1:
        raise RuntimeError('package_retired_build_original_callback')
    item = {'root': str(root), 'root_metadata': metadata(root),
            'parent_metadata': metadata(PARENT), 'pid': child['pid'],
            'identity': child['identity'], 'token': child['token'],
            'parent': child['parent'], 'helper': child['helper'],
            'profile_sha256': child['profile_sha256'],
            'operation_sha256': sha(context['token'].encode()),
            'ready_sha256': sha(json.dumps(ready[0], sort_keys=True).encode()),
            'callback_sha256': sha(json.dumps(calls[0], sort_keys=True).encode())}
    ledger = getattr(producers, 'package_retired_build_consumers', [])
    if len(ledger) >= 4 or any(row['pid'] == child['pid'] for row in ledger):
        raise RuntimeError('package_retired_build_duplicate')
    producers.package_retired_build_consumers = [*ledger, item]
    producers.records.append({'kind': 'primary_package_build_root_consumption', **item})


def names(ledger, final, *, preexisting):
    """Pure operation-specific identity rules, separate from live authentication."""
    if (preexisting or len(ledger) != 4 or {row['helper'] for row in ledger} != HELPERS
            or len({row['pid'] for row in ledger}) != 4
            or final['type'] != stat.S_IFDIR or final['mode'] != 0o755
            or final['uid'] != 20000 or final['gid'] != 20000 or final['links'] != 2
            or not final['empty'] or final['leaf_count'] != 0):
        raise RuntimeError('package_retired_build_final_parent')
    result = {}
    for row in ledger:
        root = Path(row['root'])
        before = row['parent_metadata']
        child = row['root_metadata']
        # ctime/mtime and link count change when the native TempDir is dropped;
        # device, inode, type/mode and ownership must remain the observed ones.
        if (root.parent != PARENT or not root.name.startswith('.tmp') or root.resolve() != root
                or before['identity'][:5] != final['identity'][:5]
                or before['type'] != stat.S_IFDIR or before['mode'] != 0o755
                or before['uid'] != 20000 or before['gid'] != 20000
                or before['empty'] or before['links'] < 3
                or child['type'] != stat.S_IFDIR or child['uid'] != 20000
                or child['gid'] != 20000 or child['mode'] != 0o700):
            raise RuntimeError('package_retired_build_lineage_drift')
        relative = root.relative_to('/work/cache').as_posix()
        result[sha(relative.encode())] = relative
    return result


def current_names(producers, context, trace):
    origin = context.get('package_origin')
    if (origin is None or context['operation'] != 'source-build' or trace.poison
            or producers.supervisor.poisoned or producers.common['cache'] != '/work/cache'):
        raise RuntimeError('package_retired_build_origin')
    receipt = producers.interface.protected_json(origin['path'], origin['sha256'])
    plan = json.loads(Path('/inputs/plan.json').read_bytes())
    if (receipt['identity'] != context['identity']
            or producers.kernel.identity(context['pid']) != context['identity']
            or receipt['parent_identity'] != producers.kernel.identity(context['owner_pid'])
            or receipt['plan'] != plan or plan['duty'] != 'Build wheel and source distribution'
            or plan['commands'] != [['uv', 'build']] or plan['package_mode'] not in {'TEST', 'FULL'}
            or receipt['argv'] != ['uv', 'build'] or receipt['cwd'] != '/source'
            or receipt['environment'] != context['profile']['environment']
            or sha(Path('/inputs/github-script.sh').read_bytes()) != plan['script_sha256']
            or context['identity']['uid'] != 20000
            or not any(row['kind'] == 'kernel_exit' and row['pid'] == context['pid'] and row['raw'] == 0
                       for row in trace.records)):
        raise RuntimeError('package_retired_build_live_origin')
    if not {trace.identities[pid]['tgid'] for pid in trace.active} <= {context['pid'], context['owner_pid']}:
        raise RuntimeError('package_retired_build_foreign_writer')
    children = context['children']
    if len(children) != 5 or {row['helper'] for row in children} != HELPERS | {'main'}:
        raise RuntimeError('package_retired_build_children')
    for child in children:
        waits = [row for row in trace.records if row['kind'] == 'original_parent_wait4'
                 and row['child'] == child['pid'] and row['parent_tgid'] == context['pid']]
        if len(waits) != 1 or waits[0]['raw'] != 0:
            raise RuntimeError('package_retired_build_child_wait')
    ledger = getattr(producers, 'package_retired_build_consumers', [])
    for row in ledger:
        matches = [child for child in children if child['pid'] == row['pid']]
        if (len(matches) != 1 or any(row[key] != matches[0][key] for key in (
                'identity', 'token', 'parent', 'helper', 'profile_sha256'))
                or row['operation_sha256'] != sha(context['token'].encode())
                or row['pid'] not in producers.response_receipts):
            raise RuntimeError('package_retired_build_consumer_drift')
    final = metadata(PARENT)
    result = names(ledger, final, preexisting=sha(b'builds-v0') in producers.cache_current)
    producers.package_retired_parent = final
    producers.records.append({'kind': 'primary_package_retired_build_names',
                              'pid': context['pid'], 'identity': context['identity'],
                              'names': result, 'consumer_pids': sorted(row['pid'] for row in ledger),
                              'parent_metadata': final, 'release_certificate': False})
    return result


def checked_view(original, expected):
    def view(spec, external):
        current, paths = original(spec, external)
        key = sha(b'builds-v0')
        if (spec['cache'] != '/work/cache' or paths.get(key) != 'builds-v0'
                or current.get(key) != {'type': 'directory', 'identity': expected['identity'][:4]}
                or metadata(PARENT) != expected):
            raise RuntimeError('package_retired_build_census_drift')
        return current, paths
    return view
