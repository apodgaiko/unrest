"""Fresh original bootstrap outputs for the exact PRIMARY archive command.

The source-suite bootstrap predicate stays unchanged in producer_profile.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat

from producer_profile import cache_view, hashed, identities, load


def bootstrap_cache(spec, trace, pid, primary):
    """Seal the original PRIMARY bootstrap outputs before product Python runs."""
    parent = trace.identities[pid]['ppid']
    context = primary.contexts.get(parent)
    if (trace.poison or primary.denials or context is None or context['role'] != 'uv'
            or context['command'] != ['uv', 'run', 'python', 'tools/check_distribution.py', 'dist']
            or identities.identity(parent) != context['identity']):
        raise RuntimeError('primary_cache_bootstrap_context')
    children = [(child, value) for child, value in primary.contexts.items()
                if value.get('role') in {'query', 'editable_backend'} and value['identity']['ppid'] == parent]
    if (len(children) != 3 or [value['role'] for _, value in children].count('query') != 1
            or [value['role'] for _, value in children].count('editable_backend') != 2):
        raise RuntimeError('primary_cache_bootstrap_original_producers')
    external, provenance = set(), []
    policy = load('cache_bootstrap_policy', '/guard/primary_policy.py')
    for child, value in children:
        records = [record for record in primary.records if record['kind'] == 'primary_native_preinit'
                   and record['pid'] == child and record['parent'] == parent and record['role'] == value['role']]
        waits = [event for event in trace.records if event['kind'] == 'original_parent_wait4'
                 and event['child'] == child and event['parent_tgid'] == parent]
        if len(records) != 1 or len(waits) != 1 or waits[0]['raw'] != 0 or records[0]['identity'] != value['identity']:
            raise RuntimeError('primary_cache_bootstrap_actual_wait')
        path = Path('/receipts/primary-startup') / (str(child) + '.json')
        info, body = path.lstat(), path.read_bytes()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444
                or info.st_nlink != 1 or hashlib.sha256(body).hexdigest() != records[0]['profile_sha256']):
            raise RuntimeError('primary_cache_bootstrap_profile')
        header = json.loads(body)
        if (header['pid'] != child or header['parent'] != parent
                or header['start_ticks'] != value['identity']['start_ticks']
                or header['boot_id'] != value['identity']['boot_id']):
            raise RuntimeError('primary_cache_bootstrap_birth')
        if value['role'] == 'editable_backend':
            helper = policy.backend_request(header['orig_argv'][-1])
            if helper not in {'get_requires_for_build_editable', 'build_editable'}:
                raise RuntimeError('primary_cache_bootstrap_helper')
            runtime = Path(header['orig_argv'][0]).parent.parent
            for name in ('python', 'python3', 'python3.13'):
                link = runtime / 'bin' / name
                external.add(hashlib.sha256(str(link.relative_to(spec['cache'])).encode()).hexdigest())
        provenance.append({'pid': child, 'role': value['role'], 'parent_wait_raw': 0,
                           'identity_sha256': hashed(value['identity']),
                           'profile_sha256': records[0]['profile_sha256']})
    # The only live writer before this exec fence is the already admitted UV;
    # its exact query/editable children have returned and been numerically reaped.
    for task in trace.active:
        tgid = trace.identities[task]['tgid']
        if tgid not in {primary.root, parent, pid}:
            raise RuntimeError('primary_cache_bootstrap_foreign_writer')
    entries, _ = cache_view(spec, external)
    return {'schema': 'unrest.v046.primary-cache-bootstrap.v1', 'entries': entries,
            'external_links': sorted(external), 'source_pid': pid, 'parent': parent,
            'parent_identity_sha256': hashed(context['identity']), 'producers': provenance,
            'source_checkpoint_ready': False, 'selected_carrier': None}
