"""One complete interpreter metadata output of the original PRIMARY build.

UV0.11.0 commit1f31f0e9fbcfcf95aed89b44a376596e14b40e06 serializes
CachedByTimestamp<InterpreterInfo>. On Linux its timestamp is the canonical
image's ctime, not mtime. Only the live original build/query/consumers below
can introduce this data output; it never grants an executable or cache mount.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from primary_package_cache_diagnostic import decode, LIMIT

FIELDS = ('manylinux_compatible', 'sys_prefix', 'sys_base_exec_prefix', 'sys_base_prefix',
          'sys_base_executable', 'sys_executable', 'sys_path', 'site_packages', 'stdlib',
          'standalone', 'pointer_size', 'gil_disabled', 'debug_enabled')
SCHEME = ('purelib', 'platlib', 'scripts', 'data', 'include')


def expected(query, ctime_ns):
    if type(query) is not dict or query.get('result') != 'success' or type(ctime_ns) is not int or ctime_ns < 0:
        raise ValueError('package_cache_query_or_timestamp')
    platform = query['platform']
    os_value = platform['os']
    if set(os_value) != {'name', 'major', 'minor'} or platform['arch'] != 'x86_64':
        raise ValueError('package_cache_platform')
    info = [[[os_value[key] for key in ('name', 'major', 'minor')], platform['arch']],
            query['markers'], [query['scheme'][key] for key in SCHEME],
            [query['virtualenv'][key] for key in SCHEME], *[query[key] for key in FIELDS]]
    return [[ctime_ns // 1_000_000_000, ctime_ns % 1_000_000_000], info]


def identical(actual, wanted):
    if type(actual) is not type(wanted):
        return False
    if type(actual) is list:
        return len(actual) == len(wanted) and all(identical(a, b) for a, b in zip(actual, wanted))
    if type(actual) is dict:
        return (actual.keys() == wanted.keys() and all(type(key) is str for key in actual)
                and all(identical(actual[key], wanted[key]) for key in actual))
    return actual == wanted


def admit(producers, context, key, entry, current, names, trace):
    """Provisional data output; final success still needs the UV parent's wait."""
    origin = context.get('package_origin')
    if (type(origin) is not dict or set(origin) != {'path', 'sha256'}
            or context.get('operation') != 'source-build'):
        return False
    relative = Path(names[key])
    if (entry['type'] != 'file' or len(relative.parts) != 3
            or relative.parts[0] != 'interpreter-v4' or relative.suffix != '.msgpack'):
        return False
    candidates = [name for name, row in current.items() if name not in producers.cache_current
                  and row['type'] == 'file' and len(Path(names[name]).parts) == 3
                  and Path(names[name]).parts[0] == 'interpreter-v4'
                  and Path(names[name]).suffix == '.msgpack']
    if candidates != [key] or trace.poison or producers.supervisor.poisoned:
        return False
    identity = producers.kernel.identity(context['pid'])
    origin = context['package_origin']
    receipt = producers.interface.protected_json(origin['path'], origin['sha256'])
    plan = json.loads(Path('/inputs/plan.json').read_bytes())
    if (receipt['identity'] != identity or identity != context['identity']
            or receipt['plan'] != plan or plan['duty'] != 'Build wheel and source distribution'
            or plan['commands'] != [['uv', 'build']] or plan['package_mode'] not in {'TEST', 'FULL'}
            or receipt['parent_identity'] != producers.kernel.identity(context['owner_pid'])
            or receipt['argv'] != ['uv', 'build'] or receipt['cwd'] != '/source'
            or receipt['environment'] != context['profile']['environment']
            or hashlib.sha256(Path('/inputs/github-script.sh').read_bytes()).hexdigest()
            != plan['script_sha256'] or identity['uid'] != 20000
            or not any(row['kind'] == 'kernel_exit' and row['pid'] == context['pid'] and row['raw'] == 0
                       for row in trace.records)):
        return False
    children = context['children']
    if (len(children) != 5 or sorted(row['helper'] for row in children) != sorted([
            'main', 'get_requires_for_build_sdist', 'build_sdist',
            'get_requires_for_build_wheel', 'build_wheel'])):
        return False
    for child in children:
        waits = [row for row in trace.records if row['kind'] == 'original_parent_wait4'
                 and row['child'] == child['pid'] and row['parent_tgid'] == context['pid']]
        if len(waits) != 1 or waits[0]['raw'] != 0:
            return False
    active = {trace.identities[pid]['tgid'] for pid in trace.active}
    if not active <= {context['pid'], context['owner_pid']}:
        return False
    events = producers.supervisor.events()
    query = next(row for row in children if row['role'] == 'isolated-uv-query')
    returns = [row for row in events if row['kind'] == 'query_actual_main_return'
               and row['owner_pid'] == query['pid'] and row['parent_pid'] == context['pid']]
    dispatches = [row for row in events if row['kind'] == 'query_original_dispatch'
                  and row['owner_pid'] == query['pid']]
    if len(returns) != 1 or len(dispatches) != 1:
        return False
    base = Path('/usr/local/bin/python-primary-audit')
    if (producers.common['base'] != str(base)
            or producers.activation.identity(base) != producers.common['base_identity']):
        return False
    image = base.stat()
    if image.st_uid != 0 or returns[0]['info']['sys_executable'] != str(base):
        return False
    path = Path('/work/cache') / relative
    if producers.common['cache'] != '/work/cache':
        return False
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 20000
                or before.st_nlink != 1 or not 0 < before.st_size <= LIMIT):
            return False
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        def identity_of(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (identity_of(before) != identity_of(os.fstat(descriptor))
                or identity_of(before) != identity_of(path.lstat()) or len(body) != before.st_size
                or hashlib.sha256(body).hexdigest() != entry['sha256']):
            return False
    finally:
        os.close(descriptor)
    try:
        wanted = expected(returns[0]['info'], image.st_ctime_ns)
        if not identical(decode(body), wanted):
            return False
    except (ValueError, TypeError, KeyError):
        return False
    if (base.stat().st_ctime_ns != image.st_ctime_ns
            or producers.activation.identity(base) != producers.common['base_identity']):
        return False
    producers.records.append({'kind': 'primary_package_interpreter_cache_output',
                              'pid': context['pid'], 'identity': identity,
                              'member_sha256': key, 'file_sha256': entry['sha256'],
                              'query_pid': query['pid'], 'complete_bytes': len(body),
                              'consumer_helpers': 4, 'release_certificate': False})
    return True
