"""Bounded data-only observations after an unchanged cache refusal.

This decoder and its projections grant no cache authority. No raw cache body,
encoded payload, executable, or cache directory crosses a capsule boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

LIMIT = 65536
NODES = 4096


def decode(body):
    if type(body) is not bytes or not 0 < len(body) <= LIMIT:
        raise ValueError('cache_diagnostic_bound')
    offset, count = 0, 0

    def take(size):
        nonlocal offset
        if type(size) is not int or not 0 <= size <= LIMIT or offset + size > len(body):
            raise ValueError('cache_diagnostic_truncated')
        value = body[offset:offset + size]
        offset += size
        return value

    def integer(size, signed=False):
        return int.from_bytes(take(size), 'big', signed=signed)

    def value(depth):
        nonlocal count
        count += 1
        if count > NODES or depth > 16:
            raise ValueError('cache_diagnostic_complexity')
        tag = integer(1)
        if tag <= 0x7f:
            return tag
        if tag >= 0xe0:
            return tag - 256
        if 0xa0 <= tag <= 0xbf:
            return take(tag & 31).decode('utf-8')
        if tag == 0xc0:
            return None
        if tag in {0xc2, 0xc3}:
            return tag == 0xc3
        if tag in {0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3}:
            return integer(1 << ((tag - (0xd0 if tag >= 0xd0 else 0xcc)) & 3), tag >= 0xd0)
        if tag in {0xca, 0xcb}:
            result = struct.unpack('>f' if tag == 0xca else '>d', take(4 if tag == 0xca else 8))[0]
            import math
            if not math.isfinite(result):
                raise ValueError('cache_diagnostic_nonfinite')
            return result
        if tag in {0xc4, 0xc5, 0xc6, 0xd9, 0xda, 0xdb}:
            size = integer(1 << ((tag - (0xd9 if tag >= 0xd9 else 0xc4)) & 3))
            result = take(size)
            return result.decode('utf-8') if tag >= 0xd9 else result
        if 0x90 <= tag <= 0x9f or tag in {0xdc, 0xdd}:
            size = tag & 15 if tag <= 0x9f else integer(2 if tag == 0xdc else 4)
            if size > NODES - count:
                raise ValueError('cache_diagnostic_complexity')
            return [value(depth + 1) for _ in range(size)]
        if 0x80 <= tag <= 0x8f or tag in {0xde, 0xdf}:
            size = tag & 15 if tag <= 0x8f else integer(2 if tag == 0xde else 4)
            if 2 * size > NODES - count:
                raise ValueError('cache_diagnostic_complexity')
            result = {}
            for _ in range(size):
                key = value(depth + 1)
                if type(key) not in {str, int} or key in result:
                    raise ValueError('cache_diagnostic_map_key')
                result[key] = value(depth + 1)
            return result
        raise ValueError('cache_diagnostic_tag')

    result = value(0)
    if offset != len(body):
        raise ValueError('cache_diagnostic_trailing')
    return result


def projection(value, query):
    def fingerprint(item):
        if type(item) is bytes:
            body = item
        else:
            body = json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        return hashlib.sha256(body).hexdigest()
    known = {}
    def leaves(item, path):
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is str and re.fullmatch('[a-zA-Z_][a-zA-Z_0-9]{0,63}', key):
                    leaves(child, path + [key])
        elif type(item) is list:
            for index, child in enumerate(item):
                leaves(child, path + [str(index)])
        else:
            known.setdefault((type(item).__name__, fingerprint(item)), []).append('.'.join(path))
    leaves(query, [])
    def shape(item):
        if type(item) is list:
            return {'type': 'array', 'items': [shape(child) for child in item]}
        if type(item) is dict:
            return {'type': 'map', 'items': [{'key': key if type(key) is str and re.fullmatch(
                '[a-zA-Z_][a-zA-Z_0-9]{0,63}', key) else {'sha256': fingerprint(key)},
                'value': shape(child)} for key, child in item.items()]}
        digest = fingerprint(item)
        result = {'type': type(item).__name__, 'sha256': digest,
                  'query_field_matches': known.get((type(item).__name__, digest), [])}
        if type(item) in {str, bytes}:
            result['bytes'] = len(item.encode() if type(item) is str else item)
        return result
    result = shape(value)
    if len(json.dumps(result).encode()) > LIMIT:
        raise ValueError('cache_diagnostic_projection_bound')
    return result


def observe(producers, context):
    from producer_profile import cache_view
    if producers.kernel.identity(context['pid']) != context['identity']:
        raise RuntimeError('cache_diagnostic_writer_birth')
    refused = [row for row in producers.records if row['kind'] == 'primary_cache_output_unbound'
               and row['pid'] == context['pid']]
    if len(refused) != 1:
        raise RuntimeError('cache_diagnostic_refusal_identity')
    # Reconstruct only the same already byte-bound backend aliases used by
    # the failing original closure. Its provisional local set is deliberately
    # not published into producers.cache_external after a refusal.
    external = set(producers.cache_external)
    from primary_custody import read_regular
    for child in context['children']:
        if child['role'] != 'isolated-uv-helper':
            continue
        header = read_regular(Path('/receipts/native-startup') / (str(child['pid']) + '.json'), LIMIT, 0o444)
        if hashlib.sha256(header).hexdigest() != child['profile_sha256']:
            raise RuntimeError('cache_diagnostic_profile_drift')
        profile = json.loads(header)
        spec = producers.interface.protected_json(profile['spec'], profile['spec_sha256'])
        if spec['parent_operation']['identity'] != context['identity']:
            raise RuntimeError('cache_diagnostic_parent_drift')
        runtime = Path(spec['primary_runtime_output']['root'])
        if runtime.parent != Path('/work/cache/builds-v0') or not runtime.name.startswith('.tmp'):
            raise RuntimeError('cache_diagnostic_runtime_root')
        for name in ('python', 'python3', 'python3.13'):
            relative = str((runtime / 'bin' / name).relative_to('/work/cache'))
            external.add(hashlib.sha256(relative.encode()).hexdigest())
    current, names = cache_view(producers.common, external)
    key = refused[0]['member_sha256']
    entry = current[key]
    relative = Path(names[key])
    result = {'schema': 'unrest.v046.primary-package-cache-refusal.v1',
              'status': 'not-an-interpreter-record', 'member_sha256': key,
              'member_type': entry['type'], 'authority_granted': False,
              'eligible_certificate': False, 'source_checkpoint_ready': False,
              'selected_carrier': None}
    if (entry['type'] != 'file' or len(relative.parts) != 3
            or relative.parts[0] != 'interpreter-v4' or relative.suffix != '.msgpack'):
        return result
    root = Path('/work/cache')
    if producers.common['cache'] != str(root) or relative.is_absolute() or '..' in relative.parts:
        raise RuntimeError('cache_diagnostic_path')
    path = root / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 20000
                or before.st_nlink != 1 or not 0 < before.st_size <= LIMIT):
            raise RuntimeError('cache_diagnostic_carrier')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        def identity(info):
            return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        if (identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.lstat())
                or len(body) != before.st_size or hashlib.sha256(body).hexdigest() != entry['sha256']):
            raise RuntimeError('cache_diagnostic_race')
    finally:
        os.close(descriptor)
    queries = [row for row in producers.supervisor.events() if row['kind'] == 'query_actual_main_return'
               and row['parent_pid'] == context['pid']]
    if len(queries) != 1:
        raise RuntimeError('cache_diagnostic_query_return')
    result.update(status='interpreter-record-observed-not-admitted', bytes=len(body),
                  file_sha256=hashlib.sha256(body).hexdigest(),
                  writer_identity=context['identity'],
                  query_result_sha256=hashlib.sha256(json.dumps(queries[0]['info'],
                      sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                  initial_format_tag=body[0])
    try:
        result['shape'] = projection(decode(body), queries[0]['info'])
    except (ValueError, TypeError) as error:
        result['status'] = 'interpreter-record-format-unverified'
        result['decoder_refusal_class'] = type(error).__name__
    return result
