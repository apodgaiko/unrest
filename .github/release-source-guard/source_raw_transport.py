"""PRIMARY v2 named bytes: bounded canonical table followed by exact raw bodies.

There is no compression, reference resolution, log inspection or format fallback.
The physical stdout and every original exported member are retained separately.
"""
from __future__ import annotations

import re
import subprocess
import sys

import structured_evidence as evidence

PREFIX = b'PRIVATE-EVIDENCE-RAW-V2:'
SCHEMA = 'unrest.v046.primary-raw-records.v2'
TABLE_LIMIT = 8192


def table_for(records, identity, invocation):
    evidence.identity_check(identity)
    evidence.require(type(invocation) is str and re.fullmatch('[0-9a-f]{64}', invocation),
                     'raw_invocation')
    evidence.require(type(records) is dict and set(records) <= evidence.SOURCE | evidence.OPAQUE
                     and 'kernel-source.json' in records, 'raw_records')
    evidence.require(all(type(body) is bytes and len(body) <= evidence.LIMIT
                         for body in records.values()), 'record_bound')
    return {'schema': SCHEMA, 'identity': identity, 'invocation_sha256': invocation,
            'records': [{'name': name, 'size': len(body), 'sha256': evidence.digest(body)}
                        for name, body in sorted(records.items())]}


def encode(records, identity, invocation):
    table = evidence.canonical(table_for(records, identity, invocation))
    evidence.require(len(table) <= TABLE_LIMIT, 'raw_table_bound')
    length = len(PREFIX) + 8 + len(table) + sum(map(len, records.values()))
    evidence.require(length <= evidence.LIMIT, 'transport_bound')
    return PREFIX + len(table).to_bytes(8, 'big') + table + b''.join(
        body for _, body in sorted(records.items()))


def decode(frame, identity, invocation, descriptors):
    # Aggregate admission precedes table/payload parsing or persistence.
    evidence.require(type(frame) is bytes and len(frame) <= evidence.LIMIT, 'transport_bound')
    evidence.identity_check(identity)
    evidence.require(type(invocation) is str and re.fullmatch('[0-9a-f]{64}', invocation),
                     'raw_invocation')
    start = len(PREFIX) + 8
    evidence.require(frame.startswith(PREFIX) and len(frame) >= start, 'raw_prefix')
    size = int.from_bytes(frame[len(PREFIX):start], 'big')
    evidence.require(0 < size <= TABLE_LIMIT and start + size <= len(frame), 'raw_table_bound')
    encoded = frame[start:start + size]
    table = evidence.loads(encoded)
    evidence.require(type(table) is dict and set(table) == {
        'schema', 'identity', 'invocation_sha256', 'records'}
        and evidence.canonical(table) == encoded, 'raw_table_fields')
    evidence.require(table['schema'] == SCHEMA and table['identity'] == identity
                     and table['invocation_sha256'] == invocation, 'raw_identity')
    rows = table['records']
    evidence.require(type(rows) is list and 1 <= len(rows) <= len(evidence.SOURCE | evidence.OPAQUE),
                     'raw_record_count')
    names = []
    total = start + size
    for row in rows:
        evidence.require(type(row) is dict and set(row) == {'name', 'size', 'sha256'},
                         'raw_descriptor')
        evidence.require(type(row['name']) is str
                         and row['name'] in evidence.SOURCE | evidence.OPAQUE, 'unknown_record')
        evidence.require(type(row['size']) is int and 0 <= row['size'] <= evidence.LIMIT,
                         'record_bound')
        evidence.require(type(row['sha256']) is str
                         and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'raw_hash')
        names.append(row['name'])
        total += row['size']
        evidence.require(total <= evidence.LIMIT, 'transport_bound')
    evidence.require(names == sorted(set(names)) and 'kernel-source.json' in names, 'raw_record_order')
    evidence.require(set(names) == set(descriptors), 'header_record_binding')
    evidence.require(total == len(frame), 'raw_body_length')
    records = {}
    offset = start + size
    for row in rows:
        name, size = row['name'], row['size']
        descriptor = descriptors[name]
        evidence.require(size == descriptor['decoded_bytes']
                         and row['sha256'] == descriptor['sha256'], 'header_record_binding')
        body = frame[offset:offset + size]
        evidence.require(evidence.digest(body) == row['sha256'], 'raw_body_hash')
        records[name] = body
        offset += size
    return records


def emit_source(records, kernel, identity, invocation, exit_code):
    header = evidence.source_header(records, kernel, identity, invocation, exit_code)
    frame = encode(records, identity, invocation)
    evidence.require(len(header) + len(frame) <= evidence.LIMIT, 'transport_bound')
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()


def capture(argv, raw, identity, scope, *, source_invocation, **kwargs):
    evidence.require(scope == 'primary-executor', 'raw_scope')
    with (raw / 'coordinator.log').open('ab') as errors:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=errors, check=False, **kwargs)
    current = result.stdout
    end = current.find(b'\n', 0, evidence.HEADER_LIMIT)
    evidence.require(end >= 0 and current.startswith(evidence.HEADER_PREFIX), 'header_prefix')
    encoded = current[len(evidence.HEADER_PREFIX):end]
    header = evidence.loads(encoded)
    evidence.validate_header(header, identity, source_invocation)
    evidence.require(evidence.canonical(header) == encoded, 'header_canonical')
    if len(current) > evidence.LIMIT:
        # Preserve only the admitted bounded diagnostic, as on legacy refusal.
        (raw / evidence.HEADER).write_bytes(encoded)
        raise evidence.EvidenceRefused('transport_bound')
    records = decode(current[end + 1:], identity, source_invocation, header['records'])
    # Validate every frame/member before writing any payload; opaque bytes are
    # hashed and copied but never interpreted, searched or returned to callers.
    (raw / evidence.HEADER).write_bytes(encoded)
    (raw / 'current-process.stdout').write_bytes(current)
    envelope_descriptors = {}
    for name, body in sorted(records.items()):
        structured = name in evidence.SOURCE
        path = raw / (('structured-' if structured else 'private-') + name)
        path.write_bytes(body)
        if structured:
            envelope_descriptors[name] = {'member': path.name, 'sha256': evidence.digest(body),
                                          'size': len(body)}
    envelope = {'schema': evidence.SCHEMA, 'scope': scope, 'identity': identity,
                'records': envelope_descriptors, 'source_checkpoint_ready': False,
                'selected_carrier': None}
    (raw / evidence.MEMBER).write_bytes(evidence.canonical(envelope))
    return result, {name: body for name, body in records.items() if name in evidence.SOURCE}
