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


# V3 is explicitly selected by PRIMARY. V2 above remains a separate protocol.
PACKED_PREFIX = b'PRIVATE-EVIDENCE-PACKED-V3:'
PACKED_SCHEMA = 'unrest.v047.primary-packed-records.v3'
PACKED_ENVELOPE = 'unrest.v047.packed-private-records.v3'
LOGICAL_MEMBER_LIMIT = 128 * 1024 * 1024
LOGICAL_TOTAL_LIMIT = 256 * 1024 * 1024


def packed_rows(rows):
    evidence.require(type(rows) is list and 1 <= len(rows) <= len(evidence.SOURCE | evidence.OPAQUE),
                     'packed_record_count')
    names, total = [], 0
    for row in rows:
        evidence.require(type(row) is dict and set(row) == {
            'name', 'size', 'sha256', 'packed_size', 'packed_sha256'}, 'packed_descriptor')
        evidence.require(type(row['name']) is str and row['name'] in evidence.SOURCE | evidence.OPAQUE,
                         'unknown_record')
        evidence.require(type(row['size']) is int and 0 <= row['size'] <= LOGICAL_MEMBER_LIMIT,
                         'logical_record_bound')
        evidence.require(type(row['packed_size']) is int and 0 < row['packed_size'] <= evidence.LIMIT,
                         'packed_record_bound')
        for key in ('sha256', 'packed_sha256'):
            evidence.require(type(row[key]) is str and re.fullmatch('[0-9a-f]{64}', row[key]),
                             'packed_hash')
        names.append(row['name'])
        total += row['size']
        evidence.require(total <= LOGICAL_TOTAL_LIMIT, 'logical_total_bound')
    evidence.require(names == sorted(set(names)) and 'kernel-source.json' in names,
                     'packed_record_order')


def encode_packed(records, identity, invocation):
    import zlib
    evidence.identity_check(identity)
    evidence.require(type(invocation) is str and re.fullmatch('[0-9a-f]{64}', invocation),
                     'raw_invocation')
    evidence.require(type(records) is dict and set(records) <= evidence.SOURCE | evidence.OPAQUE
                     and 'kernel-source.json' in records, 'raw_records')
    evidence.require(all(type(body) is bytes and len(body) <= LOGICAL_MEMBER_LIMIT
                         for body in records.values()), 'logical_record_bound')
    evidence.require(sum(map(len, records.values())) <= LOGICAL_TOTAL_LIMIT, 'logical_total_bound')
    packed = {name: zlib.compress(body, level=6) for name, body in sorted(records.items())}
    rows = [{'name': name, 'size': len(records[name]), 'sha256': evidence.digest(records[name]),
             'packed_size': len(body), 'packed_sha256': evidence.digest(body)}
            for name, body in packed.items()]
    packed_rows(rows)
    table = evidence.canonical({'schema': PACKED_SCHEMA, 'identity': identity,
                                'invocation_sha256': invocation, 'records': rows})
    evidence.require(len(table) <= TABLE_LIMIT, 'raw_table_bound')
    evidence.require(len(PACKED_PREFIX) + 8 + len(table) + sum(map(len, packed.values()))
                     <= evidence.LIMIT, 'transport_bound')
    return PACKED_PREFIX + len(table).to_bytes(8, 'big') + table + b''.join(packed.values())


def packed_parts(frame, identity, invocation, descriptors):
    evidence.require(type(frame) is bytes and len(frame) <= evidence.LIMIT, 'transport_bound')
    evidence.identity_check(identity)
    evidence.require(type(invocation) is str and re.fullmatch('[0-9a-f]{64}', invocation),
                     'raw_invocation')
    start = len(PACKED_PREFIX) + 8
    evidence.require(frame.startswith(PACKED_PREFIX) and len(frame) >= start, 'packed_prefix')
    size = int.from_bytes(frame[len(PACKED_PREFIX):start], 'big')
    evidence.require(0 < size <= TABLE_LIMIT and start + size <= len(frame), 'raw_table_bound')
    encoded = frame[start:start + size]
    table = evidence.loads(encoded)
    evidence.require(type(table) is dict and set(table) == {
        'schema', 'identity', 'invocation_sha256', 'records'}
        and evidence.canonical(table) == encoded, 'packed_table_fields')
    evidence.require(table['schema'] == PACKED_SCHEMA and table['identity'] == identity
                     and table['invocation_sha256'] == invocation, 'packed_identity')
    rows = table['records']
    packed_rows(rows)
    evidence.require({row['name'] for row in rows} == set(descriptors), 'header_record_binding')
    total = start + size + sum(row['packed_size'] for row in rows)
    evidence.require(total <= evidence.LIMIT and total == len(frame), 'packed_body_length')
    parts, offset = {}, start + size
    for row in rows:
        name = row['name']
        descriptor = descriptors[name]
        evidence.require(row['size'] == descriptor['decoded_bytes']
                         and row['sha256'] == descriptor['sha256'], 'header_record_binding')
        body = frame[offset:offset + row['packed_size']]
        evidence.require(evidence.digest(body) == row['packed_sha256'], 'packed_body_hash')
        parts[name] = body
        offset += row['packed_size']
    return rows, parts


def inflate_packed(rows, parts):
    import zlib
    # All names, both size domains and the aggregate budget precede inflation.
    packed_rows(rows)
    evidence.require(set(parts) == {row['name'] for row in rows}, 'packed_members')
    for row in rows:
        body = parts[row['name']]
        evidence.require(type(body) is bytes and len(body) == row['packed_size']
                         and evidence.digest(body) == row['packed_sha256'], 'packed_body_hash')
    result = {}
    for row in rows:
        decoder = zlib.decompressobj()
        try:
            body = decoder.decompress(parts[row['name']], row['size'] + 1)
        except zlib.error:
            raise evidence.EvidenceRefused('packed_codec') from None
        evidence.require(len(body) == row['size'] and decoder.eof and not decoder.unused_data
                         and not decoder.unconsumed_tail, 'packed_inflation')
        evidence.require(evidence.digest(body) == row['sha256'], 'raw_body_hash')
        result[row['name']] = body
    return result


def decode_packed(frame, identity, invocation, descriptors):
    rows, parts = packed_parts(frame, identity, invocation, descriptors)
    return inflate_packed(rows, parts)


def emit_packed_source(records, kernel, identity, invocation, exit_code):
    header = evidence.source_header(records, kernel, identity, invocation, exit_code)
    try:
        frame = encode_packed(records, identity, invocation)
        evidence.require(len(header) + len(frame) <= evidence.LIMIT, 'transport_bound')
    except evidence.EvidenceRefused:
        # A valid bounded status survives a refusal, but is never a certificate.
        # The outer capture rejects the incomplete frame even if status was zero.
        sys.stdout.buffer.write(header)
        sys.stdout.buffer.flush()
        raise
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()


def capture_packed(argv, raw, identity, scope, *, source_invocation, **kwargs):
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
    with (raw / evidence.HEADER).open('xb') as output:
        output.write(encoded)
    evidence.require(len(current) <= evidence.LIMIT, 'transport_bound')
    with (raw / 'current-process.stdout').open('xb') as output:
        output.write(current)
    rows, parts = packed_parts(current[end + 1:], identity, source_invocation, header['records'])
    descriptors = {row['name']: {'member': 'packed-' + row['name'],
                                **{k: v for k, v in row.items() if k != 'name'}} for row in rows}
    envelope = {'schema': PACKED_ENVELOPE, 'scope': scope, 'identity': identity,
                'invocation_sha256': source_invocation, 'records': descriptors,
                'physical_stdout_sha256': evidence.digest(current), 'physical_stdout_size': len(current),
                'source_checkpoint_ready': False, 'selected_carrier': None}
    envelope_body = evidence.canonical(envelope)
    evidence.require(len(envelope_body) <= TABLE_LIMIT, 'envelope_bound')
    existing = list(raw.iterdir())
    evidence.require(all(p.is_file() and not p.is_symlink() and p.stat().st_size <= evidence.LIMIT for p in existing), 'archive_member')
    evidence.require(len(existing) + len(parts) + 1 <= 40, 'archive_inventory')
    evidence.require(sum(p.stat().st_size for p in existing) + len(envelope_body)
                     + sum(map(len, parts.values())) <= 2 * evidence.LIMIT, 'archive_bound')
    records = inflate_packed(rows, parts)
    for name, body in parts.items():
        with (raw / ('packed-' + name)).open('xb') as output:
            output.write(body)
    with (raw / evidence.MEMBER).open('xb') as output:
        output.write(envelope_body)
    return result, {name: body for name, body in records.items() if name in evidence.SOURCE}


def consume_packed(envelope_body, envelope_sha256, expected, names, read):
    evidence.require(evidence.digest(envelope_body) == envelope_sha256, 'envelope_digest')
    envelope = evidence.loads(envelope_body)
    evidence.require(type(envelope) is dict and set(envelope) == {
        'schema', 'scope', 'identity', 'invocation_sha256', 'records', 'physical_stdout_sha256',
        'physical_stdout_size', 'source_checkpoint_ready', 'selected_carrier'}, 'envelope_fields')
    evidence.require(envelope['schema'] == PACKED_ENVELOPE and envelope['scope'] == 'primary-executor'
                     and envelope['identity'] == expected, 'schema_scope')
    evidence.require(envelope['source_checkpoint_ready'] is False and envelope['selected_carrier'] is None,
                     'scope_escalation')
    descriptors = envelope['records']
    evidence.require(type(descriptors) is dict and set(descriptors) <= evidence.SOURCE | evidence.OPAQUE
                     and 'kernel-source.json' in descriptors, 'unknown_record')
    permitted = {evidence.MEMBER, evidence.HEADER, 'coordinator.log', 'current-process.stdout',
                 'prepared.stdout', 'container-inspect.json', 'container-state.json', 'source-pins.json',
                 'negative-control-proof.json', 'provenance.json', 'prerequisite-status.json'}
    evidence.require(set(names) <= permitted | {'packed-' + name for name in descriptors},
                     'unknown_archive_member')
    current = read('current-process.stdout')
    evidence.require(type(envelope['physical_stdout_size']) is int
                     and envelope['physical_stdout_size'] == len(current) <= evidence.LIMIT
                     and envelope['physical_stdout_sha256'] == evidence.digest(current), 'physical_carrier')
    end = current.find(b'\n', 0, evidence.HEADER_LIMIT)
    evidence.require(end >= 0 and current.startswith(evidence.HEADER_PREFIX), 'header_prefix')
    encoded = current[len(evidence.HEADER_PREFIX):end]
    header = evidence.loads(encoded)
    evidence.validate_header(header, expected, envelope['invocation_sha256'])
    evidence.require(evidence.canonical(header) == encoded and read(evidence.HEADER) == encoded,
                     'header_canonical')
    rows, parts = packed_parts(current[end + 1:], expected, envelope['invocation_sha256'], header['records'])
    wanted = {row['name']: {'member': 'packed-' + row['name'],
                          **{k: v for k, v in row.items() if k != 'name'}} for row in rows}
    evidence.require(descriptors == wanted, 'descriptor_fields')
    for name, part in parts.items():
        evidence.require('packed-' + name in names and read('packed-' + name) == part, 'record_digest')
    records = inflate_packed(rows, parts)
    return 'primary-executor', {name: body for name, body in records.items() if name in evidence.SOURCE}
