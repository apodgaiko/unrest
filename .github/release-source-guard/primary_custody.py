"""Run-bound custody for current capsule records and finite package outputs.

The MAC key belongs to the host control plane and is never a payload mount.
Only the original build can introduce archives; later phases consume the same
bytes and may add only the original checksum file. No cache or interpreter is
an output of this channel.
"""
from __future__ import annotations

from approval_wait_evidence import unresolved, adopted_waits

from dataclasses import dataclass
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat

from checkpoint_packages import WHEEL, SDIST, LIMIT
from checkpoint_receipt import DEFINITION_FIELDS
from structured_evidence import canonical, loads, require

from phase_catalog import (BUILD, ARCHIVE as ARCHIVE, INSTALLED as INSTALLED,
                           CHECKSUM, SOURCE as SOURCE, ORDER)
OUTPUTS = (WHEEL, SDIST, 'SHA256SUMS')


def sha(body):
    return hashlib.sha256(body).hexdigest()


def file_identity(info):
    # Reading can update atime; it is not evidence of an output-byte mutation.
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


@dataclass(frozen=True)
class Binding:
    definition: dict
    run_id: int
    run_attempt: int

    def value(self):
        require(set(self.definition) == set(DEFINITION_FIELDS), 'custody_definition')
        require(all(type(value) is str and re.fullmatch(
            '[0-9a-f]{40}' if key in {'head_sha', 'source_tree'} else '[0-9a-f]{64}', value)
            for key, value in self.definition.items()), 'custody_definition_digest')
        require(type(self.run_id) is int and self.run_id > 0
                and type(self.run_attempt) is int and self.run_attempt > 0, 'custody_run')
        return {'definition': self.definition, 'run_id': self.run_id,
                'run_attempt': self.run_attempt}


def read_regular(path, limit, mode=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= limit and before.st_uid == os.getuid()
                and (mode is None or stat.S_IMODE(before.st_mode) == mode), 'custody_file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(limit + 1)
        after = os.fstat(descriptor)
        require(file_identity(before) == file_identity(after) == file_identity(Path(path).lstat())
                and len(body) == before.st_size, 'custody_file_changed')
        return body
    finally:
        os.close(descriptor)


def exclusive(path, body, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def kernel_success(records, script_sha256):
    kernel = loads(records['kernel-source.json'])
    require(type(kernel.get('root_parent_wait_raw')) is int and kernel['root_parent_wait_raw'] == 0
            and kernel.get('poison') == [] and kernel.get('primary_denials') == []
            and kernel.get('failure_code') is None
            and kernel.get('native_preinit_refusal') is False
            and kernel.get('all_commands_dispatched') is True
            and kernel.get('actual_script_sha256') == script_sha256
            and kernel.get('unregistered_processes') == []
            and not unresolved(kernel), 'custody_kernel_result')
    identity = kernel['source_preexec_identity']
    require(identity['uids'] == [20000] * 4 and not any(identity['capabilities'].values())
            and identity['no_new_privs'] == 1, 'custody_source_identity')
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']]
    adopted = adopted_waits(kernel)
    for birth in births:
        if birth['child'] in adopted:
            continue
        waits = [row for row in kernel['records']
                 if row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
                 and (row['kind'] == 'original_parent_wait4' or row['reaps'])
                 and row['child'] == birth['child']
                 and row['parent_tgid'] == birth['identity']['ppid']]
        require(len(waits) == 1 and type(waits[0].get(
            'raw' if waits[0]['kind'] == 'original_parent_wait4' else 'status')) is int,
            'custody_actual_parent_wait')
    return kernel


def decode_outputs(body, duty):
    value = loads(body)
    wanted = set(OUTPUTS if duty == CHECKSUM else OUTPUTS[:2])
    require(type(value) is dict and set(value) == {'schema', 'members'}
            and value['schema'] == 'unrest.v046.primary-package-output.v1'
            and set(value['members']) == wanted, 'custody_output_inventory')
    result = {}
    for name, record in value['members'].items():
        require(type(record) is dict and set(record) == {'sha256', 'size', 'bytes'}
                and type(record['size']) is int and 0 < record['size'] <= LIMIT
                and type(record['bytes']) is str and len(record['bytes']) <= 2 * LIMIT,
                'custody_output_descriptor')
        try:
            data = base64.b64decode(record['bytes'], validate=True)
        except ValueError:
            raise RuntimeError('custody_output_encoding') from None
        require(len(data) == record['size'] and sha(data) == record['sha256'], 'custody_output_bytes')
        result[name] = data
    require(sum(map(len, result.values())) <= LIMIT, 'custody_output_bound')
    if duty == CHECKSUM:
        require(result['SHA256SUMS'] == b''.join(
            (sha(result[name]) + '  ' + name + '\n').encode() for name in (WHEEL, SDIST)),
            'custody_checksum_bytes')
    return result



SOURCE_RECORD_CODEC = 'unrest.v047.source-records.zlib.v1'
SOURCE_PHASE_LIMIT = 64 * 1024 * 1024


def packed_source_records(records):
    import zlib
    from source_raw_transport import packed_rows, LOGICAL_MEMBER_LIMIT, LOGICAL_TOTAL_LIMIT
    require(all(type(body) is bytes and len(body) <= LOGICAL_MEMBER_LIMIT
                for body in records.values()) and sum(map(len, records.values())) <= LOGICAL_TOTAL_LIMIT,
            'custody_logical_bound')
    values = {}
    rows = []
    for name, body in sorted(records.items()):
        packed = zlib.compress(body, level=6)
        row = {'name': name, 'size': len(body), 'sha256': sha(body),
               'packed_size': len(packed), 'packed_sha256': sha(packed)}
        rows.append(row)
        values[name] = {**{key: value for key, value in row.items() if key != 'name'},
                        'bytes': base64.b64encode(packed).decode()}
    packed_rows(rows)
    return values


def phase_records(phase):
    if 'record_codec' not in phase:
        return {name: base64.b64decode(body, validate=True) for name, body in phase['records'].items()}
    from source_raw_transport import packed_rows, inflate_packed
    from structured_evidence import LIMIT as PHYSICAL_LIMIT
    require(phase['record_codec'] == SOURCE_RECORD_CODEC and phase['duty'] == SOURCE
            and type(phase['records']) is dict, 'custody_record_codec')
    from structured_evidence import SOURCE as SOURCE_MEMBERS
    require(set(phase['records']) <= SOURCE_MEMBERS, 'custody_duty_records')
    rows, encoded = [], {}
    for name, record in sorted(phase['records'].items()):
        require(type(record) is dict and set(record) == {
            'size', 'sha256', 'packed_size', 'packed_sha256', 'bytes'}, 'custody_record_fields')
        require(type(record['bytes']) is str and len(record['bytes']) <= 2 * PHYSICAL_LIMIT,
                'custody_packed_bound')
        rows.append({'name': name, **{key: value for key, value in record.items() if key != 'bytes'}})
        encoded[name] = record['bytes']
    packed_rows(rows)
    require(sum(row['packed_size'] for row in rows) <= PHYSICAL_LIMIT, 'custody_packed_bound')
    require(all(len(encoded[row['name']]) == 4 * ((row['packed_size'] + 2) // 3) for row in rows),
            'custody_packed_encoding')
    parts = {}
    for row in rows:
        try:
            parts[row['name']] = base64.b64decode(encoded[row['name']], validate=True)
        except (ValueError, TypeError):
            raise RuntimeError('custody_packed_encoding') from None
    return inflate_packed(rows, parts)


class Custody:
    def __init__(self, root, binding, *, create=False):
        self.root, self.binding = Path(root), binding.value()
        if create:
            self.root.mkdir(mode=0o700)
            exclusive(self.root / 'key', os.urandom(32))
            exclusive(self.root / 'binding.json', canonical(self.binding))
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_uid == os.getuid() and self.root.resolve() == self.root, 'custody_root')
        self.key = read_regular(self.root / 'key', 32, 0o600)
        require(len(self.key) == 32 and loads(read_regular(self.root / 'binding.json', 8192, 0o600))
                == self.binding, 'custody_binding')

    def phase(self, duty):
        filename = sha(duty.encode()) + '.json'
        physical = read_regular(self.root / filename, 2 * LIMIT, 0o600)
        envelope = loads(physical)
        if duty == SOURCE and 'record_codec' in envelope.get('payload', {}):
            require(len(physical) <= SOURCE_PHASE_LIMIT, 'custody_phase_bound')
        require(set(envelope) == {'payload', 'mac'}, 'custody_envelope')
        body = canonical(envelope['payload'])
        require(hmac.compare_digest(envelope['mac'], hmac.digest(self.key, body, 'sha256').hex()),
                'custody_mac')
        value = envelope['payload']
        require(value['binding'] == self.binding and value['duty'] == duty, 'custody_phase_identity')
        return value

    def record(self, duty, script_sha256, records, *, input_pins=None):
        """Called only with direct records from the current owned capture."""
        from ci_commands import REGISTRY
        from structured_evidence import SOURCE as RECORDS
        require(duty in loads(REGISTRY.read_bytes()) and set(records) <= RECORDS, 'custody_duty_records')
        kernel = kernel_success(records, script_sha256)
        require(kernel['primary_plan']['duty'] == duty
                and kernel['primary_plan']['workflow_sha256'] == self.binding['definition']['workflow_sha256'],
                'custody_plan_binding')
        prior = None
        outputs = {}
        if duty in ORDER:
            if duty != BUILD:
                prior = self.phase(ORDER[ORDER.index(duty) - 1])
            outputs = decode_outputs(records['package-output.json'], duty)
            if prior is not None:
                require(all(sha(outputs[name]) == prior['outputs'][name] for name in (WHEEL, SDIST)),
                        'custody_cross_phase_archive_drift')
        else:
            require('package-output.json' not in records, 'custody_foreign_phase_output')
        value = {'binding': self.binding, 'duty': duty, 'script_sha256': script_sha256,
                 'input_pins': dict(input_pins or {}),
                 'previous_sha256': sha(canonical(prior)) if prior else None,
                 'records': (packed_source_records(records) if duty == SOURCE else
                             {name: base64.b64encode(body).decode() for name, body in sorted(records.items())}),
                 'outputs': {name: sha(body) for name, body in sorted(outputs.items())}}
        if duty == SOURCE:
            value['record_codec'] = SOURCE_RECORD_CODEC
            require(len(canonical({'payload': value, 'mac': '0' * 64})) <= SOURCE_PHASE_LIMIT,
                    'custody_phase_bound')
        destination = self.root / sha(duty.encode())
        if outputs:
            destination.mkdir(mode=0o700)
            for name, body in sorted(outputs.items()):
                exclusive(destination / name, body)
        exclusive(self.root / (sha(duty.encode()) + '.json'), canonical({
            'payload': value, 'mac': hmac.digest(self.key, canonical(value), 'sha256').hex()}))
        return value

    def package_inputs(self, duty):
        require(duty in ORDER[1:], 'custody_consumer_duty')
        previous = ORDER[ORDER.index(duty) - 1]
        phase = self.phase(previous)
        root = self.root / sha(previous.encode())
        for name in (WHEEL, SDIST):
            require(sha(read_regular(root / name, LIMIT, 0o600)) == phase['outputs'][name],
                    'custody_input_drift')
        return root
