"""Direct private records for future runs; never consume historical logs.

The only transport parser accepts bytes captured from the current owned process.
Operator consumption opens named structured members, never private log members.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import subprocess
import tarfile

SCHEMA = 'unrest.v046.direct-private-records.v1'
MEMBER = 'structured-envelope.json'
LIMIT = 64 * 1024 * 1024
SOURCE = {'kernel-source.json', 'collection.json', 'summary.json', 'source.xml'}
CONTROLS = {'observer.json', 'source-controls.json'} | {
    f'trace-control-{status}-{mode}.json' for status in (0, 29, 31) for mode in (False, True)
} | {'trace-control-vfork-False.json', 'trace-control-vfork-True.json', 'trace-control-waitid.json'}
OPAQUE = {'source-output.log', 'custodian.stderr', 'source-diagnostics.json'}
SCOPES = {'synthetic-controls', 'inprocess', 'composed', 'backend', 'drain-controls',
          'producer-contract', 'producer-distribution', 'producer-controls'}
IDENTITY = {'repository', 'head_sha', 'run_id', 'run_attempt', 'workflow_ref', 'workflow_sha',
            'artifact_name', 'support_sha256'}


class EvidenceRefused(RuntimeError):
    """Messages are fixed codes, never caught exception bodies."""


def require(condition, code):
    if not condition:
        raise EvidenceRefused(code)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def unique(pairs):
    value = {}
    for key, body in pairs:
        require(key not in value, 'duplicate_field')
        value[key] = body
    return value


def loads(body):
    try:
        return json.loads(body, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise EvidenceRefused('invalid_json') from None


def identity_check(value):
    require(type(value) is dict and set(value) == IDENTITY, 'identity_fields')
    require(value['repository'] == 'apodgaiko/unrest', 'repository_identity')
    for key in ('head_sha', 'workflow_sha'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{40}', value[key]), 'commit_identity')
    require(type(value['support_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', value['support_sha256']), 'support_identity')
    for key in ('run_id', 'run_attempt'):
        require(type(value[key]) is str and re.fullmatch('[1-9][0-9]*', value[key]), 'run_identity')
    require(value['artifact_name'] in {
        f"v046-source-{kind}-{value['run_id']}-{value['run_attempt']}"
        for kind in ('readiness', 'producer-controls')}, 'artifact_identity')
    require(type(value['workflow_ref']) is str and re.fullmatch(
        r'apodgaiko/unrest/\.github/workflows/v046-source-readiness\.yml@refs/heads/codex/source-guard-structured-20261018-[a-z0-9-]+',
        value['workflow_ref']), 'workflow_identity')


def execution_identity(support, kind):
    pins = {str(path.relative_to(support)): digest(path.read_bytes())
            for path in sorted(support.rglob('*'))
            if path.is_file() and path.suffix in {'.py', '.json', '.pem', '.c'}}
    value = {key: os.environ[name] for key, name in {
        'repository': 'GITHUB_REPOSITORY', 'head_sha': 'GITHUB_SHA',
        'run_id': 'GITHUB_RUN_ID', 'run_attempt': 'GITHUB_RUN_ATTEMPT',
        'workflow_ref': 'GITHUB_WORKFLOW_REF', 'workflow_sha': 'GITHUB_WORKFLOW_SHA'}.items()}
    value['artifact_name'] = f"v046-source-{kind}-{value['run_id']}-{value['run_attempt']}"
    value['support_sha256'] = digest(canonical(pins))
    identity_check(value)
    return value


def capture(argv, raw, identity, scope, **kwargs):
    """Run the owned process once; its captured stdout is never printed or reread."""
    with (raw / 'coordinator.log').open('ab') as errors:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=errors, check=False, **kwargs)
    require(len(result.stdout) <= LIMIT, 'transport_bound')
    (raw / 'current-process.stdout').write_bytes(result.stdout)
    records = export(result.stdout, raw, identity, scope)
    return result, records


def export(current_stdout, raw, identity, scope):
    identity_check(identity)
    require(scope in SCOPES, 'scope')
    lines = [line[len(b'PRIVATE-EVIDENCE:'):] for line in current_stdout.splitlines()
             if line.startswith(b'PRIVATE-EVIDENCE:')]
    require(len(lines) == 1, 'direct_transport_count')
    transport = loads(lines[0])
    allowed = CONTROLS if scope == 'synthetic-controls' else SOURCE
    require(type(transport) is dict and set(transport) <= allowed | OPAQUE, 'unknown_record')
    required = CONTROLS if scope == 'synthetic-controls' else {'kernel-source.json'}
    require(required <= set(transport), 'missing_record')
    records = {}
    descriptors = {}
    for name, encoded in sorted(transport.items()):
        require(type(encoded) is str and len(encoded) <= LIMIT, 'record_bound')
        try:
            body = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise EvidenceRefused('record_encoding') from None
        require(len(body) <= LIMIT, 'record_bound')
        path = raw / (('structured-' if name in allowed else 'private-') + name)
        path.write_bytes(body)
        if name in allowed:
            records[name] = body
            descriptors[name] = {'member': path.name, 'sha256': digest(body), 'size': len(body)}
    envelope = {'schema': SCHEMA, 'scope': scope, 'identity': identity, 'records': descriptors,
                'source_checkpoint_ready': False, 'selected_carrier': None}
    (raw / MEMBER).write_bytes(canonical(envelope))
    return records


def consume(archive, expected, envelope_sha256):
    """Return private structured bytes. No generic extraction or log read exists."""
    identity_check(expected)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
        members = source.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)) and len(names) <= 40, 'archive_inventory')
        for member in members:
            require(member.isfile() and 0 <= member.size <= LIMIT
                    and PurePosixPath(member.name).name == member.name
                    and member.name not in ('.', '..'), 'archive_member')
        permitted = {MEMBER, 'coordinator.log', 'current-process.stdout', 'prepared.stdout',
                     'container-inspect.json', 'container-state.json', 'source-pins.json',
                     'negative-control-proof.json', 'provenance.json'} | {
                         'structured-' + name for name in SOURCE | CONTROLS} | {
                         'private-' + name for name in OPAQUE}
        require(set(names) <= permitted, 'unknown_archive_member')
        require(MEMBER in names, 'direct_record_missing')
        def read(name):
            stream = source.extractfile(name)
            require(stream is not None, 'record_missing')
            return stream.read(LIMIT + 1)
        body = read(MEMBER)
        require(digest(body) == envelope_sha256, 'envelope_digest')
        envelope = loads(body)
        require(type(envelope) is dict and set(envelope) == {
            'schema', 'scope', 'identity', 'records', 'source_checkpoint_ready', 'selected_carrier'},
            'envelope_fields')
        require(envelope['schema'] == SCHEMA and envelope['scope'] in SCOPES, 'schema_scope')
        require(envelope['identity'] == expected, 'execution_identity')
        require(envelope['source_checkpoint_ready'] is False and envelope['selected_carrier'] is None,
                'scope_escalation')
        allowed = CONTROLS if envelope['scope'] == 'synthetic-controls' else SOURCE
        descriptors = envelope['records']
        require(type(descriptors) is dict and set(descriptors) <= allowed, 'unknown_record')
        required = CONTROLS if envelope['scope'] == 'synthetic-controls' else {'kernel-source.json'}
        require(required <= set(descriptors), 'missing_record')
        result = {}
        for name, descriptor in descriptors.items():
            require(type(descriptor) is dict and set(descriptor) == {'member', 'sha256', 'size'},
                    'descriptor_fields')
            require(descriptor['member'] == 'structured-' + name
                    and type(descriptor['size']) is int, 'record_member')
            require(descriptor['member'] in names, 'record_missing')
            body = read(descriptor['member'])
            require(len(body) == descriptor['size'] and digest(body) == descriptor['sha256'],
                    'record_digest')
            result[name] = body
        return envelope['scope'], result
