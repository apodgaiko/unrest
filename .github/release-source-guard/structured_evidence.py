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

from source_failure_facts import build as failure_facts, validate as validate_failure_facts

SCHEMA = 'unrest.v046.direct-private-records.v1'
MEMBER = 'structured-envelope.json'
LIMIT = 64 * 1024 * 1024
SOURCE = {'runner-stage.json', 'kernel-source.json', 'collection.json', 'summary.json', 'source.xml',
          'package-output.json', 'package-proof.json', 'source-provenance.json'}
CONTROLS = {'control-suite.xml', 'observer.json', 'source-controls.json'} | {
    f'trace-control-{status}-{mode}.json' for status in (0, 29, 31) for mode in (False, True)
} | {'trace-control-vfork-False.json', 'trace-control-vfork-True.json', 'trace-control-waitid.json'}
OPAQUE = {'source-output.log', 'custodian.stderr', 'source-diagnostics.json'}
SCOPES = {'ci-mutations', 'synthetic-controls', 'inprocess', 'composed', 'backend', 'drain-controls',
          'producer-contract', 'producer-distribution', 'producer-controls', 'primary-executor', 'primary-controls'}
HEADER = 'transport-provenance.json'
HEADER_PREFIX = b'SOURCE-TRANSPORT:'
HEADER_LIMIT = 8192
HEADER_SCHEMA = 'unrest.v046.source-transport-provenance.v1'
KERNEL_FIELDS = frozenset('records poison diagnostic_trace trace_failure_status unregistered_processes native_diagnostics primary_plan primary_records primary_denials failure_code native_preinit_refusal missing_parent_waits source_preexec_identity runtime_binding_sha256 actual_script_sha256 all_commands_dispatched source_checkpoint_ready selected_carrier guard_poison receipt_ledger_poison source_events receipts diagnostic_schedule event_timings receipt_channel_diagnostics receipt_channel_diagnostic_summary native_source_records source_pipe_records source_observer_poison_sha256 root_parent_wait_raw stage frame_lines'.split())
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
        for kind in ('readiness', 'producer-controls', 'producer-contract', 'producer-distribution', 'ci-mutations', 'primary-install', 'primary-import', 'primary-help', 'primary-repository', 'primary-lint', 'primary-types', 'primary-controls', 'primary-source', 'primary-source-positive', 'primary-source-poison', 'primary-package-build', 'primary-package-archive', 'primary-package-installed', 'primary-package-checksum')}, 'artifact_identity')
    require(type(value['workflow_ref']) is str, 'workflow_identity')
    dependency_prefix = ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                         'refs/heads/codex/source-guard-structured-20261018-primary-dependency-')
    if value['workflow_ref'].startswith(dependency_prefix.removesuffix('-')):
        require(value['workflow_ref'] in {dependency_prefix + epoch
                                        for epoch in ('01', '02', '03', '04', '05', '06')},
                'workflow_identity')
    raw_prefix = ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                  'refs/heads/codex/source-guard-structured-20261018-raw-record-transport-')
    if value['workflow_ref'].startswith(raw_prefix.removesuffix('-')):
        require(value['workflow_ref'] in {raw_prefix + epoch
                                        for epoch in ('01', '02', '03', '04')},
                'workflow_identity')
    native_uv_prefix = ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                        'refs/heads/codex/source-guard-structured-20261018-native-uv-mode-')
    if value['workflow_ref'].startswith(native_uv_prefix.removesuffix('-')):
        require(value['workflow_ref'] in {native_uv_prefix + epoch
                                        for epoch in ('01', '02', '03', '04')},
                'workflow_identity')
    bootstrap_family = 'source-guard-structured-20261018-full-bootstrap'
    if bootstrap_family in value['workflow_ref']:
        prefix = ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                  'refs/heads/codex/source-guard-structured-20261018-full-bootstrap-')
        require(value['workflow_ref'] in {prefix + f'{epoch:02}' for epoch in range(1, 7)}
                and value['artifact_name'] in {
                    f"v046-source-{kind}-{value['run_id']}-{value['run_attempt']}"
                    for kind in ('readiness', 'primary-source')}, 'workflow_identity')
    readiness = re.fullmatch(
        r'apodgaiko/unrest/\.github/workflows/v046-source-readiness\.yml@refs/heads/codex/source-guard-structured-20261018-[a-z0-9-]+',
        value['workflow_ref'])
    primary = re.fullmatch(
        r'apodgaiko/unrest/\.github/workflows/ci\.yml@refs/(?:heads/(?:main|codex/release-v04[67]-[a-z0-9-]+)|pull/[1-9][0-9]*/merge)',
        value['workflow_ref'])
    primary_kinds = {'readiness', 'primary-install', 'primary-import', 'primary-help',
                     'primary-repository', 'primary-lint', 'primary-types', 'primary-controls',
                     'primary-source', 'primary-source-positive', 'primary-source-poison', 'primary-package-build', 'primary-package-archive', 'primary-package-installed', 'primary-package-checksum'}
    primary_artifact = value['artifact_name'] in {
        f"v046-source-{kind}-{value['run_id']}-{value['run_attempt']}" for kind in primary_kinds}
    package_prefix = ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                      'refs/heads/codex/source-guard-structured-20261018-package-entry-')
    if value['workflow_ref'].startswith(package_prefix.removesuffix('-')):
        require(value['workflow_ref'] in {package_prefix + epoch
                for epoch in ('01', '02', '03', '04')} | {package_prefix + 'cache-record-' + epoch
                for epoch in ('01', '02')} | {package_prefix + 'cache-lineage-' + epoch
                for epoch in ('01', '02', '03', '04', '05', '06')} | {package_prefix + 'control-input-' + epoch
                for epoch in ('01', '02', '03', '04', '05', '06')}, 'workflow_identity')
    package = re.fullmatch(
        r'apodgaiko/unrest/\.github/workflows/v046-source-readiness\.yml@refs/heads/codex/source-guard-structured-20261018-package-entry-(?:0[1-4]|cache-record-0[1-2]|cache-lineage-0[1-6]|control-input-0[1-6])',
        value['workflow_ref'])
    require(readiness is not None or (primary is not None or package is not None) and primary_artifact, 'workflow_identity')



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



def source_binding(body):
    require(type(body) is bytes and len(body) <= HEADER_LIMIT, 'binding_bound')
    value = loads(body)
    require(type(value) is dict and set(value) == {'identity', 'invocation_sha256'}, 'binding_fields')
    identity_check(value['identity'])
    require(type(value['invocation_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', value['invocation_sha256']), 'binding_invocation')
    return value


def numeric(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def source_header(records, kernel, identity, invocation, exit_code):
    """Only current producer-owned bytes supply sizes; no opaque record is parsed."""
    import xml.etree.ElementTree as ET
    identity_check(identity)
    require(set(records) <= SOURCE | OPAQUE and 'kernel-source.json' in records, 'header_records')
    require(type(kernel) is dict and set(kernel) <= KERNEL_FIELDS, 'header_kernel_fields')
    descriptors = {name: {'decoded_bytes': len(body), 'encoded_bytes': 4 * ((len(body) + 2) // 3),
                          'sha256': digest(body)} for name, body in sorted(records.items())}
    fields = {name: {'bytes': len(json.dumps(value, sort_keys=True).encode()),
                     'count': len(value) if type(value) in (list, dict) else None}
              for name, value in sorted(kernel.items())}
    counts = dict.fromkeys(('collection', 'junit_cases', 'junit_failures', 'junit_errors', 'junit_skips', 'receipt_ok', 'receipt_not_ok', 'channel_complete', 'channel_refused', 'channel_closed'))
    if 'collection.json' in records:
        collection = loads(records['collection.json'])
        if type(collection) is list:
            counts['collection'] = len(collection)
    cases = []
    if 'source.xml' in records and b'<!' not in records['source.xml']:
        try:
            cases = list(ET.fromstring(records['source.xml']).iter('testcase'))
        except ET.ParseError:
            cases = None
        if cases is not None:
            counts.update(junit_cases=len(cases), junit_failures=sum(len(c.findall('failure')) for c in cases),
                          junit_errors=sum(len(c.findall('error')) for c in cases),
                          junit_skips=sum(len(c.findall('skipped')) for c in cases))
    if 'receipts' in kernel:
        counts['receipt_ok'] = sum(row.get('ok') is True for row in kernel['receipts'])
        counts['receipt_not_ok'] = len(kernel['receipts']) - counts['receipt_ok']
    if 'receipt_channel_diagnostics' in kernel:
        for outcome in ('complete', 'refused', 'closed'):
            counts['channel_' + outcome] = sum(row.get('outcome') == outcome for row in kernel['receipt_channel_diagnostics'])
    status = {'exit_code': exit_code, 'root_parent_wait_raw': kernel.get('root_parent_wait_raw'),
              'guard_poison': kernel.get('guard_poison'), 'poison_count': len(kernel.get('poison', [])),
              'receipt_poison_count': len(kernel.get('receipt_ledger_poison', [])),
              'failure_code': kernel.get('failure_code'), 'trace_failure_status': kernel.get('trace_failure_status')}
    header = {'schema': HEADER_SCHEMA, 'identity': identity, 'invocation_sha256': invocation,
              'scope': 'primary-executor', 'records': descriptors, 'kernel_fields': fields,
              'source_status': status, 'original_counts': counts, 'failure_facts': failure_facts(kernel, cases or ()),
              'source_checkpoint_ready': False, 'selected_carrier': None}
    validate_header(header, identity, invocation)
    body = canonical(header)
    require(len(HEADER_PREFIX) + len(body) + 1 <= HEADER_LIMIT, 'header_bound')
    return HEADER_PREFIX + body + b'\n'


def validate_header(value, identity, invocation):
    require(type(value) is dict and set(value) == {'schema', 'identity', 'invocation_sha256',
            'scope', 'records', 'kernel_fields', 'source_status', 'original_counts', 'failure_facts',
            'source_checkpoint_ready', 'selected_carrier'}, 'header_fields')
    identity_check(value['identity'])
    require(value['schema'] == HEADER_SCHEMA and value['identity'] == identity
            and value['scope'] == 'primary-executor' and value['invocation_sha256'] == invocation
            and type(invocation) is str and re.fullmatch('[0-9a-f]{64}', invocation), 'header_identity')
    require(value['source_checkpoint_ready'] is False and value['selected_carrier'] is None, 'header_authority')
    require(validate_failure_facts(value['failure_facts']), 'header_failure_facts')
    descriptors = value['records']
    require(type(descriptors) is dict and set(descriptors) <= SOURCE | OPAQUE
            and 'kernel-source.json' in descriptors, 'header_records')
    for item in descriptors.values():
        require(type(item) is dict and set(item) == {'decoded_bytes', 'encoded_bytes', 'sha256'}
                and numeric(item['decoded_bytes']) and numeric(item['encoded_bytes'])
                and item['encoded_bytes'] == 4 * ((item['decoded_bytes'] + 2) // 3)
                and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'header_descriptor')
    require(type(value['kernel_fields']) is dict and set(value['kernel_fields']) <= KERNEL_FIELDS,
            'header_kernel_fields')
    for item in value['kernel_fields'].values():
        require(type(item) is dict and set(item) == {'bytes', 'count'} and numeric(item['bytes'])
                and (item['count'] is None or numeric(item['count'])), 'header_cardinality')
    counts = value['original_counts']
    require(type(counts) is dict and set(counts) == {'collection', 'junit_cases', 'junit_failures', 'junit_errors', 'junit_skips', 'receipt_ok', 'receipt_not_ok', 'channel_complete', 'channel_refused', 'channel_closed'}
            and all(v is None or numeric(v) for v in counts.values()), 'header_counts')
    status = value['source_status']
    require(type(status) is dict and set(status) == {'exit_code', 'root_parent_wait_raw', 'guard_poison',
            'poison_count', 'receipt_poison_count', 'failure_code', 'trace_failure_status'}, 'header_status')
    require(type(status['exit_code']) is int and status['exit_code'] in {0, 2, 125}
            and (status['root_parent_wait_raw'] is None or numeric(status['root_parent_wait_raw']))
            and (status['guard_poison'] is None or type(status['guard_poison']) is bool)
            and numeric(status['poison_count']) and numeric(status['receipt_poison_count'])
            and (status['failure_code'] in {None, 'trace_failure', 'source_guard_refused', 'bootstrap_failure'}
                 or status['failure_code'] == 'package_output_refused' and status['exit_code'] in {2, 125}
                 and identity['artifact_name'] in {
                     f"v046-source-primary-package-{kind}-{identity['run_id']}-{identity['run_attempt']}"
                     for kind in ('build', 'archive', 'installed', 'checksum')}), 'header_status')

    trace = status['trace_failure_status']
    if trace is not None:
        require(type(trace) is dict and set(trace) == {'exception_class', 'location_sha256'}
                and trace['exception_class'] in {'TimeoutError', 'RuntimeError', 'OSError', 'ProcessLookupError',
                    'ValueError', 'KeyError', 'TypeError', 'EvidenceRefused', 'other'}
                and (trace['location_sha256'] is None or type(trace['location_sha256']) is str
                     and re.fullmatch('[0-9a-f]{64}', trace['location_sha256'])), 'header_trace_status')


def current_header(current_stdout, identity, invocation):
    """Inspect one bounded prefix from this invocation only, before the transport cap."""
    first_end = current_stdout.find(b'\n', 0, HEADER_LIMIT)
    require(first_end >= 0 and current_stdout.startswith(HEADER_PREFIX), 'header_prefix')
    first = current_stdout[:first_end + 1]
    require(current_stdout.count(HEADER_PREFIX) == 1, 'header_count')
    value = loads(first[len(HEADER_PREFIX):-1])
    validate_header(value, identity, invocation)
    # A source stream has exactly these two complete frames and nothing else.
    start = first_end + 1
    require(current_stdout.startswith(b'PRIVATE-EVIDENCE:', start) and current_stdout.endswith(b'\n')
            and current_stdout.count(b'\n', start) == 1, 'header_stream')
    # No second whole-payload allocation is needed for a stream already over cap.
    return value, current_stdout[start:] if len(current_stdout) <= LIMIT else b''


def emit_source(records, kernel, identity, invocation, exit_code):
    import sys
    sys.stdout.buffer.write(source_header(records, kernel, identity, invocation, exit_code))
    sys.stdout.buffer.flush()
    encoded = {name: base64.b64encode(body).decode() for name, body in sorted(records.items())}
    sys.stdout.buffer.write(b'PRIVATE-EVIDENCE:' + json.dumps(encoded, sort_keys=True).encode() + b'\n')
    sys.stdout.buffer.flush()


def capture(argv, raw, identity, scope, *, source_invocation=None, **kwargs):
    """Run the owned process once; its captured stdout is never printed or reread."""
    with (raw / 'coordinator.log').open('ab') as errors:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=errors, check=False, **kwargs)
    header = None
    current = result.stdout
    if source_invocation is not None:
        require(scope == 'primary-executor', 'header_scope')
        header, current = current_header(current, identity, source_invocation)
        (raw / HEADER).write_bytes(canonical(header))
    require(len(result.stdout) <= LIMIT, 'transport_bound')
    (raw / 'current-process.stdout').write_bytes(result.stdout)
    records = export(current, raw, identity, scope, descriptors=header['records'] if header else None)
    return result, records


def export(current_stdout, raw, identity, scope, *, descriptors=None):
    identity_check(identity)
    require(scope in SCOPES, 'scope')
    lines = [line[len(b'PRIVATE-EVIDENCE:'):] for line in current_stdout.splitlines()
             if line.startswith(b'PRIVATE-EVIDENCE:')]
    require(len(lines) == 1, 'direct_transport_count')
    transport = loads(lines[0])
    allowed = CONTROLS if scope == 'synthetic-controls' else SOURCE
    require(type(transport) is dict and set(transport) <= allowed | OPAQUE, 'unknown_record')
    required = CONTROLS - {'control-suite.xml'} if scope == 'synthetic-controls' else {'kernel-source.json'}
    require(required <= set(transport), 'missing_record')
    if descriptors is not None:
        require(set(descriptors) == set(transport), 'header_record_binding')
    records = {}
    envelope_descriptors = {}
    for name, encoded in sorted(transport.items()):
        require(type(encoded) is str and len(encoded) <= LIMIT, 'record_bound')
        try:
            body = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise EvidenceRefused('record_encoding') from None
        require(len(body) <= LIMIT, 'record_bound')
        if descriptors is not None:
            item = descriptors[name]
            require(len(body) == item['decoded_bytes'] and len(encoded) == item['encoded_bytes']
                    and digest(body) == item['sha256'], 'header_record_binding')
        path = raw / (('structured-' if name in allowed else 'private-') + name)
        path.write_bytes(body)
        if name in allowed:
            records[name] = body
            envelope_descriptors[name] = {'member': path.name, 'sha256': digest(body), 'size': len(body)}
    envelope = {'schema': SCHEMA, 'scope': scope, 'identity': identity, 'records': envelope_descriptors,
                'source_checkpoint_ready': False, 'selected_carrier': None}
    (raw / MEMBER).write_bytes(canonical(envelope))
    return records


def consume(archive, expected, envelope_sha256):
    """Return private structured bytes. No generic extraction or log read exists."""
    identity_check(expected)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz', ignore_zeros=True) as source:
        members = source.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)) and len(names) <= 40, 'archive_inventory')
        require(sum(member.size for member in members) <= 2 * LIMIT, 'archive_bound')
        for member in members:
            require(member.isfile() and not member.issparse() and 0 <= member.size <= LIMIT
                    and PurePosixPath(member.name).name == member.name
                    and member.name not in ('.', '..'), 'archive_member')
        permitted = {MEMBER, HEADER, 'coordinator.log', 'current-process.stdout', 'prepared.stdout',
                     'container-inspect.json', 'container-state.json', 'source-pins.json',
                     'negative-control-proof.json', 'provenance.json', 'prerequisite-status.json'} | {
                         'structured-' + name for name in SOURCE | CONTROLS} | {
                         'private-' + name for name in OPAQUE}
        if any(name.startswith('packed-') for name in names):
            # V3 keeps the physical archive/member caps above. Its separate
            # logical budgets are validated before any bounded inflation.
            require(MEMBER in names, 'direct_record_missing')
            from source_raw_transport import consume_packed
            def read_packed(name):
                require(name in names, 'record_missing')
                stream = source.extractfile(name)
                require(stream is not None, 'record_missing')
                return stream.read(LIMIT + 1)
            return consume_packed(read_packed(MEMBER), envelope_sha256, expected, names, read_packed)
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
        required = CONTROLS - {'control-suite.xml'} if envelope['scope'] == 'synthetic-controls' else {'kernel-source.json'}
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
