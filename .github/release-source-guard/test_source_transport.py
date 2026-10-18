"""Current producer/capture checks; private canaries are never operator output."""
import base64
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import structured_evidence as evidence
from test_structured_evidence import identity

INVOCATION = 'c' * 64
CANARY = 'private_canary_only_inside_the_owned_synthetic_process'


def vector():
    kernel = {'records': [{'kind': 'original_parent_wait4', 'raw': 0, 'private': CANARY}],
              'root_parent_wait_raw': 0, 'poison': [], 'guard_poison': False,
              'receipt_ledger_poison': [], 'source_events': [], 'failure_code': None}
    records = {'kernel-source.json': json.dumps(kernel, sort_keys=True).encode(),
               'source-output.log': CANARY.encode(),
               'collection.json': json.dumps([CANARY] * 4).encode(),
               'source.xml': b'<testsuites><testsuite><testcase/><testcase><failure>private</failure></testcase></testsuite></testsuites>'}
    return kernel, records


def stream():
    kernel, records = vector()
    return (evidence.source_header(records, kernel, identity(), INVOCATION, 2)
            + b'PRIVATE-EVIDENCE:' + json.dumps({k: base64.b64encode(v).decode()
                                               for k, v in sorted(records.items())}, sort_keys=True).encode() + b'\n')


def capture(body, tmp_path, **kw):
    return evidence.capture([sys.executable, '-I', '-c', 'import os; os.write(1,' + repr(body) + ')'],
                            tmp_path, identity(), 'primary-executor', source_invocation=INVOCATION, **kw)


def test_actual_producer_and_collector_match_original_serialization(tmp_path, capsys):
    kernel, records = vector()
    source = str(Path(evidence.__file__).parent)
    code = ('import sys;sys.path.insert(0,' + repr(source) + ');from structured_evidence import emit_source;'
            'emit_source(' + repr(records) + ',' + repr(kernel) + ',' + repr(identity()) + ',' + repr(INVOCATION) + ',2)')
    result, actual = evidence.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                                     'primary-executor', source_invocation=INVOCATION)
    assert result.returncode == 0
    assert actual == {k: v for k, v in records.items() if k in evidence.SOURCE}
    header = evidence.loads((tmp_path / evidence.HEADER).read_bytes())
    assert CANARY not in json.dumps(header)
    assert header['original_counts'] == dict(collection=4, junit_cases=2, junit_failures=1, junit_errors=0, junit_skips=0, receipt_ok=None, receipt_not_ok=None, channel_complete=None, channel_refused=None, channel_closed=None)
    assert header['kernel_fields']['records']['count'] == 1
    assert header['source_status']['exit_code'] == 2
    # The original logical bytes and old aggregate frame are the independent oracle.
    original = b'PRIVATE-EVIDENCE:' + json.dumps({k: base64.b64encode(v).decode() for k, v in records.items()}, sort_keys=True).encode() + b'\n'
    assert result.stdout.split(b'\n', 1)[1] == original
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('mutate', [
    lambda b: b + b'fragment', lambda b: b'prefix' + b,
    lambda b: b + b'\n', lambda b: b[:-1],
    lambda b: b.split(b'\n', 1)[0] + b'\n' + b,
    lambda b: b.replace(b'SOURCE-TRANSPORT:', b'SOURCE-TRANSPORT:x', 1),
    lambda b: b.replace(b'"run_attempt":"1"', b'"run_attempt":"2"', 1),
    lambda b: b.replace(b'"schema":', b'"unknown":0,"schema":', 1),
    lambda b: b.replace(b'"scope":', b'"scope":"primary-executor","scope":', 1),
    lambda b: b.replace(INVOCATION.encode(), b'd' * 64, 1),
])
def test_current_stream_fragments_duplicates_stale_and_unknown_refuse(tmp_path, mutate, capsys):
    with pytest.raises(evidence.EvidenceRefused):
        capture(mutate(stream()), tmp_path)
    assert not (tmp_path / evidence.MEMBER).exists()
    assert not (tmp_path / evidence.HEADER).exists()
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('mutate', [
    lambda h: h['records']['kernel-source.json'].update(decoded_bytes=True),
    lambda h: h['records']['kernel-source.json'].update(encoded_bytes=1),
    lambda h: h['records'].update({'opaque-new.log': next(iter(h['records'].values()))}),
    lambda h: h['kernel_fields'].update({CANARY: {'bytes': 1, 'count': 1}}),
    lambda h: h['source_status'].update(failure_code=CANARY),
    lambda h: h['source_status'].update(exit_code=True),
    lambda h: h['original_counts'].update(collection=-1),
    lambda h: h.update(source_checkpoint_ready=True),
])
def test_closed_header_fields_and_counts_refuse(mutate):
    header, _ = evidence.current_header(stream(), identity(), INVOCATION)
    header = copy.deepcopy(header)
    mutate(header)
    with pytest.raises(evidence.EvidenceRefused):
        evidence.validate_header(header, identity(), INVOCATION)


def test_exact_physical_limit_refuses_after_preserving_only_named_header(tmp_path, capsys):
    # Each opaque source record remains below its existing 16MiB output bound;
    # the logical kernel record remains below 64MiB, but the aggregate exceeds it.
    source = str(Path(evidence.__file__).parent)
    code = ('import sys,json;sys.path.insert(0,' + repr(source) + ');from structured_evidence import emit_source;'
            'k={"records":["' + CANARY + '"*(1024*1024)],"poison":[],"failure_code":None};'
            'r={"kernel-source.json":json.dumps(k,sort_keys=True).encode()};'
            'emit_source(r,k,' + repr(identity()) + ',' + repr(INVOCATION) + ',2)')
    with pytest.raises(evidence.EvidenceRefused, match='^transport_bound$'):
        evidence.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                         'primary-executor', source_invocation=INVOCATION)
    header = evidence.loads((tmp_path / evidence.HEADER).read_bytes())
    assert header['records']['kernel-source.json']['decoded_bytes'] < evidence.LIMIT
    assert header['records']['kernel-source.json']['encoded_bytes'] > evidence.LIMIT
    assert len(evidence.canonical(header)) < evidence.HEADER_LIMIT
    assert not (tmp_path / evidence.MEMBER).exists()
    assert not (tmp_path / 'current-process.stdout').exists()
    assert set(p.name for p in tmp_path.iterdir()) == {'coordinator.log', evidence.HEADER}
    assert CANARY not in json.dumps(header)
    assert capsys.readouterr() == ('', '')


def test_header_itself_cannot_become_a_certificate(tmp_path):
    kernel, records = vector()
    (tmp_path / evidence.HEADER).write_bytes(evidence.source_header(records, kernel, identity(), INVOCATION, 2))
    from test_structured_evidence import archive
    with pytest.raises(evidence.EvidenceRefused, match='direct_record_missing'):
        evidence.consume(archive(tmp_path), identity(), 'a' * 64)


def test_descriptor_hash_mismatch_refuses_before_envelope(tmp_path):
    body = stream()
    header, tail = evidence.current_header(body, identity(), INVOCATION)
    header['records']['kernel-source.json']['sha256'] = '0' * 64
    body = evidence.HEADER_PREFIX + evidence.canonical(header) + b'\n' + tail
    with pytest.raises(evidence.EvidenceRefused, match='header_record_binding'):
        capture(body, tmp_path)
    assert not (tmp_path / evidence.MEMBER).exists()


def test_header_bound_and_truncated_frame_refuse(tmp_path):
    for body in (evidence.HEADER_PREFIX + b' ' * evidence.HEADER_LIMIT + b'\nPRIVATE-EVIDENCE:{}\n',
                 stream().replace(b'PRIVATE-EVIDENCE:', b'PRIVATE-EVIDENCE:fragment', 1)):
        with pytest.raises(evidence.EvidenceRefused):
            capture(body, tmp_path)
        assert not (tmp_path / evidence.MEMBER).exists()


def test_trace_failure_status_is_closed_and_excludes_message_and_source(capsys):
    import ast
    import hashlib
    tree = ast.parse(Path(__file__).with_name('primary_compartment.py').read_bytes())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'trace_failure_status')
    namespace = {'hashlib': hashlib, 'json': json}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'actual_current_trace_projection', 'exec'), namespace)
    try:
        raise TimeoutError(CANARY)
    except TimeoutError as error:
        status = namespace['trace_failure_status'](error)
    assert set(status) == {'exception_class', 'location_sha256'}
    assert status['exception_class'] == 'TimeoutError' and len(status['location_sha256']) == 64
    assert CANARY not in json.dumps(status)
    class PrivateExceptionName(Exception):
        pass
    assert namespace['trace_failure_status'](PrivateExceptionName(CANARY)) == {
        'exception_class': 'other', 'location_sha256': None}
    header, _ = evidence.current_header(stream(), identity(), INVOCATION)
    header['source_status']['trace_failure_status'] = status
    evidence.validate_header(header, identity(), INVOCATION)
    header['source_status']['trace_failure_status']['exception_class'] = CANARY
    with pytest.raises(evidence.EvidenceRefused, match='header_trace_status'):
        evidence.validate_header(header, identity(), INVOCATION)
    assert capsys.readouterr() == ('', '')
