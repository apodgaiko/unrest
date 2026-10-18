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


def test_new_control_binding_is_closed_and_bounded():
    valid = {'identity': identity(), 'invocation_sha256': INVOCATION}
    body = evidence.canonical(valid)
    assert evidence.source_binding(body) == valid
    for malformed in (body + b' ' * evidence.HEADER_LIMIT,
                      evidence.canonical({**valid, 'extra': CANARY}),
                      evidence.canonical({**valid, 'invocation_sha256': CANARY}),
                      body.replace(b'"identity":', b'"identity":{},"identity":', 1)):
        with pytest.raises(evidence.EvidenceRefused):
            evidence.source_binding(malformed)


def test_literal_binding_reader_refuses_symlink_hardlink_and_oversize(tmp_path):
    import ast
    import os
    import stat
    import types
    tree = ast.parse(Path(__file__).with_name('primary_compartment.py').read_bytes())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'read_transport_binding')
    target = tmp_path / 'binding'
    def actual_open(path, flags):
        assert path == '/inputs/transport-identity.json'
        return os.open(target, flags)
    def actual_lstat(path):
        assert path == '/inputs/transport-identity.json'
        return os.lstat(target)
    scoped = types.SimpleNamespace(open=actual_open, lstat=actual_lstat, fstat=os.fstat, read=os.read,
        close=os.close, O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC)
    namespace = {'os': scoped, 'stat': stat, 'source_binding': evidence.source_binding,
                 'HEADER_LIMIT': evidence.HEADER_LIMIT}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'actual_current_literal_binding', 'exec'), namespace)
    body = evidence.canonical({'identity': identity(), 'invocation_sha256': INVOCATION})
    target.write_bytes(body)
    assert namespace['read_transport_binding']()['invocation_sha256'] == INVOCATION
    link = tmp_path / 'hardlink'
    os.link(target, link)
    with pytest.raises(RuntimeError, match='transport_binding_carrier'):
        namespace['read_transport_binding']()
    link.unlink()
    target.write_bytes(b' ' * (evidence.HEADER_LIMIT + 1))
    with pytest.raises(RuntimeError, match='transport_binding_carrier'):
        namespace['read_transport_binding']()
    target.unlink()
    target.symlink_to(tmp_path / 'missing')
    with pytest.raises(OSError):
        namespace['read_transport_binding']()


def test_oversize_header_validation_does_not_copy_its_payload(monkeypatch):
    # Small synthetic boundary; exact real64MiB boundary is separately exercised.
    body = stream()
    monkeypatch.setattr(evidence, 'LIMIT', len(body) - 1)
    header, tail = evidence.current_header(body, identity(), INVOCATION)
    assert tail == b'' and header['invocation_sha256'] == INVOCATION


def test_transmitted_invocation_identity_is_a_digest_of_fresh_nonce():
    import ast
    import hashlib
    import types
    tree = ast.parse(Path(__file__).with_name('ci_shell.py').read_bytes())
    assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'source_invocation' for t in n.targets))
    namespace = {'hashlib': hashlib, 'secrets': types.SimpleNamespace(token_bytes=lambda count: b'x' * count)}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), 'actual_invocation_derivation', 'exec'), namespace)
    assert namespace['source_invocation'] == hashlib.sha256(b'x' * 32).hexdigest()
    assert namespace['source_invocation'] != (b'x' * 32).hex()


@pytest.mark.parametrize('name', ['result', 'record'])
def test_actual_kernel_serialization_preserves_every_value(name):
    import ast
    tree = ast.parse(Path(__file__).with_name('primary_compartment.py').read_bytes())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'dumps'
             and node.args and isinstance(node.args[0], ast.Name)
             and node.args[0].id == name]
    assert len(calls) == 1
    # Evaluate the actual producer expression; the original JSON data is the
    # independent oracle. Only insignificant inter-token spaces may disappear.
    value = {'records': [{'kind': 'original_parent_wait4', 'raw': 0,
                          'parent_tgid': 42, 'child': 43, 'text': 'a b\n雪'}],
             'poison': [], 'missing_parent_waits': [], 'guard_poison': False,
             'failure_code': None, 'nested': [True, -3, 1.25, {}, []]}
    compact = eval(compile(ast.Expression(calls[0]), 'actual_kernel_json', 'eval'),
                   {'json': json, name: value}).encode()
    original = json.dumps(value, sort_keys=True).encode()
    assert compact == evidence.canonical(value)
    assert json.loads(compact) == json.loads(original) == value
    assert len(compact) < len(original)


def test_compact_kernel_uses_original_transport_without_data_loss(tmp_path, capsys):
    kernel, records = vector()
    # Receipt-shaped records exercise separator overhead without changing the
    # transport/parser or making an assertion about unobserved hosted bytes.
    kernel['receipts'] = [{'ok': True, 'operation': 'ready', 'sequence': n,
                           'identity': {'pid': 42, 'ppid': 41}, 'values': [0, None, False]}
                          for n in range(10000)]
    records['kernel-source.json'] = evidence.canonical(kernel)
    source = str(Path(evidence.__file__).parent)
    code = ('import sys,json;sys.path.insert(0,' + repr(source)
            + ');from structured_evidence import emit_source;'
            + 'k=json.loads(sys.stdin.buffer.readline());'
            + 'r={"kernel-source.json":json.dumps(k,sort_keys=True,separators=(",",":")).encode()};'
            + 'emit_source(r,k,' + repr(identity()) + ',' + repr(INVOCATION) + ',2)')
    result, actual = evidence.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                                     'primary-executor', source_invocation=INVOCATION,
                                     input=records['kernel-source.json'] + b'\n')
    assert result.returncode == 0
    assert actual['kernel-source.json'] == records['kernel-source.json']
    assert json.loads(actual['kernel-source.json']) == kernel
    header = evidence.loads((tmp_path / evidence.HEADER).read_bytes())
    assert header['original_counts']['receipt_ok'] == 10000
    assert header['records']['kernel-source.json']['sha256'] == evidence.digest(actual['kernel-source.json'])
    assert capsys.readouterr() == ('', '')
