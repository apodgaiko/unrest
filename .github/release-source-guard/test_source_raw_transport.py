"""Lossless PRIMARY framing through actual fresh-process capture and named consumer."""
import copy
import io
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import source_raw_transport as raw
import structured_evidence as evidence
from test_source_transport import INVOCATION, CANARY, vector
from test_structured_evidence import archive, identity


def records():
    kernel, bodies = vector()
    for name in sorted(evidence.SOURCE | evidence.OPAQUE):
        bodies.setdefault(name, name.encode() + b'\x00\xff\n' + CANARY.encode())
    # Opaque/raw data can contain both transport markers without becoming a frame.
    bodies['source-output.log'] += evidence.HEADER_PREFIX + raw.PREFIX + b'PRIVATE-EVIDENCE:\n'
    return kernel, bodies


def header(bodies, kernel=None):
    return evidence.source_header(bodies, kernel or {}, identity(), INVOCATION, 2)


def descriptors(bodies):
    return evidence.loads(header(bodies)[len(evidence.HEADER_PREFIX):-1])['records']


def repack(table, payload):
    encoded = evidence.canonical(table)
    return raw.PREFIX + len(encoded).to_bytes(8, 'big') + encoded + payload


def test_actual_primary_emitter_capture_exports_every_byte_and_equivalent_consumer(tmp_path, capsys):
    kernel, bodies = records()
    code = ('import sys;sys.path.insert(0,' + repr(str(Path(raw.__file__).parent))
            + ');from source_raw_transport import emit_source;emit_source('
            + repr(bodies) + ',' + repr(kernel) + ',' + repr(identity()) + ','
            + repr(INVOCATION) + ',2)')
    result, actual = raw.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                                 'primary-executor', source_invocation=INVOCATION)
    assert result.returncode == 0
    assert actual == {k: v for k, v in bodies.items() if k in evidence.SOURCE}
    assert (tmp_path / 'current-process.stdout').read_bytes() == result.stdout
    for name, body in bodies.items():
        assert (tmp_path / (('structured-' if name in evidence.SOURCE else 'private-') + name)).read_bytes() == body
    envelope = (tmp_path / evidence.MEMBER).read_bytes()
    scope, consumed = evidence.consume(archive(tmp_path), identity(), evidence.digest(envelope))
    assert scope == 'primary-executor' and consumed == actual
    legacy = tmp_path / 'legacy'
    legacy.mkdir()
    import base64
    legacy_records = evidence.export(b'PRIVATE-EVIDENCE:' + evidence.canonical(
        {k: base64.b64encode(v).decode() for k, v in bodies.items()}) + b'\n',
        legacy, identity(), 'primary-executor', descriptors=descriptors(bodies))
    assert legacy_records == actual
    assert (legacy / evidence.MEMBER).read_bytes() == envelope
    assert evidence.consume(archive(legacy), identity(), evidence.digest(envelope)) == (scope, consumed)
    assert CANARY not in (tmp_path / evidence.HEADER).read_text()
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('mutation', [
    lambda t: t.update(schema='foreign'),
    lambda t: t.update(extra=0),
    lambda t: t['identity'].update(run_attempt='2'),
    lambda t: t.update(invocation_sha256='d' * 64),
    lambda t: t.update(records=[]),
    lambda t: t.update(records=t['records'] * 12),
    lambda t: t['records'].reverse(),
    lambda t: t['records'].append(t['records'][0]),
    lambda t: t['records'][0].update(name='unknown.json'),
    lambda t: t['records'][0].update(name='../kernel-source.json'),
    lambda t: t['records'][0].update(size=-1),
    lambda t: t['records'][0].update(size=True),
    lambda t: t['records'][0].update(size=1.0),
    lambda t: t['records'][0].update(size='1'),
    lambda t: t['records'][0].update(size=2**64),
    lambda t: t['records'][0].update(sha256='0' * 64),
    lambda t: t['records'][0].update(sha256=CANARY),
    lambda t: t['records'][0].update(offset=0),
])
def test_closed_table_identity_and_lengths_refuse(mutation):
    _, bodies = records()
    table = copy.deepcopy(raw.table_for(bodies, identity(), INVOCATION))
    mutation(table)
    frame = repack(table, b''.join(v for _, v in sorted(bodies.items())))
    with pytest.raises(evidence.EvidenceRefused):
        raw.decode(frame, identity(), INVOCATION, descriptors(bodies))


@pytest.mark.parametrize('mutation', [
    lambda f: b'prefix' + f, lambda f: f[:-1], lambda f: f + b'\n',
    lambda f: f + f, lambda f: f + b'PRIVATE-EVIDENCE:{}\n',
    lambda f: f[:len(raw.PREFIX)] + (raw.TABLE_LIMIT + 1).to_bytes(8, 'big') + f[len(raw.PREFIX) + 8:],
    lambda f: f[:len(raw.PREFIX)] + (2**64 - 1).to_bytes(8, 'big') + f[len(raw.PREFIX) + 8:],
    lambda f: f.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
    lambda f: f[:-1] + bytes([f[-1] ^ 1]),
])
def test_truncation_extra_frames_hashes_and_table_overflow_refuse(mutation):
    _, bodies = records()
    with pytest.raises(evidence.EvidenceRefused):
        raw.decode(mutation(raw.encode(bodies, identity(), INVOCATION)), identity(),
                   INVOCATION, descriptors(bodies))


def test_noncanonical_table_and_missing_required_member_refuse():
    _, bodies = records()
    frame = raw.encode(bodies, identity(), INVOCATION)
    start = len(raw.PREFIX) + 8
    size = int.from_bytes(frame[len(raw.PREFIX):start], 'big')
    table = frame[start:start + size]
    malformed = raw.PREFIX + (size + 1).to_bytes(8, 'big') + b' ' + table + frame[start + size:]
    with pytest.raises(evidence.EvidenceRefused, match='raw_table_fields'):
        raw.decode(malformed, identity(), INVOCATION, descriptors(bodies))
    with pytest.raises(evidence.EvidenceRefused, match='raw_records'):
        raw.encode({'source-output.log': b'opaque'}, identity(), INVOCATION)


def test_exact_frame_and_whole_caps_and_member_bound(monkeypatch):
    _, bodies = records()
    frame = raw.encode(bodies, identity(), INVOCATION)
    desc = descriptors(bodies)
    monkeypatch.setattr(evidence, 'LIMIT', len(frame))
    assert raw.encode(bodies, identity(), INVOCATION) == frame
    assert raw.decode(frame, identity(), INVOCATION, desc) == bodies
    monkeypatch.setattr(evidence, 'LIMIT', len(frame) - 1)
    with pytest.raises(evidence.EvidenceRefused, match='transport_bound'):
        raw.decode(frame, identity(), INVOCATION, desc)
    with pytest.raises(evidence.EvidenceRefused, match='transport_bound'):
        raw.encode(bodies, identity(), INVOCATION)
    monkeypatch.setattr(evidence, 'LIMIT', 3)
    with pytest.raises(evidence.EvidenceRefused, match='record_bound'):
        raw.encode({'kernel-source.json': b'four'}, identity(), INVOCATION)


def test_capture_whole_bound_before_decode_or_payload_persistence(tmp_path, monkeypatch):
    kernel, bodies = records()
    stream = header(bodies, kernel) + raw.encode(bodies, identity(), INVOCATION)
    monkeypatch.setattr(evidence, 'LIMIT', len(stream))
    code = 'import os;os.write(1,' + repr(stream) + ')'
    result, actual = raw.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                                 'primary-executor', source_invocation=INVOCATION)
    assert result.stdout == stream and actual['kernel-source.json'] == bodies['kernel-source.json']
    other = tmp_path / 'over'
    other.mkdir()
    monkeypatch.setattr(evidence, 'LIMIT', len(stream) - 1)
    monkeypatch.setattr(raw, 'decode', lambda *a: pytest.fail('overcap payload was parsed'))
    with pytest.raises(evidence.EvidenceRefused, match='transport_bound'):
        raw.capture([sys.executable, '-I', '-c', code], other, identity(),
                    'primary-executor', source_invocation=INVOCATION)
    assert {p.name for p in other.iterdir()} == {'coordinator.log', evidence.HEADER}


@pytest.mark.parametrize('mode', ['legacy', 'bad_hash', 'foreign', 'double', 'truncated'])
def test_current_process_malformed_never_falls_back_or_persists_payload(tmp_path, mode, capsys):
    kernel, bodies = records()
    frame = raw.encode(bodies, identity(), INVOCATION)
    if mode == 'legacy':
        frame = b'PRIVATE-EVIDENCE:{}\n'
    elif mode == 'bad_hash':
        frame = frame[:-1] + bytes([frame[-1] ^ 1])
    elif mode == 'foreign':
        frame = frame.replace(INVOCATION.encode(), b'd' * 64, 1)
    elif mode == 'double':
        frame += frame
    else:
        frame = frame[:-1]
    stream = header(bodies, kernel) + frame
    with pytest.raises(evidence.EvidenceRefused):
        raw.capture([sys.executable, '-I', '-c', 'import os;os.write(1,' + repr(stream) + ')'],
                    tmp_path, identity(), 'primary-executor', source_invocation=INVOCATION)
    assert {p.name for p in tmp_path.iterdir()} == {'coordinator.log'}
    assert capsys.readouterr() == ('', '')


def test_expanded_archive_bound_unchanged_and_exact(monkeypatch):
    # Test existing consumer aggregate refusal before opening envelope contents.
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name in (evidence.MEMBER, 'current-process.stdout'):
            info = tarfile.TarInfo(name)
            info.size = 8
            tar.addfile(info, io.BytesIO(b'12345678'))
    monkeypatch.setattr(evidence, 'LIMIT', 8)
    with pytest.raises(evidence.EvidenceRefused, match='envelope_digest'):
        evidence.consume(stream.getvalue(), identity(), '0' * 64)
    monkeypatch.setattr(evidence, 'LIMIT', 7)
    with pytest.raises(evidence.EvidenceRefused, match='archive_bound'):
        evidence.consume(stream.getvalue(), identity(), '0' * 64)


def test_public_primary_dispatch_and_controls_include_new_codec():
    import ast
    root = Path(__file__).parent
    entry = ast.parse((root / 'primary_compartment.py').read_bytes())
    assert any(isinstance(n, ast.ImportFrom) and n.module == 'source_raw_transport'
               and any(a.name == 'emit_packed_source' and a.asname == 'emit_source' for a in n.names) for n in ast.walk(entry))
    shell = (root / 'ci_shell.py').read_text()
    assert "capture_raw_source(['docker', 'start', '--attach', container]" in shell
    controls = (root / 'compartment_probe.py').read_text()
    assert '/guard/test_source_raw_transport.py' in controls
    assert '/guard/test_raw_transport_refs.py' in controls


def test_descriptor_size_representative_retains_physical_carrier_and_all_members(tmp_path):
    # Deterministic synthetic bytes at the admitted descriptor sizes. This is
    # framing/overhead coverage, never reconstruction of refused SOURCE bytes.
    sizes = {'collection.json': 389, 'kernel-source.json': 50655408,
             'source-output.log': 1747, 'source-provenance.json': 1402,
             'source.xml': 796, 'summary.json': 5167344}
    bodies = {name: bytes([index + 1]) * size
              for index, (name, size) in enumerate(sorted(sizes.items()))}
    bodies['collection.json'] = b'[]' + b' ' * (sizes['collection.json'] - 2)
    kernel = {}
    head = header(bodies, kernel)
    frame = raw.encode(bodies, identity(), INVOCATION)
    assert sum(sizes.values()) == 55827086
    assert len(head) + len(frame) < evidence.LIMIT
    assert raw.decode(frame, identity(), INVOCATION, descriptors(bodies)) == bodies
    # Input is generated by the new process, rather than passed as argv/body or
    # reread from any historical output carrier.
    code = ('import sys;sys.path.insert(0,' + repr(str(Path(raw.__file__).parent))
            + ');from source_raw_transport import emit_source;sizes=' + repr(sizes)
            + ';r={n:bytes([i+1])*s for i,(n,s) in enumerate(sorted(sizes.items()))};'
            + 'r["collection.json"]=b"[]"+b" "*(sizes["collection.json"]-2);'
            + 'emit_source(r,{},' + repr(identity()) + ',' + repr(INVOCATION) + ',2)')
    result, actual = raw.capture([sys.executable, '-I', '-c', code], tmp_path, identity(),
                                 'primary-executor', source_invocation=INVOCATION)
    assert result.stdout == head + frame
    assert actual == {n: b for n, b in bodies.items() if n in evidence.SOURCE}
    members = {p.name: p.stat().st_size for p in tmp_path.iterdir()}
    assert members['current-process.stdout'] == len(head) + len(frame)
    expanded = sum(members.values())
    assert expanded > 2 * sum(sizes.values()) and expanded <= 2 * evidence.LIMIT
    envelope = (tmp_path / evidence.MEMBER).read_bytes()
    assert evidence.consume(archive(tmp_path), identity(), evidence.digest(envelope)) == ('primary-executor', actual)
    proof = {'synthetic': True, 'record_bytes': sum(sizes.values()), 'header_bytes': len(head),
             'frame_overhead_bytes': len(frame) - sum(sizes.values()),
             'physical_stdout_bytes': len(result.stdout), 'expanded_member_bytes': expanded,
             'whole_limit': evidence.LIMIT, 'expanded_limit': 2 * evidence.LIMIT}
    (tmp_path / 'synthetic-size-proof.json').write_bytes(evidence.canonical(proof))


def test_actual_64mib_frame_boundary_and_one_byte_over():
    table = raw.table_for({'kernel-source.json': b''}, identity(), INVOCATION)
    size = evidence.LIMIT
    for _ in range(3):
        table['records'][0]['size'] = size
        size = evidence.LIMIT - len(raw.PREFIX) - 8 - len(evidence.canonical(table))
    bodies = {'kernel-source.json': b'x' * size}
    frame = raw.encode(bodies, identity(), INVOCATION)
    assert len(frame) == evidence.LIMIT == 67108864
    assert raw.decode(frame, identity(), INVOCATION, descriptors(bodies)) == bodies
    with pytest.raises(evidence.EvidenceRefused, match='transport_bound'):
        raw.decode(frame + b'x', identity(), INVOCATION, descriptors(bodies))
    bodies['kernel-source.json'] += b'x'
    with pytest.raises(evidence.EvidenceRefused, match='transport_bound'):
        raw.encode(bodies, identity(), INVOCATION)


def test_decoder_refuses_foreign_expected_identity_and_descriptor_membership():
    _, bodies = records()
    frame = raw.encode(bodies, identity(), INVOCATION)
    foreign = {**identity(), 'head_sha': 'e' * 40}
    with pytest.raises(evidence.EvidenceRefused, match='raw_identity'):
        raw.decode(frame, foreign, INVOCATION, descriptors(bodies))
    desc = descriptors(bodies)
    del desc['source-output.log']
    with pytest.raises(evidence.EvidenceRefused, match='header_record_binding'):
        raw.decode(frame, identity(), INVOCATION, desc)
