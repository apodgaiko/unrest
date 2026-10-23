"""Lossless V3 capacity controls, never a source-suite result or certificate."""

import copy
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import source_raw_transport as raw
import structured_evidence as evidence
from test_source_transport import INVOCATION, CANARY
from test_structured_evidence import archive, identity


def bodies():
    return {
        "kernel-source.json": b"{}",
        "summary.json": b'{"events":[]}',
        "source-output.log": CANARY.encode() + b"\x00\xff",
    }


def descriptors(data):
    header = evidence.source_header(data, {}, identity(), INVOCATION, 2)
    return evidence.loads(header[len(evidence.HEADER_PREFIX) : -1])["records"]


def parts(data=None):
    data = bodies() if data is None else data
    frame = raw.encode_packed(data, identity(), INVOCATION)
    rows, encoded = raw.packed_parts(frame, identity(), INVOCATION, descriptors(data))
    return data, frame, rows, encoded


def repack(rows, encoded):
    table = evidence.canonical(
        {
            "schema": raw.PACKED_SCHEMA,
            "identity": identity(),
            "invocation_sha256": INVOCATION,
            "records": rows,
        }
    )
    return (
        raw.PACKED_PREFIX
        + len(table).to_bytes(8, "big")
        + table
        + b"".join(encoded[row["name"]] for row in rows)
    )


def emit_code(expression):
    return (
        "import sys;sys.path.insert(0,"
        + repr(str(Path(raw.__file__).parent))
        + ");from source_raw_transport import emit_packed_source;r="
        + expression
        + ";emit_packed_source(r,{},"
        + repr(identity())
        + ","
        + repr(INVOCATION)
        + ",2)"
    )


def test_fresh_capture_and_archive_recover_every_original_byte(tmp_path, capsys):
    data = bodies()
    result, actual = raw.capture_packed(
        [sys.executable, "-I", "-c", emit_code(repr(data))],
        tmp_path,
        identity(),
        "primary-executor",
        source_invocation=INVOCATION,
    )
    assert actual == {name: body for name, body in data.items() if name in evidence.SOURCE}
    assert (tmp_path / "current-process.stdout").read_bytes() == result.stdout
    for name, body in data.items():
        assert zlib.decompress((tmp_path / ("packed-" + name)).read_bytes()) == body
    scope, consumed = evidence.consume(
        archive(tmp_path), identity(), evidence.digest((tmp_path / evidence.MEMBER).read_bytes())
    )
    assert scope == "primary-executor" and consumed == actual
    assert CANARY not in (tmp_path / evidence.HEADER).read_text()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "kernel_mib,summary_mib,legacy_error", [(40, 30, "transport_bound"), (80, 40, "record_bound")]
)
def test_real_aggregate_over_v2_cap_remains_lossless_in_new_process(
    tmp_path, kernel_mib, summary_mib, legacy_error
):
    sizes = {
        "kernel-source.json": kernel_mib * 1024 * 1024,
        "summary.json": summary_mib * 1024 * 1024,
    }
    data = {name: b"{}" + b" " * (size - 2) for name, size in sizes.items()}
    with pytest.raises(evidence.EvidenceRefused, match=legacy_error):
        raw.encode(data, identity(), INVOCATION)
    expression = "{n:b'{}'+b' '*(s-2) for n,s in " + repr(sizes) + ".items()}"
    result, actual = raw.capture_packed(
        [sys.executable, "-I", "-c", emit_code(expression)],
        tmp_path,
        identity(),
        "primary-executor",
        source_invocation=INVOCATION,
    )
    assert result.returncode == 0 and actual == data
    assert len(result.stdout) < evidence.LIMIT
    assert sum(p.stat().st_size for p in tmp_path.iterdir()) < 2 * evidence.LIMIT
    assert evidence.consume(
        archive(tmp_path), identity(), evidence.digest((tmp_path / evidence.MEMBER).read_bytes())
    ) == ("primary-executor", data)


def test_single_logical_member_over_old_cap_has_explicit_new_bound(monkeypatch):
    monkeypatch.setattr(evidence, "LIMIT", 1024)
    monkeypatch.setattr(raw, "LOGICAL_MEMBER_LIMIT", 2048)
    monkeypatch.setattr(raw, "LOGICAL_TOTAL_LIMIT", 4096)
    data = {"kernel-source.json": b" " * 2048}
    with pytest.raises(evidence.EvidenceRefused, match="record_bound"):
        raw.encode(data, identity(), INVOCATION)
    frame = raw.encode_packed(data, identity(), INVOCATION)
    assert raw.decode_packed(frame, identity(), INVOCATION, descriptors(data)) == data
    with pytest.raises(evidence.EvidenceRefused, match="logical_record_bound"):
        raw.encode_packed({"kernel-source.json": b" " * 2049}, identity(), INVOCATION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", -1),
        ("size", True),
        ("size", 1.0),
        ("size", 2**64),
        ("packed_size", 0),
        ("packed_size", True),
        ("packed_size", 2**64),
        ("name", "../kernel-source.json"),
        ("sha256", CANARY),
        ("packed_sha256", "x" * 64),
    ],
)
def test_descriptor_corruption_refuses_before_inflation(monkeypatch, field, value):
    data, _, rows, encoded = parts()
    rows[0][field] = value
    frame = (
        repack(rows, encoded)
        if field != "name"
        else repack(rows, {**encoded, value: encoded["kernel-source.json"]})
    )
    monkeypatch.setattr(
        raw, "inflate_packed", lambda *a: pytest.fail("invalid descriptor inflated")
    )
    with pytest.raises(evidence.EvidenceRefused):
        raw.decode_packed(frame, identity(), INVOCATION, descriptors(data))


@pytest.mark.parametrize(
    "change", ["truncated", "trailing", "second-stream", "bomb", "wrong-hash", "wrong-codec"]
)
def test_inflation_is_exact_bounded_and_single_stream(change):
    data, _, rows, encoded = parts()
    row = rows[0]
    name = row["name"]
    payload = encoded[name]
    if change == "truncated":
        payload = payload[:-1]
    elif change == "trailing":
        payload += b"x"
    elif change == "second-stream":
        payload += zlib.compress(b"other")
    elif change == "bomb":
        payload = zlib.compress(b"x" * 10000)
    elif change == "wrong-hash":
        row["sha256"] = "0" * 64
    else:
        payload = b"not zlib"
    encoded[name] = payload
    row["packed_size"] = len(payload)
    row["packed_sha256"] = evidence.digest(payload)
    with pytest.raises(evidence.EvidenceRefused):
        raw.inflate_packed(rows, encoded)


def test_aggregate_logical_budget_precedes_inflation(monkeypatch):
    _, _, rows, encoded = parts()
    monkeypatch.setattr(raw, "LOGICAL_TOTAL_LIMIT", sum(row["size"] for row in rows) - 1)
    monkeypatch.setattr(zlib, "decompressobj", lambda: pytest.fail("over-budget inflation"))
    with pytest.raises(evidence.EvidenceRefused, match="logical_total_bound"):
        raw.inflate_packed(rows, encoded)


@pytest.mark.parametrize("frame", [b"PRIVATE-EVIDENCE:{}\n", b"PRIVATE-EVIDENCE-RAW-V2:whatever"])
def test_no_protocol_fallback(frame):
    with pytest.raises(evidence.EvidenceRefused, match="packed_prefix"):
        raw.decode_packed(frame, identity(), INVOCATION, descriptors(bodies()))


def test_physical_archive_budget_precedes_payload_inflation(tmp_path, monkeypatch):
    (tmp_path / "coordinator.log").write_bytes(b"x" * 16384)
    (tmp_path / "provenance.json").write_bytes(b"x" * 16384)
    monkeypatch.setattr(evidence, "LIMIT", 16384)
    monkeypatch.setattr(raw, "inflate_packed", lambda *a: pytest.fail("archive overflow inflated"))
    with pytest.raises(evidence.EvidenceRefused, match="archive_bound"):
        raw.capture_packed(
            [sys.executable, "-I", "-c", emit_code(repr(bodies()))],
            tmp_path,
            identity(),
            "primary-executor",
            source_invocation=INVOCATION,
        )
    assert not (tmp_path / evidence.MEMBER).exists()
    assert not list(tmp_path.glob("packed-*"))


def test_malformed_payload_retains_only_validated_diagnostic_carrier(tmp_path):
    data = bodies()
    header = evidence.source_header(data, {}, identity(), INVOCATION, 0)
    stream = header + b"not a frame"
    with pytest.raises(evidence.EvidenceRefused, match="packed_prefix"):
        raw.capture_packed(
            [sys.executable, "-I", "-c", "import os;os.write(1," + repr(stream) + ")"],
            tmp_path,
            identity(),
            "primary-executor",
            source_invocation=INVOCATION,
        )
    assert (tmp_path / "current-process.stdout").read_bytes() == stream
    assert not (tmp_path / evidence.MEMBER).exists()
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path), identity(), "0" * 64)


def test_packed_source_custody_preserves_exact_values_and_rejects_codec_drift(tmp_path):
    from primary_custody import Custody, SOURCE, phase_records
    from test_primary_custody import binding, records
    from checkpoint_issuer import records as issuer_records

    data = records(SOURCE)
    data["summary.json"] = b'{"events":[]}'
    custody = Custody(tmp_path / "custody", binding(), create=True)
    phase = custody.record(SOURCE, "b" * 64, data)
    assert phase_records(phase) == issuer_records(phase) == data
    assert custody.phase(SOURCE) == phase
    bad = copy.deepcopy(phase)
    bad["record_codec"] = "foreign"
    with pytest.raises(RuntimeError):
        phase_records(bad)
    bad = copy.deepcopy(phase)
    bad["records"]["kernel-source.json"]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceRefused):
        phase_records(bad)


@pytest.mark.parametrize(
    "mutation", ["schema", "identity", "invocation", "extra", "order", "duplicate", "empty"]
)
def test_closed_v3_table_and_execution_identity(mutation):
    data, frame, _, _ = parts()
    start = len(raw.PACKED_PREFIX) + 8
    length = int.from_bytes(frame[len(raw.PACKED_PREFIX) : start], "big")
    table = evidence.loads(frame[start : start + length])
    if mutation == "schema":
        table["schema"] = "foreign"
    elif mutation == "identity":
        table["identity"]["run_attempt"] = "2"
    elif mutation == "invocation":
        table["invocation_sha256"] = "d" * 64
    elif mutation == "extra":
        table["extra"] = True
    elif mutation == "order":
        table["records"].reverse()
    elif mutation == "duplicate":
        table["records"].append(table["records"][0])
    else:
        table["records"] = []
    encoded = evidence.canonical(table)
    changed = (
        raw.PACKED_PREFIX + len(encoded).to_bytes(8, "big") + encoded + frame[start + length :]
    )
    with pytest.raises(evidence.EvidenceRefused):
        raw.decode_packed(changed, identity(), INVOCATION, descriptors(data))


def test_real_emitter_capacity_refusal_preserves_header_without_a_certificate(tmp_path):
    code = (
        "import sys;sys.path.insert(0,"
        + repr(str(Path(raw.__file__).parent))
        + ");import source_raw_transport as t;t.LOGICAL_MEMBER_LIMIT=1;"
        + 't.emit_packed_source({"kernel-source.json":b"{}"},{},'
        + repr(identity())
        + ","
        + repr(INVOCATION)
        + ",0)"
    )
    with pytest.raises(evidence.EvidenceRefused, match="packed_prefix"):
        raw.capture_packed(
            [sys.executable, "-I", "-c", code],
            tmp_path,
            identity(),
            "primary-executor",
            source_invocation=INVOCATION,
        )
    header = evidence.loads((tmp_path / evidence.HEADER).read_bytes())
    assert header["source_status"]["exit_code"] == 0
    assert not (tmp_path / evidence.MEMBER).exists()
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path), identity(), "0" * 64)


@pytest.mark.parametrize(
    "mutation", ["carrier", "member", "logical-hash", "member-path", "extra-member"]
)
def test_archive_binding_refuses_replaced_bytes_or_descriptors(tmp_path, mutation):
    raw.capture_packed(
        [sys.executable, "-I", "-c", emit_code(repr(bodies()))],
        tmp_path,
        identity(),
        "primary-executor",
        source_invocation=INVOCATION,
    )
    envelope_path = tmp_path / evidence.MEMBER
    envelope = evidence.loads(envelope_path.read_bytes())
    if mutation == "carrier":
        (tmp_path / "current-process.stdout").write_bytes(b"foreign")
    elif mutation == "member":
        (tmp_path / "packed-kernel-source.json").write_bytes(b"foreign")
    elif mutation == "logical-hash":
        envelope["records"]["kernel-source.json"]["sha256"] = "0" * 64
    elif mutation == "member-path":
        envelope["records"]["kernel-source.json"]["member"] = "../foreign"
    else:
        (tmp_path / "packed-unknown.json").write_bytes(b"foreign")
    envelope_path.write_bytes(evidence.canonical(envelope))
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path), identity(), evidence.digest(envelope_path.read_bytes()))


def test_reader_rejects_authenticated_oversized_packed_source_phase(tmp_path, monkeypatch):
    import hmac
    import primary_custody as custody_module
    from primary_custody import Custody, SOURCE, canonical, sha
    from test_primary_custody import binding, records

    custody = Custody(tmp_path / "custody", binding(), create=True)
    custody.record(SOURCE, "b" * 64, records(SOURCE))
    path = custody.root / (sha(SOURCE.encode()) + ".json")
    size = path.stat().st_size
    monkeypatch.setattr(custody_module, "SOURCE_PHASE_LIMIT", size - 1)
    with pytest.raises(RuntimeError, match="custody_phase_bound"):
        custody.phase(SOURCE)
    envelope = evidence.loads(path.read_bytes())
    assert hmac.compare_digest(
        envelope["mac"], hmac.digest(custody.key, canonical(envelope["payload"]), "sha256").hex()
    )
    monkeypatch.setattr(custody_module, "SOURCE_PHASE_LIMIT", size)
    assert custody.phase(SOURCE) == envelope["payload"]


def test_incompressible_wire_exact_bound_and_overflow(monkeypatch):
    import random

    generator = random.Random(17)
    data = {
        "kernel-source.json": generator.randbytes(1800),
        "summary.json": generator.randbytes(1800),
    }
    frame = raw.encode_packed(data, identity(), INVOCATION)
    monkeypatch.setattr(evidence, "LIMIT", len(frame))
    assert raw.encode_packed(data, identity(), INVOCATION) == frame
    assert raw.decode_packed(frame, identity(), INVOCATION, descriptors(data)) == data
    monkeypatch.setattr(evidence, "LIMIT", len(frame) - 1)
    with pytest.raises(evidence.EvidenceRefused, match="transport_bound"):
        raw.encode_packed(data, identity(), INVOCATION)
    with pytest.raises(evidence.EvidenceRefused, match="transport_bound"):
        raw.decode_packed(frame, identity(), INVOCATION, descriptors(data))


def test_encoder_rejects_logical_total_before_compression(monkeypatch):
    monkeypatch.setattr(raw, "LOGICAL_MEMBER_LIMIT", 1000)
    monkeypatch.setattr(raw, "LOGICAL_TOTAL_LIMIT", 1000)
    monkeypatch.setattr(zlib, "compress", lambda *a, **k: pytest.fail("over-budget compression"))
    with pytest.raises(evidence.EvidenceRefused, match="logical_total_bound"):
        raw.encode_packed(
            {"kernel-source.json": b"x" * 600, "summary.json": b"x" * 600}, identity(), INVOCATION
        )


def test_custody_base64_length_checked_before_decoding(monkeypatch):
    import primary_custody as custody_module
    from primary_custody import SOURCE, SOURCE_RECORD_CODEC, packed_source_records, phase_records

    records = packed_source_records({"kernel-source.json": b"{}"})
    records["kernel-source.json"]["bytes"] += "AAAA"
    monkeypatch.setattr(
        custody_module.base64, "b64decode", lambda *a, **k: pytest.fail("invalid length decoded")
    )
    with pytest.raises(RuntimeError, match="custody_packed_encoding"):
        phase_records({"duty": SOURCE, "record_codec": SOURCE_RECORD_CODEC, "records": records})
