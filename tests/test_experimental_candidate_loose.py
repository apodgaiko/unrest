"""Bounded local Git objects, including hostile compression and exact boundaries."""
from __future__ import annotations

import hashlib
from pathlib import Path
import zlib

import pytest

from unrest_harness import experimental_candidate as candidate


def object_file(root: Path, expanded: bytes, *, encoded: bytes | None = None) -> tuple[str, Path]:
    oid = hashlib.sha1(expanded).hexdigest()
    path = root / '.git/objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(expanded) if encoded is None else encoded)
    return oid, path


@pytest.mark.parametrize('kind,body', [('blob', b''), ('blob', b'bytes\x00\xff\n'),
                                      ('tree', b'100644 a\x00' + bytes(20)),
                                      ('commit', b'tree ' + b'0' * 40 + b'\n\nmessage\n')])
def test_canonical_loose_bytes_and_current_observation(kind: str, body: bytes, tmp_path: Path) -> None:
    expanded = kind.encode() + b' ' + str(len(body)).encode() + b'\x00' + body
    oid, path = object_file(tmp_path, expanded)
    first = candidate._Observation(tmp_path)
    assert first.object(oid, kind) == body
    path.write_bytes(zlib.compress(expanded[:-1] + b'x'))
    # The existing cache remains confined to this single stable-custody observation.
    assert first.object(oid, kind) == body
    with pytest.raises(candidate.CandidateInputError):
        candidate._Observation(tmp_path).object(oid, kind)


@pytest.mark.parametrize('change', ['truncated', 'trailing', 'second-stream', 'garbage',
                                   'bad-size', 'leading-zero', 'no-nul', 'bad-type', 'wrong-hash'])
def test_malformed_compression_and_object_identity_never_return_bytes(change: str, tmp_path: Path) -> None:
    expanded = b'blob 6\x00secret'
    encoded = zlib.compress(expanded)
    oid, path = object_file(tmp_path, expanded)
    if change == 'truncated':
        encoded = encoded[:-1]
    elif change == 'trailing':
        encoded += b'x'
    elif change == 'second-stream':
        encoded += zlib.compress(b'blob 0\x00')
    elif change == 'garbage':
        encoded = b'not zlib'
    elif change == 'wrong-hash':
        encoded = zlib.compress(b'blob 6\x00Secret')
    else:
        malformed = {'bad-size': b'blob 7\x00secret', 'leading-zero': b'blob 06\x00secret',
                     'no-nul': b'blob 6 secret', 'bad-type': b'tag 6\x00secret'}[change]
        oid, path = object_file(tmp_path, malformed)
        encoded = zlib.compress(malformed)
    path.write_bytes(encoded)
    with pytest.raises(candidate.CandidateInputError) as caught:
        candidate._Observation(tmp_path).object(oid, 'blob')
    assert 'secret' not in str(caught.value)


def test_exact_raw_cap_preserves_header_room_and_oversize_expansion_refuses(tmp_path: Path) -> None:
    for excess in (0, 1):
        body = b'x' * (candidate.MAX_FILE_BYTES + excess)
        expanded = b'blob ' + str(len(body)).encode() + b'\x00' + body
        oid, _ = object_file(tmp_path, expanded)
        if excess:
            with pytest.raises(candidate.CandidateInputError, match='^object_size$'):
                candidate._Observation(tmp_path).object(oid, 'blob')
        else:
            assert candidate._Observation(tmp_path).object(oid, 'blob') == body


def test_compressed_and_expanded_bytes_both_count_against_aggregate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'payload'
    expanded = b'blob 7\x00' + body
    oid, path = object_file(tmp_path, expanded)
    required = path.stat().st_size + len(body)
    monkeypatch.setattr(candidate, 'MAX_TOTAL_BYTES', required)
    assert candidate._Observation(tmp_path).object(oid, 'blob') == body
    monkeypatch.setattr(candidate, 'MAX_TOTAL_BYTES', required - 1)
    with pytest.raises(candidate.CandidateInputError, match='^aggregate_size$'):
        candidate._Observation(tmp_path).object(oid, 'blob')


def test_acquisition_and_decode_deadline_preserves_original_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oid, _ = object_file(tmp_path, b'blob 1\x00x')
    observation = candidate._Observation(tmp_path)
    original = observation.read
    def expired(path: Path) -> bytes:
        result = original(path)
        monkeypatch.setattr(candidate.time, 'monotonic', lambda: observation.deadline + 1)
        return result
    monkeypatch.setattr(observation, 'read', expired)
    with pytest.raises(candidate.CandidateInputError, match='^observation_deadline$'):
        observation.object(oid, 'blob')
