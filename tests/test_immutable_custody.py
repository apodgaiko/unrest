"""Local custody persistence; no provider or session construction."""
from collections import Counter
from dataclasses import asdict, replace
import inspect
import json
from pathlib import Path

import pytest

from unrest_harness import experimental_custody as module
from unrest_harness.experimental_candidate import CandidateManifest
from unrest_harness.experimental_custody import Custody, git
from unrest_harness.experimental_lease import LeaseRefused


def custody(tmp_path: Path) -> Custody:
    root = tmp_path / 'candidate'
    root.mkdir()
    git(root, 'init', '--initial-branch=main', '--object-format=sha1')
    (root / 'a').write_text('base\n')
    git(root, 'add', '.')
    git(root, 'commit', '-m', 'base')
    base = git(root, 'rev-parse', 'HEAD')
    return Custody(root, tmp_path / 'broker', tmp_path / 'seal.json',
                   base=base, commit=base, writes=('a',), targets=('VAL-A',))


def test_persist_reuses_digest_without_caching_observation_or_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = custody(tmp_path)
    manifest = owner.manifest
    raw, digest, projection = manifest.canonical_bytes, manifest.digest, asdict(manifest)
    record = owner.record.read_bytes()
    authority = owner.authority_digest
    calls: list[CandidateManifest] = []
    observations = []
    syncs = []
    original_bytes = inspect.getattr_static(CandidateManifest, 'canonical_bytes').fget
    original_verify, original_sync = module.verify_candidate_inputs, module.os.fsync

    def canonical(value):
        calls.append(value)
        return original_bytes(value)

    def verify(root, expected):
        observations.append((root, expected))
        return original_verify(root, expected)

    def sync(fd):
        syncs.append(fd)
        return original_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(CandidateManifest, 'canonical_bytes', property(canonical))
        patch.setattr(module, 'verify_candidate_inputs', verify)
        patch.setattr(module.os, 'fsync', sync)
        owner._persist()
        assert Counter(id(value) for value in calls)[id(manifest)] == 2
        assert len(calls) == 3  # Digest, observed copy, retained expectation.
        assert len(observations) == 1 and observations[0][1] is manifest
        assert len(syncs) >= 2
        calls.clear()
        owner._persist()
        assert len(calls) == 3  # A later persist computes and observes afresh.
    assert owner.record.read_bytes() == record
    fields = json.loads(record)
    assert fields['manifest'] == json.loads(json.dumps(projection))
    assert fields['manifest_digest'] == digest
    assert fields['authority_digest'] == authority
    assert set(projection) == {
        'base_oid', 'candidate_commit_oid', 'candidate_tree_oid', 'tracked_inputs',
        'extra_inputs', 'extra_input_files', 'output_directories', 'targets',
    }
    assert manifest.canonical_bytes == raw and asdict(manifest) == projection


def test_persist_refuses_manifest_substitution_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = custody(tmp_path)
    before = owner.record.read_bytes()
    original = module.verify_candidate_inputs

    def verify(root, expected):
        original(root, expected)
        owner.manifest = replace(expected, targets=('VAL-B',))

    monkeypatch.setattr(module, 'verify_candidate_inputs', verify)
    with pytest.raises(LeaseRefused, match='candidate_authority_changed'):
        owner._persist()
    assert owner.record.read_bytes() == before
