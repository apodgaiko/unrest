from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from unrest_harness.canonical_identity import FoundationValidationError, construct_identity
from unrest_harness.foundation_store import CustodyActor, FoundationStore
from unrest_harness.receipts import verify_receipt


_VECTORS = Path(__file__).parent / "fixtures/v03_decisions/identity/canonical-vectors.v1.json"


def _vectors() -> dict[str, object]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


def _artifact_identity():
    vectors = _vectors()["identity_vectors"]
    vector = next(item for item in vectors if item["identity_kind"] == "artifact_identity.v1")
    return construct_identity("artifact", vector["structured_payload"])


def _cleanup_receipt():
    vectors = _vectors()["receipt_vectors"]
    vector = next(item for item in vectors if item["receipt_kind"] == "cleanup_receipt.v1")
    return verify_receipt(bytes.fromhex(vector["stored_canonical_hex"]), vector["expected_digest"])


def _all_receipts():
    vectors = _vectors()["receipt_vectors"]
    return [
        verify_receipt(bytes.fromhex(vector["stored_canonical_hex"]), vector["expected_digest"])
        for vector in vectors
    ]


def _custodian(receipt):
    return CustodyActor(
        actor_id=receipt.record["issuer"]["issuer_id"],
        authority_class=receipt.record["issuer_authority"]["authority_class"],
        decision_ref=receipt.record["issuer_authority"]["decision_ref"],
    )


def test_store_separates_durable_records_from_runtime_cursor_and_restarts(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    identity = _artifact_identity()
    receipt = _cleanup_receipt()
    identity_path = store.append_identity(identity)
    receipt_path = store.append_receipt(receipt, custodian=_custodian(receipt))

    assert identity_path.relative_to(tmp_path).parts[:2] == (".unrest", "foundation")
    assert receipt_path.relative_to(tmp_path).parts[:2] == (".unrest", "foundation")
    assert (tmp_path / ".unrest-runtime/foundation/custody-head.json").is_file()
    assert not (tmp_path / ".unrest/foundation/custody-head.json").exists()
    assert store.load_identity(identity.kind, identity.digest) == identity
    assert store.load_receipt(receipt.family, receipt.digest) == receipt
    assert store.has_local_custody(receipt.digest)

    restarted = FoundationStore(tmp_path, custody_root_id="local:test-root")
    assert restarted.verify_custody_chain()[0].record_digest == receipt.digest
    assert restarted.list_identity_digests("artifact") == (identity.digest,)
    assert restarted.list_receipt_digests("cleanup_receipt.v1") == (receipt.digest,)


def test_append_is_idempotent_but_bytes_are_never_rewritten(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    identity = _artifact_identity()
    receipt = _cleanup_receipt()
    first_identity = store.append_identity(identity)
    first_receipt = store.append_receipt(receipt, custodian=_custodian(receipt))
    first_custody = store.verify_custody_chain()
    assert store.append_identity(identity) == first_identity
    assert store.append_receipt(receipt, custodian=_custodian(receipt)) == first_receipt
    assert store.verify_custody_chain() == first_custody

    first_identity.write_bytes(b"not-the-same-bytes")
    with pytest.raises(FoundationValidationError):
        store.append_identity(identity)


def test_custody_chain_links_all_nine_families_without_rewriting(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    receipts = _all_receipts()
    for receipt in receipts:
        store.append_receipt(receipt, custodian=_custodian(receipt))
    entries = store.verify_custody_chain()
    assert [entry.record_kind for entry in entries] == [receipt.family for receipt in receipts]
    assert [entry.sequence for entry in entries] == list(range(1, 10))
    first_bytes = entries[0].canonical_bytes
    store.append_receipt(receipts[0], custodian=_custodian(receipts[0]))
    assert store.verify_custody_chain()[0].canonical_bytes == first_bytes


def test_wrong_issuer_cannot_create_local_custody(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    receipt = _cleanup_receipt()
    wrong = CustodyActor(
        actor_id="issuer:substitute",
        authority_class=receipt.record["issuer_authority"]["authority_class"],
        decision_ref=receipt.record["issuer_authority"]["decision_ref"],
    )
    with pytest.raises(FoundationValidationError) as caught:
        store.append_receipt(receipt, custodian=wrong)
    assert caught.value.code == "unauthorized"
    assert not store.has_local_custody(receipt.digest)


def test_copied_store_cannot_be_relabelled_as_another_custody_root(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.mkdir()
    store = FoundationStore(original, custody_root_id="local:original")
    receipt = _cleanup_receipt()
    store.append_receipt(receipt, custodian=_custodian(receipt))
    copied = tmp_path / "copied"
    shutil.copytree(original, copied)
    with pytest.raises(FoundationValidationError) as caught:
        FoundationStore(copied, custody_root_id="local:substitute")
    assert caught.value.code == "custody_root_mismatch"


def test_custody_tamper_or_missing_receipt_fails_closed(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    receipt = _cleanup_receipt()
    path = store.append_receipt(receipt, custodian=_custodian(receipt))
    path.unlink()
    with pytest.raises(FoundationValidationError) as caught:
        store.verify_custody_chain()
    assert caught.value.code == "integrity_error"


def test_store_export_enforces_family_consumer_and_local_custody(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    receipt = _cleanup_receipt()
    store.append_receipt(receipt, custodian=_custodian(receipt))
    exported = store.export_receipt(
        receipt.family,
        receipt.digest,
        consumer_id="evidence_store",
        authoritative=True,
    )
    assert exported.authoritative
    with pytest.raises(FoundationValidationError) as caught:
        store.export_receipt(
            receipt.family,
            receipt.digest,
            consumer_id="third_party_auditor",
            authoritative=True,
        )
    assert caught.value.code == "signature_suite_unsupported"
    non_authoritative = store.export_receipt(
        receipt.family,
        receipt.digest,
        consumer_id="third_party_auditor",
        authoritative=False,
    )
    assert non_authoritative.label == "integrity_only_non_authoritative"


def test_path_components_and_symlink_roots_fail_closed(tmp_path: Path) -> None:
    store = FoundationStore(tmp_path, custody_root_id="local:test-root")
    with pytest.raises(FoundationValidationError):
        store.list_identity_digests("../escape")
    outside = tmp_path / "outside"
    outside.mkdir()
    symlinked = tmp_path / "symlinked"
    symlinked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(FoundationValidationError):
        FoundationStore(symlinked, custody_root_id="local:test-root")
