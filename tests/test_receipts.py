from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path

import pytest

from unrest_harness.canonical_identity import FoundationValidationError, canonical_json_bytes
from unrest_harness.receipts import (
    AuthorityGrant,
    FreshnessStatus,
    construct_receipt,
    derive_freshness,
    export_receipt,
    load_receipt_catalog,
    verify_receipt,
)


_VECTORS = Path(__file__).parent / "fixtures/v03_decisions/identity/canonical-vectors.v1.json"


def _vectors() -> dict[str, object]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


def _receipt_vector(family: str) -> dict[str, object]:
    vectors = _vectors()["receipt_vectors"]
    assert isinstance(vectors, list)
    return next(item for item in vectors if item["receipt_kind"] == family)


def _cleanup_receipt():
    vector = _receipt_vector("cleanup_receipt.v1")
    return verify_receipt(bytes.fromhex(vector["stored_canonical_hex"]), vector["expected_digest"])


def _grant(receipt, *, self_authorized: bool = False) -> AuthorityGrant:
    issuer = receipt.record["issuer"]
    authority = receipt.record["issuer_authority"]
    return AuthorityGrant(
        authority_class=authority["authority_class"],
        decision_ref=authority["decision_ref"],
        issuer_id=issuer["issuer_id"],
        issuer_identity_digest=issuer["identity_digest"],
        grantor_id=issuer["issuer_id"] if self_authorized else "maintainer:one",
    )


def _upstreams(receipt) -> dict[str, FreshnessStatus]:
    return {
        item["dependency_digest"]: FreshnessStatus.FRESH
        for item in receipt.record["dependencies"]
        if item["dependency_type"] == "receipt"
    }


def test_catalog_is_exact_and_all_independent_vectors_verify() -> None:
    catalog = load_receipt_catalog()
    assert tuple(sorted(catalog.families)) == (
        "cleanup_receipt.v1", "evaluation_receipt.v1", "integration_receipt.v1",
        "patch_receipt.v1", "promotion_receipt.v1", "review_receipt.v1",
        "rollback_receipt.v1", "run_receipt.v1", "workspace_receipt.v1",
    )
    vectors = _vectors()["receipt_vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        record = verify_receipt(
            bytes.fromhex(vector["stored_canonical_hex"]), vector["expected_digest"]
        )
        assert record.digest == vector["expected_digest"]
        rebuilt = construct_receipt(vector["structured_without_digest"])
        assert rebuilt.canonical_bytes == record.canonical_bytes


def test_every_family_derives_fresh_stale_revoked_and_unverifiable() -> None:
    vectors = _vectors()["receipt_vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        receipt = verify_receipt(
            bytes.fromhex(vector["stored_canonical_hex"]), vector["expected_digest"]
        )
        consumer = receipt.record["consumers"][0]
        dependencies = list(receipt.record["dependencies"])
        common = {
            "consumer_id": consumer,
            "issuer_grant": _grant(receipt),
            "revocation_view_available": True,
            "upstream_freshness": _upstreams(receipt),
        }
        assert derive_freshness(
            receipt, current_dependencies=dependencies, **common
        ).status is FreshnessStatus.FRESH
        changed = [dict(item) for item in dependencies]
        changed[0]["dependency_digest"] = "sha256:" + "f" * 64
        assert derive_freshness(
            receipt, current_dependencies=changed, **common
        ).status is FreshnessStatus.STALE
        assert derive_freshness(
            receipt,
            current_dependencies=dependencies,
            revoked_receipt_digests=frozenset({receipt.digest}),
            **common,
        ).status is FreshnessStatus.REVOKED
        assert derive_freshness(
            receipt,
            current_dependencies=dependencies,
            **{**common, "issuer_grant": None},
        ).status is FreshnessStatus.UNVERIFIABLE


def test_integrity_family_replay_and_common_field_mutations_fail() -> None:
    receipt = _cleanup_receipt()
    mutated = dict(receipt.record)
    mutated["receipt_kind"] = "workspace_receipt.v1"
    with pytest.raises(FoundationValidationError):
        construct_receipt(mutated)
    mutated = dict(receipt.record)
    mutated.pop("receipt_digest")
    mutated["chronology_is_authority"] = True
    with pytest.raises(FoundationValidationError, match="schema_violation"):
        construct_receipt(mutated)
    mutated = dict(receipt.record)
    mutated.pop("receipt_digest")
    mutated.pop("cost")
    with pytest.raises(FoundationValidationError, match="schema_violation"):
        construct_receipt(mutated)
    changed_bytes = bytearray(receipt.canonical_bytes)
    changed_bytes[-3] = ord("x")
    with pytest.raises(FoundationValidationError):
        verify_receipt(bytes(changed_bytes), receipt.digest)


def test_freshness_requires_external_authority_exact_dependencies_and_revocation_view() -> None:
    receipt = _cleanup_receipt()
    common = {
        "consumer_id": "evidence_store",
        "issuer_grant": _grant(receipt),
        "current_dependencies": receipt.record["dependencies"],
        "revocation_view_available": True,
        "upstream_freshness": _upstreams(receipt),
    }
    assert derive_freshness(receipt, **common).status is FreshnessStatus.FRESH

    assert derive_freshness(
        receipt, **{**common, "revocation_view_available": False}
    ).status is FreshnessStatus.UNVERIFIABLE
    assert derive_freshness(
        receipt, **{**common, "issuer_grant": _grant(receipt, self_authorized=True)}
    ).status is FreshnessStatus.UNVERIFIABLE
    assert derive_freshness(
        receipt, **{**common, "issuer_grant": None}
    ).status is FreshnessStatus.UNVERIFIABLE
    assert derive_freshness(
        receipt, **{**common, "revoked_receipt_digests": frozenset({receipt.digest})}
    ).status is FreshnessStatus.REVOKED


def test_freshness_detects_missing_extra_changed_and_upstream_dependencies() -> None:
    receipt = _cleanup_receipt()
    common = {
        "consumer_id": "evidence_store",
        "issuer_grant": _grant(receipt),
        "revocation_view_available": True,
        "upstream_freshness": _upstreams(receipt),
    }
    dependencies = list(receipt.record["dependencies"])
    assert derive_freshness(
        receipt, current_dependencies=dependencies[:-1], **common
    ).status is FreshnessStatus.STALE
    changed = [dict(item) for item in dependencies]
    changed[0]["dependency_digest"] = "sha256:" + "f" * 64
    assert derive_freshness(
        receipt, current_dependencies=changed, **common
    ).status is FreshnessStatus.STALE
    assert derive_freshness(
        receipt, current_dependencies=None, **common
    ).status is FreshnessStatus.UNVERIFIABLE
    upstream = {key: FreshnessStatus.REVOKED for key in _upstreams(receipt)}
    assert derive_freshness(
        receipt,
        current_dependencies=dependencies,
        **{**common, "upstream_freshness": upstream},
    ).status is FreshnessStatus.STALE


def test_expiry_uses_only_a_consumer_trusted_clock() -> None:
    source = dict(_cleanup_receipt().record)
    source.pop("receipt_digest")
    policy = dict(source["freshness_policy"])
    policy["expiry"] = {
        "state": "present",
        "value": {"expires_at": "2026-08-24T00:00:00Z", "trusted_clock_id": "clock:one"},
    }
    source["freshness_policy"] = policy
    receipt = construct_receipt(source)
    common = {
        "consumer_id": "evidence_store",
        "issuer_grant": _grant(receipt),
        "current_dependencies": receipt.record["dependencies"],
        "revocation_view_available": True,
        "upstream_freshness": _upstreams(receipt),
    }
    assert derive_freshness(receipt, **common).status is FreshnessStatus.UNVERIFIABLE
    assert derive_freshness(
        receipt, trusted_now=datetime(2026, 8, 24, tzinfo=UTC), **common
    ).status is FreshnessStatus.STALE


def test_authoritative_export_is_local_custody_only_until_signature_suite_exists() -> None:
    receipt = _cleanup_receipt()
    evidence = export_receipt(
        receipt,
        consumer_id="third_party_auditor",
        authoritative=False,
        local_custody_verified=False,
    )
    assert evidence.label == "integrity_only_non_authoritative"
    assert not evidence.authoritative
    with pytest.raises(FoundationValidationError) as caught:
        export_receipt(
            receipt,
            consumer_id="third_party_auditor",
            authoritative=True,
            local_custody_verified=False,
        )
    assert caught.value.code == "signature_suite_unsupported"
    with pytest.raises(FoundationValidationError) as caught:
        export_receipt(
            receipt,
            consumer_id="promotion_authority",
            authoritative=True,
            local_custody_verified=True,
        )
    assert caught.value.code == "unauthorized"
    local = export_receipt(
        receipt,
        consumer_id="evidence_store",
        authoritative=True,
        local_custody_verified=True,
    )
    assert local.authoritative and local.canonical_bytes == receipt.canonical_bytes


def test_receipt_bytes_always_have_one_lf() -> None:
    receipt = _cleanup_receipt()
    assert receipt.canonical_bytes == canonical_json_bytes(receipt.record)
    assert receipt.canonical_bytes.endswith(b"\n")
    assert not receipt.canonical_bytes.endswith(b"\n\n")
