from __future__ import annotations

import json
from pathlib import Path

import pytest

from unrest_harness.canonical_identity import (
    FoundationValidationError,
    canonical_json_bytes,
    construct_identity,
    identity_digest,
    load_identity_catalog,
    strict_parse_json,
    verify_canonical_json_bytes,
    verify_identity,
)


_VECTORS = Path(__file__).parent / "fixtures/v03_decisions/identity/canonical-vectors.v1.json"


def _vectors() -> dict[str, object]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


def test_catalog_v2_is_closed_and_preserves_all_v1_vectors() -> None:
    catalog = load_identity_catalog()
    assert set(catalog.kinds) == {
        "accepted_working_point", "artifact", "base", "budget", "candidate", "campaign",
        "context", "control_operation", "environment", "evaluator", "evidence", "inquiry",
        "inquiry_branch", "inquiry_handoff", "inquiry_synthesis", "policy",
        "provider_configuration", "review", "route_profile", "run", "secret_set_version",
        "seed", "workload", "workspace_lease",
    }
    vectors = _vectors()["identity_vectors"]
    assert isinstance(vectors, list)
    by_domain = {entry.domain: kind for kind, entry in catalog.kinds.items()}
    for vector in vectors:
        kind = by_domain[vector["identity_kind"]]
        record = construct_identity(kind, vector["structured_payload"])
        assert record.canonical_bytes == bytes.fromhex(vector["canonical_payload_hex"])
        assert record.digest == vector["expected_digest"]
        assert verify_identity(kind, record.canonical_bytes, record.digest) == record


def test_each_original_kind_changes_identity_when_one_material_dimension_changes() -> None:
    catalog = load_identity_catalog()
    vectors = _vectors()["identity_vectors"]
    assert isinstance(vectors, list)
    by_domain = {entry.domain: kind for kind, entry in catalog.kinds.items()}
    for vector in vectors:
        kind = by_domain[vector["identity_kind"]]
        original = construct_identity(kind, vector["structured_payload"])
        changed = dict(vector["structured_payload"])
        dimension = catalog.kinds[kind].required_dimensions[0]
        old_value = changed[dimension]
        if isinstance(old_value, int):
            changed[dimension] = old_value + 1
        elif isinstance(old_value, dict):
            changed[dimension] = {**old_value, "amount": old_value["amount"] + 1}
        elif dimension == "base_revision":
            changed[dimension] = "b" * 40
        elif dimension == "secret_set_version_id":
            changed[dimension] = "secret-set:demo:v2"
        elif dimension == "workspace_lease_id":
            changed[dimension] = "lease:changed"
        else:
            changed[dimension] = "sha256:" + "f" * 64
        assert construct_identity(kind, changed).digest != original.digest


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("inquiry", {"budget_envelope": {"amount": 4, "unit": "steps"}, "capability_policy_digest": "sha256:" + "1" * 64, "public_id": "inquiry:one", "question_digest": "sha256:" + "2" * 64, "schema_version": 1}),
        ("inquiry_branch", {"branch_id": "branch:direct", "branch_role": "direct", "budget_envelope": {"amount": 1, "unit": "steps"}, "inquiry_digest": "sha256:" + "1" * 64, "provider_configuration_digest": "sha256:" + "2" * 64, "public_id": "inquiry_branch:one", "route_profile_digest": "sha256:" + "3" * 64, "schema_version": 1}),
        ("inquiry_synthesis", {"branch_set_digest": "sha256:" + "1" * 64, "inquiry_digest": "sha256:" + "2" * 64, "public_id": "inquiry_synthesis:one", "schema_version": 1, "synthesis_digest": "sha256:" + "3" * 64}),
        ("inquiry_handoff", {"consumer_id": "mission:one", "handoff_digest": "sha256:" + "1" * 64, "inquiry_digest": "sha256:" + "2" * 64, "public_id": "inquiry_handoff:one", "schema_version": 1, "synthesis_digest": "sha256:" + "3" * 64}),
        ("control_operation", {"idempotency_key_digest": "sha256:" + "1" * 64, "operation": "advance_project", "public_id": "control_operation:one", "run_digest": "sha256:" + "2" * 64, "schema_version": 1}),
        ("campaign", {"accepted_working_point_digest": "sha256:" + "1" * 64, "budget_envelope": {"amount": 5, "unit": "steps"}, "campaign_digest": "sha256:" + "2" * 64, "evaluator_digest": "sha256:" + "3" * 64, "public_id": "campaign:one", "schema_version": 1, "workload_digest": "sha256:" + "4" * 64}),
    ],
)
def test_each_v2_kind_has_a_closed_constructor(kind: str, payload: dict[str, object]) -> None:
    record = construct_identity(kind, payload)
    changed = dict(payload)
    changed[next(key for key in payload if key.endswith("_digest"))] = "sha256:" + "f" * 64
    assert construct_identity(kind, changed).digest != record.digest
    with pytest.raises(FoundationValidationError, match="unknown_field"):
        construct_identity(kind, {**payload, "unknown": "value"})


@pytest.mark.parametrize(
    ("source", "code"),
    [
        (b'{"a":1,"a":2}', "duplicate_key"),
        (b'{"a":1.5}', "float_not_allowed"),
        (b'{"a":1e2}', "float_not_allowed"),
        (b'{"a":9007199254740992}', "unsafe_integer"),
        (b'{"a":null}', "null_not_allowed"),
        (b'\xef\xbb\xbf{"a":1}', "bom_not_allowed"),
        (b'{"a":"\xff"}', "invalid_utf8"),
        (b'{"a":"\\ud800"}', "invalid_unicode"),
        ('{"a":"e\u0301"}'.encode(), "non_nfc"),
    ],
)
def test_strict_parser_rejects_each_ambiguous_class(source: bytes, code: str) -> None:
    with pytest.raises(FoundationValidationError) as caught:
        strict_parse_json(source)
    assert caught.value.code == code
    assert repr(source) not in str(caught.value)


@pytest.mark.parametrize(
    "source",
    [
        b'{ "a": 1 }\n',
        b'{"b":1,"a":2}\n',
        b'{"a":"\\u0061"}\n',
        b'{"a":1}',
        b'{"a":1}\n\n',
    ],
)
def test_stored_bytes_must_be_canonical(source: bytes) -> None:
    with pytest.raises(FoundationValidationError) as caught:
        verify_canonical_json_bytes(source)
    assert caught.value.code == "non_canonical_bytes"


def test_encoding_uses_exact_escapes_literal_unicode_and_one_lf() -> None:
    assert canonical_json_bytes({"z": "é/\b\u0001", "a": True}) == (
        b'{"a":true,"z":"\xc3\xa9/\\b\\u0001"}\n'
    )


def test_identity_domain_separation_and_digest_mutation() -> None:
    payload = canonical_json_bytes({"public_id": "artifact:one", "schema_version": 1, "artifact_digest": "sha256:" + "1" * 64})
    artifact = identity_digest("artifact", payload)
    with pytest.raises(FoundationValidationError):
        verify_identity("base", payload, identity_digest("base", payload))
    changed = construct_identity("artifact", {"public_id": "artifact:one", "schema_version": 1, "artifact_digest": "sha256:" + "2" * 64})
    assert changed.digest != artifact
