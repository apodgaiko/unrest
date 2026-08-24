"""Nine-family append-only receipts and derived freshness.

Receipt integrity, issuer authority, freshness, and operation authorization are
separate checks.  In particular, a valid digest is never treated as a grant.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import lru_cache
import hashlib
from importlib import resources
import re
from typing import Any

from .canonical_identity import (
    FoundationValidationError,
    canonical_json_bytes,
    load_identity_catalog,
    strict_parse_json,
    validate_canonical_value,
    validate_closed_schema,
    verify_canonical_json_bytes,
)


_RECEIPT_PREFIX = b"unrest.receipt.v1\0"
_CATALOG_RESOURCE = "bundled/foundation/receipt-catalog.v1.json"
_DIGEST = {"pattern": "^sha256:[0-9a-f]{64}$", "type": "string"}
_NONEMPTY = {"min_length": 1, "type": "string"}
_SAFE_INT = {"maximum": 9_007_199_254_740_991, "minimum": -9_007_199_254_740_991, "type": "integer"}
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


@dataclass(frozen=True)
class ReceiptFamily:
    id: str
    issuer_authority: str
    subject_kind: str
    dependencies: tuple[Mapping[str, Any], ...]
    outcomes: tuple[str, ...]
    terminal_dispositions: tuple[str, ...]
    consumers: tuple[str, ...]
    expiry_rule: str
    revocation_authority: str
    signature_policy: str


@dataclass(frozen=True)
class ReceiptCatalog:
    schema_version: int
    families: Mapping[str, ReceiptFamily]
    local_authoritative_consumers: frozenset[str]


@dataclass(frozen=True)
class ReceiptRecord:
    family: str
    record: Mapping[str, Any]
    digest: str
    canonical_bytes: bytes


class FreshnessStatus(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    REVOKED = "revoked"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class AuthorityGrant:
    authority_class: str
    decision_ref: str
    issuer_id: str
    issuer_identity_digest: str
    grantor_id: str


@dataclass(frozen=True)
class FreshnessResult:
    status: FreshnessStatus
    reason: str


@dataclass(frozen=True)
class ReceiptExport:
    canonical_bytes: bytes
    authoritative: bool
    label: str


def _optional_schema(value_schema: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "one_of": [
            {
                "additional_properties": False,
                "properties": {"state": {"const": "absent", "type": "string"}},
                "required": ["state"],
                "type": "object",
            },
            {
                "additional_properties": False,
                "properties": {
                    "state": {"const": "present", "type": "string"},
                    "value": value_schema,
                },
                "required": ["state", "value"],
                "type": "object",
            },
        ]
    }


def _common_schema() -> Mapping[str, Any]:
    identity_kinds = sorted(load_identity_catalog().kinds)
    receipt_kinds = sorted(load_receipt_catalog().families)
    dependency_kinds = [*identity_kinds, *receipt_kinds]
    return {
        "additional_properties": False,
        "properties": {
            "append_only_disposition": {"const": "immutable", "type": "string"},
            "artifact_refs": {
                "items": {
                    "additional_properties": False,
                    "properties": {
                        "artifact_digest": _DIGEST,
                        "artifact_id": _NONEMPTY,
                        "media_type": _NONEMPTY,
                        "size_bytes": _SAFE_INT,
                    },
                    "required": ["artifact_id", "artifact_digest", "media_type", "size_bytes"],
                    "type": "object",
                },
                "type": "array",
            },
            "chronology_is_authority": {"const": False, "type": "boolean"},
            "consumers": {"items": _NONEMPTY, "type": "array", "unique_items": True},
            "cost": {
                "additional_properties": False,
                "properties": {
                    "accounting_boundary": _NONEMPTY,
                    "completeness": {"enum": ["complete", "partial", "not_applicable"], "type": "string"},
                    "quantities": {
                        "items": {
                            "additional_properties": False,
                            "properties": {"amount": _SAFE_INT, "unit": _NONEMPTY},
                            "required": ["amount", "unit"],
                            "type": "object",
                        },
                        "type": "array",
                    },
                },
                "required": ["accounting_boundary", "completeness", "quantities"],
                "type": "object",
            },
            "dependencies": {
                "items": {
                    "additional_properties": False,
                    "properties": {
                        "dependency_digest": _DIGEST,
                        "dependency_id": _NONEMPTY,
                        "dependency_kind": {"enum": dependency_kinds, "type": "string"},
                        "dependency_type": {"enum": ["identity", "receipt"], "type": "string"},
                        "must_be_fresh": {"type": "boolean"},
                        "role": _NONEMPTY,
                    },
                    "required": ["dependency_type", "dependency_kind", "dependency_id", "dependency_digest", "role", "must_be_fresh"],
                    "type": "object",
                },
                "type": "array",
            },
            "deviations": {
                "items": {
                    "additional_properties": False,
                    "properties": {"code": _NONEMPTY, "decision_ref": _NONEMPTY, "interpretation_effect": _NONEMPTY, "scope": _NONEMPTY},
                    "required": ["code", "decision_ref", "scope", "interpretation_effect"],
                    "type": "object",
                },
                "type": "array",
            },
            "freshness_policy": {
                "additional_properties": False,
                "properties": {
                    "dependency_mode": {"const": "exact_typed_set", "type": "string"},
                    "expiry": _optional_schema({
                        "additional_properties": False,
                        "properties": {"expires_at": _NONEMPTY, "trusted_clock_id": _NONEMPTY},
                        "required": ["expires_at", "trusted_clock_id"],
                        "type": "object",
                    }),
                    "policy_id": _NONEMPTY,
                    "revocation_authority": _NONEMPTY,
                    "revocation_view": _optional_schema({
                        "additional_properties": False,
                        "properties": {"authority_decision_ref": _NONEMPTY, "watermark": _NONEMPTY},
                        "required": ["authority_decision_ref", "watermark"],
                        "type": "object",
                    }),
                    "unavailable_dependency": {"const": "unverifiable", "type": "string"},
                },
                "required": ["policy_id", "dependency_mode", "expiry", "revocation_authority", "revocation_view", "unavailable_dependency"],
                "type": "object",
            },
            "integrity": {
                "additional_properties": False,
                "properties": {
                    "canonicalization": {"const": "canonical-json-v1", "type": "string"},
                    "detached_signature": _optional_schema({
                        "additional_properties": False,
                        "properties": {"public_key_id": _NONEMPTY, "public_key_version": _NONEMPTY, "signature_artifact_digest": _DIGEST, "signature_artifact_id": _NONEMPTY, "suite_id": _NONEMPTY},
                        "required": ["public_key_id", "public_key_version", "signature_artifact_digest", "signature_artifact_id", "suite_id"],
                        "type": "object",
                    }),
                    "digest_algorithm": {"const": "sha256", "type": "string"},
                    "domain": {"const": "unrest.receipt.v1", "type": "string"},
                },
                "required": ["canonicalization", "detached_signature", "digest_algorithm", "domain"],
                "type": "object",
            },
            "issuer": {
                "additional_properties": False,
                "properties": {"identity_digest": _DIGEST, "issuer_id": _NONEMPTY, "issuer_kind": {"enum": identity_kinds, "type": "string"}},
                "required": ["identity_digest", "issuer_id", "issuer_kind"],
                "type": "object",
            },
            "issuer_authority": {
                "additional_properties": False,
                "properties": {"authority_class": _NONEMPTY, "decision_ref": _NONEMPTY},
                "required": ["authority_class", "decision_ref"],
                "type": "object",
            },
            "observed_at": _NONEMPTY,
            "outcome": _NONEMPTY,
            "receipt_digest": _DIGEST,
            "receipt_id": _NONEMPTY,
            "receipt_kind": {"enum": receipt_kinds, "type": "string"},
            "schema_version": {"const": 1, "type": "integer"},
            "sequence": _SAFE_INT,
            "subject": {
                "additional_properties": False,
                "properties": {"subject_digest": _DIGEST, "subject_id": _NONEMPTY, "subject_kind": {"enum": identity_kinds, "type": "string"}},
                "required": ["subject_digest", "subject_id", "subject_kind"],
                "type": "object",
            },
            "terminal_disposition": _NONEMPTY,
        },
        "required": ["append_only_disposition", "artifact_refs", "chronology_is_authority", "consumers", "cost", "dependencies", "deviations", "freshness_policy", "integrity", "issuer", "issuer_authority", "observed_at", "outcome", "receipt_digest", "receipt_id", "receipt_kind", "schema_version", "sequence", "subject", "terminal_disposition"],
        "type": "object",
    }


def _parse_utc(value: str, path: str) -> datetime:
    if _RFC3339_UTC.fullmatch(value) is None:
        raise FoundationValidationError("schema_violation", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FoundationValidationError("schema_violation", path) from exc
    return parsed.astimezone(UTC)


def _dependency_key(item: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item.get("dependency_type", "")),
        str(item.get("dependency_kind", "")),
        str(item.get("dependency_id", "")),
        str(item.get("role", "")),
    )


def _dependency_spec(item: Mapping[str, Any]) -> tuple[str, str, str, bool]:
    return (
        str(item.get("dependency_type", "")),
        str(item.get("dependency_kind", "")),
        str(item.get("role", "")),
        item.get("must_be_fresh") is True,
    )


def _is_sorted_unique(items: Sequence[Mapping[str, Any]], key: Any) -> bool:
    values = [key(item) for item in items]
    return values == sorted(set(values))


@lru_cache(maxsize=1)
def load_receipt_catalog() -> ReceiptCatalog:
    package_root = resources.files("unrest_harness")
    document = strict_parse_json(package_root.joinpath(_CATALOG_RESOURCE).read_bytes())
    if not isinstance(document, Mapping) or document.get("schema_version") != 1:
        raise FoundationValidationError("invalid_catalog")
    raw_families = document.get("receipt_families")
    raw_local = document.get("local_authoritative_consumers")
    if not isinstance(raw_families, list) or not isinstance(raw_local, list):
        raise FoundationValidationError("invalid_catalog")
    families: dict[str, ReceiptFamily] = {}
    for item in raw_families:
        if not isinstance(item, Mapping):
            raise FoundationValidationError("invalid_catalog")
        family_id = item.get("id")
        if not isinstance(family_id, str) or family_id in families:
            raise FoundationValidationError("invalid_catalog")
        try:
            dependencies = tuple(item["dependencies"])
            family = ReceiptFamily(
                id=family_id,
                issuer_authority=str(item["issuer_authority"]),
                subject_kind=str(item["subject_kind"]),
                dependencies=dependencies,
                outcomes=tuple(item["outcomes"]),
                terminal_dispositions=tuple(item["terminal_dispositions"]),
                consumers=tuple(item["consumers"]),
                expiry_rule=str(item["expiry_rule"]),
                revocation_authority=str(item["revocation_authority"]),
                signature_policy=str(item["signature_policy"]),
            )
        except (KeyError, TypeError) as exc:
            raise FoundationValidationError("invalid_catalog") from exc
        if family.consumers != tuple(sorted(set(family.consumers))):
            raise FoundationValidationError("invalid_catalog")
        if len({_dependency_spec(entry) for entry in dependencies}) != len(dependencies):
            raise FoundationValidationError("invalid_catalog")
        families[family_id] = family
    expected = {
        "cleanup_receipt.v1", "evaluation_receipt.v1", "integration_receipt.v1",
        "patch_receipt.v1", "promotion_receipt.v1", "review_receipt.v1",
        "rollback_receipt.v1", "run_receipt.v1", "workspace_receipt.v1",
    }
    if set(families) != expected or not all(isinstance(item, str) for item in raw_local):
        raise FoundationValidationError("invalid_catalog")
    return ReceiptCatalog(
        schema_version=1,
        families=families,
        local_authoritative_consumers=frozenset(raw_local),
    )


def _validate_family(record: Mapping[str, Any]) -> ReceiptFamily:
    family_id = record.get("receipt_kind")
    family = load_receipt_catalog().families.get(str(family_id))
    if family is None:
        raise FoundationValidationError("unknown_receipt_family", "$.receipt_kind")
    if record.get("issuer_authority", {}).get("authority_class") != family.issuer_authority:
        raise FoundationValidationError("unauthorized", "$.issuer_authority.authority_class")
    if record.get("subject", {}).get("subject_kind") != family.subject_kind:
        raise FoundationValidationError("schema_violation", "$.subject.subject_kind")
    if record.get("outcome") not in family.outcomes:
        raise FoundationValidationError("schema_violation", "$.outcome")
    if record.get("terminal_disposition") not in family.terminal_dispositions:
        raise FoundationValidationError("schema_violation", "$.terminal_disposition")
    if tuple(record.get("consumers", ())) != family.consumers:
        raise FoundationValidationError("unauthorized", "$.consumers")
    if record.get("freshness_policy", {}).get("revocation_authority") != family.revocation_authority:
        raise FoundationValidationError("unauthorized", "$.freshness_policy.revocation_authority")

    dependencies = record.get("dependencies")
    if not isinstance(dependencies, list) or not _is_sorted_unique(dependencies, _dependency_key):
        raise FoundationValidationError("schema_violation", "$.dependencies")
    if {_dependency_spec(item) for item in dependencies} != {
        _dependency_spec(item) for item in family.dependencies
    }:
        raise FoundationValidationError("stale", "$.dependencies")
    artifacts = record.get("artifact_refs")
    deviations = record.get("deviations")
    quantities = record.get("cost", {}).get("quantities")
    if not isinstance(artifacts, list) or not _is_sorted_unique(
        artifacts, lambda item: (str(item.get("artifact_id", "")), str(item.get("artifact_digest", "")))
    ):
        raise FoundationValidationError("schema_violation", "$.artifact_refs")
    if not isinstance(deviations, list) or not _is_sorted_unique(
        deviations, lambda item: (str(item.get("code", "")), str(item.get("decision_ref", "")), str(item.get("scope", "")))
    ):
        raise FoundationValidationError("schema_violation", "$.deviations")
    if not isinstance(quantities, list) or not _is_sorted_unique(
        quantities, lambda item: str(item.get("unit", ""))
    ):
        raise FoundationValidationError("schema_violation", "$.cost.quantities")
    _parse_utc(str(record.get("observed_at", "")), "$.observed_at")
    expiry = record.get("freshness_policy", {}).get("expiry", {})
    if expiry.get("state") == "present":
        _parse_utc(str(expiry.get("value", {}).get("expires_at", "")), "$.freshness_policy.expiry.value.expires_at")
    return family


def receipt_digest(family: str, record_without_digest: Mapping[str, Any]) -> str:
    if family not in load_receipt_catalog().families:
        raise FoundationValidationError("unknown_receipt_family", "$.receipt_kind")
    encoded = canonical_json_bytes(record_without_digest)
    preimage = _RECEIPT_PREFIX + family.encode("ascii") + b"\0" + encoded
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def construct_receipt(fields: Mapping[str, Any]) -> ReceiptRecord:
    """Construct a complete receipt, computing or checking its self-digest."""

    validate_canonical_value(fields)
    record = dict(fields)
    supplied_digest = record.pop("receipt_digest", None)
    family_id = record.get("receipt_kind")
    if not isinstance(family_id, str):
        raise FoundationValidationError("schema_violation", "$.receipt_kind")
    computed = receipt_digest(family_id, record)
    if supplied_digest is not None and supplied_digest != computed:
        raise FoundationValidationError("digest_mismatch", "$.receipt_digest")
    record["receipt_digest"] = computed
    validate_closed_schema(record, _common_schema())
    _validate_family(record)
    encoded = canonical_json_bytes(record)
    return ReceiptRecord(family=family_id, record=record, digest=computed, canonical_bytes=encoded)


def verify_receipt(stored_bytes: bytes, expected_digest: str | None = None) -> ReceiptRecord:
    parsed = verify_canonical_json_bytes(stored_bytes)
    if not isinstance(parsed, Mapping):
        raise FoundationValidationError("schema_violation")
    record = construct_receipt(parsed)
    if record.canonical_bytes != stored_bytes:
        raise FoundationValidationError("non_canonical_bytes")
    if expected_digest is not None and record.digest != expected_digest:
        raise FoundationValidationError("digest_mismatch", "$.receipt_digest")
    return record


def derive_freshness(
    receipt: ReceiptRecord,
    *,
    consumer_id: str,
    issuer_grant: AuthorityGrant | None,
    current_dependencies: Sequence[Mapping[str, Any]] | None,
    revocation_view_available: bool,
    revoked_receipt_digests: frozenset[str] = frozenset(),
    trusted_now: datetime | None = None,
    upstream_freshness: Mapping[str, FreshnessStatus] | None = None,
) -> FreshnessResult:
    """Derive freshness from authority and current state, never chronology."""

    try:
        checked = verify_receipt(receipt.canonical_bytes, receipt.digest)
    except FoundationValidationError:
        return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "integrity")
    family = load_receipt_catalog().families[checked.family]
    if consumer_id not in family.consumers:
        return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "consumer")
    issuer = checked.record["issuer"]
    authority = checked.record["issuer_authority"]
    if (
        issuer_grant is None
        or issuer_grant.grantor_id == issuer_grant.issuer_id
        or issuer_grant.authority_class != family.issuer_authority
        or issuer_grant.authority_class != authority["authority_class"]
        or issuer_grant.decision_ref != authority["decision_ref"]
        or issuer_grant.issuer_id != issuer["issuer_id"]
        or issuer_grant.issuer_identity_digest != issuer["identity_digest"]
    ):
        return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "issuer_authority")
    if current_dependencies is None:
        return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "dependencies_unavailable")
    expected = {
        _dependency_key(item): item.get("dependency_digest")
        for item in checked.record["dependencies"]
    }
    current = {_dependency_key(item): item.get("dependency_digest") for item in current_dependencies}
    if expected != current or len(current) != len(current_dependencies):
        return FreshnessResult(FreshnessStatus.STALE, "dependency_mismatch")
    upstream = upstream_freshness or {}
    for dependency in checked.record["dependencies"]:
        if dependency["dependency_type"] == "receipt" and dependency["must_be_fresh"]:
            status = upstream.get(dependency["dependency_digest"])
            if status is None:
                return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "upstream_unavailable")
            if status is not FreshnessStatus.FRESH:
                return FreshnessResult(FreshnessStatus.STALE, "upstream_not_fresh")
    if not revocation_view_available:
        return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "revocation_view_unavailable")
    if checked.digest in revoked_receipt_digests:
        return FreshnessResult(FreshnessStatus.REVOKED, "revoked")
    expiry = checked.record["freshness_policy"]["expiry"]
    if expiry["state"] == "present":
        if trusted_now is None:
            return FreshnessResult(FreshnessStatus.UNVERIFIABLE, "clock_unavailable")
        expires_at = _parse_utc(expiry["value"]["expires_at"], "$.freshness_policy.expiry")
        now = trusted_now if trusted_now.tzinfo is not None else trusted_now.replace(tzinfo=UTC)
        if now.astimezone(UTC) >= expires_at:
            return FreshnessResult(FreshnessStatus.STALE, "expired")
    return FreshnessResult(FreshnessStatus.FRESH, "verified")


def export_receipt(
    receipt: ReceiptRecord,
    *,
    consumer_id: str,
    authoritative: bool,
    local_custody_verified: bool,
) -> ReceiptExport:
    """Export a receipt without pretending an unsupported signature exists."""

    checked = verify_receipt(receipt.canonical_bytes, receipt.digest)
    if not authoritative:
        return ReceiptExport(checked.canonical_bytes, False, "integrity_only_non_authoritative")
    catalog = load_receipt_catalog()
    family = catalog.families[checked.family]
    if consumer_id not in catalog.local_authoritative_consumers:
        raise FoundationValidationError("signature_suite_unsupported", "$.consumer_id")
    if consumer_id not in family.consumers:
        raise FoundationValidationError("unauthorized", "$.consumer_id")
    if not local_custody_verified:
        raise FoundationValidationError("signature_suite_unsupported", "$.consumer_id")
    return ReceiptExport(checked.canonical_bytes, True, "verified_local_custody")


__all__ = [
    "AuthorityGrant",
    "FreshnessResult",
    "FreshnessStatus",
    "ReceiptCatalog",
    "ReceiptExport",
    "ReceiptFamily",
    "ReceiptRecord",
    "construct_receipt",
    "derive_freshness",
    "export_receipt",
    "load_receipt_catalog",
    "receipt_digest",
    "verify_receipt",
]
