"""Strict canonical public identities for the v0.3 foundation.

The encoder is deliberately smaller than general JSON.  It provides one
reproducible byte grammar for identities and receipts and never normalizes or
coerces caller input on the way to a digest.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from importlib import resources
import json
import re
import unicodedata
from typing import Any, NoReturn


_SAFE_INTEGER = 9_007_199_254_740_991
_IDENTITY_PREFIX = b"unrest.identity-fingerprint.v1\0"
_CATALOG_RESOURCE = "bundled/foundation/identity-catalog.v2.json"


class FoundationValidationError(ValueError):
    """A bounded validation failure that never includes rejected input."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True)
class IdentityKind:
    id: str
    domain: str
    required_dimensions: tuple[str, ...]
    consumers: tuple[str, ...]
    payload_schema: Mapping[str, Any]


@dataclass(frozen=True)
class IdentityCatalog:
    schema_version: int
    kinds: Mapping[str, IdentityKind]


@dataclass(frozen=True)
class IdentityRecord:
    kind: str
    payload: Mapping[str, Any]
    digest: str
    canonical_bytes: bytes


def _fail(code: str, path: str = "$") -> NoReturn:
    raise FoundationValidationError(code, path)


def _reject_float(_: str) -> NoReturn:
    _fail("float_not_allowed")


def _reject_constant(_: str) -> NoReturn:
    _fail("non_json_number")


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("duplicate_key")
        value[key] = item
    return value


def _validate_string(value: str, path: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail("invalid_unicode", path)
    if unicodedata.normalize("NFC", value) != value:
        _fail("non_nfc", path)


def validate_canonical_value(value: Any, path: str = "$") -> None:
    """Validate the schema-independent Canonical JSON v1 data model."""

    if value is None:
        _fail("null_not_allowed", path)
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -_SAFE_INTEGER <= value <= _SAFE_INTEGER:
            _fail("unsafe_integer", path)
        return
    if isinstance(value, float):
        _fail("float_not_allowed", path)
    if isinstance(value, str):
        _validate_string(value, path)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("non_string_key", path)
            _validate_string(key, f"{path}{{key}}")
            validate_canonical_value(item, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        for index, item in enumerate(value):
            validate_canonical_value(item, f"{path}[{index}]")
        return
    _fail("unsupported_type", path)


def strict_parse_json(source: bytes | bytearray | memoryview) -> Any:
    """Parse JSON bytes without accepting any Canonical JSON v1 ambiguity."""

    raw = bytes(source)
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("bom_not_allowed")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("invalid_utf8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_to_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except FoundationValidationError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _fail("invalid_json")
    validate_canonical_value(value)
    return value


def _encode_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _encode_value(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, Mapping):
        return "{" + ",".join(
            f"{_encode_string(key)}:{_encode_value(value[key])}"
            for key in sorted(value)
        ) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return "[" + ",".join(_encode_value(item) for item in value) + "]"
    _fail("unsupported_type")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a validated value with exactly one trailing LF."""

    validate_canonical_value(value)
    return (_encode_value(value) + "\n").encode("utf-8")


def verify_canonical_json_bytes(source: bytes | bytearray | memoryview) -> Any:
    """Parse stored bytes and reject encodings that merely decode equivalently."""

    raw = bytes(source)
    value = strict_parse_json(raw)
    if canonical_json_bytes(value) != raw:
        _fail("non_canonical_bytes")
    return value


def validate_closed_schema(value: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    """Validate the finite schema vocabulary used by bundled foundation assets."""

    alternatives = schema.get("one_of")
    if isinstance(alternatives, list):
        matches = 0
        for alternative in alternatives:
            try:
                validate_closed_schema(value, alternative, path)
            except FoundationValidationError:
                continue
            matches += 1
        if matches != 1:
            _fail("schema_violation", path)
        return

    declared_type = schema.get("type")
    if declared_type == "object":
        if not isinstance(value, Mapping):
            _fail("schema_violation", path)
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            _fail("invalid_schema", path)
        missing = [key for key in required if key not in value]
        if missing:
            _fail("schema_violation", f"{path}.{missing[0]}")
        if schema.get("additional_properties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                _fail("unknown_field", f"{path}.{unknown[0]}")
        for key, item in value.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                validate_closed_schema(item, child_schema, f"{path}.{key}")
    elif declared_type == "array":
        if not isinstance(value, list):
            _fail("schema_violation", path)
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_closed_schema(item, item_schema, f"{path}[{index}]")
        if schema.get("unique_items") and len({_encode_value(item) for item in value}) != len(value):
            _fail("schema_violation", path)
    elif declared_type == "string":
        if not isinstance(value, str):
            _fail("schema_violation", path)
        minimum = schema.get("min_length")
        if isinstance(minimum, int) and len(value) < minimum:
            _fail("schema_violation", path)
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            _fail("schema_violation", path)
    elif declared_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            _fail("schema_violation", path)
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            _fail("schema_violation", path)
        if isinstance(maximum, int) and value > maximum:
            _fail("schema_violation", path)
    elif declared_type == "boolean":
        if not isinstance(value, bool):
            _fail("schema_violation", path)
    elif declared_type is not None:
        _fail("invalid_schema", path)

    if "const" in schema and value != schema["const"]:
        _fail("schema_violation", path)
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        _fail("schema_violation", path)


def _read_catalog_asset() -> Mapping[str, Any]:
    package_root = resources.files("unrest_harness")
    raw = package_root.joinpath(_CATALOG_RESOURCE).read_bytes()
    value = strict_parse_json(raw)
    if not isinstance(value, Mapping):
        _fail("invalid_catalog")
    return value


@lru_cache(maxsize=1)
def load_identity_catalog() -> IdentityCatalog:
    """Load and validate the installed 24-kind Identity Catalog v2."""

    document = _read_catalog_asset()
    if document.get("schema_version") != 2:
        _fail("invalid_catalog", "$.schema_version")
    field_definitions = document.get("field_definitions")
    entries = document.get("identity_kinds")
    if not isinstance(field_definitions, Mapping) or not isinstance(entries, list):
        _fail("invalid_catalog")
    kinds: dict[str, IdentityKind] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            _fail("invalid_catalog")
        kind_id = entry.get("id")
        domain = entry.get("domain")
        dimensions = entry.get("required_dimensions")
        consumers = entry.get("consumers")
        if (
            not isinstance(kind_id, str)
            or not isinstance(domain, str)
            or not domain.isascii()
            or not isinstance(dimensions, list)
            or not all(isinstance(item, str) for item in dimensions)
            or not isinstance(consumers, list)
            or not all(isinstance(item, str) for item in consumers)
            or kind_id in kinds
        ):
            _fail("invalid_catalog")
        required = ["schema_version", "public_id", *dimensions]
        properties: dict[str, Any] = {}
        for field in required:
            definition = field_definitions.get(field)
            if not isinstance(definition, Mapping):
                _fail("invalid_catalog", f"$.field_definitions.{field}")
            properties[field] = definition
        properties["public_id"] = {
            "pattern": f"^{re.escape(kind_id)}:[a-z0-9:-]+$",
            "type": "string",
        }
        schema = {
            "additional_properties": False,
            "properties": properties,
            "required": required,
            "type": "object",
        }
        kinds[kind_id] = IdentityKind(
            id=kind_id,
            domain=domain,
            required_dimensions=tuple(dimensions),
            consumers=tuple(consumers),
            payload_schema=schema,
        )
    expected = {
        "accepted_working_point", "artifact", "base", "budget", "candidate", "campaign",
        "context", "control_operation", "environment", "evaluator", "evidence", "inquiry",
        "inquiry_branch", "inquiry_handoff", "inquiry_synthesis", "policy",
        "provider_configuration", "review", "route_profile", "run", "secret_set_version",
        "seed", "workload", "workspace_lease",
    }
    if set(kinds) != expected:
        _fail("invalid_catalog", "$.identity_kinds")
    return IdentityCatalog(schema_version=2, kinds=kinds)


def identity_digest(kind: str, payload_bytes: bytes) -> str:
    """Compute an identity digest from already-canonical payload bytes."""

    entry = load_identity_catalog().kinds.get(kind)
    if entry is None:
        _fail("unknown_identity_kind", "$.kind")
    verify_canonical_json_bytes(payload_bytes)
    preimage = _IDENTITY_PREFIX + entry.domain.encode("ascii") + b"\0" + payload_bytes
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def construct_identity(kind: str, payload: Mapping[str, Any]) -> IdentityRecord:
    """Validate and construct one closed identity record."""

    entry = load_identity_catalog().kinds.get(kind)
    if entry is None:
        _fail("unknown_identity_kind", "$.kind")
    validate_canonical_value(payload)
    validate_closed_schema(payload, entry.payload_schema)
    encoded = canonical_json_bytes(payload)
    return IdentityRecord(
        kind=kind,
        payload=dict(payload),
        digest=identity_digest(kind, encoded),
        canonical_bytes=encoded,
    )


def verify_identity(kind: str, stored_bytes: bytes, expected_digest: str) -> IdentityRecord:
    """Verify kind, schema, canonical stored bytes, and digest together."""

    payload = verify_canonical_json_bytes(stored_bytes)
    if not isinstance(payload, Mapping):
        _fail("schema_violation")
    record = construct_identity(kind, payload)
    if record.canonical_bytes != stored_bytes:
        _fail("non_canonical_bytes")
    if record.digest != expected_digest:
        _fail("digest_mismatch", "$.digest")
    return record


__all__ = [
    "FoundationValidationError",
    "IdentityCatalog",
    "IdentityKind",
    "IdentityRecord",
    "canonical_json_bytes",
    "construct_identity",
    "identity_digest",
    "load_identity_catalog",
    "strict_parse_json",
    "validate_canonical_value",
    "validate_closed_schema",
    "verify_canonical_json_bytes",
    "verify_identity",
]
