"""Versioned, fail-closed role capability policy and runtime enforcement helpers."""
from __future__ import annotations

import base64
import binascii
import builtins
import copy
import hashlib
import ast
import importlib.util
import json
import math
import os
import re
import string
import tomllib
import urllib.parse
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

if TYPE_CHECKING:
    from .providers import ProviderDefinition

CAPABILITY_POLICY_VERSION = 1
SAFE_PROFILE = "safe"
UNSAFE_DEVELOPMENT_PROFILE = "unsafe-development-unrestricted"
UNSAFE_DEVELOPMENT_ENV = "UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED"
CAPABILITY_PROFILE_ENV = "UNREST_CAPABILITY_PROFILE"
CAPABILITY_VERSION_ENV = "UNREST_CAPABILITY_POLICY_VERSION"

RoleName = Literal["orchestrator", "worker", "validator", "terminal_reviewer"]
RootName = Literal["workspace", "project_record", "deliverable_roots", "host"]
ToolKind = Literal[
    "read",
    "edit",
    "delete",
    "move",
    "search",
    "execute",
    "think",
    "fetch",
    "other",
]
SECURITY_TRANSFORM_IDS = (
    "base64-standard-utf8",
    "base64-urlsafe-unpadded-utf8",
    "delimited-container",
    "hex-utf8",
    "json",
    "percent-utf8",
    "python-format-ast",
    "toml",
    "uri-fields",
)
SECURITY_SEMANTIC_ROLE_IDS = (
    "container-item",
    "format-attribute",
    "format-conversion",
    "format-index",
    "format-nested-field",
    "format-root",
    "format-spec-literal",
    "mapping-key",
    "mapping-value",
    "root",
    "sequence-item",
    "uri-fragment-field",
    "uri-matrix-field",
    "uri-path-field",
    "uri-query-field",
    "uri-userinfo-field",
)
CAPABILITY_SINK_IDS = (
    "acp-adapter-stderr",
    "acp-callback-errors",
    "acp-callback-results",
    "acp-outbound-requests",
    "acp-progress",
    "acp-request-errors",
    "acp-request-results",
    "acp-terminal-output",
    "acp-wire-write",
    "agent-environment",
    "artifact-atomic-boundary",
    "attempt-handoff-json",
    "cli-atomic-text-boundary",
    "codex-structured-config",
    "diagnostic-errors",
    "generated-bootstrap-config",
    "generated-claude-user-config",
    "generated-codex-user-config",
    "installed-policy-assets",
    "mcp-environment",
    "mcp-sensitive-inventory-channel",
    "synthesized-handoff",
    "terminal-environment",
    "terminal-review-handoff-json",
    "terminal-review-stderr",
    "worker-filesystem-write",
    "worker-handoff-json",
)
CAPABILITY_SINK_OMISSION_IDS = (
    "acp-cancel-client-cleanup",
    "acp-cancel-read-loop",
    "acp-cancel-terminal-review",
    "acp-node-request-callers",
    "acp-session-mode-request-caller",
    "acp-session-update-callback-delegation",
    "acp-terminal-review-progress-print",
    "acp-terminal-review-request-callers",
    "baseline-cli-output",
    "baseline-fixture-bytes",
    "baseline-running-mission-fixture",
    "baseline-storage-fixture",
    "capability-projection-owner-path-reversal",
    "generated-managed-config-block",
    "generated-provider-assets",
    "generated-provider-settings",
    "installed-wheel-lifecycle-fixtures",
    "mock-dispatcher-callback",
    "repository-contract-html-stack-reverse",
    "storage-atomic-json",
    "storage-attempt",
    "storage-attention",
    "storage-contract-state",
    "storage-decision",
    "storage-mission-closeout",
    "storage-project-create",
    "storage-project-record",
    "storage-state",
    "storage-task-list",
    "storage-task-state",
    "storage-terminal-review",
    "storage-terminal-review-config",
)


class StrictPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RootCapability(StrictPolicyModel):
    name: RootName
    read: bool
    write: bool

    @model_validator(mode="after")
    def write_requires_read(self) -> RootCapability:
        if self.write and not self.read:
            raise ValueError("write access requires read access")
        return self


class ProcessCapability(StrictPolicyModel):
    enabled: bool
    commands: tuple[str, ...]

    @model_validator(mode="after")
    def commands_match_enabled_state(self) -> ProcessCapability:
        if not self.enabled and self.commands:
            raise ValueError("disabled process capability cannot declare commands")
        if self.enabled and not self.commands:
            raise ValueError("enabled process capability requires commands")
        if len(set(self.commands)) != len(self.commands):
            raise ValueError("process commands must be unique")
        return self


class NetworkCapability(StrictPolicyModel):
    mode: Literal["allow", "deny"]


class EnvironmentCapability(StrictPolicyModel):
    forward: tuple[str, ...]
    credentials: tuple[str, ...]
    terminal_injection: tuple[str, ...]
    internal: tuple[str, ...]
    inherit_all: bool = False

    @model_validator(mode="after")
    def names_are_deterministic(self) -> EnvironmentCapability:
        for field_name in ("forward", "credentials", "terminal_injection", "internal"):
            values = getattr(self, field_name)
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name} names must be unique")
            if tuple(sorted(values)) != values:
                raise ValueError(f"{field_name} names must be sorted")
        if self.inherit_all and (
            self.forward != ("*",)
            or self.credentials != ("*",)
            or self.terminal_injection != ("*",)
        ):
            raise ValueError("inherit_all requires '*' forwarding declarations")
        if not self.inherit_all and "*" in (
            *self.forward,
            *self.credentials,
            *self.terminal_injection,
        ):
            raise ValueError("'*' is reserved for inherit_all profiles")
        return self


class ApprovalCapability(StrictPolicyModel):
    behavior: Literal["deny", "allow_once"]
    tool_kinds: tuple[ToolKind, ...]

    @model_validator(mode="after")
    def deny_has_no_allowed_kinds(self) -> ApprovalCapability:
        if self.behavior == "deny" and self.tool_kinds:
            raise ValueError("deny approval behavior cannot declare allowed tool kinds")
        if len(set(self.tool_kinds)) != len(self.tool_kinds):
            raise ValueError("approval tool kinds must be unique")
        return self


class RoleCapability(StrictPolicyModel):
    filesystem: tuple[RootCapability, ...]
    process: ProcessCapability
    network: NetworkCapability
    environment: EnvironmentCapability
    approvals: ApprovalCapability

    @model_validator(mode="after")
    def roots_are_unique(self) -> RoleCapability:
        names = [item.name for item in self.filesystem]
        if len(set(names)) != len(names):
            raise ValueError("filesystem root names must be unique")
        return self


class RoleCapabilities(StrictPolicyModel):
    orchestrator: RoleCapability
    worker: RoleCapability
    validator: RoleCapability
    terminal_reviewer: RoleCapability

    def for_role(self, role: RoleName) -> RoleCapability:
        return getattr(self, role)


class CapabilityProfiles(StrictPolicyModel):
    safe: RoleCapabilities
    unsafe_development_unrestricted: RoleCapabilities = Field(
        alias="unsafe-development-unrestricted",
    )

    def named(self, profile: str) -> RoleCapabilities:
        if profile == SAFE_PROFILE:
            return self.safe
        if profile == UNSAFE_DEVELOPMENT_PROFILE:
            return self.unsafe_development_unrestricted
        raise KeyError(profile)


class CapabilityPolicy(StrictPolicyModel):
    policy_id: Literal["unrest-role-capabilities"]
    schema_version: Literal[1]
    profiles: CapabilityProfiles

    def role(self, profile: str, role: RoleName) -> RoleCapability:
        return self.profiles.named(profile).for_role(role)


class SecurityTransform(StrictPolicyModel):
    id: str
    kind: Literal["structural", "string", "grammar"]
    reversible: bool


class SecuritySemanticRole(StrictPolicyModel):
    id: str
    propagates_parent_provenance: bool


class SecurityJoin(StrictPolicyModel):
    id: str
    operation: Literal["set-union"]
    commutative: Literal[True]
    idempotent: Literal[True]
    monotonic: Literal[True]


class SecurityCeilings(StrictPolicyModel):
    text_bytes: int
    semantic_depth: int
    semantic_nodes: int
    transform_count: int
    decoded_bytes: int
    aggregate_work_bytes: int
    format_ast_depth: int
    expansion_nodes: int


class CapabilitySecurityModel(StrictPolicyModel):
    model_id: Literal["unrest-capability-security-model"]
    schema_version: Literal[1]
    transforms: tuple[SecurityTransform, ...]
    semantic_roles: tuple[SecuritySemanticRole, ...]
    joins: tuple[SecurityJoin, ...]
    ceilings: SecurityCeilings
    sink_catalog: Literal["capability-sinks.v1.json"]
    unsupported_behavior: Literal["fail-closed"]
    exhaustion_behavior: Literal["fail-closed-with-concrete-provenance"]

    @model_validator(mode="after")
    def closed_members_are_sorted_and_unique(self) -> CapabilitySecurityModel:
        for field_name in ("transforms", "semantic_roles", "joins"):
            records = getattr(self, field_name)
            ids = tuple(record.id for record in records)
            if ids != tuple(sorted(set(ids))):
                raise ValueError(f"{field_name} must be sorted and unique")
        if tuple(record.id for record in self.transforms) != SECURITY_TRANSFORM_IDS:
            raise ValueError("transforms do not match the reachable version-1 implementation")
        if (
            tuple(record.id for record in self.semantic_roles)
            != SECURITY_SEMANTIC_ROLE_IDS
        ):
            raise ValueError(
                "semantic_roles do not match the reachable version-1 implementation"
            )
        if tuple(record.id for record in self.joins) != ("sensitivity-provenance",):
            raise ValueError("joins do not match the version-1 provenance algebra")
        expected_ceilings = {
            "aggregate_work_bytes": 2 * 1024 * 1024,
            "decoded_bytes": 1024 * 1024,
            "expansion_nodes": 4096,
            "format_ast_depth": 4,
            "semantic_depth": 24,
            "semantic_nodes": 4096,
            "text_bytes": 256 * 1024,
            "transform_count": 24,
        }
        if self.ceilings.model_dump() != expected_ceilings:
            raise ValueError("ceilings do not match the version-1 implementation")
        return self


class CapabilitySink(StrictPolicyModel):
    id: str
    sink_class: Literal[
        "runtime",
        "protocol",
        "diagnostic",
        "artifact",
        "package",
    ]
    implementation: str
    enforcement: str
    inventory: Literal["SensitiveValueInventory"]


class CapabilitySinkOmission(StrictPolicyModel):
    id: str
    implementation: str
    reason: str


class CapabilitySinkCatalog(StrictPolicyModel):
    catalog_id: Literal["unrest-capability-sinks"]
    schema_version: Literal[1]
    reachable_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    omissions: tuple[CapabilitySinkOmission, ...]
    sinks: tuple[CapabilitySink, ...]

    @model_validator(mode="after")
    def sinks_are_sorted_and_unique(self) -> CapabilitySinkCatalog:
        ids = tuple(sink.id for sink in self.sinks)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("sinks must be sorted and unique")
        if ids != CAPABILITY_SINK_IDS:
            raise ValueError("sinks do not match the reachable version-1 implementation")
        omission_ids = tuple(item.id for item in self.omissions)
        if omission_ids != tuple(sorted(set(omission_ids))):
            raise ValueError("omissions must be sorted and unique")
        if omission_ids != CAPABILITY_SINK_OMISSION_IDS:
            raise ValueError("omissions do not match the reachable version-1 implementation")
        return self


class CapabilityPolicyError(ValueError):
    """Stable provider/role/version/capability diagnostic."""

    def __init__(
        self,
        *,
        provider: str,
        role: str,
        version: int | str,
        capability: str,
        reason: str,
    ) -> None:
        provider = _diagnostic_identifier(
            provider,
            allowed={"claude", "codex", "hermes", "unresolved"},
        )
        role = _diagnostic_identifier(
            role,
            allowed={"orchestrator", "worker", "validator", "terminal_reviewer", "unresolved"},
        )
        version = (
            version
            if isinstance(version, int)
            else _diagnostic_identifier(str(version), allowed={"1"})
        )
        allowed_capabilities = {
            CAPABILITY_PROFILE_ENV,
            CAPABILITY_VERSION_ENV,
            UNSAFE_DEVELOPMENT_ENV,
            "network:allow",
            "network:deny",
            "policy-document",
            "policy-version",
            "profile:safe",
            f"profile:{UNSAFE_DEVELOPMENT_PROFILE}",
            "provider",
            "role",
            "security-model",
            "sink-catalog",
            "unsafe-development-opt-in",
        }
        capability = _diagnostic_identifier(
            capability,
            allowed=allowed_capabilities,
        )
        self.provider = provider
        self.role = role
        self.version = version
        self.capability = capability
        self.reason = reason
        super().__init__(
            "CAP-POLICY-001 "
            f"provider={provider} role={role} version={version} "
            f"capability={capability}: {reason}"
        )


def _diagnostic_identifier(value: str, *, allowed: set[str]) -> str:
    if value in allowed:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"opaque#{digest}"


class CapabilityAccessError(PermissionError):
    """A stable runtime denial raised by ACP callback enforcement."""

    def __init__(self, capability: str, reason: str) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(f"CAP-ACCESS-001 capability={capability}: {reason}")


class CapabilityBoundaryError(ValueError):
    """Stable, value-free canonical inventory/redaction failure."""

    def __init__(
        self,
        classification: Literal[
            "cyclic-container",
            "resource-exhausted",
            "unsupported-container",
        ],
    ) -> None:
        self.classification = classification
        super().__init__(
            "CAP-BOUNDARY-001 "
            f"classification={classification}: output blocked before serialization"
        )


_CapabilityAssetModel = TypeVar("_CapabilityAssetModel", bound=BaseModel)


class _DuplicateCapabilityAssetMember(ValueError):
    """Internal signal for an ambiguous JSON object member."""


def _load_strict_capability_asset(
    path: Path,
    *,
    model: type[_CapabilityAssetModel],
    capability: str,
    resource_kind: str,
) -> _CapabilityAssetModel:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateCapabilityAssetMember
            result[key] = value
        return result

    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
        return model.model_validate(raw)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateCapabilityAssetMember,
        ValidationError,
    ) as exc:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=CAPABILITY_POLICY_VERSION,
            capability=capability,
            reason=f"cannot load strict {resource_kind} resource {path.name}",
        ) from exc


@dataclass(frozen=True)
class ResolvedRoot:
    name: RootName
    path: Path
    read: bool
    write: bool


@dataclass(frozen=True)
class ResolvedRoleCapability:
    provider: str
    role: RoleName
    profile: str
    version: int
    roots: tuple[ResolvedRoot, ...]
    process: ProcessCapability
    network: NetworkCapability
    environment: EnvironmentCapability
    approvals: ApprovalCapability

    def authorize_path(
        self,
        raw_path: str | os.PathLike[str],
        *,
        access: Literal["read", "write", "cwd"],
        working_dir: Path,
    ) -> Path:
        path = Path(raw_path)
        if not path.is_absolute():
            path = working_dir / path
        candidate = _canonical_access_path(path, for_write=access == "write")
        for root in self.roots:
            permitted = root.read if access in ("read", "cwd") else root.write
            if permitted and _is_within(candidate, root.path):
                return candidate
        raise CapabilityAccessError(
            f"filesystem:{access}",
            f"path is outside permitted canonical roots for role={self.role}",
        )

    def authorize_terminal_environment(self, names: Sequence[str]) -> None:
        if self.environment.inherit_all:
            return
        allowed = set(self.environment.terminal_injection)
        rejected = sorted({name for name in names if name not in allowed})
        if rejected:
            raise CapabilityAccessError(
                "terminal:environment",
                f"disallowed names for role={self.role}: {', '.join(rejected)}",
            )

    def authorize_command(self, command: str) -> None:
        if not self.process.enabled:
            raise CapabilityAccessError(
                "terminal:process",
                f"process access is disabled for role={self.role}",
            )
        if "*" in self.process.commands:
            return
        executable = Path(command).name
        if command not in self.process.commands and executable not in self.process.commands:
            raise CapabilityAccessError(
                "terminal:command",
                f"command is not permitted for role={self.role}",
            )


def policy_path(bundled_dir: Path) -> Path:
    return bundled_dir / "policies" / "role-capabilities.v1.json"


def security_model_path(bundled_dir: Path) -> Path:
    return bundled_dir / "policies" / "capability-security-model.v1.json"


def sink_catalog_path(bundled_dir: Path) -> Path:
    return bundled_dir / "policies" / "capability-sinks.v1.json"


def load_capability_security_model(bundled_dir: Path) -> CapabilitySecurityModel:
    path = security_model_path(bundled_dir)
    return _load_strict_capability_asset(
        path,
        model=CapabilitySecurityModel,
        capability="security-model",
        resource_kind="model",
    )


def load_capability_sink_catalog(bundled_dir: Path) -> CapabilitySinkCatalog:
    path = sink_catalog_path(bundled_dir)
    return _load_strict_capability_asset(
        path,
        model=CapabilitySinkCatalog,
        capability="sink-catalog",
        resource_kind="catalog",
    )


class CapabilitySourceGraphError(ValueError):
    """Bounded diagnostic for an invalid capability source graph."""


def _repository_relative_python_path(
    repository_root: Path,
    raw_path: str,
    *,
    source: str,
) -> str:
    path = Path(raw_path)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise CapabilitySourceGraphError(f"{source} path escapes the repository")
    candidate = (repository_root / path).resolve()
    try:
        relative = candidate.relative_to(repository_root.resolve()).as_posix()
    except ValueError as exc:
        raise CapabilitySourceGraphError(
            f"{source} path escapes the repository"
        ) from exc
    if candidate.suffix != ".py" or not candidate.is_file():
        raise CapabilitySourceGraphError(f"{source} Python path is unavailable")
    return relative


def _strict_component_python_paths(repository_root: Path) -> tuple[str, ...]:
    path = repository_root / "docs/architecture/component-map.json"

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CapabilitySourceGraphError(
                    "component map contains duplicate object members"
                )
            result[key] = value
        return result

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilitySourceGraphError("component map is unavailable or malformed") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"components", "schema_version"}
        or document["schema_version"] != 1
    ):
        raise CapabilitySourceGraphError("component map has an invalid top-level record")
    components = document["components"]
    if not isinstance(components, list):
        raise CapabilitySourceGraphError("component map has an invalid component list")
    matches = [
        item
        for item in components
        if isinstance(item, dict) and item.get("id") == "COMP-CAPABILITY"
    ]
    if len(matches) != 1:
        raise CapabilitySourceGraphError(
            "component map must contain exactly one COMP-CAPABILITY record"
        )
    component = matches[0]
    expected_fields = {"decisions", "id", "invariants", "paths", "specifications", "tests"}
    if set(component) != expected_fields or not isinstance(component["paths"], list):
        raise CapabilitySourceGraphError("COMP-CAPABILITY record is malformed")
    raw_paths = component["paths"]
    if not all(isinstance(item, str) for item in raw_paths):
        raise CapabilitySourceGraphError("COMP-CAPABILITY paths are malformed")
    if len(raw_paths) != len(set(raw_paths)):
        raise CapabilitySourceGraphError("COMP-CAPABILITY paths are duplicated")
    python_paths = tuple(item for item in raw_paths if item.endswith(".py"))
    return tuple(
        _repository_relative_python_path(
            repository_root,
            item,
            source="COMP-CAPABILITY",
        )
        for item in python_paths
    )


def _module_name_for_path(relative_path: str) -> tuple[str, bool]:
    path = Path(relative_path)
    try:
        source_relative = path.relative_to("src")
    except ValueError as exc:
        raise CapabilitySourceGraphError(
            "capability Python path is outside the source package"
        ) from exc
    parts = source_relative.with_suffix("").parts
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    if not parts or parts[0] != "unrest_harness":
        raise CapabilitySourceGraphError(
            "capability Python path is outside unrest_harness"
        )
    return ".".join(parts), is_package


def _local_module_path(repository_root: Path, module_name: str) -> str | None:
    if module_name != "unrest_harness" and not module_name.startswith(
        "unrest_harness."
    ):
        return None
    base = repository_root / "src" / Path(*module_name.split("."))
    candidates = (base.with_suffix(".py"), base / "__init__.py")
    for candidate in candidates:
        if candidate.is_file():
            resolved = candidate.resolve()
            try:
                return resolved.relative_to(repository_root.resolve()).as_posix()
            except ValueError as exc:
                raise CapabilitySourceGraphError(
                    f"repository-local import for {module_name} escapes the repository"
                ) from exc
    return None


def _package_initializer_paths(
    repository_root: Path,
    module_name: str,
    *,
    is_package: bool,
) -> tuple[str, ...]:
    parts = module_name.split(".")
    package_count = len(parts) if is_package else len(parts) - 1
    initializers: list[str] = []
    for length in range(1, package_count + 1):
        package = ".".join(parts[:length])
        path = repository_root / "src" / Path(*package.split(".")) / "__init__.py"
        if not path.is_file():
            raise CapabilitySourceGraphError(
                f"executed package initializer for {package} is unavailable"
            )
        resolved = path.resolve()
        try:
            initializers.append(
                resolved.relative_to(repository_root.resolve()).as_posix()
            )
        except ValueError as exc:
            raise CapabilitySourceGraphError(
                f"executed package initializer for {package} escapes the repository"
            ) from exc
    return tuple(initializers)


def _local_import_paths(
    repository_root: Path,
    relative_path: str,
    tree: ast.Module,
) -> tuple[str, ...]:
    module_name, is_package = _module_name_for_path(relative_path)
    package_name = module_name if is_package else module_name.rpartition(".")[0]
    imported: set[str] = set()
    for node in ast.walk(tree):
        candidates: list[str] = []
        if isinstance(node, ast.Import):
            candidates.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                relative_name = "." * node.level + (node.module or "")
                try:
                    base_name = importlib.util.resolve_name(
                        relative_name,
                        package_name,
                    )
                except (ImportError, ValueError) as exc:
                    raise CapabilitySourceGraphError(
                        f"unresolved relative import in {relative_path}"
                    ) from exc
            else:
                base_name = node.module or ""
            if base_name:
                candidates.append(base_name)
                candidates.extend(
                    f"{base_name}.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
        for candidate in candidates:
            local_path = _local_module_path(repository_root, candidate)
            if local_path is None:
                continue
            imported.add(local_path)
            imported.update(
                _package_initializer_paths(
                    repository_root,
                    candidate,
                    is_package=local_path.endswith("/__init__.py"),
                )
            )
    return tuple(sorted(imported))


def build_reachable_capability_source_graph(
    repository_root: Path,
    catalog: CapabilitySinkCatalog,
) -> tuple[str, ...]:
    """Return the deterministic repository-local capability import closure."""
    roots = set(_strict_component_python_paths(repository_root))
    declarations: tuple[CapabilitySink | CapabilitySinkOmission, ...] = (
        *catalog.sinks,
        *catalog.omissions,
    )
    for declaration in declarations:
        raw_path, separator, anchor = declaration.implementation.partition(":")
        if not separator or not raw_path or not anchor:
            raise CapabilitySourceGraphError("capability implementation locator is malformed")
        if raw_path.endswith(".py"):
            roots.add(
                _repository_relative_python_path(
                    repository_root,
                    raw_path,
                    source="capability implementation",
                )
            )
    if not roots:
        raise CapabilitySourceGraphError("capability source graph has no Python roots")

    pending = sorted(roots)
    closure: set[str] = set()
    while pending:
        relative_path = pending.pop(0)
        if relative_path in closure:
            continue
        path = repository_root / relative_path
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise CapabilitySourceGraphError(
                f"reachable Python source {relative_path} is unavailable or malformed"
            ) from exc
        closure.add(relative_path)
        module_name, is_package = _module_name_for_path(relative_path)
        discovered = set(
            _package_initializer_paths(
                repository_root,
                module_name,
                is_package=is_package,
            )
        )
        discovered.update(_local_import_paths(repository_root, relative_path, tree))
        pending = sorted(set(pending) | (discovered - closure))
    return tuple(sorted(closure))


def _normalized_egress_expression(node: ast.AST) -> Any:
    """Serialize egress-relevant expressions without CPython AST field drift."""
    if isinstance(node, ast.Name):
        return ["name", node.id]
    if isinstance(node, ast.Attribute):
        return ["attribute", _normalized_egress_expression(node.value), node.attr]
    if isinstance(node, ast.Constant):
        normalized_value: Any = node.value
        if isinstance(normalized_value, bytes):
            normalized_value = {"bytes_hex": normalized_value.hex()}
        elif not isinstance(
            normalized_value,
            (str, int, float, complex, bool, type(None)),
        ):
            normalized_value = type(normalized_value).__name__
        return ["constant", normalized_value]
    if isinstance(node, ast.Call):
        return [
            "call",
            _normalized_egress_expression(node.func),
            [_normalized_egress_expression(item) for item in node.args],
            [
                [item.arg, _normalized_egress_expression(item.value)]
                for item in node.keywords
            ],
        ]
    if isinstance(node, ast.Await):
        return ["await", _normalized_egress_expression(node.value)]
    if isinstance(node, ast.Subscript):
        return [
            "subscript",
            _normalized_egress_expression(node.value),
            _normalized_egress_expression(node.slice),
        ]
    if isinstance(node, ast.Slice):
        return [
            "slice",
            *[
                None if item is None else _normalized_egress_expression(item)
                for item in (node.lower, node.upper, node.step)
            ],
        ]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [
            type(node).__name__.lower(),
            [_normalized_egress_expression(item) for item in node.elts],
        ]
    if isinstance(node, ast.Dict):
        return [
            "dict",
            [
                [
                    None if key is None else _normalized_egress_expression(key),
                    _normalized_egress_expression(value),
                ]
                for key, value in zip(node.keys, node.values, strict=True)
            ],
        ]
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.Compare)):
        children = [
            _normalized_egress_expression(item)
            for item in ast.iter_child_nodes(node)
            if not isinstance(item, (ast.operator, ast.boolop, ast.unaryop, ast.cmpop))
        ]
        operators = [
            type(item).__name__
            for item in ast.iter_child_nodes(node)
            if isinstance(item, (ast.operator, ast.boolop, ast.unaryop, ast.cmpop))
        ]
        return [type(node).__name__.lower(), operators, children]
    if isinstance(node, ast.IfExp):
        return [
            "if-expression",
            _normalized_egress_expression(node.test),
            _normalized_egress_expression(node.body),
            _normalized_egress_expression(node.orelse),
        ]
    if isinstance(node, ast.Starred):
        return ["starred", _normalized_egress_expression(node.value)]
    if isinstance(node, ast.JoinedStr):
        return [
            "joined-string",
            [_normalized_egress_expression(item) for item in node.values],
        ]
    if isinstance(node, ast.FormattedValue):
        return [
            "formatted-value",
            _normalized_egress_expression(node.value),
            node.conversion,
            None
            if node.format_spec is None
            else _normalized_egress_expression(node.format_spec),
        ]
    if isinstance(node, ast.Lambda):
        return ["lambda", _normalized_egress_expression(node.body)]
    if isinstance(node, ast.MatchValue):
        return ["match-value", _normalized_egress_expression(node.value)]
    if isinstance(node, ast.MatchSingleton):
        return ["match-singleton", node.value]
    if isinstance(node, ast.MatchSequence):
        return [
            "match-sequence",
            [_normalized_egress_expression(item) for item in node.patterns],
        ]
    if isinstance(node, ast.MatchMapping):
        return [
            "match-mapping",
            [_normalized_egress_expression(item) for item in node.keys],
            [_normalized_egress_expression(item) for item in node.patterns],
            node.rest,
        ]
    if isinstance(node, ast.MatchClass):
        return [
            "match-class",
            _normalized_egress_expression(node.cls),
            [_normalized_egress_expression(item) for item in node.patterns],
            list(node.kwd_attrs),
            [_normalized_egress_expression(item) for item in node.kwd_patterns],
        ]
    if isinstance(node, ast.MatchStar):
        return ["match-star", node.name]
    if isinstance(node, ast.MatchAs):
        return [
            "match-as",
            None
            if node.pattern is None
            else _normalized_egress_expression(node.pattern),
            node.name,
        ]
    if isinstance(node, ast.MatchOr):
        return [
            "match-or",
            [_normalized_egress_expression(item) for item in node.patterns],
        ]
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return [
            type(node).__name__.lower(),
            _normalized_egress_expression(node.elt),
            [
                [
                    _normalized_egress_expression(generator.target),
                    _normalized_egress_expression(generator.iter),
                    generator.is_async,
                ]
                for generator in node.generators
            ],
        ]
    if isinstance(node, ast.DictComp):
        return [
            "dictcomp",
            _normalized_egress_expression(node.key),
            _normalized_egress_expression(node.value),
            [
                [
                    _normalized_egress_expression(generator.target),
                    _normalized_egress_expression(generator.iter),
                    generator.is_async,
                ]
                for generator in node.generators
            ],
        ]
    return ["expression", type(node).__name__]


def _normalized_bound_egress_expression(
    node: ast.AST,
    bindings: Mapping[str, ast.AST],
) -> Any:
    """Serialize after substituting acyclic, structurally stable bindings."""

    class _Resolver(ast.NodeTransformer):
        def __init__(self) -> None:
            self.resolving: set[str] = set()

        def visit_Name(self, candidate: ast.Name) -> ast.AST:  # noqa: N802
            binding = bindings.get(candidate.id)
            if binding is None or candidate.id in self.resolving:
                return candidate
            self.resolving.add(candidate.id)
            try:
                return self.visit(copy.deepcopy(binding))
            finally:
                self.resolving.remove(candidate.id)

    return _normalized_egress_expression(_Resolver().visit(copy.deepcopy(node)))


def normalized_external_egress_records(
    relative_path: str,
    tree: ast.Module,
) -> tuple[dict[str, Any], ...]:
    """Project data-bearing calls that cannot resolve to local Python code."""
    side_effect_free_import_roots = {"math"}
    imported: dict[str, tuple[str, bool]] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = (
                    alias.name,
                    alias.name == "unrest_harness" or alias.name.startswith("unrest_harness."),
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            is_local = bool(node.level) or module == "unrest_harness" or module.startswith(
                "unrest_harness."
            )
            for alias in node.names:
                imported[alias.asname or alias.name] = (
                    f"{module}.{alias.name}" if module else alias.name,
                    is_local,
                )

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def owner(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        cursor: ast.AST | None = node
        while cursor is not None:
            if isinstance(cursor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cursor
            cursor = parents.get(cursor)
        return None

    def anchor(node: ast.AST) -> str:
        cursor: ast.AST | None = node
        names: list[str] = []
        while cursor is not None:
            if isinstance(cursor, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.insert(0, cursor.name)
            cursor = parents.get(cursor)
        return "<module>" if not names else ".".join(names)

    records: list[dict[str, Any]] = []
    functions = [
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    scopes: list[ast.Module | ast.FunctionDef | ast.AsyncFunctionDef] = [
        tree,
        *functions,
    ]
    scope_literal_bindings: dict[ast.AST, dict[str, ast.AST]] = {}
    scope_unknown_literal_names: dict[ast.AST, set[str]] = {}
    scope_local_callable_names: dict[ast.AST, set[str]] = {}
    scope_local_callable_targets: dict[
        ast.AST,
        dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    ] = {}
    fixed_context_calls: dict[ast.Call, dict[str, Any]] = {}
    local_helper_calls: dict[ast.Call, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    called_local_functions: set[ast.FunctionDef | ast.AsyncFunctionDef] = set()
    for scope in scopes:
        function = None if isinstance(scope, ast.Module) else scope
        parameters = (
            set()
            if function is None
            else {
                item.arg
                for item in (
                    *function.args.posonlyargs,
                    *function.args.args,
                    *function.args.kwonlyargs,
                )
            }
        )
        tainted = set(parameters)
        external_aliases: set[str] = set()
        external_alias_bindings: dict[str, ast.AST] = {}
        pure_callable_iterables: set[str] = set()
        direct_local_callables = {
            item.name
            for item in scope.body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        scope_imports: dict[str, tuple[bool, bool]] = {}
        if function is None:
            scope_imports.update(
                {
                    name: (
                        not is_local,
                        qualified_name.split(".")[0]
                        in side_effect_free_import_roots,
                    )
                    for name, (qualified_name, is_local) in imported.items()
                }
            )

        def in_scope(node: ast.AST) -> bool:
            return owner(node) is function

        invoked_callable_names = {
            item.func.id
            for item in ast.walk(scope)
            if in_scope(item)
            and isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
        }

        def names_in(expression: ast.AST) -> set[str]:
            return {
                item.id for item in ast.walk(expression) if isinstance(item, ast.Name)
            }

        enclosing_scope: ast.AST = tree
        if function is not None:
            cursor = parents.get(function)
            while cursor is not None and not isinstance(
                cursor, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                cursor = parents.get(cursor)
            if cursor is not None:
                enclosing_scope = cursor
        inherited_literals = dict(scope_literal_bindings.get(enclosing_scope, {}))
        inherited_unknown_literals = set(
            scope_unknown_literal_names.get(enclosing_scope, set())
        )
        binding_values: dict[str, list[ast.AST | None]] = {}

        def assigned_names(target: ast.AST) -> set[str]:
            if isinstance(target, ast.Name):
                return {target.id}
            if isinstance(target, (ast.List, ast.Tuple)):
                return {
                    name
                    for item in target.elts
                    for name in assigned_names(item)
                }
            return set()

        for item in ast.walk(scope):
            if not in_scope(item):
                continue
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    for name in assigned_names(target):
                        binding_values.setdefault(name, []).append(item.value)
            elif isinstance(item, ast.AnnAssign):
                for name in assigned_names(item.target):
                    binding_values.setdefault(name, []).append(item.value)
            elif isinstance(item, ast.AugAssign):
                for name in assigned_names(item.target):
                    binding_values.setdefault(name, []).append(None)
            elif isinstance(item, ast.NamedExpr) and isinstance(item.target, ast.Name):
                binding_values.setdefault(item.target.id, []).append(item.value)

        locally_bound_names = set(binding_values) | parameters
        inherited_local_callables = set(
            scope_local_callable_names.get(enclosing_scope, set())
        )
        local_callable_bindings = (
            inherited_local_callables - locally_bound_names
        ) | direct_local_callables
        literal_bindings = {
            name: expression
            for name, expression in inherited_literals.items()
            if name not in locally_bound_names
        }
        literal_bindings.update(
            {
                name: values[0]
                for name, values in binding_values.items()
                if len(values) == 1 and values[0] is not None
            }
        )
        unknown_literal_names = {
            name
            for name in inherited_unknown_literals
            if name not in locally_bound_names
        }

        def resolved_literal(
            expression: ast.AST,
            resolving: frozenset[str] = frozenset(),
        ) -> ast.AST | None:
            if isinstance(expression, ast.Constant):
                return expression
            if isinstance(expression, (ast.List, ast.Set, ast.Tuple)):
                return expression if all(
                    resolved_literal(item, resolving) is not None
                    for item in expression.elts
                ) else None
            if isinstance(expression, ast.Dict):
                return expression if all(
                    key is not None
                    and resolved_literal(key, resolving) is not None
                    and resolved_literal(value, resolving) is not None
                    for key, value in zip(expression.keys, expression.values, strict=True)
                ) else None
            if isinstance(expression, ast.Name) and expression.id not in resolving:
                binding = literal_bindings.get(expression.id)
                if binding is not None:
                    return resolved_literal(binding, resolving | {expression.id})
            return None

        resolved_literal_bindings = {
            name: literal
            for name in literal_bindings
            if (literal := resolved_literal(ast.Name(id=name))) is not None
        }
        stable_literal_names = set(resolved_literal_bindings)
        literal_bindings = resolved_literal_bindings
        ambiguous_value_names = {
            name
            for name in inherited_unknown_literals
            if name not in locally_bound_names
        }
        ambiguous_value_names.update(set(binding_values) - stable_literal_names)
        unknown_literal_names.update(ambiguous_value_names)
        scope_literal_bindings[scope] = literal_bindings
        scope_unknown_literal_names[scope] = unknown_literal_names

        for item in ast.walk(scope):
            if not in_scope(item):
                continue
            if isinstance(item, ast.Import):
                for alias in item.names:
                    root = alias.name.split(".")[0]
                    scope_imports[alias.asname or root] = (
                        not (
                            alias.name == "unrest_harness"
                            or alias.name.startswith("unrest_harness.")
                        ),
                        root in side_effect_free_import_roots,
                    )
            elif isinstance(item, ast.ImportFrom):
                module = item.module or ""
                is_external = not (
                    bool(item.level)
                    or module == "unrest_harness"
                    or module.startswith("unrest_harness.")
                )
                for alias in item.names:
                    scope_imports[alias.asname or alias.name] = (
                        is_external,
                        module.split(".")[0] in side_effect_free_import_roots,
                    )

        def local_self_method(expression: ast.AST) -> bool:
            if not (
                isinstance(expression, ast.Attribute)
                and isinstance(expression.value, ast.Name)
                and expression.value.id in {"self", "cls"}
                and function is not None
            ):
                return False
            class_node = parents.get(function)
            return isinstance(class_node, ast.ClassDef) and any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == expression.attr
                for item in class_node.body
            )

        def side_effect_free_import_reference(expression: ast.AST) -> bool:
            root = expression
            while isinstance(root, ast.Attribute):
                root = root.value
            if not isinstance(root, ast.Name):
                return False
            scope_binding = scope_imports.get(root.id)
            if scope_binding is not None:
                return scope_binding[1]
            module_binding = imported.get(root.id)
            return module_binding is not None and (
                module_binding[0].split(".")[0] in side_effect_free_import_roots
            )

        def external_callable(expression: ast.AST) -> bool:
            if isinstance(expression, ast.Name):
                if (
                    expression.id in local_callable_bindings
                    or hasattr(builtins, expression.id)
                ):
                    return False
                if expression.id in external_aliases:
                    return True
                if expression.id in {"self", "cls"}:
                    return False
                if expression.id in scope_imports:
                    is_external, side_effect_free = scope_imports[expression.id]
                    return is_external and not side_effect_free
                binding = imported.get(expression.id)
                if binding is not None:
                    return (
                        not binding[1]
                        and binding[0].split(".")[0]
                        not in side_effect_free_import_roots
                    )
                return True
            if isinstance(expression, ast.Attribute):
                if local_self_method(expression):
                    return False
                root: ast.AST = expression
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(
                    root,
                    (ast.Constant, ast.Dict, ast.List, ast.Set, ast.Tuple),
                ):
                    return False
                if isinstance(root, ast.Name):
                    if root.id in scope_imports:
                        is_external, side_effect_free = scope_imports[root.id]
                        return is_external and not side_effect_free
                    binding = imported.get(root.id)
                    if binding is not None:
                        return (
                            not binding[1]
                            and binding[0].split(".")[0]
                            not in side_effect_free_import_roots
                        )
                    return (
                        root.id not in local_callable_bindings
                        and not hasattr(builtins, root.id)
                    )
                return True
            if (
                isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id == "getattr"
                and len(expression.args) >= 2
            ):
                method = resolved_literal(expression.args[1])
                target = expression.args[0]
                return (
                    isinstance(method, ast.Constant)
                    and isinstance(method.value, str)
                    and (
                        isinstance(target, ast.Name) and target.id in parameters
                        or external_callable(target)
                    )
                ) or not side_effect_free_import_reference(target)
            if isinstance(expression, (ast.Call, ast.IfExp)):
                return not side_effect_free_callable(expression)
            return False

        def side_effect_free_callable(expression: ast.AST) -> bool:
            if isinstance(expression, ast.Lambda):
                return True
            if isinstance(expression, ast.Name):
                if expression.id in local_callable_bindings:
                    return True
                if hasattr(builtins, expression.id):
                    return True
                scope_binding = scope_imports.get(expression.id)
                if scope_binding is not None:
                    return scope_binding[1]
                module_binding = imported.get(expression.id)
                return module_binding is not None and (
                    module_binding[0].split(".")[0]
                    in side_effect_free_import_roots
                )
            if isinstance(expression, ast.Attribute):
                return side_effect_free_import_reference(expression)
            if isinstance(expression, ast.IfExp):
                return side_effect_free_callable(
                    expression.body
                ) and side_effect_free_callable(expression.orelse)
            if isinstance(expression, ast.Subscript):
                if side_effect_free_import_reference(expression.value):
                    return True
                return (
                    isinstance(expression.value, ast.Call)
                    and isinstance(expression.value.func, ast.Name)
                    and expression.value.func.id == "vars"
                    and len(expression.value.args) == 1
                    and not expression.value.keywords
                    and side_effect_free_import_reference(expression.value.args[0])
                )
            if not isinstance(expression, ast.Call):
                return False
            if (
                isinstance(expression.func, ast.Name)
                and expression.func.id == "getattr"
                and len(expression.args) >= 2
            ):
                return side_effect_free_import_reference(expression.args[0])
            if (
                isinstance(expression.func, ast.Attribute)
                and expression.func.attr == "get"
                and side_effect_free_import_reference(expression.func.value)
            ):
                return True
            if (
                isinstance(expression.func, ast.Name)
                and expression.func.id == "next"
                and len(expression.args) == 1
                and not expression.keywords
            ):
                return proven_pure_callable_iterable(expression.args[0])
            return False

        def proven_pure_callable_iterable(expression: ast.AST) -> bool:
            if isinstance(expression, ast.Name):
                return expression.id in pure_callable_iterables
            if isinstance(expression, (ast.List, ast.Set, ast.Tuple)):
                return bool(expression.elts) and all(
                    side_effect_free_callable(item) for item in expression.elts
                )
            if (
                isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id in {"iter", "list", "set", "tuple"}
                and len(expression.args) == 1
                and not expression.keywords
            ):
                return proven_pure_callable_iterable(expression.args[0])
            return False

        data_packets: set[str] = set()

        def fixed_external_context(expression: ast.AST) -> bool:
            literal = resolved_literal(expression)
            if isinstance(literal, ast.Constant):
                return isinstance(literal.value, str) and literal.value.startswith(
                    ("http://", "https://")
                )
            return False

        def fixed_command_context(expression: ast.AST) -> bool:
            literal = resolved_literal(expression)
            return isinstance(literal, (ast.List, ast.Tuple)) and bool(literal.elts) and all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in literal.elts
            )

        def result_is_callable_source(call: ast.Call) -> bool:
            parent = parents.get(call)
            if isinstance(parent, ast.Call) and parent.func is call:
                return True
            if isinstance(parent, ast.Assign) and parent.value is call:
                assigned = {
                    name
                    for target in parent.targets
                    for name in assigned_names(target)
                }
                return bool(assigned & invoked_callable_names)
            if isinstance(parent, ast.AnnAssign) and parent.value is call:
                return bool(assigned_names(parent.target) & invoked_callable_names)
            return False

        def call_carries_data(call: ast.Call) -> bool:
            if (
                not external_callable(call.func)
                or result_is_callable_source(call)
            ):
                return False
            arguments = [*call.args, *(item.value for item in call.keywords)]
            if not arguments:
                return False
            return not (
                len(arguments) == 1
                and (
                    fixed_external_context(arguments[0])
                    or fixed_command_context(arguments[0])
                )
            )

        assignments = [
            item
            for item in ast.walk(scope)
            if in_scope(item) and isinstance(item, (ast.Assign, ast.AnnAssign))
        ]
        iteration_bindings = [
            (item.target, item.iter)
            for item in ast.walk(scope)
            if in_scope(item)
            and isinstance(item, (ast.For, ast.AsyncFor, ast.comprehension))
        ]
        for _ in range(len(assignments) + len(iteration_bindings) + 1):
            changed = False
            for assignment in assignments:
                value = assignment.value
                if value is None:
                    continue
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else (assignment.target,)
                )
                target_names = {
                    item.id
                    for target in targets
                    for item in ast.walk(target)
                    if isinstance(item, ast.Name)
                }
                if names_in(value) & tainted:
                    before = len(tainted)
                    tainted.update(target_names)
                    changed = changed or len(tainted) != before
                if external_callable(value):
                    before = len(external_aliases)
                    external_aliases.update(target_names)
                    changed = changed or len(external_aliases) != before
                    for name in target_names:
                        if binding_values.get(name) == [value]:
                            external_alias_bindings[name] = value
                if side_effect_free_callable(value):
                    proven_local_targets = {
                        name
                        for name in target_names
                        if binding_values.get(name) == [value]
                    }
                    before = len(local_callable_bindings)
                    local_callable_bindings.update(proven_local_targets)
                    changed = changed or len(local_callable_bindings) != before
                if proven_pure_callable_iterable(value):
                    before = len(pure_callable_iterables)
                    pure_callable_iterables.update(target_names)
                    changed = changed or len(pure_callable_iterables) != before
                carries_data = bool(names_in(value) & data_packets) or any(
                    isinstance(item, ast.Call) and call_carries_data(item)
                    for item in ast.walk(value)
                )
                if carries_data:
                    before = len(data_packets)
                    data_packets.update(target_names)
                    changed = changed or len(data_packets) != before
            for target, iterable in iteration_bindings:
                if not isinstance(target, ast.Name):
                    continue
                if proven_pure_callable_iterable(iterable):
                    before = len(local_callable_bindings)
                    local_callable_bindings.add(target.id)
                    changed = changed or len(local_callable_bindings) != before
            if not changed:
                break
        scope_local_callable_names[scope] = set(local_callable_bindings)

        inherited_local_targets = dict(
            scope_local_callable_targets.get(enclosing_scope, {})
        )
        local_callable_targets = {
            name: target
            for name, target in inherited_local_targets.items()
            if name not in locally_bound_names
        }
        local_callable_targets.update(
            {
                item.name: item
                for item in scope.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
        )
        for _ in range(len(assignments) + 1):
            changed = False
            for assignment in assignments:
                value = assignment.value
                if not isinstance(value, ast.Name):
                    continue
                local_function_target = local_callable_targets.get(value.id)
                if local_function_target is None:
                    continue
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else (assignment.target,)
                )
                for candidate in targets:
                    if not isinstance(candidate, ast.Name):
                        continue
                    if binding_values.get(candidate.id) != [value]:
                        continue
                    if (
                        local_callable_targets.get(candidate.id)
                        is not local_function_target
                    ):
                        local_callable_targets[candidate.id] = local_function_target
                        changed = True
            if not changed:
                break
        scope_local_callable_targets[scope] = local_callable_targets

        def resolved_callable(
            expression: ast.AST,
            resolving: frozenset[str] = frozenset(),
        ) -> ast.AST:
            if isinstance(expression, ast.Name) and expression.id not in resolving:
                binding = external_alias_bindings.get(expression.id)
                if binding is not None:
                    return resolved_callable(binding, resolving | {expression.id})
            return expression

        for call in ast.walk(scope):
            if not isinstance(call, ast.Call) or not in_scope(call):
                continue
            if isinstance(call.func, ast.Name):
                local_target = local_callable_targets.get(call.func.id)
                if local_target is not None:
                    local_helper_calls[call] = local_target
                    called_local_functions.add(local_target)
            arguments = [*call.args, *(item.value for item in call.keywords)]
            if (
                len(arguments) != 1
                or not external_callable(call.func)
                or result_is_callable_source(call)
                or not (
                    fixed_external_context(arguments[0])
                    or fixed_command_context(arguments[0])
                )
            ):
                continue
            fixed_context_calls[call] = {
                "anchor": anchor(call),
                "arguments": [
                    _normalized_bound_egress_expression(item, literal_bindings)
                    for item in call.args
                ],
                "callable": _normalized_bound_egress_expression(
                    resolved_callable(call.func),
                    literal_bindings,
                ),
                "keywords": [
                    [
                        item.arg,
                        _normalized_bound_egress_expression(
                            item.value,
                            literal_bindings,
                        ),
                    ]
                    for item in call.keywords
                ],
                "path": relative_path,
            }

        for call in ast.walk(scope):
            if not isinstance(call, ast.Call) or not in_scope(call):
                continue
            if not call_carries_data(call):
                continue

            records.append(
                {
                    "anchor": anchor(call),
                    "arguments": [
                        _normalized_bound_egress_expression(item, literal_bindings)
                        for item in call.args
                    ],
                    "callable": _normalized_bound_egress_expression(
                        resolved_callable(call.func),
                        literal_bindings,
                    ),
                    "keywords": [
                        [
                            item.arg,
                            _normalized_bound_egress_expression(
                                item.value,
                                literal_bindings,
                            ),
                        ]
                        for item in call.keywords
                    ],
                    "path": relative_path,
                }
            )

    Effect = tuple[dict[str, Any], tuple[Any, ...], tuple[Any, ...]]
    relevant_fixed_scopes: set[ast.AST] = {
        owner(call) or tree for call in fixed_context_calls
    }

    def scope_for(node: ast.AST) -> ast.Module | ast.FunctionDef | ast.AsyncFunctionDef:
        return owner(node) or tree

    def expression_bindings(
        node: ast.AST,
        parameter_bindings: Mapping[str, ast.AST],
    ) -> dict[str, ast.AST]:
        return {
            **scope_literal_bindings.get(scope_for(node), {}),
            **parameter_bindings,
        }

    def normalized_control(
        node: ast.AST,
        parameter_bindings: Mapping[str, ast.AST],
    ) -> Any:
        return _normalized_bound_egress_expression(
            node,
            expression_bindings(node, parameter_bindings),
        )

    def proven_boolean(
        node: ast.AST,
        parameter_bindings: Mapping[str, ast.AST],
        resolving: frozenset[str] = frozenset(),
    ) -> bool | None:
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            return node.value
        if isinstance(node, ast.Name) and node.id not in resolving:
            binding = parameter_bindings.get(node.id)
            if binding is None:
                binding = scope_literal_bindings.get(scope_for(node), {}).get(node.id)
            if binding is not None:
                return proven_boolean(
                    binding,
                    parameter_bindings,
                    resolving | {node.id},
                )
        return None

    def add_control(
        effects: list[Effect],
        frame: Any,
        *,
        after: int,
    ) -> list[Effect]:
        return [
            (
                record,
                (*effect_controls[:after], frame, *effect_controls[after:]),
                via,
            )
            for record, effect_controls, via in effects
        ]

    def canonical_effects(
        effects: list[Effect],
        *,
        observable_only: bool = False,
    ) -> list[str]:
        return sorted(
            json.dumps(
                [
                    (
                        {key: value for key, value in record.items() if key != "anchor"}
                        if observable_only
                        else record
                    ),
                    controls,
                    () if observable_only else via,
                ],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            for record, controls, via in effects
        )

    def common_arm_effects(
        body: list[Effect],
        orelse: list[Effect],
    ) -> list[Effect] | None:
        if canonical_effects(body, observable_only=True) != canonical_effects(
            orelse,
            observable_only=True,
        ):
            return None
        return min((body, orelse), key=canonical_effects)

    def helper_parameter_bindings(
        call: ast.Call,
        target: ast.FunctionDef | ast.AsyncFunctionDef,
        inherited: Mapping[str, ast.AST],
    ) -> dict[str, ast.AST]:
        bindings = dict(inherited)
        parameters = [*target.args.posonlyargs, *target.args.args]
        for parameter, argument in zip(parameters, call.args):
            bindings[parameter.arg] = argument
        keyword_arguments = {
            item.arg: item.value for item in call.keywords if item.arg is not None
        }
        for parameter in (*parameters, *target.args.kwonlyargs):
            keyword_argument = keyword_arguments.get(parameter.arg)
            if keyword_argument is not None:
                bindings[parameter.arg] = keyword_argument
        return bindings

    def expression_effects(
        node: ast.AST,
        controls: tuple[Any, ...],
        via: tuple[Any, ...],
        parameter_bindings: Mapping[str, ast.AST],
        call_stack: frozenset[ast.AST],
    ) -> list[Effect]:
        effects: list[Effect] = []
        fixed_record = fixed_context_calls.get(node) if isinstance(node, ast.Call) else None
        if fixed_record is not None:
            effects.append((fixed_record, controls, via))
        if isinstance(node, ast.Call):
            local_target = local_helper_calls.get(node)
            if (
                local_target is not None
                and local_target in relevant_fixed_scopes
                and local_target not in call_stack
                and len(via) < 2
            ):
                callsite = [
                    "callsite",
                    anchor(node),
                    normalized_control(node.func, parameter_bindings),
                ]
                nested_bindings = helper_parameter_bindings(
                    node,
                    local_target,
                    parameter_bindings,
                )
                nested = statement_block_effects(
                    local_target.body,
                    controls,
                    (*via, callsite),
                    nested_bindings,
                    call_stack | {local_target},
                )
                effects.extend(nested[0])
            effects.extend(
                expression_effects(
                    node.func,
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
            )
            for argument in (*node.args, *(item.value for item in node.keywords)):
                effects.extend(
                    expression_effects(
                        argument,
                        controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
            return effects
        if isinstance(node, ast.IfExp):
            effects.extend(
                expression_effects(
                    node.test,
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
            )
            constant = proven_boolean(node.test, parameter_bindings)
            if constant is not None:
                selected = node.body if constant else node.orelse
                effects.extend(
                    expression_effects(
                        selected,
                        controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
                return effects
            body = expression_effects(
                node.body,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            orelse = expression_effects(
                node.orelse,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            common = common_arm_effects(body, orelse)
            if common is not None:
                effects.extend(common)
            else:
                predicate = normalized_control(node.test, parameter_bindings)
                effects.extend(
                    add_control(
                        body,
                        ["if-expression", predicate, "body"],
                        after=len(controls),
                    )
                )
                effects.extend(
                    add_control(
                        orelse,
                        ["if-expression", predicate, "else"],
                        after=len(controls),
                    )
                )
            return effects
        if isinstance(node, ast.BoolOp):
            active_controls = controls
            operator = "and" if isinstance(node.op, ast.And) else "or"
            preceding: list[Any] = []
            for value in node.values:
                effects.extend(
                    expression_effects(
                        value,
                        active_controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
                constant = proven_boolean(value, parameter_bindings)
                if constant is not None:
                    if (operator == "and" and not constant) or (
                        operator == "or" and constant
                    ):
                        break
                    continue
                preceding.append(normalized_control(value, parameter_bindings))
                active_controls = (
                    *controls,
                    ["boolean", operator, list(preceding)],
                )
            return effects
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            active_controls = controls
            for index, generator in enumerate(node.generators):
                effects.extend(
                    expression_effects(
                        generator.iter,
                        active_controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
                active_controls = (
                    *active_controls,
                    [
                        "comprehension-iterator",
                        index,
                        normalized_control(generator.iter, parameter_bindings),
                        generator.is_async,
                    ],
                )
                for filter_index, condition in enumerate(generator.ifs):
                    effects.extend(
                        expression_effects(
                            condition,
                            active_controls,
                            via,
                            parameter_bindings,
                            call_stack,
                        )
                    )
                    constant = proven_boolean(condition, parameter_bindings)
                    if constant is False:
                        return effects
                    if constant is None:
                        active_controls = (
                            *active_controls,
                            [
                                "comprehension-filter",
                                index,
                                filter_index,
                                normalized_control(condition, parameter_bindings),
                            ],
                        )
            result_nodes = (
                (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
            )
            for result_node in result_nodes:
                effects.extend(
                    expression_effects(
                        result_node,
                        active_controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
            return effects
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.comprehension)):
                continue
            effects.extend(
                expression_effects(
                    child,
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
            )
        return effects

    def statement_effects(
        statement: ast.stmt,
        controls: tuple[Any, ...],
        via: tuple[Any, ...],
        parameter_bindings: Mapping[str, ast.AST],
        call_stack: frozenset[ast.AST],
    ) -> list[Effect]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return []
        if isinstance(statement, ast.If):
            effects = expression_effects(
                statement.test,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            constant = proven_boolean(statement.test, parameter_bindings)
            if constant is not None:
                selected = statement.body if constant else statement.orelse
                selected_effects, _ = statement_block_effects(
                    selected,
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
                return [*effects, *selected_effects]
            body, _ = statement_block_effects(
                statement.body,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            orelse, _ = statement_block_effects(
                statement.orelse,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            common = common_arm_effects(body, orelse)
            if common is not None:
                return [*effects, *common]
            predicate = normalized_control(statement.test, parameter_bindings)
            return [
                *effects,
                *add_control(
                    body,
                    ["if", predicate, "body"],
                    after=len(controls),
                ),
                *add_control(
                    orelse,
                    ["if", predicate, "else"],
                    after=len(controls),
                ),
            ]
        if isinstance(statement, ast.While):
            effects = expression_effects(
                statement.test,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            constant = proven_boolean(statement.test, parameter_bindings)
            if constant is False:
                orelse, _ = statement_block_effects(
                    statement.orelse,
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
                return [*effects, *orelse]
            body_controls = controls
            if constant is None:
                body_controls = (
                    *controls,
                    ["while", normalized_control(statement.test, parameter_bindings), "body"],
                )
            body, _ = statement_block_effects(
                statement.body,
                body_controls,
                via,
                parameter_bindings,
                call_stack,
            )
            orelse, _ = statement_block_effects(
                statement.orelse,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            return [*effects, *body, *orelse]
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            effects = expression_effects(
                statement.iter,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            loop_frame = [
                "async-for" if isinstance(statement, ast.AsyncFor) else "for",
                normalized_control(statement.iter, parameter_bindings),
                "body",
            ]
            body, _ = statement_block_effects(
                statement.body,
                (*controls, loop_frame),
                via,
                parameter_bindings,
                call_stack,
            )
            orelse, _ = statement_block_effects(
                statement.orelse,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            return [*effects, *body, *orelse]
        if isinstance(statement, ast.Match):
            effects = expression_effects(
                statement.subject,
                controls,
                via,
                parameter_bindings,
                call_stack,
            )
            subject = normalized_control(statement.subject, parameter_bindings)
            subject_boolean = proven_boolean(statement.subject, parameter_bindings)
            for index, case in enumerate(statement.cases):
                guard_boolean = (
                    None
                    if case.guard is None
                    else proven_boolean(case.guard, parameter_bindings)
                )
                if guard_boolean is False:
                    continue
                wildcard = (
                    isinstance(case.pattern, ast.MatchAs)
                    and case.pattern.pattern is None
                    and case.pattern.name is None
                )
                boolean_pattern = (
                    case.pattern.value
                    if isinstance(case.pattern, ast.MatchSingleton)
                    and type(case.pattern.value) is bool
                    else None
                )
                statically_selected = subject_boolean is not None and (
                    wildcard or boolean_pattern is subject_boolean
                )
                if subject_boolean is not None and not statically_selected:
                    continue
                if wildcard and len(statement.cases) == 1:
                    statically_selected = True
                if statically_selected:
                    case_effects, _ = statement_block_effects(
                        case.body,
                        controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                    effects.extend(case_effects)
                    break
                case_controls = (
                    *controls,
                    [
                        "match",
                        subject,
                        index,
                        _normalized_egress_expression(case.pattern),
                        None
                        if case.guard is None or guard_boolean is True
                        else normalized_control(case.guard, parameter_bindings),
                    ],
                )
                if case.guard is not None:
                    effects.extend(
                        expression_effects(
                            case.guard,
                            case_controls,
                            via,
                            parameter_bindings,
                            call_stack,
                        )
                    )
                case_effects, _ = statement_block_effects(
                    case.body,
                    case_controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
                effects.extend(case_effects)
            return effects
        fallback_effects: list[Effect] = []
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                fallback_effects.extend(
                    expression_effects(
                        child,
                        controls,
                        via,
                        parameter_bindings,
                        call_stack,
                    )
                )
            elif isinstance(child, ast.stmt):
                nested, _ = statement_block_effects(
                    (child,),
                    controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
                fallback_effects.extend(nested)
        return fallback_effects

    def terminal_kind(statements: Sequence[ast.stmt]) -> str | None:
        if not statements:
            return None
        final = statements[-1]
        if isinstance(final, ast.Return):
            return "return"
        if isinstance(final, ast.Break):
            return "break"
        if isinstance(final, ast.Continue):
            return "continue"
        return None

    def statement_block_effects(
        statements: Sequence[ast.stmt],
        controls: tuple[Any, ...],
        via: tuple[Any, ...],
        parameter_bindings: Mapping[str, ast.AST],
        call_stack: frozenset[ast.AST],
    ) -> tuple[list[Effect], str | None]:
        effects: list[Effect] = []
        active_controls = controls
        for statement in statements:
            effects.extend(
                statement_effects(
                    statement,
                    active_controls,
                    via,
                    parameter_bindings,
                    call_stack,
                )
            )
            if isinstance(statement, (ast.Return, ast.Break, ast.Continue)):
                return effects, type(statement).__name__.lower()
            if not isinstance(statement, ast.If):
                continue
            constant = proven_boolean(statement.test, parameter_bindings)
            body_terminal = terminal_kind(statement.body)
            else_terminal = terminal_kind(statement.orelse)
            if constant is not None:
                selected_terminal = body_terminal if constant else else_terminal
                if selected_terminal is not None:
                    return effects, selected_terminal
                continue
            if body_terminal is not None and else_terminal is not None:
                return effects, body_terminal
            terminal = body_terminal or else_terminal
            if terminal is not None:
                active_controls = (
                    *active_controls,
                    [
                        "early-exit",
                        terminal,
                        normalized_control(statement.test, parameter_bindings),
                        "else" if body_terminal is not None else "body",
                    ],
                )
        return effects, None

    helper_edges: dict[ast.AST, set[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for helper_call, helper_target in local_helper_calls.items():
        helper_edges.setdefault(scope_for(helper_call), set()).add(helper_target)

    for _ in range(len(functions) + 1):
        newly_relevant = {
            caller
            for caller, targets in helper_edges.items()
            if targets & relevant_fixed_scopes
        }
        before = len(relevant_fixed_scopes)
        relevant_fixed_scopes.update(newly_relevant)
        if len(relevant_fixed_scopes) == before:
            break

    roots: list[ast.Module | ast.FunctionDef | ast.AsyncFunctionDef] = []
    if tree in relevant_fixed_scopes:
        roots.append(tree)
    function_roots = [
        function
        for function in functions
        if function in relevant_fixed_scopes and function not in called_local_functions
    ]
    roots.extend(function_roots)
    covered_functions: set[ast.FunctionDef | ast.AsyncFunctionDef] = set()

    def cover_helpers(start: ast.AST) -> None:
        pending = list(helper_edges.get(start, set()))
        while pending:
            pending_target = pending.pop()
            if pending_target in covered_functions:
                continue
            covered_functions.add(pending_target)
            pending.extend(helper_edges.get(pending_target, set()))

    cover_helpers(tree)
    for function in function_roots:
        covered_functions.add(function)
        cover_helpers(function)
    for function in sorted(functions, key=anchor):
        if function not in relevant_fixed_scopes or function in covered_functions:
            continue
        roots.append(function)
        covered_functions.add(function)
        cover_helpers(function)
    guarded_effects: list[Effect] = []
    for analysis_root in roots:
        root_effects, _ = statement_block_effects(
            analysis_root.body,
            (),
            (),
            {},
            frozenset({analysis_root})
            if not isinstance(analysis_root, ast.Module)
            else frozenset(),
        )
        guarded_effects.extend(root_effects)
    for record, controls, via in guarded_effects:
        if not controls:
            continue
        guarded_record = dict(record)
        guarded_record["control"] = list(controls)
        if via:
            guarded_record["via"] = list(via)
        records.append(guarded_record)
    return tuple(
        sorted(
            records,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    )


def validate_capability_sink_anchors(
    repository_root: Path,
    catalog: CapabilitySinkCatalog,
) -> tuple[str, ...]:
    """Bind declarations and reject undeclared reachable capability effects."""
    errors: list[str] = []
    try:
        source_graph = build_reachable_capability_source_graph(
            repository_root,
            catalog,
        )
    except CapabilitySourceGraphError as exc:
        return (f"reachable-capability-closure: {exc}",)

    for sink in catalog.sinks:
        relative_path, separator, anchor = sink.implementation.partition(":")
        if not separator or not relative_path or not anchor:
            errors.append(f"{sink.id}: invalid implementation locator")
            continue
        path = repository_root / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"{sink.id}: implementation file is unavailable")
            continue
        if relative_path == "pyproject.toml":
            section = f"[{anchor}]"
            if section not in text:
                errors.append(f"{sink.id}: implementation anchor is absent")
            if sink.enforcement not in text:
                errors.append(f"{sink.id}: enforcement anchor is absent")
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            errors.append(f"{sink.id}: implementation file is not parseable")
            continue
        parts = anchor.split(".")
        candidates: Sequence[ast.AST] = tree.body
        selected: ast.AST | None = None
        for part in parts:
            selected = next(
                (
                    node
                    for node in candidates
                    if isinstance(
                        node,
                        (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
                    )
                    and node.name == part
                ),
                None,
            )
            if selected is None:
                break
            candidates = getattr(selected, "body", ())
        if selected is None:
            errors.append(f"{sink.id}: implementation anchor is absent")
            continue
        selected_text = ast.get_source_segment(text, selected) or ""
        if sink.enforcement not in selected_text:
            errors.append(f"{sink.id}: enforcement anchor is absent")
    sink_implementations = {item.implementation for item in catalog.sinks}
    omission_implementations = {
        item.implementation for item in catalog.omissions
    }
    declared_implementations = sink_implementations | omission_implementations

    # These are effects, rather than a list of validator spellings. Any stream
    # write, serializer-to-stream call, log emission, dynamic callback, ACP
    # wire write, or reversible codec operation is governed by the function
    # that owns it. A new owner has no declaration and therefore fails closed.
    stream_methods = {
        "_write",
        "communicate",
        "critical",
        "debug",
        "emit",
        "error",
        "exception",
        "info",
        "log",
        "send",
        "sendall",
        "sendmsg",
        "sendto",
        "warning",
        "warn",
        "write",
        "write_bytes",
        "write_text",
        "writerow",
        "writerows",
        "writev",
        "writelines",
        "writestr",
    }
    direct_channel_functions = {
        "atomic_write_json",
        "atomic_write_text",
        "cancel",
        "print",
        "send_request",
    }
    serializer_modules = {
        "json": {"dump"},
        "marshal": {"dump"},
        "msgpack": {"dump", "pack"},
        "pickle": {"dump"},
        "plistlib": {"dump"},
        "toml": {"dump"},
        "yaml": {"dump", "safe_dump"},
    }
    descriptor_functions = {
        "os.pwrite",
        "os.pwritev",
        "os.write",
        "os.writev",
    }
    reversible_module_operations = {
        "base64": {
            "b16decode",
            "b16encode",
            "b32decode",
            "b32encode",
            "b32hexdecode",
            "b32hexencode",
            "b64decode",
            "b64encode",
            "b85decode",
            "b85encode",
            "decodebytes",
            "encodebytes",
            "urlsafe_b64decode",
            "urlsafe_b64encode",
        },
        "binascii": {
            "a2b_base64",
            "a2b_hex",
            "b2a_base64",
            "b2a_hex",
            "hexlify",
            "unhexlify",
        },
        "bz2": {"compress", "decompress"},
        "codecs": {"decode", "encode"},
        "lzma": {"compress", "decompress"},
        "quopri": {"decode", "decodestring", "encode", "encodestring"},
        "urllib.parse": {"quote", "quote_plus", "unquote", "unquote_plus"},
        "zlib": {"compress", "decompress"},
    }
    protected_dynamic_modules = {
        "os",
        *serializer_modules,
        *reversible_module_operations,
    }
    supported_transform_owners = {
        "base64.b64decode": "_decode_base64_text",
        "bytes.fromhex": "_decode_hex_text",
        "urllib.parse.unquote": "_decode_percent_text",
        "urllib.parse.quote": "_bounded_candidate_alias_representations",
    }
    canonical_delegations = {
        "atomic_write_json",
        "atomic_write_text",
        "cancel",
        "send_request",
    }
    expected_omission_primitives = {
        "src/unrest_harness/acp_runner.py:ACPNodeRunner._run_terminal_review_lifecycle": (
            "warning",
        ),
        "src/unrest_harness/acp_runner.py:ACPTerminalReviewer._report_progress": (
            "print",
        ),
        "src/unrest_harness/acp_runner.py:ACPClient._dispatch": (
            "_session_update_handler",
        ),
        "src/unrest_harness/baseline.py:_seed_running_mission": ("write_text",),
        "src/unrest_harness/baseline.py:_storage_state": ("write_text",),
        "src/unrest_harness/baseline.py:generate_baseline": ("write_bytes",),
        "src/unrest_harness/baseline.py:main": ("print", "print", "print"),
        "src/unrest_harness/cli.py:_replace_managed_block": ("write_text",),
        "src/unrest_harness/cli.py:_setup_provider_assets": ("write_text",),
        "src/unrest_harness/installed_wheel_check.py:run_installed_wheel_check": (
            "write_text",
            "write_text",
        ),
        "src/unrest_harness/dispatcher.py:MockDispatcher.dispatch": (
            "_responder",
        ),
    }
    observed_omission_primitives: dict[str, list[str]] = {}
    observed_effects: list[tuple[str, str, str]] = []
    completeness_records: list[dict[str, Any]] = []

    def expression_name(
        expression: ast.expr,
        aliases: Mapping[str, str],
        constants: Mapping[str, str | int] | None = None,
    ) -> str:
        """Resolve a locally assigned callable without inspecting values."""
        if isinstance(expression, ast.Name):
            return aliases.get(expression.id, expression.id)
        if isinstance(expression, ast.Attribute):
            owner = expression_name(expression.value, aliases, constants)
            return f"{owner}.{expression.attr}" if owner else expression.attr
        if isinstance(expression, ast.Subscript):
            owner = expression_name(expression.value, aliases, constants)
            key = constant_string(expression.slice, constants or {})
            if owner.endswith(".__dict__"):
                module_name = owner.removesuffix(".__dict__")
                if key is not None:
                    return f"{module_name}.{key}"
                if module_name in protected_dynamic_modules:
                    return f"{module_name}.<dynamic>"
            container_key = constant_container_key(
                expression.slice,
                constants or {},
            )
            if container_key is not None:
                slot = container_slot(owner, container_key)
                resolved = aliases.get(slot)
                if resolved is not None:
                    return resolved
                return slot
            return f"{owner}[]" if owner else ""
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id == "getattr"
            and len(expression.args) >= 2
        ):
            owner = expression_name(expression.args[0], aliases, constants)
            attribute = constant_string(
                expression.args[1],
                constants or {},
            )
            if owner and attribute is not None:
                return f"{owner}.{attribute}"
            if owner in protected_dynamic_modules:
                return f"{owner}.<dynamic>"
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id == "vars"
            and len(expression.args) == 1
        ):
            owner = expression_name(expression.args[0], aliases, constants)
            return f"{owner}.__dict__" if owner else ""
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "get"
            and len(expression.args) >= 1
        ):
            owner = expression_name(
                expression.func.value,
                aliases,
                constants,
            )
            if owner.endswith(".__dict__"):
                module_name = owner.removesuffix(".__dict__")
                attribute = constant_string(
                    expression.args[0],
                    constants or {},
                )
                if attribute is not None:
                    return f"{module_name}.{attribute}"
                if module_name in protected_dynamic_modules:
                    return f"{module_name}.<dynamic>"
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id == "next"
            and len(expression.args) == 1
            and isinstance(expression.args[0], ast.Call)
            and isinstance(expression.args[0].func, ast.Name)
            and expression.args[0].func.id == "iter"
            and len(expression.args[0].args) == 1
        ):
            owner = expression_name(
                expression.args[0].args[0],
                aliases,
                constants,
            )
            return aliases.get(container_slot(owner, "<singleton>"), "")
        return ""

    def constant_string(
        expression: ast.AST,
        constants: Mapping[str, str | int],
    ) -> str | None:
        value = constant_primitive(expression, constants)
        return value if isinstance(value, str) else None

    def constant_primitive(
        expression: ast.AST,
        constants: Mapping[str, str | int],
    ) -> str | int | None:
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value,
            (str, int),
        ):
            return expression.value
        if isinstance(expression, ast.Name):
            return constants.get(expression.id)
        return None

    def constant_container_key(
        expression: ast.AST,
        constants: Mapping[str, str | int],
    ) -> str | int | None:
        return constant_primitive(expression, constants)

    def container_slot(owner: str, key: str | int) -> str:
        return f"{owner}[{key!r}]"

    def literal_container_items(
        expression: ast.expr,
        constants: Mapping[str, str | int],
    ) -> tuple[tuple[tuple[str | int, ...], ast.expr], ...]:
        immediate: tuple[tuple[str | int, ast.expr], ...]
        if isinstance(expression, (ast.List, ast.Tuple)):
            immediate = tuple(enumerate(expression.elts))
        elif isinstance(expression, ast.Dict):
            immediate = tuple(
                (key, value)
                for key_node, value in zip(
                    expression.keys,
                    expression.values,
                    strict=True,
                )
                if key_node is not None
                and (
                    key := constant_container_key(key_node, constants)
                )
                is not None
            )
        elif isinstance(expression, ast.Set) and len(expression.elts) == 1:
            immediate = (("<singleton>", expression.elts[0]),)
        else:
            return ()
        output: list[tuple[tuple[str | int, ...], ast.expr]] = []
        for key, item in immediate:
            nested = literal_container_items(item, constants)
            if nested:
                output.extend(
                    ((key, *path), leaf) for path, leaf in nested
                )
            else:
                output.append(((key,), item))
        return tuple(output)

    def annotation_is_callable(annotation: ast.expr | None) -> bool:
        if annotation is None:
            return False
        for item in ast.walk(annotation):
            if isinstance(item, ast.Name) and item.id == "Callable":
                return True
            if isinstance(item, ast.Attribute) and item.attr == "Callable":
                return True
        return False

    def shape_matched_assignments(
        target: ast.expr,
        value: ast.expr,
    ) -> tuple[tuple[tuple[str, ...], ast.expr], ...]:
        if isinstance(target, ast.Name):
            return (((target.id,), value),)
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(isinstance(item, ast.Starred) for item in target.elts)
        ):
            return tuple(
                assignment
                for target_item, value_item in zip(
                    target.elts,
                    value.elts,
                    strict=True,
                )
                for assignment in shape_matched_assignments(
                    target_item,
                    value_item,
                )
            )
        return ()

    def shape_matched_state_values(
        target: ast.expr,
        value: ast.expr,
    ) -> tuple[ast.expr, ...]:
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            return (value,)
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(
                isinstance(item, ast.Starred)
                for item in (*target.elts, *value.elts)
            )
        ):
            return tuple(
                state_value
                for target_item, value_item in zip(
                    target.elts,
                    value.elts,
                    strict=True,
                )
                for state_value in shape_matched_state_values(
                    target_item,
                    value_item,
                )
            )
        return ()

    def expression_contains_callable(
        expression: ast.AST,
        callable_names: set[str],
    ) -> bool:
        if isinstance(expression, ast.Name):
            return expression.id in callable_names
        if isinstance(expression, (ast.Tuple, ast.List, ast.Set)):
            return any(
                expression_contains_callable(item, callable_names)
                for item in expression.elts
            )
        if isinstance(expression, ast.Dict):
            return any(
                expression_contains_callable(item, callable_names)
                for item in (*expression.keys, *expression.values)
                if item is not None
            )
        if isinstance(expression, (ast.Attribute, ast.Subscript)):
            return expression_contains_callable(expression.value, callable_names)
        if isinstance(expression, ast.Lambda):
            positional = (
                *expression.args.posonlyargs,
                *expression.args.args,
            )
            default_count = len(expression.args.defaults)
            default_arguments = (
                positional[-default_count:] if default_count else ()
            )
            captured_names = {
                argument.arg
                for argument, default in zip(
                    default_arguments,
                    expression.args.defaults,
                    strict=True,
                )
                if expression_contains_callable(default, callable_names)
            }
            captured_names.update(
                argument.arg
                for argument, default in zip(
                    expression.args.kwonlyargs,
                    expression.args.kw_defaults,
                    strict=True,
                )
                if default is not None
                and expression_contains_callable(default, callable_names)
            )
            return any(
                expression_contains_callable(
                    item.func,
                    callable_names | captured_names,
                )
                for item in ast.walk(expression.body)
                if isinstance(item, ast.Call)
            )
        return False

    def callable_alias_source_names(expression: ast.AST) -> set[str]:
        if isinstance(expression, ast.Name):
            return {expression.id}
        if isinstance(expression, (ast.Tuple, ast.List, ast.Set)):
            return {
                name
                for item in expression.elts
                for name in callable_alias_source_names(item)
            }
        if isinstance(expression, ast.Dict):
            return {
                name
                for item in (*expression.keys, *expression.values)
                if item is not None
                for name in callable_alias_source_names(item)
            }
        if isinstance(expression, (ast.Attribute, ast.Subscript)):
            return callable_alias_source_names(expression.value)
        return set()

    def called_local_name(function: ast.expr) -> str | None:
        if isinstance(function, ast.Name):
            return function.id
        if isinstance(function, ast.Subscript):
            names = callable_alias_source_names(function.value)
            return next(iter(names)) if len(names) == 1 else None
        return None

    def serializer_channel(call_name: str, node: ast.Call) -> bool:
        module_name, separator, operation = call_name.rpartition(".")
        if (
            separator
            and (
                operation in serializer_modules.get(module_name, set())
                or (
                    operation == "<dynamic>"
                    and module_name in serializer_modules
                )
            )
        ):
            return len(node.args) >= 2 or any(
                keyword.arg in {"file", "fp", "stream"}
                for keyword in node.keywords
            )
        # A two-argument dump has the serializer-to-stream shape even when a
        # new serializer module has not yet been added to this reviewed list.
        return operation == "dump" and len(node.args) >= 2

    def reversible_operation(call_name: str) -> bool:
        if call_name == "bytes.fromhex":
            return True
        module_name, separator, operation = call_name.rpartition(".")
        if (
            separator
            and operation == "<dynamic>"
            and module_name in reversible_module_operations
        ):
            return True
        if separator and operation in reversible_module_operations.get(
            module_name,
            set(),
        ):
            return True
        return operation in {"maketrans", "translate"}

    def capability_callable_family(call_name: str) -> str | None:
        if reversible_operation(call_name):
            return "transform"
        module_name, separator, operation = call_name.rpartition(".")
        if separator and operation in serializer_modules.get(
            module_name,
            set(),
        ):
            return "serializer"
        if operation == "<dynamic>" and module_name in serializer_modules:
            return "serializer"
        if (
            call_name in direct_channel_functions
            or call_name in descriptor_functions
            or call_name == "os.<dynamic>"
        ):
            return "writer"
        return None

    def effect_implementation(
        node: ast.AST,
        parents: Mapping[ast.AST, ast.AST],
        relative_path: str,
    ) -> tuple[str, str]:
        cursor: ast.AST | None = node
        names: list[str] = []
        while cursor is not None:
            if isinstance(
                cursor,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                names.append(cursor.name)
            cursor = parents.get(cursor)
        anchor = "<module>" if not names else ".".join(reversed(names))
        return anchor, f"{relative_path}:{anchor}"

    def reverse_slice(node: ast.Subscript) -> bool:
        slice_node = node.slice
        return (
            isinstance(slice_node, ast.Slice)
            and isinstance(slice_node.step, ast.UnaryOp)
            and isinstance(slice_node.step.op, ast.USub)
            and isinstance(slice_node.step.operand, ast.Constant)
            and slice_node.step.operand.value == 1
        )

    def joined_reversal(node: ast.Call) -> bool:
        if (
            not isinstance(node.func, ast.Attribute)
            or node.func.attr != "join"
            or len(node.args) != 1
        ):
            return False
        candidate = node.args[0]
        return (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Name)
            and candidate.func.id == "reversed"
        )

    def materialized_reversal(node: ast.Call) -> bool:
        if (
            not isinstance(node.func, ast.Name)
            or node.func.id not in {"bytearray", "bytes", "list", "tuple"}
            or len(node.args) != 1
        ):
            return False
        candidate = node.args[0]
        return (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Name)
            and candidate.func.id == "reversed"
        )

    for relative_path in source_graph:
        path = repository_root / relative_path
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, UnicodeError, SyntaxError):
            errors.append(f"reachable-sink-closure: {relative_path} is unavailable")
            continue
        completeness_records.extend(
            normalized_external_egress_records(relative_path, tree)
        )
        import_aliases: dict[str, str] = {}
        for module_statement in tree.body:
            if isinstance(module_statement, ast.Import):
                for alias in module_statement.names:
                    import_aliases[alias.asname or alias.name] = alias.name
            elif (
                isinstance(module_statement, ast.ImportFrom)
                and module_statement.module
            ):
                for alias in module_statement.names:
                    import_aliases[alias.asname or alias.name] = (
                        f"{module_statement.module}.{alias.name}"
                    )
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        def is_invoked_callable_reference(node: ast.AST) -> bool:
            parent = parents.get(node)
            return isinstance(parent, ast.Call) and parent.func is node

        def resolved_capability_references(
            expression: ast.AST,
            aliases: Mapping[str, str],
            constants: Mapping[str, str | int],
        ) -> set[tuple[str, str]]:
            references: set[tuple[str, str]] = set()
            for item in ast.walk(expression):
                if not isinstance(
                    item,
                    (ast.Name, ast.Attribute, ast.Subscript, ast.Call),
                ) or is_invoked_callable_reference(item):
                    continue
                name = expression_name(item, aliases, constants)
                family = capability_callable_family(name)
                if family is not None:
                    references.add((family, name))
                if not name:
                    continue
                slot_prefix = f"{name}["
                for slot, slot_name in aliases.items():
                    if not slot.startswith(slot_prefix):
                        continue
                    slot_family = capability_callable_family(slot_name)
                    if slot_family is not None:
                        references.add((slot_family, slot_name))
            return references

        function_parameters: dict[ast.AST, set[str]] = {}
        parameter_annotations: dict[ast.AST, dict[str, ast.expr | None]] = {}
        for owner_node in ast.walk(tree):
            if not isinstance(
                owner_node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            function_parameters[owner_node] = {
                argument.arg
                for argument in (
                    *owner_node.args.posonlyargs,
                    *owner_node.args.args,
                    *owner_node.args.kwonlyargs,
                )
            }
            parameter_annotations[owner_node] = {
                argument.arg: argument.annotation
                for argument in (
                    *owner_node.args.posonlyargs,
                    *owner_node.args.args,
                    *owner_node.args.kwonlyargs,
                )
            }

        def lexical_owner(node: ast.AST) -> ast.AST:
            cursor: ast.AST | None = node
            while cursor is not None:
                if isinstance(cursor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return cursor
                cursor = parents.get(cursor)
            return tree

        def lexical_class(node: ast.AST) -> ast.ClassDef | None:
            cursor: ast.AST | None = node
            while cursor is not None:
                if isinstance(cursor, ast.ClassDef):
                    return cursor
                cursor = parents.get(cursor)
            return None

        assigned_callable_attributes: dict[ast.ClassDef, set[str]] = {}
        called_attributes: dict[ast.ClassDef, set[str]] = {}
        callable_attribute_assignments: list[
            tuple[ast.ClassDef, str, ast.AST, str]
        ] = []
        for statement in ast.walk(tree):
            owner_class = lexical_class(statement)
            if owner_class is None:
                continue
            if (
                isinstance(statement, (ast.Assign, ast.AnnAssign))
                and isinstance(statement.value, ast.Name)
            ):
                attribute_targets = (
                    tuple(statement.targets)
                    if isinstance(statement, ast.Assign)
                    else (statement.target,)
                )
                owner_scope = lexical_owner(statement)
                if statement.value.id not in function_parameters.get(
                    owner_scope,
                    set(),
                ):
                    continue
                for target in attribute_targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        assigned_callable_attributes.setdefault(
                            owner_class,
                            set(),
                        ).add(target.attr)
                        callable_attribute_assignments.append(
                            (
                                owner_class,
                                target.attr,
                                owner_scope,
                                statement.value.id,
                            )
                        )
            elif (
                isinstance(statement, ast.Call)
                and isinstance(statement.func, ast.Attribute)
                and isinstance(statement.func.value, ast.Name)
                and statement.func.value.id == "self"
            ):
                called_attributes.setdefault(owner_class, set()).add(
                    statement.func.attr
                )
        class_callback_attributes = {
            owner_class: attributes
            & called_attributes.get(owner_class, set())
            for owner_class, attributes in assigned_callable_attributes.items()
        }
        callable_attribute_parameters: dict[ast.AST, set[str]] = {}
        for owner_class, attribute, owner_scope, parameter in (
            callable_attribute_assignments
        ):
            if attribute in class_callback_attributes.get(owner_class, set()):
                callable_attribute_parameters.setdefault(
                    owner_scope,
                    set(),
                ).add(parameter)

        def is_class_callback_call(function: ast.expr, node: ast.AST) -> bool:
            owner_class = lexical_class(node)
            return (
                owner_class is not None
                and isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "self"
                and function.attr
                in class_callback_attributes.get(owner_class, set())
            )

        scopes: tuple[ast.AST, ...] = (tree, *function_parameters)
        scope_aliases: dict[ast.AST, dict[str, str]] = {
            scope: dict(import_aliases) for scope in scopes
        }
        for statement in ast.walk(tree):
            aliases = scope_aliases[lexical_owner(statement)]
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    aliases[alias.asname or alias.name] = alias.name
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    aliases[alias.asname or alias.name] = (
                        f"{statement.module}.{alias.name}"
                    )
        scope_assignments: dict[
            ast.AST,
            list[tuple[tuple[str, ...], ast.expr]],
        ] = {scope: [] for scope in scopes}
        for statement in ast.walk(tree):
            target_nodes: tuple[ast.expr, ...]
            value: ast.expr | None
            if isinstance(statement, ast.Assign):
                target_nodes = tuple(statement.targets)
                value = statement.value
            elif isinstance(statement, ast.AnnAssign):
                target_nodes = (statement.target,)
                value = statement.value
            else:
                continue
            if value is None:
                continue
            for target in target_nodes:
                scope_assignments[lexical_owner(statement)].extend(
                    shape_matched_assignments(target, value)
                )

        scope_constants: dict[ast.AST, dict[str, str | int]] = {}
        for scope in scopes:
            constants = (
                {}
                if scope is tree
                else dict(scope_constants.get(tree, {}))
            )
            assignments = scope_assignments[scope]
            local_counts: dict[str, int] = {}
            for names, _value in assignments:
                for name in names:
                    local_counts[name] = local_counts.get(name, 0) + 1
                    constants.pop(name, None)
            for _ in range(len(assignments) + 1):
                changed = False
                for names, value in assignments:
                    resolved = constant_primitive(value, constants)
                    if resolved is None:
                        continue
                    for name in names:
                        if local_counts[name] != 1:
                            continue
                        if constants.get(name) != resolved:
                            constants[name] = resolved
                            changed = True
                if not changed:
                    break
            scope_constants[scope] = constants

        # Resolve simple and bound callable aliases to a fixed point. This is
        # deliberately lexical and value-free: it models ownership/flow, not
        # runtime data or arbitrary source text.
        for scope in scopes:
            aliases = scope_aliases[scope]
            for _ in range(len(scope_assignments[scope]) + 1):
                changed = False
                for names, value in scope_assignments[scope]:
                    resolved = expression_name(
                        value,
                        aliases,
                        scope_constants[scope],
                    )
                    if resolved:
                        for name in names:
                            if aliases.get(name) != resolved:
                                aliases[name] = resolved
                                changed = True
                    for key_path, item in literal_container_items(
                        value,
                        scope_constants[scope],
                    ):
                        item_name = expression_name(
                            item,
                            aliases,
                            scope_constants[scope],
                        )
                        if not item_name:
                            continue
                        for name in names:
                            slot = name
                            for key in key_path:
                                slot = container_slot(slot, key)
                            if aliases.get(slot) != item_name:
                                aliases[slot] = item_name
                                changed = True
                if not changed:
                    break

        scope_callable_names: dict[ast.AST, set[str]] = {
            scope: set() for scope in scopes
        }
        scope_callback_wrappers: dict[ast.AST, set[str]] = {
            scope: set() for scope in scopes
        }
        scope_output_callback_names: dict[ast.AST, set[str]] = {
            scope: set() for scope in scopes
        }
        for scope in function_parameters:
            output_names = scope_output_callback_names[scope]
            output_names.update(
                name
                for name in function_parameters[scope]
                if name == "callback"
            )
            output_names.update(
                callable_attribute_parameters.get(scope, set())
            )
            for _ in range(len(scope_assignments[scope]) + 1):
                changed = False
                for targets, value in scope_assignments[scope]:
                    if expression_contains_callable(value, output_names):
                        before = len(output_names)
                        output_names.update(targets)
                        changed = changed or len(output_names) != before
                if not changed:
                    break
        nested_callback_wrappers: dict[ast.AST, set[str]] = {}
        for nested in function_parameters:
            if not isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            parent_node = parents.get(nested)
            if parent_node is None:
                continue
            enclosing = lexical_owner(parent_node)
            if enclosing is tree:
                continue
            enclosing_output_names = scope_output_callback_names[enclosing]
            positional = (*nested.args.posonlyargs, *nested.args.args)
            default_count = len(nested.args.defaults)
            default_arguments = (
                positional[-default_count:] if default_count else ()
            )
            captured_default_names = {
                argument.arg
                for argument, default in zip(
                    default_arguments,
                    nested.args.defaults,
                    strict=True,
                )
                if expression_name(
                    default,
                    scope_aliases[enclosing],
                    scope_constants[enclosing],
                )
                in enclosing_output_names
            }
            captured_default_names.update(
                argument.arg
                for argument, default in zip(
                    nested.args.kwonlyargs,
                    nested.args.kw_defaults,
                    strict=True,
                )
                if default is not None
                and expression_name(
                    default,
                    scope_aliases[enclosing],
                    scope_constants[enclosing],
                )
                in enclosing_output_names
            )
            invokes_enclosing_parameter = any(
                (
                    called_name in captured_default_names
                    or expression_name(
                        call.func,
                        scope_aliases[enclosing],
                        scope_constants[enclosing],
                    )
                    in enclosing_output_names
                )
                for call in ast.walk(nested)
                if isinstance(call, ast.Call) and lexical_owner(call) is nested
                if (called_name := called_local_name(call.func)) is not None
            )
            if invokes_enclosing_parameter:
                nested_callback_wrappers.setdefault(enclosing, set()).add(
                    nested.name
                )
        for scope in function_parameters:
            parameters = function_parameters[scope]
            callable_names = scope_callable_names[scope]
            callable_names.update(
                name
                for name, annotation in parameter_annotations[scope].items()
                if annotation_is_callable(annotation)
            )
            callable_names.update(nested_callback_wrappers.get(scope, set()))
            owner_class = lexical_class(scope)
            if owner_class is not None and class_callback_attributes.get(
                owner_class,
                set(),
            ):
                callable_names.update(
                    callable_attribute_parameters.get(scope, set())
                )
            called_names = {
                called_name
                for node in ast.walk(scope)
                if isinstance(node, ast.Call) and lexical_owner(node) is scope
                if (called_name := called_local_name(node.func)) is not None
            }
            for called_name in sorted(called_names):
                alias_chain = {called_name}
                for _ in range(len(scope_assignments[scope]) + 1):
                    before = len(alias_chain)
                    for targets, value in scope_assignments[scope]:
                        if set(targets) & alias_chain:
                            alias_chain.update(
                                callable_alias_source_names(value)
                            )
                    if len(alias_chain) == before:
                        break
                if alias_chain & (parameters - {"cls", "self"}):
                    callable_names.update(alias_chain)
            for _ in range(len(scope_assignments[scope]) + 1):
                changed = False
                for targets, value in scope_assignments[scope]:
                    if expression_contains_callable(value, callable_names):
                        before = len(callable_names)
                        callable_names.update(targets)
                        changed = changed or len(callable_names) != before
                if not changed:
                    break
            wrapper_names = scope_callback_wrappers[scope]
            wrapper_names.update(nested_callback_wrappers.get(scope, set()))
            for _ in range(len(scope_assignments[scope]) + 1):
                changed = False
                for targets, value in scope_assignments[scope]:
                    is_lambda_wrapper = (
                        isinstance(value, ast.Lambda)
                        and expression_contains_callable(
                            value,
                            callable_names,
                        )
                    )
                    aliases_wrapper = expression_contains_callable(
                        value,
                        wrapper_names,
                    )
                    if is_lambda_wrapper or aliases_wrapper:
                        before = len(wrapper_names)
                        wrapper_names.update(targets)
                        changed = changed or len(wrapper_names) != before
                if not changed:
                    break

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            scope = lexical_owner(node)
            call_name = expression_name(
                function,
                scope_aliases[scope],
                scope_constants[scope],
            )
            leaf_name = call_name.rsplit(".", 1)[-1]
            owner: ast.FunctionDef | ast.AsyncFunctionDef | None = None
            cursor: ast.AST | None = node
            while cursor is not None:
                if owner is None and isinstance(
                    cursor,
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                ):
                    owner = cursor
                cursor = parents.get(cursor)
            anchor, implementation = effect_implementation(
                node,
                parents,
                relative_path,
            )

            callback_channel = (
                owner is not None
                and (
                    (
                        expression_contains_callable(
                            function,
                            scope_callable_names[owner],
                        )
                        and isinstance(
                            parents.get(node),
                            (ast.Expr, ast.Await),
                        )
                    )
                    or is_class_callback_call(function, node)
                    or expression_contains_callable(
                        function,
                        scope_output_callback_names[owner],
                    )
                    or expression_contains_callable(
                        function,
                        scope_callback_wrappers[owner],
                    )
                )
            )
            is_serializer_channel = serializer_channel(call_name, node)
            data_bearing_call = bool(node.args or node.keywords)
            output_effect = data_bearing_call and (
                leaf_name in stream_methods
                or leaf_name in direct_channel_functions
                or call_name in descriptor_functions
                or call_name == "os.<dynamic>"
                or is_serializer_channel
                or callback_channel
            )
            if output_effect:
                if is_serializer_channel:
                    effect_family = "serializer"
                elif callback_channel:
                    effect_family = "callback"
                elif leaf_name in direct_channel_functions:
                    effect_family = "direct-channel"
                else:
                    effect_family = "stream-channel"
                effect_primitive = (
                    call_name
                    if effect_family in {"serializer", "direct-channel"}
                    else (
                        "<dynamic-callback>"
                        if effect_family == "callback"
                        else leaf_name
                    )
                )
                observed_effects.append(
                    (implementation, effect_family, effect_primitive)
                )
            if output_effect and implementation not in declared_implementations:
                errors.append(
                    "reachable-sink-closure: "
                    f"uncataloged output effect at {implementation}:{node.lineno}"
                )
            elif (
                output_effect
                and implementation in omission_implementations
                and implementation not in sink_implementations
                and leaf_name not in canonical_delegations
            ):
                observed_omission_primitives.setdefault(
                    implementation,
                    [],
                ).append(leaf_name)

            expected_owner = supported_transform_owners.get(call_name)
            unsupported_transform = (
                reversible_operation(call_name) and expected_owner is None
            )
            if expected_owner is not None and anchor != expected_owner:
                errors.append(
                    "reachable-transform-closure: "
                    f"{call_name} is outside its declared transform owner at "
                    f"{implementation}:{node.lineno}"
                )
            elif unsupported_transform:
                errors.append(
                    "reachable-transform-closure: "
                    f"unsupported reversible operation at {implementation}:{node.lineno}"
                )
            if expected_owner is not None:
                observed_effects.append(
                    (implementation, "supported-transform", call_name)
                )
            elif unsupported_transform:
                observed_effects.append(
                    (implementation, "unsupported-transform", call_name)
                )

        # Callable capability may leave its lexical owner without being
        # invoked there (registration, return, or assignment to externally
        # reachable state). Those flows are security effects in their own
        # right; otherwise an alias can move the eventual write beyond the
        # reviewed owner.
        for node in ast.walk(tree):
            scope = lexical_owner(node)
            if scope is tree:
                continue
            callable_names = scope_callable_names[scope]
            aliases = scope_aliases[scope]
            escape_kind: str | None = None
            escape_values: tuple[ast.expr, ...] = ()
            if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                escape_kind = "return"
                escape_values = () if node.value is None else (node.value,)
            elif isinstance(node, ast.Assign):
                if any(
                    isinstance(target, (ast.Attribute, ast.Subscript))
                    for target in node.targets
                ):
                    escape_kind = "state"
                    escape_values = (node.value,)
                else:
                    escape_values = tuple(
                        state_value
                        for target in node.targets
                        for state_value in shape_matched_state_values(
                            target,
                            node.value,
                        )
                    )
                    if escape_values:
                        escape_kind = "state"
            elif isinstance(node, ast.AnnAssign) and isinstance(
                node.target,
                (ast.Attribute, ast.Subscript),
            ):
                escape_kind = "state"
                escape_values = () if node.value is None else (node.value,)
            for escape_value in escape_values:
                if (
                    escape_kind is not None
                    and expression_contains_callable(
                        escape_value,
                        callable_names,
                    )
                ):
                    _anchor, implementation = effect_implementation(
                        node,
                        parents,
                        relative_path,
                    )
                    observed_effects.append(
                        (implementation, "callback-escape", escape_kind)
                    )

                escaped_capabilities = resolved_capability_references(
                    escape_value,
                    aliases,
                    scope_constants[scope],
                )
                for family, capability_name in sorted(escaped_capabilities):
                    _anchor, implementation = effect_implementation(
                        node,
                        parents,
                        relative_path,
                    )
                    observed_effects.append(
                        (
                            implementation,
                            f"{family}-escape",
                            capability_name,
                        )
                    )

            if not isinstance(node, ast.Call):
                continue
            if expression_contains_callable(node.func, callable_names):
                continue
            escaped_argument = any(
                expression_contains_callable(argument, callable_names)
                for argument in (
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                )
            )
            if escaped_argument:
                _anchor, implementation = effect_implementation(
                    node,
                    parents,
                    relative_path,
                )
                observed_effects.append(
                    (implementation, "callback-escape", "argument")
                )
                if implementation not in declared_implementations:
                    errors.append(
                        "reachable-sink-closure: "
                        f"uncataloged callback escape at "
                        f"{implementation}:{node.lineno}"
                    )

            capability_references: set[tuple[str, str]] = set()
            for argument in (
                *node.args,
                *(keyword.value for keyword in node.keywords),
            ):
                capability_references.update(
                    resolved_capability_references(
                        argument,
                        aliases,
                        scope_constants[scope],
                    )
                )
            for family, capability_name in sorted(capability_references):
                _anchor, implementation = effect_implementation(
                    node,
                    parents,
                    relative_path,
                )
                observed_effects.append(
                    (implementation, f"{family}-escape", capability_name)
                )
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and reverse_slice(node):
                transform_primitive = "reverse-slice"
            elif isinstance(node, ast.Call) and joined_reversal(node):
                transform_primitive = "join-reversed"
            elif isinstance(node, ast.Call) and materialized_reversal(node):
                transform_primitive = "materialize-reversed"
            else:
                continue
            _anchor, implementation = effect_implementation(
                node,
                parents,
                relative_path,
            )
            observed_effects.append(
                (
                    implementation,
                    "unsupported-transform",
                    transform_primitive,
                )
            )
            if implementation not in omission_implementations:
                errors.append(
                    "reachable-transform-closure: "
                    f"unsupported reversible operation at "
                    f"{implementation}:{node.lineno}"
                )
    for implementation in sorted(
        set(expected_omission_primitives) | set(observed_omission_primitives)
    ):
        observed = tuple(sorted(observed_omission_primitives.get(implementation, ())))
        expected = tuple(sorted(expected_omission_primitives.get(implementation, ())))
        if observed != expected:
            errors.append(
                "reachable-sink-closure: "
                f"declared omission effect drift at {implementation}"
            )
    observed_effect_digest = hashlib.sha256(
        json.dumps(
            {
                "completeness": sorted(
                    completeness_records,
                    key=lambda item: json.dumps(
                        item,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
                "effects": sorted(observed_effects),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if observed_effect_digest != catalog.reachable_source_sha256:
        errors.append(
            "reachable-capability-closure: "
            "effect graph does not match the reviewed catalog "
            f"(observed sha256={observed_effect_digest})"
        )
    return tuple(errors)


def _integer_constant_expression(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp):
        left = _integer_constant_expression(node.left)
        right = _integer_constant_expression(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Mult):
            return left * right
    return None


def validate_capability_model_anchors(
    repository_root: Path,
    model: CapabilitySecurityModel,
) -> tuple[str, ...]:
    """Bind every declared ceiling to the version-1 implementation constant."""
    path = repository_root / "src/unrest_harness/capability_policy.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return ("capability-policy: implementation file is unavailable",)
    constants = {
        target.id: _integer_constant_expression(node.value)
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        if node.value is not None
        for target in (
            node.targets
            if isinstance(node, ast.Assign)
            else (node.target,)
        )
        if isinstance(target, ast.Name)
    }
    bindings = {
        "aggregate_work_bytes": "_SEMANTIC_INSPECTION_MAX_WORK",
        "decoded_bytes": "_SEMANTIC_INSPECTION_MAX_DECODED_BYTES",
        "expansion_nodes": "_SEMANTIC_INSPECTION_MAX_EXPANSIONS",
        "format_ast_depth": "_FORMAT_AST_MAX_DEPTH",
        "semantic_depth": "_SEMANTIC_INSPECTION_MAX_DEPTH",
        "semantic_nodes": "_SEMANTIC_INSPECTION_MAX_NODES",
        "text_bytes": "_SEMANTIC_INSPECTION_MAX_TEXT",
        "transform_count": "_SEMANTIC_INSPECTION_MAX_TRANSFORMS",
    }
    declared = model.ceilings.model_dump()
    return tuple(
        f"{field_name}: implementation constant {constant_name} does not match"
        for field_name, constant_name in sorted(bindings.items())
        if constants.get(constant_name) != declared[field_name]
    )


def load_capability_policy(bundled_dir: Path) -> CapabilityPolicy:
    path = policy_path(bundled_dir)
    return _load_strict_capability_asset(
        path,
        model=CapabilityPolicy,
        capability="policy-document",
        resource_kind="policy",
    )


def resolve_profile_from_environment(
    environment: Mapping[str, str],
) -> tuple[int, str]:
    raw_version = environment.get(CAPABILITY_VERSION_ENV, str(CAPABILITY_POLICY_VERSION))
    try:
        version = int(raw_version)
    except ValueError as exc:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=raw_version,
            capability="policy-version",
            reason="must be an integer",
        ) from exc
    if version != CAPABILITY_POLICY_VERSION:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability="policy-version",
            reason="unsupported policy version",
        )

    profile = environment.get(CAPABILITY_PROFILE_ENV, SAFE_PROFILE)
    opt_in = environment.get(UNSAFE_DEVELOPMENT_ENV)
    if opt_in is not None and opt_in != "1":
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability=UNSAFE_DEVELOPMENT_ENV,
            reason="explicit unsafe development opt-in must be exactly '1'",
        )
    if profile == UNSAFE_DEVELOPMENT_PROFILE and opt_in != "1":
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability=f"profile:{profile}",
            reason=f"requires {UNSAFE_DEVELOPMENT_ENV}=1",
        )
    if opt_in == "1" and profile != UNSAFE_DEVELOPMENT_PROFILE:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability=UNSAFE_DEVELOPMENT_ENV,
            reason=f"requires {CAPABILITY_PROFILE_ENV}={UNSAFE_DEVELOPMENT_PROFILE}",
        )
    if profile not in (SAFE_PROFILE, UNSAFE_DEVELOPMENT_PROFILE):
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability=f"profile:{profile}",
            reason="unsupported capability profile",
        )
    suspicious = sorted(
        key
        for key in environment
        if key.startswith("UNREST_")
        and "UNSAFE" in key
        and key != UNSAFE_DEVELOPMENT_ENV
    )
    if suspicious:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=version,
            capability="unsafe-development-opt-in",
            reason=(
                "unknown unsafe setting "
                f"identifier={_diagnostic_identifier(suspicious[0], allowed=set())}"
            ),
        )
    return version, profile


def profile_environment(profile: str) -> dict[str, str]:
    env = {
        CAPABILITY_PROFILE_ENV: profile,
        CAPABILITY_VERSION_ENV: str(CAPABILITY_POLICY_VERSION),
    }
    if profile == UNSAFE_DEVELOPMENT_PROFILE:
        env[UNSAFE_DEVELOPMENT_ENV] = "1"
    return env


def validate_provider_support(
    provider: ProviderDefinition,
    *,
    role: RoleName,
    policy: CapabilityPolicy,
    profile: str,
) -> RoleCapability:
    version = policy.schema_version
    if version not in provider.capability_policy_versions:
        raise CapabilityPolicyError(
            provider=provider.name,
            role=role,
            version=version,
            capability="policy-version",
            reason="provider does not support this version",
        )
    if profile not in provider.capability_profiles:
        raise CapabilityPolicyError(
            provider=provider.name,
            role=role,
            version=version,
            capability=f"profile:{profile}",
            reason="provider does not support this profile",
        )
    if role not in provider.capability_roles:
        raise CapabilityPolicyError(
            provider=provider.name,
            role=role,
            version=version,
            capability="role",
            reason="provider cannot enforce this role",
        )
    try:
        role_policy = policy.role(profile, role)
    except KeyError as exc:
        raise CapabilityPolicyError(
            provider=provider.name,
            role=role,
            version=version,
            capability=f"profile:{profile}",
            reason="profile is absent from the policy",
        ) from exc
    if role_policy.network.mode not in provider.network_modes:
        raise CapabilityPolicyError(
            provider=provider.name,
            role=role,
            version=version,
            capability=f"network:{role_policy.network.mode}",
            reason="provider cannot enforce this network capability",
        )
    if role != "orchestrator":
        if role_policy.filesystem and not provider.acp_filesystem_enforcement:
            raise CapabilityPolicyError(
                provider=provider.name,
                role=role,
                version=version,
                capability="filesystem",
                reason="provider lacks ACP filesystem enforcement",
            )
        if role_policy.process.enabled and not provider.acp_terminal_enforcement:
            raise CapabilityPolicyError(
                provider=provider.name,
                role=role,
                version=version,
                capability="terminal",
                reason="provider lacks ACP terminal enforcement",
            )
        if not provider.acp_permission_enforcement:
            raise CapabilityPolicyError(
                provider=provider.name,
                role=role,
                version=version,
                capability="approvals",
                reason="provider lacks ACP permission enforcement",
            )
    return role_policy


def resolve_role_capability(
    provider: ProviderDefinition,
    *,
    role: RoleName,
    policy: CapabilityPolicy,
    profile: str,
    workspace: Path,
    project_record: Path,
    deliverable_roots: Sequence[Path] = (),
) -> ResolvedRoleCapability:
    role_policy = validate_provider_support(
        provider,
        role=role,
        policy=policy,
        profile=profile,
    )
    locations: dict[RootName, tuple[Path, ...]] = {
        "workspace": (workspace,),
        "project_record": (project_record,),
        "deliverable_roots": tuple(deliverable_roots),
        "host": (Path(workspace.anchor or os.sep),),
    }
    roots: list[ResolvedRoot] = []
    seen: set[tuple[str, str, bool, bool]] = set()
    for declaration in role_policy.filesystem:
        selected = locations[declaration.name]
        if declaration.name == "deliverable_roots" and not selected:
            continue
        for raw_root in selected:
            try:
                canonical = raw_root.expanduser().resolve(strict=True)
            except OSError as exc:
                raise CapabilityPolicyError(
                    provider=provider.name,
                    role=role,
                    version=policy.schema_version,
                    capability=f"filesystem-root:{declaration.name}",
                    reason="root does not resolve canonically",
                ) from exc
            identity = (
                declaration.name,
                str(canonical),
                declaration.read,
                declaration.write,
            )
            if identity in seen:
                continue
            seen.add(identity)
            roots.append(
                ResolvedRoot(
                    name=declaration.name,
                    path=canonical,
                    read=declaration.read,
                    write=declaration.write,
                )
            )
    return ResolvedRoleCapability(
        provider=provider.name,
        role=role,
        profile=profile,
        version=policy.schema_version,
        roots=tuple(roots),
        process=role_policy.process,
        network=role_policy.network,
        environment=role_policy.environment,
        approvals=role_policy.approvals,
    )


def build_role_environment(
    policy: ResolvedRoleCapability,
    host_environment: Mapping[str, str],
    *,
    internal: Mapping[str, str] | None = None,
    include_credentials: bool = True,
) -> dict[str, str]:
    declaration = policy.environment
    if declaration.inherit_all:
        result = dict(sorted(host_environment.items()))
    else:
        names = set(declaration.forward)
        if include_credentials:
            names.update(declaration.credentials)
        result = {
            name: host_environment[name]
            for name in sorted(names)
            if name in host_environment
        }
    for name, value in sorted((internal or {}).items()):
        if name not in declaration.internal:
            raise CapabilityPolicyError(
                provider=policy.provider,
                role=policy.role,
                version=policy.version,
                capability=f"environment-internal:{name}",
                reason="internal runtime name is not declared by policy",
            )
        result[name] = value
    return enforce_environment_credential_provenance(
        result,
        credential_values(policy, host_environment),
        inherit_all=declaration.inherit_all,
    )


def credential_values(
    policy: ResolvedRoleCapability,
    environment: Mapping[str, str],
) -> dict[str, str]:
    return declared_credential_values(policy.environment, environment)


_CREDENTIAL_VALUE_COMPONENTS = frozenset(
    {
        "AUTHORIZATION",
        "CREDENTIAL",
        "CREDENTIALS",
        "JWT",
        "PASS",
        "PASSPHRASE",
        "PASSWD",
        "PASSWORD",
        "PAT",
        "SECRET",
        "TOKEN",
    }
)
_CREDENTIAL_KEY_QUALIFIERS = frozenset(
    {
        "ACCESS",
        "API",
        "AUTH",
        "ENCRYPTION",
        "MASTER",
        "PRIVATE",
        "SECRET",
        "SIGNING",
    }
)
_CREDENTIAL_AUTH_COMPONENTS = frozenset(
    {
        "AUTH",
        "BEARER",
        "OAUTH",
    }
)
_CREDENTIAL_AUTH_CARRIERS = frozenset(
    {
        "CACHE",
        "CONFIG",
        "COOKIE",
        "CREDENTIAL",
        "CREDENTIALS",
        "DATA",
        "FILE",
        "HEADER",
        "IDENTITY",
        "JAR",
        "JSON",
        "KEY",
        "PEM",
        "SIGNATURE",
        "TOKEN",
        "VALUE",
    }
)
_CREDENTIAL_CONNECTION_COMPONENTS = frozenset(
    {
        "CONNECTION",
        "DATABASE",
        "DB",
        "JDBC",
        "ODBC",
    }
)
_CREDENTIAL_CONNECTION_CARRIERS = frozenset({"DSN", "STRING", "URI", "URL"})
_CREDENTIAL_REFERENCE_COMPONENTS = frozenset(
    {
        "CCACHE",
        "COOKIE",
        "IDENTITY",
        "KRB5",
        "KUBECONFIG",
        "NETRC",
        "PGPASSFILE",
    }
)
_CREDENTIAL_REFERENCE_CARRIERS = frozenset(
    {
        "CACHE",
        "CONFIG",
        "DATA",
        "FILE",
        "JAR",
        "JSON",
        "LOCATOR",
        "PATH",
        "PEM",
        "VALUE",
    }
)
_CREDENTIAL_NON_VALUE_DESCRIPTORS = frozenset(
    {
        "ALGORITHM",
        "CHECKSUM",
        "COMMIT",
        "DIGEST",
        "ENABLED",
        "ENDPOINT",
        "ETAG",
        "EXAMPLE",
        "FORMAT",
        "HASH",
        "LENGTH",
        "METADATA",
        "MODE",
        "MODEL",
        "POLICY",
        "PREFIX",
        "PUBLIC",
        "REQUIRED",
        "REQUIREMENT",
        "REQUIREMENTS",
        "ROTATION",
        "REVISION",
        "RULE",
        "RULES",
        "SCHEMA",
        "TEMPLATE",
        "TTL",
        "TYPE",
    }
)
_CREDENTIAL_BENIGN_COMPACT_PATTERN = re.compile(
    r"(?:"
    r"PASSWORDPOLICY|PUBLICKEY|SECRETARY|TOKENENDPOINT|TOKENIZER|"
    r"URLTEMPLATE|URITEMPLATE|DSNTEMPLATE|MODELCONFIG|POLICYCONFIG"
    r")"
)
_CREDENTIAL_STRONG_COMPACT_PATTERN = re.compile(
    r"(?:"
    r"AUTH(?!ORITY)|CCACHE|COOKIE|CREDENTIAL|JWT|KUBECONFIG|NETRC|"
    r"PGPASSFILE|PRIVATEKEY|SECRET(?!ARY)|SERVICEACCOUNT|SSHIDENTITY"
    r")"
)
_CREDENTIAL_COMPACT_PATTERN = re.compile(
    r"(?:"
    r"ACCESSKEY|ACCESSTOKEN|APIKEY|AUTHCONFIG|AUTHTOKEN|BEARERTOKEN|"
    r"CLIENTSECRET|CREDENTIALS?|"
    r"COOKIEJAR|DATABASE(?:URI|URL)|DB(?:URI|URL)|"
    r"ENCRYPTIONKEY|IDTOKEN|JWT|MASTERKEY|PASSPHRASE|PASSWD|PASSWORD|"
    r"PRIVATEKEY|REFRESHTOKEN|SECRETKEY|SIGNINGKEY|SSHIDENTITY|"
    r"CONNECTION(?:STRING|URI|URL)|DSN|"
    r"KUBECONFIG|NETRC|PGPASSFILE|SERVICEACCOUNT|CCACHE"
    r")"
)
_SEMANTIC_FIELD_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_. -]*")


@dataclass(frozen=True)
class _NameSensitivity:
    evidence: tuple[str, ...]
    benign_evidence: tuple[str, ...] = ()
    conditional_on_payload: bool = False

    @property
    def classified(self) -> bool:
        return bool(self.evidence)


@dataclass(frozen=True)
class SensitiveValueProvenance:
    """One sensitive token and the ambient source that established it."""

    source_name: str
    value: str
    evidence: tuple[str, ...]
    derived: bool


class SensitiveValueInventory(dict[str, str]):
    """Compatibility mapping plus exact derived-value provenance."""

    provenance: tuple[SensitiveValueProvenance, ...]

    def __init__(
        self,
        values: Mapping[str, str] | None = None,
        *,
        provenance: Iterable[SensitiveValueProvenance] = (),
    ) -> None:
        super().__init__(sorted((values or {}).items()))
        self.provenance = tuple(
            sorted(
                provenance,
                key=lambda item: (
                    -len(item.value),
                    item.source_name,
                    item.value,
                    item.evidence,
                    item.derived,
                ),
            )
        )

    def copy(self) -> SensitiveValueInventory:
        return SensitiveValueInventory(self, provenance=self.provenance)


def serialize_sensitive_value_inventory(
    inventory: Mapping[str, str],
) -> bytes:
    """Serialize an explicit inventory for a private parent/child channel."""
    return json.dumps(
        {
            "provenance": [
                {
                    "derived": item.derived,
                    "evidence": list(item.evidence),
                    "source_name": item.source_name,
                    "value": item.value,
                }
                for item in sensitive_value_provenance(inventory)
            ],
            "values": dict(sorted(inventory.items())),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def deserialize_sensitive_value_inventory(
    payload: bytes,
) -> SensitiveValueInventory:
    """Restore an inventory received over the private startup channel."""
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("sensitive inventory payload must be an object")
    values = decoded.get("values")
    provenance = decoded.get("provenance")
    if not isinstance(values, dict) or not isinstance(provenance, list):
        raise ValueError("sensitive inventory payload has an invalid shape")
    if not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in values.items()
    ):
        raise ValueError("sensitive inventory values must be strings")
    records: list[SensitiveValueProvenance] = []
    for item in provenance:
        if not isinstance(item, dict):
            raise ValueError("sensitive inventory provenance must be objects")
        source_name = item.get("source_name")
        value = item.get("value")
        evidence = item.get("evidence")
        derived = item.get("derived")
        if (
            not isinstance(source_name, str)
            or not isinstance(value, str)
            or not isinstance(evidence, list)
            or not all(isinstance(reason, str) for reason in evidence)
            or not isinstance(derived, bool)
        ):
            raise ValueError("sensitive inventory provenance is invalid")
        records.append(
            SensitiveValueProvenance(
                source_name=source_name,
                value=value,
                evidence=tuple(evidence),
                derived=derived,
            )
        )
    return SensitiveValueInventory(values, provenance=records)


def _name_components(name: str) -> tuple[str, ...]:
    return tuple(
        item
        for item in re.split(r"[^A-Z0-9]+", name.upper())
        if item and not re.fullmatch(r"V?[0-9]+", item)
    )


def _benign_name_evidence(
    components: tuple[str, ...],
) -> tuple[str, ...]:
    evidence: set[str] = set()
    component_set = set(components)

    def adjacent(left: str, right: str) -> bool:
        return any(
            first == left and second == right
            for first, second in zip(components, components[1:])
        )

    if (
        any(
            _CREDENTIAL_BENIGN_COMPACT_PATTERN.search(component)
            is not None
            for component in components
        )
        or adjacent("PASSWORD", "POLICY")
        or adjacent("PUBLIC", "KEY")
        or adjacent("TOKEN", "ENDPOINT")
        or adjacent("URL", "TEMPLATE")
        or adjacent("URI", "TEMPLATE")
        or adjacent("DSN", "TEMPLATE")
        or adjacent("MODEL", "CONFIG")
        or adjacent("POLICY", "CONFIG")
        or (
            "TEMPLATE" in component_set
            and {"PASSWORD", "POLICY"}.issubset(component_set)
        )
        or (
            "TEMPLATE" in component_set
            and {"TOKEN", "ENDPOINT"}.issubset(component_set)
        )
        or (
            "TEMPLATE" in component_set
            and {"DSN", "URI", "URL"}.intersection(component_set)
        )
        or {"MODEL", "CONFIG"}.issubset(component_set)
        or {"POLICY", "CONFIG"}.issubset(component_set)
    ):
        evidence.add("benign-family-name")
    if {"PUBLIC", "KEY"}.issubset(component_set):
        evidence.add("public-key-descriptor")
    if {"BASE", "URL"}.issubset(component_set):
        evidence.add("base-url-descriptor")
    if _CREDENTIAL_NON_VALUE_DESCRIPTORS.intersection(component_set):
        evidence.add("non-value-descriptor")
    return tuple(sorted(evidence))


def _name_sensitivity(name: str) -> _NameSensitivity:
    components = _name_components(name)
    if not components:
        return _NameSensitivity(())
    compact = "".join(components)
    benign_evidence = _benign_name_evidence(components)

    evidence: set[str] = set()
    for index, component in enumerate(components):
        following = components[index + 1 :]
        if component in _CREDENTIAL_VALUE_COMPONENTS:
            evidence.add("credential-value-name")
        if component in {"CREDENTIAL", "CREDENTIALS"}:
            evidence.add("explicit-credential-name")
        if component == "JWT":
            evidence.add("jwt-material-name")
        if component == "PWD" and len(components) > 1:
            evidence.add("password-reference-name")
        if component in _CREDENTIAL_AUTH_COMPONENTS and (
            not following
            or _CREDENTIAL_AUTH_CARRIERS.intersection(following)
        ):
            evidence.add("auth-material-name")
            if (
                _CREDENTIAL_AUTH_CARRIERS.intersection(following)
                - {"TOKEN"}
            ):
                evidence.add("auth-carrier-name")
        if component == "KEY" and _CREDENTIAL_KEY_QUALIFIERS.intersection(
            components[:index]
        ):
            evidence.add("qualified-key-name")
        if (
            component == "SIGNATURE"
            and (
                "SAS" in components[:index]
                or {"SHARED", "ACCESS"}.issubset(components[:index])
                or "AUTH" in components[:index]
            )
            and not _CREDENTIAL_NON_VALUE_DESCRIPTORS.intersection(following)
        ):
            evidence.add("signature-material-name")

    if (
        _CREDENTIAL_REFERENCE_COMPONENTS.intersection(components)
        and _CREDENTIAL_REFERENCE_CARRIERS.intersection(components)
    ):
        evidence.add("credential-reference-name")
    if (
        "COOKIE" in components
        and {"SESSION", "JAR", "FILE", "CACHE", "DATA"}.intersection(components)
    ):
        evidence.add("cookie-material-name")
    if (
        {"SERVICE", "ACCOUNT"}.issubset(components)
        and {"CONFIG", "DATA", "FILE", "JSON", "KEY"}.intersection(components)
    ):
        evidence.add("service-account-material-name")
    if (
        {"SSH", "IDENTITY"}.issubset(components)
        or {"KRB5", "CCACHE"}.issubset(components)
        or {"SAS", "SIGNATURE"}.issubset(components)
    ):
        evidence.add("credential-carrier-name")
    if _CREDENTIAL_COMPACT_PATTERN.search(compact) is not None:
        evidence.add("compact-credential-structure")
    if any(
        _CREDENTIAL_STRONG_COMPACT_PATTERN.search(component) is not None
        and _CREDENTIAL_COMPACT_PATTERN.search(component) is not None
        for component in components
    ):
        evidence.add("compact-strong-credential-structure")

    connection_name = bool(
        _CREDENTIAL_CONNECTION_CARRIERS.intersection(components)
        and (
            _CREDENTIAL_CONNECTION_COMPONENTS.intersection(components)
            or components[-1] in _CREDENTIAL_CONNECTION_CARRIERS
        )
    )
    if connection_name:
        evidence.add("connection-material-name")
    if (
        connection_name
        and "credential-value-name" in evidence
        and "TOKEN" in components
    ):
        evidence.add("multi-factor-credential-name")

    # SECURITY[SEC-SENSITIVITY-PROVENANCE-001]: A specific benign family can
    # disambiguate its own weak credential word. Generic descriptors are only
    # independent evidence and never erase stronger sensitivity provenance.
    strong_evidence = {
        "explicit-credential-name",
        "qualified-key-name",
        "credential-reference-name",
        "cookie-material-name",
        "service-account-material-name",
        "credential-carrier-name",
        "signature-material-name",
        "jwt-material-name",
        "auth-carrier-name",
        "compact-strong-credential-structure",
        "multi-factor-credential-name",
    }
    independent_connection_evidence = (
        "connection-material-name" in evidence
        and "base-url-descriptor" not in benign_evidence
        and "benign-family-name" not in benign_evidence
    )
    if (
        {
            "benign-family-name",
            "base-url-descriptor",
            "public-key-descriptor",
        }.intersection(benign_evidence)
        and not strong_evidence.intersection(evidence)
        and not independent_connection_evidence
    ):
        evidence.difference_update(
            {
                "credential-value-name",
                "auth-material-name",
                "compact-credential-structure",
                "connection-material-name",
            }
        )

    return _NameSensitivity(
        tuple(sorted(evidence)),
        benign_evidence,
        conditional_on_payload=(
            evidence == {"connection-material-name"}
        ),
    )


def is_credential_source_name(name: str) -> bool:
    """Return whether a name structurally denotes credential-bearing material."""
    return _name_sensitivity(name).classified


def credential_source_values(
    environment: Mapping[str, str],
    *,
    declared_names: Sequence[str] = (),
) -> SensitiveValueInventory:
    """Inventory ambient sensitivity from provenance, structure, and payload."""
    declared = {
        name
        for name in declared_names
        if name != "*"
    }
    values: dict[str, str] = {}
    provenance: list[SensitiveValueProvenance] = []
    for name, value in sorted(environment.items()):
        if not value:
            continue
        source_provenance = _sensitive_source_provenance(
            name,
            value,
            declared=name in declared,
        )
        if not source_provenance:
            continue
        values[name] = value
        provenance.extend(source_provenance)
    return SensitiveValueInventory(values, provenance=provenance)


def declared_credential_values(
    declaration: EnvironmentCapability,
    environment: Mapping[str, str],
) -> dict[str, str]:
    return credential_source_values(
        environment,
        declared_names=declaration.credentials,
    )


def _is_credential_token_character(character: str | None) -> bool:
    return bool(
        character
        and (character.isalnum() or character in {"_", "-", "."})
    )


def _credential_requires_token_boundaries(credential: str) -> bool:
    # Short, word-like values occur naturally in labels (for example "KEY").
    # Stronger values are matched wherever embedded so prefix/suffix aliases
    # cannot turn provenance into a spelling convention.
    return len(credential) < 8 and all(
        _is_credential_token_character(character)
        for character in credential
    )


def contains_credential_token(text: str, credential: str) -> bool:
    """Return whether *text* contains a complete credential token."""
    if not credential:
        return False
    if not _credential_requires_token_boundaries(credential):
        return credential in text
    start = 0
    while (index := text.find(credential, start)) >= 0:
        end = index + len(credential)
        left = text[index - 1] if index else None
        right = text[end] if end < len(text) else None
        if (
            not _is_credential_token_character(left)
            and not _is_credential_token_character(right)
        ):
            return True
        start = index + 1
    return False


_SEMANTIC_INSPECTION_MAX_TEXT = 256 * 1024
_SEMANTIC_INSPECTION_MAX_DEPTH = 24
_SEMANTIC_INSPECTION_MAX_NODES = 4096
_SEMANTIC_INSPECTION_MAX_TRANSFORMS = 24
_SEMANTIC_INSPECTION_MAX_DECODED_BYTES = 1024 * 1024
_SEMANTIC_INSPECTION_MAX_WORK = 2 * 1024 * 1024
_SEMANTIC_INSPECTION_MAX_EXPANSIONS = 4096
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_BASE64_WRAPPER_PATTERN = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HEX_WRAPPER_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}){4,}")
_SEMANTIC_FRAGMENT_PATTERN = re.compile(
    r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9_.~+=/_-]){8,}"
)
_BOUNDED_ALIAS_FRAGMENT_PATTERN = re.compile(r"""[^\s"'{}\[\],:;=]+""")
_BOUNDED_ALIAS_MIN_FRAGMENT = 12
_BOUNDED_ALIAS_MAX_INSPECTED_FRAGMENT = 4096
_TOML_ASSIGNMENT_PATTERN = re.compile(
    r"""(?mx)
    ^[ \t]*
    (?:
        [A-Za-z0-9_-]+
        |
        "(?:[^"\\]|\\.)+"
        |
        '(?:[^']|'{2})+'
    )
    [ \t]*=
    """
)
_TOML_TABLE_PATTERN = re.compile(r"(?m)^[ \t]*\[[^\]\r\n]+\][ \t]*(?:#.*)?$")
_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"(?![A-Za-z0-9_-])"
)
_HIGH_ENTROPY_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9_.+=~-]{23,})(?![A-Za-z0-9])"
)
_AUTH_HEADER_PATTERN = re.compile(
    r"(?i)(?:^|[\s,;])(?:authorization\s*[:=]\s*)?"
    r"(?:basic|bearer|token)\s+([^\s,;]+)"
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_PUBLIC_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PUBLIC KEY-----",
)


def _looks_like_json_wrapper(value: str) -> bool:
    return value.lstrip().startswith(("{", "[", '"'))


def _looks_like_toml_wrapper(value: str) -> bool:
    return (
        _TOML_ASSIGNMENT_PATTERN.search(value) is not None
        or _TOML_TABLE_PATTERN.search(value) is not None
    )


def _looks_like_percent_wrapper(value: str) -> bool:
    return _PERCENT_ESCAPE_PATTERN.search(value) is not None


def _looks_like_base64_wrapper(value: str) -> bool:
    if not 8 <= len(value) <= _SEMANTIC_INSPECTION_MAX_TEXT:
        return False
    if _BASE64_WRAPPER_PATTERN.fullmatch(value) is None:
        return False
    unpadded = value.rstrip("=")
    return len(unpadded) % 4 != 1


def _looks_like_hex_wrapper(value: str) -> bool:
    return bool(
        len(value) <= _SEMANTIC_INSPECTION_MAX_TEXT
        and _HEX_WRAPPER_PATTERN.fullmatch(value)
    )


def _looks_like_reversible_wrapper(value: str) -> bool:
    return (
        _looks_like_json_wrapper(value)
        or _looks_like_toml_wrapper(value)
        or _looks_like_percent_wrapper(value)
        or _looks_like_base64_wrapper(value)
        or _looks_like_hex_wrapper(value)
    )


def _structured_semantic_candidates(value: str) -> tuple[Any, ...]:
    candidates: list[Any] = []
    if _looks_like_json_wrapper(value):
        try:
            candidates.append(json.loads(value))
        except (json.JSONDecodeError, RecursionError):
            pass
    if _looks_like_toml_wrapper(value):
        try:
            candidates.append(tomllib.loads(value))
        except (tomllib.TOMLDecodeError, RecursionError):
            pass
    return tuple(candidates)


def _decode_percent_text(value: str) -> str | None:
    if not _looks_like_percent_wrapper(value):
        return None
    try:
        decoded = urllib.parse.unquote(
            value,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != value else None


def _decode_base64_text(value: str) -> str | None:
    if not _looks_like_base64_wrapper(value):
        return None
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded_bytes = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return None
    if not decoded_bytes or len(decoded_bytes) > _SEMANTIC_INSPECTION_MAX_TEXT:
        return None
    try:
        decoded = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if decoded != value else None


def _decode_hex_text(value: str) -> str | None:
    if not _looks_like_hex_wrapper(value):
        return None
    try:
        decoded_bytes = bytes.fromhex(value)
        decoded = decoded_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded and decoded != value else None


def _entropy_bits(value: str) -> float:
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    return sum(
        -count * math.log2(count / len(value))
        for count in counts.values()
    )


def _raw_high_entropy_tokens(value: str) -> tuple[str, ...]:
    tokens: list[str] = []
    template_spans = tuple(
        (token.start, token.end)
        for token in _parse_template_tokens(value)
        if token.kind == "template"
    )
    for match in _HIGH_ENTROPY_TOKEN_PATTERN.finditer(value):
        if any(
            start <= match.start(1) and match.end(1) <= end
            for start, end in template_spans
        ):
            continue
        token = match.group(1)
        if len(set(token)) < 6:
            continue
        has_alpha = any(character.isalpha() for character in token)
        has_digit = any(character.isdigit() for character in token)
        has_case_mix = any(character.islower() for character in token) and any(
            character.isupper() for character in token
        )
        if not has_alpha or not (has_digit or has_case_mix):
            continue
        if _entropy_bits(token) < 96:
            continue
        tokens.append(token)
    return tuple(tokens)


@dataclass(frozen=True)
class _TemplateRecognition:
    """Template evidence kept separate from concrete credential evidence."""

    forms: tuple[str, ...]
    complete: bool


@dataclass(frozen=True)
class _ParsedGrammarToken:
    """One literal or atomic placeholder from the component grammar."""

    kind: Literal["literal", "template"]
    text: str
    start: int
    end: int
    format_field: _FormatFieldAst | None = None


@dataclass(frozen=True)
class _FormatTraversalAst:
    """One attribute or index traversal in a Python replacement field."""

    kind: Literal["attribute", "index"]
    value: str


@dataclass(frozen=True)
class _FormatSpecAst:
    """Literal and recursively nested fields in one format specification."""

    literals: tuple[str, ...]
    fields: tuple[_FormatFieldAst, ...]


@dataclass(frozen=True)
class _FormatFieldAst:
    """A stdlib-parsed Python replacement field with its structured parts."""

    text: str
    field_name: str
    root: str
    traversal: tuple[_FormatTraversalAst, ...]
    conversion: str | None
    format_spec: _FormatSpecAst


@dataclass(frozen=True)
class _FormatInspectionValue:
    """A non-opaque format AST value that re-enters sensitivity traversal."""

    value: str
    origin: str
    sensitivity_provenance: tuple[str, ...] = ()


class _FormatFieldProbe:
    """Side-effect-free receiver for stdlib format field-name traversal."""

    def __getattribute__(self, name: str) -> _FormatFieldProbe:
        del name
        return self

    def __getitem__(self, key: object) -> _FormatFieldProbe:
        del key
        return self


class _FormatGrammarParser(string.Formatter):
    """Validate stdlib grammar/numbering without resolving caller-owned values."""

    def get_value(
        self,
        key: int | str,
        args: Sequence[Any],
        kwargs: Mapping[str, Any],
    ) -> _FormatFieldProbe:
        del key, args, kwargs
        return _FORMAT_FIELD_PROBE

    def convert_field(
        self,
        value: object,
        conversion: str | None,
    ) -> _FormatFieldProbe:
        del value
        if conversion not in (None, "r", "s", "a"):
            raise ValueError(f"Unknown conversion specifier {conversion!s}")
        return _FORMAT_FIELD_PROBE

    def format_field(self, value: object, format_spec: str) -> str:
        del value, format_spec
        return ""


_FORMAT_FIELD_PROBE = _FormatFieldProbe()
_FORMATTER = _FormatGrammarParser()
_FORMAT_AST_MAX_DEPTH = 4


def _python_field_traversal(
    field_name: str,
) -> tuple[str, tuple[_FormatTraversalAst, ...]] | None:
    """Split a stdlib-validated field name while preserving index strings."""
    try:
        _FORMATTER.get_field(field_name, (), {})
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return None

    boundary = len(field_name)
    for marker in (".", "["):
        position = field_name.find(marker)
        if position >= 0:
            boundary = min(boundary, position)
    root = field_name[:boundary]
    traversal: list[_FormatTraversalAst] = []
    position = boundary
    while position < len(field_name):
        marker = field_name[position]
        if marker == ".":
            end = len(field_name)
            for next_marker in (".", "["):
                next_position = field_name.find(next_marker, position + 1)
                if next_position >= 0:
                    end = min(end, next_position)
            traversal.append(
                _FormatTraversalAst(
                    "attribute",
                    field_name[position + 1 : end],
                )
            )
            position = end
            continue
        if marker == "[":
            end = field_name.find("]", position + 1)
            if end < 0:
                return None
            traversal.append(
                _FormatTraversalAst(
                    "index",
                    field_name[position + 1 : end],
                )
            )
            position = end + 1
            continue
        return None
    return root, tuple(traversal)


def _format_field_text(
    source: str,
    field_name: str,
    format_spec: str,
    conversion: str | None,
) -> str | None:
    prefix = "{" + field_name
    if conversion is not None:
        prefix += f"!{conversion}"
    candidates = (
        (f"{prefix}:{format_spec}}}", f"{prefix}}}")
        if not format_spec
        else (f"{prefix}:{format_spec}}}",)
    )
    return next(
        (candidate for candidate in candidates if source.startswith(candidate)),
        None,
    )


def _format_spec_ast(
    format_spec: str,
    *,
    depth: int,
) -> _FormatSpecAst | None:
    if depth > _FORMAT_AST_MAX_DEPTH:
        return None
    try:
        parsed = tuple(_FORMATTER.parse(format_spec))
    except ValueError:
        return None
    literals: list[str] = []
    fields: list[_FormatFieldAst] = []
    for literal, field_name, nested_spec, conversion in parsed:
        if literal:
            literals.append(literal)
        if field_name is None:
            continue
        field = _format_field_ast(
            field_name,
            nested_spec or "",
            conversion,
            depth=depth + 1,
        )
        if field is None:
            return None
        fields.append(field)
    return _FormatSpecAst(tuple(literals), tuple(fields))


def _format_field_ast(
    field_name: str,
    format_spec: str,
    conversion: str | None,
    *,
    depth: int,
    text: str = "",
) -> _FormatFieldAst | None:
    traversal = _python_field_traversal(field_name)
    if traversal is None:
        return None
    spec_ast = _format_spec_ast(format_spec, depth=depth)
    if spec_ast is None:
        return None
    root, steps = traversal
    return _FormatFieldAst(
        text=text,
        field_name=field_name,
        root=root,
        traversal=steps,
        conversion=conversion,
        format_spec=spec_ast,
    )


def _python_format_field_at(
    value: str,
    start: int,
) -> tuple[int, _FormatFieldAst] | None:
    """Return the stdlib-produced field at *start* and its exact source span."""
    try:
        literal, field_name, format_spec, conversion = next(
            iter(_FORMATTER.parse(value[start:]))
        )
    except (StopIteration, ValueError):
        return None
    if literal or field_name is None:
        return None
    text = _format_field_text(
        value[start:],
        field_name,
        format_spec or "",
        conversion,
    )
    if text is None:
        return None
    field = _format_field_ast(
        field_name,
        format_spec or "",
        conversion,
        depth=0,
        text=text,
    )
    if field is None:
        return None
    return start + len(text), field


def _python_format_fields_are_valid(
    fields: Sequence[_FormatFieldAst],
) -> bool:
    """Apply stdlib conversion, nesting, and automatic/manual numbering rules."""
    if not fields:
        return True
    try:
        _FORMATTER.vformat("".join(field.text for field in fields), (), {})
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return False
    return True


def _is_symbolic_template_name(value: str) -> bool:
    if value.isascii() and value.isdigit():
        return True
    return bool(
        value
        and value[0].isascii()
        and (value[0].isalpha() or value[0] == "_")
        and all(
            character.isascii()
            and (character.isalnum() or character in "_.-")
            for character in value[1:]
        )
    )


def _template_token_at(
    value: str,
    start: int,
) -> _ParsedGrammarToken | None:
    if value.startswith("${", start):
        end = value.find("}", start + 2)
        if end >= 0 and _is_symbolic_template_name(
            value[start + 2 : end].strip()
        ):
            return _ParsedGrammarToken(
                "template",
                value[start : end + 1],
                start,
                end + 1,
            )
        return None
    if value.startswith("{{", start):
        parsed = _python_format_field_at(value, start + 1)
        if parsed is not None:
            inner_end, field = parsed
            if inner_end < len(value) and value[inner_end] == "}":
                return _ParsedGrammarToken(
                    "template",
                    value[start : inner_end + 1],
                    start,
                    inner_end + 1,
                    field,
                )
        return None
    if value.startswith("{", start):
        parsed = _python_format_field_at(value, start)
        if parsed is not None:
            end, field = parsed
            return _ParsedGrammarToken(
                "template",
                value[start:end],
                start,
                end,
                field,
            )
        return None
    for angle_template in ("<token>", "<secret>"):
        if value.startswith(angle_template, start):
            end = start + len(angle_template)
            return _ParsedGrammarToken(
                "template",
                value[start:end],
                start,
                end,
            )
    return None


def _parse_template_tokens(value: str) -> tuple[_ParsedGrammarToken, ...]:
    """Build one token/format AST before component delimiters are interpreted."""
    tokens: list[_ParsedGrammarToken] = []
    literal_start = 0
    search_start = 0
    while search_start < len(value):
        starts = tuple(
            position
            for character in ("{", "$", "<")
            if (position := value.find(character, search_start)) >= 0
        )
        if not starts:
            break
        index = min(starts)
        token = _template_token_at(value, index)
        if token is None:
            search_start = index + 1
            continue
        if literal_start < index:
            tokens.append(
                _ParsedGrammarToken(
                    "literal",
                    value[literal_start:index],
                    literal_start,
                    index,
                )
            )
        tokens.append(token)
        literal_start = token.end
        search_start = token.end
    if literal_start < len(value):
        tokens.append(
            _ParsedGrammarToken(
                "literal",
                value[literal_start:],
                literal_start,
                len(value),
            )
        )
    python_fields = tuple(
        token.format_field
        for token in tokens
        if token.format_field is not None
    )
    if _python_format_fields_are_valid(python_fields):
        return tuple(tokens)
    return tuple(
        _ParsedGrammarToken(
            "literal" if token.format_field is not None else token.kind,
            token.text,
            token.start,
            token.end,
            token.format_field,
        )
        for token in tokens
    )


def _format_context_is_invalid(value: str) -> bool:
    return any(
        token.kind == "literal" and token.format_field is not None
        for token in _parse_template_tokens(value)
    )


def _format_component_inspection_values(
    value: str,
    origin: str,
) -> tuple[_FormatInspectionValue, ...]:
    values = [_FormatInspectionValue(value, origin)]
    # Python permits opening and closing braces inside an index string. Treat
    # those braces as semantic boundaries for credential assignments while
    # retaining the complete index for Formatter-compatible lookup.
    components = (value, *re.split(r"[{}]", value))
    for component in components:
        if not component:
            continue
        for unit in _credential_scan_units(component):
            assignment = _credential_assignment(
                unit,
                assignment_markers="=",
            )
            if assignment is None:
                continue
            _, field_value, provenance = assignment
            values.append(
                _FormatInspectionValue(
                    field_value,
                    f"{origin}-assignment-value",
                    provenance,
                )
            )
            for match in _BOUNDED_ALIAS_FRAGMENT_PATTERN.finditer(field_value):
                fragment = match.group(0)
                if (
                    fragment != field_value
                    and _looks_like_reversible_wrapper(fragment)
                ):
                    values.append(
                        _FormatInspectionValue(
                            fragment,
                            f"{origin}-assignment-wrapper",
                            provenance,
                        )
                    )
    return tuple(values)


def _format_field_inspection_values(
    field: _FormatFieldAst,
) -> tuple[_FormatInspectionValue, ...]:
    values: list[_FormatInspectionValue] = []
    if field.root:
        values.extend(
            _format_component_inspection_values(
                field.root,
                "format-field-root",
            )
        )
    for step in field.traversal:
        if not step.value:
            continue
        values.extend(
            _format_component_inspection_values(
                step.value,
                (
                    "format-field-attribute"
                if step.kind == "attribute"
                    else "format-field-index"
                ),
            )
        )
    if field.conversion:
        values.append(
            _FormatInspectionValue(
                field.conversion,
                "format-field-conversion",
            )
        )
    for literal in field.format_spec.literals:
        if literal:
            values.extend(
                _format_component_inspection_values(
                    literal,
                    "format-spec-literal",
                )
            )
    for nested in field.format_spec.fields:
        values.extend(_format_field_inspection_values(nested))
    return tuple(values)


def _format_inspection_values(
    value: str,
) -> tuple[_FormatInspectionValue, ...]:
    return tuple(
        inspection
        for token in _parse_template_tokens(value)
        if token.format_field is not None and token.kind == "template"
        for inspection in _format_field_inspection_values(token.format_field)
    )


def _recognize_templates(value: str) -> _TemplateRecognition:
    forms: set[str] = set()
    stripped = value.strip()
    candidates = [stripped]
    for _ in range(_SEMANTIC_INSPECTION_MAX_DEPTH):
        decoded = _decode_percent_text(candidates[-1])
        if decoded is None:
            break
        candidates.append(decoded.strip())

    complete = False
    for candidate in candidates:
        tokens = _parse_template_tokens(candidate)
        template_tokens = tuple(
            token for token in tokens if token.kind == "template"
        )
        forms.update(token.text for token in template_tokens)
        complete = complete or bool(
            len(tokens) == 1 and tokens[0].kind == "template"
        )
    return _TemplateRecognition(tuple(sorted(forms)), complete)


def _is_template_text(value: str) -> bool:
    return _recognize_templates(value).complete


def _is_plain_path(value: str) -> bool:
    return (
        value.startswith(("/", "./", "../"))
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
    )


def _is_relative_path_list_entry(value: str) -> bool:
    return bool(
        value
        and not _is_plain_path(value)
        and all(
            character.isalnum() or character in "._+-/\\"
            for character in value
        )
        and all(
            part not in ("", ".", "..")
            for part in re.split(r"[/\\]", value)
        )
    )


@dataclass(frozen=True)
class _SemanticField:
    component: str
    name: str
    value: str
    sensitivity_provenance: tuple[str, ...]


@dataclass(frozen=True)
class _NormalizedString:
    """Component-neutral parse output consumed by bounded derivation."""

    container_items: tuple[str, ...]
    fields: tuple[_SemanticField, ...]
    format_items: tuple[_FormatInspectionValue, ...]


def _decoded_component(value: str) -> str:
    return _decode_percent_text(value) or value


def _structural_delimiter_positions(
    value: str,
    delimiters: set[str],
) -> tuple[int, ...]:
    return tuple(
        token.start + offset
        for token in _parse_template_tokens(value)
        if token.kind == "literal"
        for offset, character in enumerate(token.text)
        if character in delimiters
    )


def _split_structural_components(
    value: str,
    separators: str,
) -> tuple[str, ...]:
    positions = _structural_delimiter_positions(value, set(separators))
    if not positions:
        return (value,)
    parts: list[str] = []
    start = 0
    for position in positions:
        parts.append(value[start:position])
        start = position + 1
    parts.append(value[start:])
    return tuple(parts)


def _partition_structural_component(
    value: str,
    markers: str,
) -> tuple[str, str, str]:
    positions = _structural_delimiter_positions(value, set(markers))
    for marker in markers:
        for position in positions:
            if value[position] == marker:
                return value[:position], marker, value[position + 1 :]
    return value, "", ""


def _rpartition_structural_component(
    value: str,
    marker: str,
) -> tuple[str, str, str]:
    positions = _structural_delimiter_positions(value, {marker})
    if not positions:
        return "", "", value
    position = positions[-1]
    return value[:position], marker, value[position + 1 :]


def _protect_template_tokens(
    value: str,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    replacements: list[tuple[str, str]] = []
    parts: list[str] = []
    for token in _parse_template_tokens(value):
        if token.kind == "literal":
            parts.append(token.text)
            continue
        index = len(replacements)
        marker = f"UNRESTTEMPLATEATOMIC{index}Q"
        while marker in value:
            marker += "Q"
        replacements.append((marker, token.text))
        parts.append(marker)
    return "".join(parts), tuple(replacements)


def _restore_template_tokens(
    value: str,
    replacements: tuple[tuple[str, str], ...],
) -> str:
    for marker, template in replacements:
        value = value.replace(marker, template)
    return value


def _is_plain_semantic_field_name(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped
        and all(
            token.kind == "literal"
            for token in _parse_template_tokens(stripped)
        )
        and _SEMANTIC_FIELD_NAME_PATTERN.fullmatch(stripped) is not None
    )


def _is_alternating_credential_field(name: str) -> bool:
    if not _is_plain_semantic_field_name(name):
        return False
    components = _name_components(name)
    benign = _benign_name_evidence(components)
    return bool(
        _CREDENTIAL_VALUE_COMPONENTS.intersection(components)
        and not {
            "benign-family-name",
            "base-url-descriptor",
            "public-key-descriptor",
        }.intersection(benign)
    )


def _sensitive_semantic_field_provenance(name: str) -> tuple[str, ...]:
    evidence = _name_sensitivity(name)
    if evidence.classified and not evidence.conditional_on_payload:
        return tuple(
            f"semantic-field:{reason}"
            for reason in evidence.evidence
        )
    components = set(_name_components(name))
    if {"COOKIE", "SESSION", "SESSIONID"}.intersection(components):
        return ("semantic-field:session-material-name",)
    return ()


def _named_component_fields(
    component: str,
    value: str,
    *,
    separators: str,
    assignment_markers: str = "=:",
) -> tuple[_SemanticField, ...]:
    """Normalize URI key/value and alternating key/value component forms."""
    parts = tuple(
        _decoded_component(item)
        for item in _split_structural_components(value, separators)
        if item
    )
    fields: list[_SemanticField] = []
    index = 0
    while index < len(parts):
        item = parts[index]
        name, marker, field_value = _partition_structural_component(
            item,
            assignment_markers,
        )
        if (
            marker
            and _is_plain_semantic_field_name(name)
            and field_value
        ):
            fields.append(
                _SemanticField(
                    component,
                    name,
                    field_value,
                    _sensitive_semantic_field_provenance(name),
                )
            )
            index += 1
            continue

        if (
            _is_alternating_credential_field(item)
            and not _is_template_text(item)
            and index + 1 < len(parts)
        ):
            fields.append(
                _SemanticField(
                    component,
                    item,
                    parts[index + 1],
                    _sensitive_semantic_field_provenance(item),
                )
            )
            index += 2
            continue
        index += 1
    return tuple(fields)


def _uri_semantic_fields(value: str) -> tuple[_SemanticField, ...]:
    """Parse credential-relevant URI fields without classifying the URI."""
    if _is_template_text(value):
        return ()
    if not any(
        delimiter in value
        for delimiter in ("=", ":", "?", "#", ";", "/", "@")
    ):
        return ()
    protected, replacements = _protect_template_tokens(value)
    try:
        parsed = urllib.parse.urlsplit(protected)
    except ValueError:
        return ()

    fields: list[_SemanticField] = []
    netloc = _restore_template_tokens(parsed.netloc, replacements)
    path = _restore_template_tokens(parsed.path, replacements)
    query = _restore_template_tokens(parsed.query, replacements)
    fragment = _restore_template_tokens(parsed.fragment, replacements)
    authority, separator, host_adjacent = _rpartition_structural_component(
        netloc,
        "@",
    )
    if not separator:
        host_adjacent = netloc
    if separator and authority:
        fields.extend(
            _named_component_fields(
                "userinfo",
                authority,
                separators=";,",
                assignment_markers="=",
            )
        )
        username, password_separator, password = (
            _partition_structural_component(authority, ":")
        )
        if username:
            fields.append(
                _SemanticField(
                    "userinfo",
                    "username",
                    _decoded_component(username),
                    ("semantic-field:userinfo-username",),
                )
            )
        if password_separator and password:
            fields.append(
                _SemanticField(
                    "userinfo",
                    "password",
                    _decoded_component(password),
                    ("semantic-field:userinfo-password",),
                )
            )

    fields.extend(
        _named_component_fields(
            "authority",
            host_adjacent,
            separators=";,",
            assignment_markers="=",
        )
    )
    fields.extend(
        _named_component_fields(
            "path",
            path,
            separators="/;",
        )
    )
    fields.extend(
        _named_component_fields(
            "query",
            query,
            separators="&;",
        )
    )
    fields.extend(
        _named_component_fields(
            "fragment",
            fragment,
            separators="/;&",
        )
    )
    return tuple(
        sorted(
            set(fields),
            key=lambda item: (
                item.component,
                item.name,
                item.value,
                item.sensitivity_provenance,
            ),
        )
    )


def _container_semantic_items(
    value: str,
    *,
    structured: bool | None = None,
) -> tuple[str, ...]:
    """Return plain PATH-like/list items while retaining the aggregate."""
    if (
        structured
        if structured is not None
        else bool(_structured_semantic_candidates(value))
    ):
        return ()
    if not any(
        delimiter in value
        for delimiter in (os.pathsep, "\n", "\r", ",", ";")
    ):
        return ()
    path_items: list[str] = []
    item_start = 0
    template_relative_path = False
    for index in _structural_delimiter_positions(value, {os.pathsep}):
        current = value[item_start:index]
        remainder = value[index + 1 :]
        next_item = remainder.partition(os.pathsep)[0]
        suffix_start = len(current)
        while (
            suffix_start
            and (
                current[suffix_start - 1].isalnum()
                or current[suffix_start - 1] in "+.-"
            )
        ):
            suffix_start -= 1
        scheme = current[suffix_start:]
        scheme_boundary = bool(
            not _is_plain_path(current)
            and scheme
            and scheme[0].isalpha()
            and (
                remainder.startswith("//")
                or any(
                    delimiter in remainder.partition(os.pathsep)[0]
                    for delimiter in (";", "?", "#", "@")
                )
            )
        )
        remaining_items = _split_structural_components(
            remainder,
            os.pathsep,
        )
        relative_prefix, prefix_separator, prefixed_value = current.partition(
            os.pathsep
        )
        has_relative_prefix = bool(
            prefix_separator
            and _is_relative_path_list_entry(relative_prefix)
            and not prefixed_value.startswith(("/", "\\"))
            and _recognize_templates(prefixed_value).forms
        )
        template_relative_boundary = bool(
            remaining_items
            and _recognize_templates(current).forms
            and _is_relative_path_list_entry(remaining_items[0])
            and (
                (
                    len(remaining_items) >= 2
                    and _is_relative_path_list_entry(remaining_items[1])
                )
                or has_relative_prefix
            )
        )
        continuing_relative_boundary = bool(
            path_items
            and _is_relative_path_list_entry(current)
            and _is_relative_path_list_entry(next_item)
        )
        if not scheme_boundary and (
            _is_plain_path(current)
            or _is_plain_path(next_item)
            or template_relative_boundary
            or continuing_relative_boundary
        ):
            path_items.append(current)
            item_start = index + 1
            template_relative_path = (
                template_relative_path
                or template_relative_boundary
                or continuing_relative_boundary
            )
    if path_items:
        path_items.append(value[item_start:])
        if (
            sum(_is_plain_path(item) for item in path_items) >= 2
            or any(
                _looks_like_reversible_wrapper(item)
                for item in path_items
            )
            or template_relative_path
            or (
                any(
                    _recognize_templates(item).forms
                    for item in path_items
                )
                and sum(
                    _is_relative_path_list_entry(item)
                    for item in path_items
                )
                >= 2
            )
        ):
            return tuple(item for item in path_items if item)

    delimiters = {"\n", "\r", ","}
    try:
        protected, _ = _protect_template_tokens(value)
        parsed = urllib.parse.urlsplit(protected)
    except ValueError:
        parsed = None
    if ";" in value and not (parsed and parsed.scheme):
        delimiters.add(";")
    if not delimiters.intersection(value):
        return ()
    parts = _split_structural_components(
        value,
        "".join(sorted(delimiters)),
    )
    if len(parts) == 1:
        return ()
    return tuple(
        item
        for item in (part.strip() for part in parts)
        if item and item != value
    )


def _normalize_semantic_string(value: str) -> _NormalizedString:
    """Decompose containers and URI-like structures before derivation."""
    structured = bool(_structured_semantic_candidates(value))
    container_items = _container_semantic_items(
        value,
        structured=structured,
    )
    return _NormalizedString(
        container_items=container_items,
        fields=(
            ()
            if container_items or structured
            else _uri_semantic_fields(value)
        ),
        format_items=(
            ()
            if structured
            else _format_inspection_values(value)
        ),
    )


def _credential_scan_units(value: str) -> tuple[str, ...]:
    """Tokenize credential assignments at structural component boundaries."""
    containers = _container_semantic_items(value)
    values = containers or (value,)
    units = tuple(
        item
        for candidate in values
        for item in (
            part.strip()
            for part in _split_structural_components(
                candidate,
                "/;?#&,\r\n",
            )
        )
        if item
    )
    return units or (value,)


def _credential_assignment(
    unit: str,
    *,
    assignment_markers: str = "=:",
) -> tuple[str, str, tuple[str, ...]] | None:
    name, marker, field_value = _partition_structural_component(
        unit,
        assignment_markers,
    )
    if not marker or not _is_plain_semantic_field_name(name):
        return None
    provenance = _sensitive_semantic_field_provenance(name)
    if not provenance:
        return None
    token = field_value.strip()
    if (
        len(token) >= 2
        and token[0] == token[-1]
        and token[0] in {'"', "'"}
    ):
        token = token[1:-1]
    if not token:
        return None
    return name.strip(), token, provenance


def _is_template_credential_assignment(name: str, value: str) -> bool:
    if _is_template_text(value):
        return True
    components = set(_name_components(name))
    if not {"AUTH", "AUTHORIZATION"}.intersection(components):
        return False
    scheme, separator, parameter = value.strip().partition(" ")
    return bool(
        separator
        and scheme.casefold() in {"basic", "bearer", "token"}
        and _is_template_text(parameter.strip())
    )


def _explicit_sensitive_tokens(
    value: str,
    *,
    allow_high_entropy: bool = True,
    assignment_markers: str = "=:",
) -> tuple[tuple[str, str], ...]:
    if not value:
        return ()

    found: set[tuple[str, str]] = set()
    if _PUBLIC_KEY_PATTERN.search(value) is None:
        for match in _PRIVATE_KEY_PATTERN.finditer(value):
            found.add((match.group(0), "private-key-payload"))
            body = "".join(
                line.strip()
                for line in match.group(0).splitlines()
                if not line.startswith("-----")
            )
            if body:
                found.add((body, "private-key-body"))
    for match in _JWT_PATTERN.finditer(value):
        found.add((match.group(0), "jwt-payload"))
    protected, replacements = _protect_template_tokens(value)
    for match in _AUTH_HEADER_PATTERN.finditer(protected):
        token = _restore_template_tokens(match.group(1), replacements)
        if _is_template_text(token):
            continue
        found.add((token, "authorization-material"))
        found.add((value, "authorization-material"))
    assignment_units = (
        ()
        if assignment_markers == "=:"
        and _structured_semantic_candidates(value)
        else _credential_scan_units(value)
    )
    for unit in assignment_units:
        assignment = _credential_assignment(
            unit,
            assignment_markers=assignment_markers,
        )
        if assignment is None:
            continue
        name, token, provenance = assignment
        if _is_template_credential_assignment(name, token):
            continue
        components = set(_name_components(name))
        evidence = (
            "cookie-material"
            if {"COOKIE", "SESSION", "SESSIONID"}.intersection(components)
            else "connection-auth-material"
        )
        found.add((token, evidence))
        found.add((unit, evidence))
        found.update((token, reason) for reason in provenance)
    wrapper = (
        _looks_like_json_wrapper(value)
        or _looks_like_toml_wrapper(value)
        or _looks_like_percent_wrapper(value)
        or _decode_base64_text(value) is not None
    )
    if (
        allow_high_entropy
        and not found
        and not _is_template_text(value)
        and not wrapper
        and not _is_plain_path(value)
    ):
        for token in _raw_high_entropy_tokens(value):
            found.add((token, "high-entropy-token"))
    return tuple(sorted(found, key=lambda item: (-len(item[0]), item[0], item[1])))


def _structured_key_is_sensitive(value: str) -> bool:
    evidence = _name_sensitivity(value)
    return evidence.classified and not evidence.conditional_on_payload


@dataclass(frozen=True)
class _SemanticNode:
    value: Any
    depth: int
    sensitivity_provenance: tuple[str, ...] = ()
    transform_count: int = 0
    mapping_key: bool = False
    origin: str = "value"
    format_context_invalid: bool = False
    format_ast_component: bool = False


@dataclass(frozen=True)
class _SemanticTraversal:
    nodes: tuple[_SemanticNode, ...]
    exhausted: bool
    exhausted_with_sensitivity: bool
    exhaustion_reasons: tuple[str, ...] = ()
    resource_usage: tuple[tuple[str, int], ...] = ()
    guard_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class _SemanticCredentialDecision:
    matched: bool
    bounded_unknown: bool
    concrete_sensitivity_provenance: bool

    @property
    def filter_required(self) -> bool:
        return self.matched or (
            self.bounded_unknown
            and self.concrete_sensitivity_provenance
        )


def _semantic_candidates(value: str) -> tuple[tuple[Any, bool], ...]:
    candidates = [
        (candidate, False)
        for candidate in _structured_semantic_candidates(value)
    ]
    percent_decoded = _decode_percent_text(value)
    if percent_decoded is not None:
        candidates.append((percent_decoded, True))
    base64_decoded = _decode_base64_text(value)
    if base64_decoded is not None:
        candidates.append((base64_decoded, True))
    hex_decoded = _decode_hex_text(value)
    if hex_decoded is not None:
        candidates.append((hex_decoded, True))
    return tuple(candidates)


def _node_has_sensitivity_evidence(node: _SemanticNode) -> bool:
    if node.sensitivity_provenance:
        return (
            not isinstance(node.value, str)
            or node.format_context_invalid
            or not _is_template_text(node.value)
        )
    if not isinstance(node.value, str):
        return False
    if node.mapping_key and _structured_key_is_sensitive(node.value):
        return True
    return bool(
        _explicit_sensitive_tokens(
            node.value,
            allow_high_entropy=False,
            assignment_markers=(
                "=" if node.format_ast_component else "=:"
            ),
        )
    )


def _format_ast_observed_depth(value: str) -> int:
    """Return the maximum valid Formatter nesting depth, or zero."""
    if _structured_semantic_candidates(value):
        return 0

    def visit(format_value: str, depth: int) -> int:
        try:
            parsed = tuple(_FORMATTER.parse(format_value))
        except ValueError:
            return 0
        observed = 0
        for _, field_name, format_spec, _ in parsed:
            if field_name is None:
                continue
            traversal = _python_field_traversal(field_name)
            if traversal is None or not _is_symbolic_template_name(
                traversal[0]
            ):
                continue
            observed = max(observed, depth)
            if format_spec:
                observed = max(observed, visit(format_spec, depth + 1))
        return observed

    return visit(value, 0)


def _bounded_semantic_traversal(
    text: Any,
    *,
    sensitivity_provenance: tuple[str, ...] = (),
) -> _SemanticTraversal:
    pending: deque[tuple[_SemanticNode, frozenset[int]]] = deque(
        [
            (
                _SemanticNode(
                    text,
                    0,
                    sensitivity_provenance=sensitivity_provenance,
                ),
                frozenset(),
            )
        ]
    )
    nodes: list[_SemanticNode] = []
    seen_strings: set[
        tuple[str, tuple[str, ...], bool, str, bool, bool]
    ] = set()
    usage = {
        "aggregate_work_bytes": 0,
        "decoded_bytes": 0,
        "expansion_nodes": 0,
        "format_ast_depth": 0,
        "semantic_depth": 0,
        "semantic_nodes": 0,
        "text_bytes": 0,
        "transform_count": 0,
    }
    ceilings = {
        "aggregate_work_bytes": _SEMANTIC_INSPECTION_MAX_WORK,
        "decoded_bytes": _SEMANTIC_INSPECTION_MAX_DECODED_BYTES,
        "expansion_nodes": _SEMANTIC_INSPECTION_MAX_EXPANSIONS,
        "format_ast_depth": _FORMAT_AST_MAX_DEPTH,
        "semantic_depth": _SEMANTIC_INSPECTION_MAX_DEPTH,
        "semantic_nodes": _SEMANTIC_INSPECTION_MAX_NODES,
        "text_bytes": _SEMANTIC_INSPECTION_MAX_TEXT,
        "transform_count": _SEMANTIC_INSPECTION_MAX_TRANSFORMS,
    }
    exhaustion_reasons: set[str] = set()
    guard_values: set[str] = set()
    exhausted_with_sensitivity = False

    def exhausted_item_has_sensitivity(item: _SemanticNode) -> bool:
        if _node_has_sensitivity_evidence(item):
            if isinstance(item.value, str):
                guard_values.add(item.value)
                guard_values.update(
                    token
                    for token, _ in _explicit_sensitive_tokens(
                        item.value,
                        allow_high_entropy=False,
                        assignment_markers="=:",
                    )
                )
            return True
        if not isinstance(item.value, str):
            return False
        # The first node outside a ceiling is never admitted to the inventory.
        # Inspect exactly one candidate edge for classification only, so a
        # bound+1 wrapper around an explicit credential cannot turn exhaustion
        # into a provenance drop.
        found = False
        for candidate, _ in _semantic_candidates(item.value):
            if not isinstance(candidate, str):
                continue
            tokens = _explicit_sensitive_tokens(
                candidate,
                allow_high_entropy=False,
                assignment_markers="=:",
            )
            if tokens:
                guard_values.add(candidate)
                guard_values.update(token for token, _ in tokens)
                found = True
        return found

    def exhaust(reason: str, items: Iterable[_SemanticNode] = ()) -> None:
        nonlocal exhausted_with_sensitivity
        exhaustion_reasons.add(reason)
        exhausted_with_sensitivity = exhausted_with_sensitivity or any(
            exhausted_item_has_sensitivity(item) for item in items
        )

    def observe_max(field_name: str, amount: int) -> bool:
        usage[field_name] = max(usage[field_name], amount)
        if amount <= ceilings[field_name]:
            return True
        exhaust(field_name)
        return False

    def consume(field_name: str, amount: int) -> bool:
        candidate = usage[field_name] + amount
        usage[field_name] = candidate
        if candidate <= ceilings[field_name]:
            return True
        exhaust(field_name)
        return False

    def expand(
        items: Iterable[_SemanticNode],
        ancestors: frozenset[int],
    ) -> bool:
        materialized = tuple(items)
        if not all(
            observe_max("semantic_depth", item.depth)
            and observe_max("transform_count", item.transform_count)
            for item in materialized
        ):
            exhaust("resource", materialized)
            return False
        if not consume("expansion_nodes", len(materialized)):
            exhaust("expansion_nodes", materialized)
            return False
        for item in materialized:
            value = item.value
            if isinstance(value, (Mapping, list, tuple)):
                identity = id(value)
                if identity in ancestors:
                    exhaust("cyclic-container", (item,))
                    return False
                pending.append((item, ancestors | {identity}))
            else:
                pending.append((item, ancestors))
        return True

    while pending:
        node, ancestors = pending.popleft()
        # SECURITY[SEC-SENSITIVITY-PROVENANCE-001]: Sensitivity is monotonic
        # across the traversal. A later ordinary branch may exhaust a bound,
        # but it cannot erase concrete evidence already visited elsewhere.
        exhausted_with_sensitivity = (
            exhausted_with_sensitivity
            or _node_has_sensitivity_evidence(node)
        )
        if not consume("semantic_nodes", 1):
            exhausted_with_sensitivity = (
                exhausted_with_sensitivity
                or _node_has_sensitivity_evidence(node)
                or any(
                    _node_has_sensitivity_evidence(item)
                    for item, _ in pending
                )
            )
            break
        nodes.append(node)

        value = node.value
        if isinstance(value, str):
            marker = (
                value,
                node.sensitivity_provenance,
                node.mapping_key,
                node.origin,
                node.format_context_invalid,
                node.format_ast_component,
            )
            if marker in seen_strings:
                continue
            seen_strings.add(marker)
            value_bytes = len(value.encode("utf-8"))
            if not observe_max("text_bytes", value_bytes):
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or _node_has_sensitivity_evidence(node)
                )
                continue
            if not consume("aggregate_work_bytes", value_bytes):
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or _node_has_sensitivity_evidence(node)
                )
                break
            format_depth = _format_ast_observed_depth(value)
            if not observe_max("format_ast_depth", format_depth):
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or _node_has_sensitivity_evidence(node)
                )
                continue
            normalized = _normalize_semantic_string(value)
            format_context_invalid = (
                node.format_context_invalid
                or _format_context_is_invalid(value)
            )
            container_transform_count = node.transform_count + (
                1 if normalized.container_items else 0
            )
            if not expand(
                (
                    _SemanticNode(
                        item,
                        node.depth + 1,
                        sensitivity_provenance=node.sensitivity_provenance,
                        transform_count=container_transform_count,
                        origin="container-item",
                        format_context_invalid=format_context_invalid,
                        format_ast_component=node.format_ast_component,
                    )
                    for item in normalized.container_items
                ),
                ancestors,
            ):
                break
            format_transform_count = node.transform_count + (
                1 if normalized.format_items else 0
            )
            if not expand(
                (
                    _SemanticNode(
                        item.value,
                        node.depth + 1,
                        sensitivity_provenance=tuple(
                            sorted(
                                {
                                    *node.sensitivity_provenance,
                                    *item.sensitivity_provenance,
                                }
                            )
                        ),
                        transform_count=format_transform_count,
                        origin=item.origin,
                        format_context_invalid=format_context_invalid,
                        format_ast_component=True,
                    )
                    for item in normalized.format_items
                ),
                ancestors,
            ):
                break
            field_transform_count = node.transform_count + (
                1 if normalized.fields else 0
            )
            for field in normalized.fields:
                if not expand(
                    (
                        _SemanticNode(
                            field.name,
                            node.depth + 1,
                            transform_count=field_transform_count,
                            mapping_key=True,
                            origin=f"uri-{field.component}-key",
                            format_context_invalid=format_context_invalid,
                            format_ast_component=node.format_ast_component,
                        ),
                        _SemanticNode(
                            field.value,
                            node.depth + 1,
                            sensitivity_provenance=tuple(
                                sorted(
                                    {
                                        *node.sensitivity_provenance,
                                        *field.sensitivity_provenance,
                                    }
                                )
                            ),
                            transform_count=field_transform_count,
                            origin=f"uri-{field.component}-value",
                            format_context_invalid=format_context_invalid,
                            format_ast_component=node.format_ast_component,
                        ),
                    ),
                    ancestors,
                ):
                    break
            if exhaustion_reasons:
                break
            for decoded, encoded in _semantic_candidates(value):
                if decoded == value:
                    continue
                transform_count = node.transform_count + 1
                if not observe_max("transform_count", transform_count):
                    exhaust(
                        "transform_count",
                        (
                            _SemanticNode(
                                decoded,
                                node.depth + 1,
                                sensitivity_provenance=(
                                    node.sensitivity_provenance
                                ),
                                transform_count=transform_count,
                                origin="bounded-guard",
                            ),
                        ),
                    )
                    exhausted_with_sensitivity = (
                        exhausted_with_sensitivity
                        or _node_has_sensitivity_evidence(node)
                    )
                    pending.clear()
                    break
                if isinstance(decoded, str):
                    if not consume(
                        "decoded_bytes",
                        len(decoded.encode("utf-8")),
                    ):
                        exhausted_with_sensitivity = (
                            exhausted_with_sensitivity
                            or _node_has_sensitivity_evidence(node)
                        )
                        pending.clear()
                        break
                if not expand(
                    (
                        _SemanticNode(
                            decoded,
                            node.depth + 1,
                            sensitivity_provenance=node.sensitivity_provenance,
                            transform_count=transform_count,
                            origin="derived",
                            format_context_invalid=(
                                format_context_invalid
                                if isinstance(decoded, str)
                                else False
                            ),
                            format_ast_component=node.format_ast_component,
                        ),
                    ),
                    ancestors,
                ):
                    break
            continue
        if isinstance(value, Mapping):
            if not observe_max("semantic_depth", node.depth):
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or bool(node.sensitivity_provenance)
                    or any(
                        isinstance(key, str) and _structured_key_is_sensitive(key)
                        for key in value
                    )
                )
            ordered_keys = sorted(
                value,
                key=lambda item: (type(item).__name__, repr(item)),
            )
            for key in ordered_keys:
                key_provenance = (
                    isinstance(key, str)
                    and _sensitive_semantic_field_provenance(key)
                )
                if not expand(
                    (
                        _SemanticNode(
                            key,
                            node.depth + 1,
                            transform_count=node.transform_count,
                            mapping_key=True,
                            origin="structured-key",
                            format_context_invalid=node.format_context_invalid,
                            format_ast_component=node.format_ast_component,
                        ),
                        _SemanticNode(
                            value[key],
                            node.depth + 1,
                            transform_count=node.transform_count,
                            sensitivity_provenance=tuple(
                                sorted(
                                    {
                                        *node.sensitivity_provenance,
                                        *(
                                            key_provenance
                                            if isinstance(key_provenance, tuple)
                                            else ()
                                        ),
                                    }
                                )
                            ),
                            origin="structured-value",
                            format_context_invalid=node.format_context_invalid,
                            format_ast_component=node.format_ast_component,
                        ),
                    ),
                    ancestors,
                ):
                    break
            continue
        if isinstance(value, (list, tuple)):
            expand(
                (
                    _SemanticNode(
                        item,
                        node.depth + 1,
                        transform_count=node.transform_count,
                        sensitivity_provenance=node.sensitivity_provenance,
                        origin="structured-item",
                        format_context_invalid=node.format_context_invalid,
                        format_ast_component=node.format_ast_component,
                    )
                    for item in value
                ),
                ancestors,
            )

    return _SemanticTraversal(
        tuple(nodes),
        bool(exhaustion_reasons),
        exhausted_with_sensitivity,
        tuple(sorted(exhaustion_reasons)),
        tuple(sorted(usage.items())),
        tuple(sorted(guard_values, key=lambda item: (-len(item), item))),
    )


def _contains_any_credential(
    value: str,
    credential_tokens: Sequence[str],
) -> bool:
    return any(
        contains_credential_token(value, credential)
        for credential in credential_tokens
    )


def contains_semantic_credential(
    text: str,
    credentials: Sequence[str],
) -> bool:
    """Find sensitive provenance through a bounded semantic fixed point."""
    return _semantic_credential_decision(text, credentials).matched


def _semantic_credential_decision(
    text: str,
    credentials: Sequence[str],
) -> _SemanticCredentialDecision:
    credential_tokens = tuple(
        sorted(
            {credential for credential in credentials if credential},
            key=lambda value: (-len(value), value),
        )
    )
    if not credential_tokens:
        return _SemanticCredentialDecision(False, False, False)
    traversal = _bounded_semantic_traversal(text)
    matched = any(
        isinstance(node.value, str)
        and _contains_any_credential(node.value, credential_tokens)
        for node in traversal.nodes
    )
    return _SemanticCredentialDecision(
        matched=matched,
        bounded_unknown=traversal.exhausted and not matched,
        concrete_sensitivity_provenance=(
            traversal.exhausted_with_sensitivity
        ),
    )


def _requires_sensitive_value_filtering(
    text: str,
    credentials: Sequence[str],
) -> bool:
    return _semantic_credential_decision(
        text,
        credentials,
    ).filter_required


@dataclass(frozen=True)
class SensitivityClassification:
    """Deterministic aggregate produced by the sensitivity pipeline."""

    source_name: str
    source_value: str
    declared: bool
    name_evidence: tuple[str, ...]
    benign_name_evidence: tuple[str, ...]
    name_conditional_on_payload: bool
    template_evidence: tuple[str, ...]
    credential_evidence: tuple[tuple[str, tuple[str, ...]], ...]
    traversal_exhausted: bool
    traversal_exhausted_with_sensitivity: bool

    @property
    def concrete_payload_sensitive(self) -> bool:
        return (
            self.traversal_exhausted
            and self.traversal_exhausted_with_sensitivity
        ) or any(
            set(reasons) != {"high-entropy-token"}
            for _, reasons in self.credential_evidence
        )

    @property
    def entropy_supported(self) -> bool:
        return (
            any(
                "high-entropy-token" in reasons
                for _, reasons in self.credential_evidence
            )
            and bool(self.name_evidence)
            and "benign-family-name" not in self.benign_name_evidence
        )

    @property
    def name_sensitive(self) -> bool:
        return bool(self.name_evidence) and (
            not self.name_conditional_on_payload
            or self.concrete_payload_sensitive
            or self.entropy_supported
        )

    @property
    def sensitive(self) -> bool:
        return (
            self.declared
            or self.name_sensitive
            or self.concrete_payload_sensitive
        )

    @property
    def fail_closed(self) -> bool:
        concrete_source_provenance = (
            self.declared
            or (
                bool(self.name_evidence)
                and not self.name_conditional_on_payload
            )
            or self.concrete_payload_sensitive
        )
        return self.traversal_exhausted and concrete_source_provenance

    @property
    def verdict(
        self,
    ) -> Literal["safe", "template-only", "sensitive", "sensitive-unknown"]:
        if not self.sensitive:
            return "template-only" if self.template_evidence else "safe"
        return "sensitive-unknown" if self.fail_closed else "sensitive"

    @property
    def source_evidence(self) -> tuple[str, ...]:
        evidence = set(self.name_evidence)
        if self.declared:
            evidence.add("declared-credential-provenance")
        if self.concrete_payload_sensitive or self.entropy_supported:
            evidence.add("sensitive-payload")
        if self.fail_closed:
            evidence.add("bounded-inspection-fail-closed")
        return tuple(sorted(evidence))


def classify_environment_value(
    name: str,
    value: str,
    *,
    declared: bool = False,
) -> SensitivityClassification:
    """Run normalization, derivation, recognition, extraction, and aggregation."""
    name_evidence = _name_sensitivity(name)
    source_sensitivity_provenance = tuple(
        sorted(
            {
                *(
                    name_evidence.evidence
                    if (
                        name_evidence.classified
                        and not name_evidence.conditional_on_payload
                    )
                    else ()
                ),
                *(("declared-credential-provenance",) if declared else ()),
            }
        )
    )
    traversal = _bounded_semantic_traversal(
        value,
        sensitivity_provenance=source_sensitivity_provenance,
    )
    derived: dict[str, set[str]] = {}
    templates: set[str] = set()
    allow_high_entropy = (
        "benign-family-name" not in name_evidence.benign_evidence
        or name_evidence.classified
    )

    def concrete_format_provenance(node: _SemanticNode) -> bool:
        if not node.format_ast_component:
            return True
        if any(
            not reason.startswith("semantic-field:")
            for reason in node.sensitivity_provenance
        ):
            return True
        return node.origin == "derived" or node.origin.endswith(
            "-assignment-value"
        )

    for node in traversal.nodes:
        if not isinstance(node.value, str) or not node.value:
            continue
        recognition = (
            _TemplateRecognition((), False)
            if node.format_context_invalid
            else _recognize_templates(node.value)
        )
        templates.update(recognition.forms)
        if (
            node.sensitivity_provenance
            and not node.mapping_key
            and not recognition.complete
            and concrete_format_provenance(node)
        ):
            derived.setdefault(node.value, set()).add(
                f"{node.origin}-credential-field"
            )
            derived[node.value].update(node.sensitivity_provenance)
        for token, evidence in _explicit_sensitive_tokens(
            node.value,
            allow_high_entropy=allow_high_entropy,
            assignment_markers=(
                "=" if node.format_ast_component else "=:"
            ),
        ):
            derived.setdefault(token, set()).add(evidence)
    for guard_value in traversal.guard_values:
        derived.setdefault(guard_value, set()).add(
            "bounded-inspection-guard"
        )

    return SensitivityClassification(
        source_name=name,
        source_value=value,
        declared=declared,
        name_evidence=name_evidence.evidence,
        benign_name_evidence=name_evidence.benign_evidence,
        name_conditional_on_payload=name_evidence.conditional_on_payload,
        template_evidence=tuple(sorted(templates)),
        credential_evidence=tuple(
            (
                token,
                tuple(sorted(evidence)),
            )
            for token, evidence in sorted(
                derived.items(),
                key=lambda item: (-len(item[0]), item[0]),
            )
            if token
        ),
        traversal_exhausted=traversal.exhausted,
        traversal_exhausted_with_sensitivity=(
            traversal.exhausted_with_sensitivity
        ),
    )


def _sensitive_source_provenance(
    name: str,
    value: str,
    *,
    declared: bool,
) -> tuple[SensitiveValueProvenance, ...]:
    classification = classify_environment_value(
        name,
        value,
        declared=declared,
    )
    if not classification.sensitive:
        return ()

    provenance = [
        SensitiveValueProvenance(
            source_name=name,
            value=value,
            evidence=classification.source_evidence,
            derived=False,
        )
    ]
    provenance.extend(
        SensitiveValueProvenance(
            source_name=name,
            value=token,
            evidence=evidence,
            derived=token != value,
        )
        for token, evidence in classification.credential_evidence
    )
    unique: dict[tuple[str, str], SensitiveValueProvenance] = {}
    for item in provenance:
        marker = (item.source_name, item.value)
        existing = unique.get(marker)
        if existing is None:
            unique[marker] = item
            continue
        unique[marker] = SensitiveValueProvenance(
            source_name=item.source_name,
            value=item.value,
            evidence=tuple(sorted({*existing.evidence, *item.evidence})),
            derived=existing.derived and item.derived,
        )
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (-len(item.value), item.source_name, item.value),
        )
    )


def sensitive_value_provenance(
    credentials: Mapping[str, str],
) -> tuple[SensitiveValueProvenance, ...]:
    if isinstance(credentials, SensitiveValueInventory):
        return credentials.provenance
    return tuple(
        SensitiveValueProvenance(
            source_name=name,
            value=value,
            evidence=("explicit-sensitive-mapping",),
            derived=False,
        )
        for name, value in sorted(credentials.items())
        if value
    )


def sensitive_values(credentials: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                item.value
                for item in sensitive_value_provenance(credentials)
                if item.value
            },
            key=lambda value: (-len(value), value),
        )
    )


def _bounded_sensitive_sources(
    credentials: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            {
                (item.source_name, item.value)
                for item in sensitive_value_provenance(credentials)
                if (
                    not item.derived
                    and "bounded-inspection-fail-closed" in item.evidence
                    and item.value
                )
            },
            key=lambda item: (item[0], item[1]),
        )
    )


def _bounded_candidate_alias_representations(value: str) -> tuple[str, ...]:
    decoded_values = {value}
    frontier = {value}
    for _ in range(3):
        next_frontier: set[str] = set()
        for candidate in sorted(frontier):
            next_frontier.update(
                decoded
                for decoded, _ in _semantic_candidates(candidate)
                if isinstance(decoded, str) and decoded not in decoded_values
            )
        if not next_frontier:
            break
        decoded_values.update(next_frontier)
        frontier = next_frontier

    # SECURITY[SEC-SENSITIVITY-PROVENANCE-001]: The source may contain an
    # unvisited raw leaf. Candidate exhaustion must therefore bridge toward
    # that source by decoding remaining wrappers, never by encoding away from
    # it. JSON/percent spellings cover how the decoded leaf appears in source.
    representations = {
        representation
        for decoded in decoded_values
        for representation in (
            decoded,
            json.dumps(decoded, ensure_ascii=True)[1:-1],
            urllib.parse.quote(decoded, safe=""),
        )
    }
    return tuple(
        sorted(
            (item for item in representations if item),
            key=lambda item: (-len(item), item),
        )
    )


def _bounded_source_contains_alias(source: str, candidate: str) -> bool:
    representations = set(_bounded_candidate_alias_representations(candidate))
    fragments = {
        match.group(0)
        for representation in tuple(representations)
        for match in _BOUNDED_ALIAS_FRAGMENT_PATTERN.finditer(representation)
    }
    for fragment in sorted(fragments):
        if (
            len(fragment) <= _SEMANTIC_INSPECTION_MAX_TEXT
            and _looks_like_reversible_wrapper(fragment)
        ):
            traversal = _bounded_semantic_traversal(fragment)
            representations.update(
                representation
                for node in traversal.nodes
                if isinstance(node.value, str) and node.value
                for representation in (
                    _bounded_candidate_alias_representations(node.value)
                )
            )
        else:
            representations.add(fragment)

    for representation in sorted(
        representations,
        key=lambda item: (-len(item), item),
    ):
        if len(representation) < _BOUNDED_ALIAS_MIN_FRAGMENT:
            if contains_credential_token(source, representation):
                return True
            continue
        if representation in source:
            return True
        if len(representation) > _BOUNDED_ALIAS_MAX_INSPECTED_FRAGMENT:
            continue
        if (
            _decode_base64_text(representation) is not None
            or _looks_like_percent_wrapper(representation)
            or _decode_hex_text(representation) is not None
        ):
            continue
        for start in range(
            len(representation) - _BOUNDED_ALIAS_MIN_FRAGMENT + 1
        ):
            window = representation[
                start : start + _BOUNDED_ALIAS_MIN_FRAGMENT
            ]
            if window in source:
                return True
    return False


def _bounded_sensitive_alias_source(
    value: str,
    credentials: Mapping[str, str],
) -> str | None:
    sources = _bounded_sensitive_sources(credentials)
    if not sources or not value:
        return None
    traversal = _bounded_semantic_traversal(value)
    for node in traversal.nodes:
        if not isinstance(node.value, str) or not node.value:
            continue
        for source_name, source_value in sources:
            if _bounded_source_contains_alias(source_value, node.value):
                return source_name
    return None


def _authorized_credential_pairs(
    credentials: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(credentials, SensitiveValueInventory):
        return tuple(
            (name, value)
            for name, value in sorted(credentials.items())
            if value
        )
    declared_sources = {
        item.source_name
        for item in credentials.provenance
        if (
            not item.derived
            and "declared-credential-provenance" in item.evidence
        )
    }
    return tuple(
        (name, value)
        for name, value in sorted(credentials.items())
        if name in declared_sources and value
    )


def enforce_environment_credential_provenance(
    environment: Mapping[str, str],
    credentials: Mapping[str, str],
    *,
    inherit_all: bool = False,
) -> dict[str, str]:
    """Drop credential tokens outside their exact runtime-authorized pair."""
    if inherit_all:
        return dict(sorted(environment.items()))

    names_by_value: dict[str, set[str]] = {}
    for name, value in _authorized_credential_pairs(credentials):
        names_by_value.setdefault(value, set()).add(name)
    sensitive_tokens = sensitive_values(credentials)

    return {
        name: value
        for name, value in sorted(environment.items())
        if (
            name in names_by_value.get(value, set())
            or (
                not _requires_sensitive_value_filtering(
                    value,
                    sensitive_tokens,
                )
                and _bounded_sensitive_alias_source(
                    value,
                    credentials,
                )
                is None
            )
        )
    }


def enforce_persisted_environment_credential_provenance(
    environment: Mapping[str, str],
    credentials: Mapping[str, str],
) -> dict[str, str]:
    """Omit every credential-bearing value from a persisted environment."""
    credential_tokens = sensitive_values(credentials)
    return {
        name: value
        for name, value in sorted(environment.items())
        if (
            not _requires_sensitive_value_filtering(
                value,
                credential_tokens,
            )
            and _bounded_sensitive_alias_source(
                value,
                credentials,
            )
            is None
        )
    }


def validate_role_environment(
    policy: ResolvedRoleCapability,
    environment: Mapping[str, str],
) -> None:
    if policy.environment.inherit_all:
        return
    allowed = {
        *policy.environment.forward,
        *policy.environment.credentials,
        *policy.environment.internal,
    }
    unexpected = sorted(set(environment) - allowed)
    if unexpected:
        raise CapabilityPolicyError(
            provider=policy.provider,
            role=policy.role,
            version=policy.version,
            capability=f"environment:{unexpected[0]}",
            reason="generated environment name is not declared by policy",
        )


def _credential_patterns(
    credentials: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            {
                (item.value, item.source_name)
                for item in sensitive_value_provenance(credentials)
                if item.value
            },
            key=lambda item: (-len(item[0]), item[1]),
        )
    )


def _semantic_credential_name(
    value: str,
    credentials: Mapping[str, str],
) -> str | None:
    for item in sensitive_value_provenance(credentials):
        if contains_semantic_credential(value, (item.value,)):
            return item.source_name
    return _bounded_sensitive_alias_source(value, credentials)


def _redact_semantic_fragments(
    text: str,
    credentials: Mapping[str, str],
    *,
    final: bool,
) -> str:
    raw_tokens = sensitive_values(credentials)
    spans: list[tuple[int, int, str]] = []
    stripped = text.strip()
    stripped_start = len(text) - len(text.lstrip())
    bounded_name = _bounded_sensitive_alias_source(stripped, credentials)
    if (
        bounded_name is not None
        and (final or stripped_start + len(stripped) < len(text))
    ):
        spans.append(
            (
                stripped_start,
                stripped_start + len(stripped),
                bounded_name,
            )
        )
    if (
        stripped
        and _looks_like_reversible_wrapper(stripped)
        and not _contains_any_credential(stripped, raw_tokens)
    ):
        name = _semantic_credential_name(stripped, credentials)
        if name is not None:
            spans.append((stripped_start, stripped_start + len(stripped), name))

    for match in _SEMANTIC_FRAGMENT_PATTERN.finditer(text):
        candidate = match.group(0)
        if _contains_any_credential(candidate, raw_tokens):
            continue
        name = _semantic_credential_name(candidate, credentials)
        if (
            name is not None
            and (final or match.end() < len(text))
        ):
            spans.append((match.start(), match.end(), name))

    if not spans:
        return text
    selected: list[tuple[int, int, str]] = []
    for start, end, name in sorted(
        spans,
        key=lambda item: (item[0], -(item[1] - item[0]), item[2]),
    ):
        if any(start < chosen_end and end > chosen_start for chosen_start, chosen_end, _ in selected):
            continue
        selected.append((start, end, name))
    for start, end, name in sorted(selected, reverse=True):
        text = text[:start] + f"<redacted:{name}>" + text[end:]
    return text


def _could_be_semantic_stream_suffix(value: str) -> bool:
    if not value or any(character.isspace() for character in value):
        return False
    if value.startswith(("{", "[", '"')):
        return True
    return all(
        character.isalnum() or character in "%+/_=.-~"
        for character in value
    )


class StreamingCredentialRedactor:
    """Redact credential tokens without leaking prefixes between chunks."""

    def __init__(self, credentials: Mapping[str, str]) -> None:
        self._credentials = credentials
        self._patterns = _credential_patterns(credentials)
        self._environment_assignments = tuple(
            sorted(
                (
                    f"{name}="
                    for name, value in credentials.items()
                    if value
                ),
                key=lambda assignment: (-len(assignment), assignment),
            )
        )
        self._pending = ""
        self._left_character: str | None = None
        self._finished = False

    def feed(self, text: str, *, final: bool = False) -> str:
        if self._finished:
            if text:
                raise RuntimeError("credential redactor is already finished")
            return ""

        self._pending += text
        source = _redact_semantic_fragments(
            self._pending,
            self._credentials,
            final=final,
        )
        output: list[str] = []
        cursor = 0

        while cursor < len(source):
            left_character = (
                source[cursor - 1] if cursor else self._left_character
            )
            left_boundary = not _is_credential_token_character(left_character)
            remainder = source[cursor:]

            if left_boundary:
                assignment = next(
                    (
                        item
                        for item in self._environment_assignments
                        if source.startswith(item, cursor)
                    ),
                    None,
                )
                if assignment is not None:
                    output.append(assignment)
                    cursor += len(assignment)
                    self._left_character = "="
                    continue
                if not final and any(
                    item.startswith(remainder)
                    for item in self._environment_assignments
                ):
                    break

            if (
                not final
                and left_boundary
                and _could_be_semantic_stream_suffix(remainder)
            ):
                break

            if not final and any(
                (
                    left_boundary
                    or not _credential_requires_token_boundaries(secret)
                )
                and len(remainder) < len(secret)
                and secret.startswith(remainder)
                for secret, _ in self._patterns
            ):
                break

            match: tuple[str, str] | None = None
            unresolved_right_boundary = False
            for secret, name in self._patterns:
                requires_boundaries = _credential_requires_token_boundaries(secret)
                if (requires_boundaries and not left_boundary) or not source.startswith(
                    secret,
                    cursor,
                ):
                    continue
                end = cursor + len(secret)
                if end == len(source) and not final:
                    unresolved_right_boundary = True
                    continue
                right_character = source[end] if end < len(source) else None
                if (
                    not requires_boundaries
                    or not _is_credential_token_character(right_character)
                ):
                    match = (secret, name)
                    break

            if match is not None:
                secret, name = match
                output.append(f"<redacted:{name}>")
                cursor += len(secret)
                self._left_character = secret[-1]
                continue
            if unresolved_right_boundary:
                break

            self._left_character = source[cursor]
            output.append(source[cursor])
            cursor += 1

        self._pending = source[cursor:]
        if final:
            self._finished = True
            if self._pending:
                raise AssertionError("final credential redaction left pending text")
        return "".join(output)

    def finish(self) -> str:
        return self.feed("", final=True)


def redact_credential_values(text: str, credentials: Mapping[str, str]) -> str:
    return StreamingCredentialRedactor(credentials).feed(text, final=True)


def _inventory_strings(
    value: Any,
    *,
    path: str = "payload",
) -> SensitiveValueInventory:
    """Build one inventory from every reachable textual leaf and mapping key."""
    sources: dict[str, str] = {}
    active_containers: set[int] = set()

    def visit(item: Any, item_path: str) -> None:
        if isinstance(item, str):
            sources[item_path] = item
            return
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active_containers:
                raise CapabilityBoundaryError("cyclic-container")
            active_containers.add(identity)
            try:
                for index, (key, child) in enumerate(
                    sorted(
                        item.items(),
                        key=lambda entry: (
                            type(entry[0]).__name__,
                            repr(entry[0]),
                        ),
                    )
                ):
                    if isinstance(key, str):
                        sources[f"{item_path}.key[{index}]"] = key
                    visit(child, f"{item_path}.value[{index}]")
            finally:
                active_containers.remove(identity)
            return
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active_containers:
                raise CapabilityBoundaryError("cyclic-container")
            active_containers.add(identity)
            try:
                for index, child in enumerate(item):
                    visit(child, f"{item_path}[{index}]")
            finally:
                active_containers.remove(identity)

    visit(value, path)
    raw_inventories = tuple(
        credential_source_values({name: text})
        for name, text in sources.items()
    )
    inventories = tuple(
        SensitiveValueInventory(
            inventory,
            provenance=(
                tuple(
                    item
                    for item in inventory.provenance
                    if (
                        (
                            item.derived
                            and set(item.evidence)
                            not in (
                                {"high-entropy-token"},
                                {
                                    "semantic-field:credential-value-name",
                                    "uri-path-value-credential-field",
                                },
                            )
                        )
                        or (
                            not item.derived
                            and "bounded-inspection-fail-closed" in item.evidence
                        )
                    )
                )
                if any(item.derived for item in inventory.provenance)
                else inventory.provenance
            ),
        )
        for inventory in raw_inventories
    )
    values = {
        name: text
        for inventory in inventories
        for name, text in inventory.items()
    }
    provenance = (
        item
        for inventory in inventories
        for item in inventory.provenance
    )
    return SensitiveValueInventory(values, provenance=provenance)


def redact_sensitive_value(
    value: Any,
    inventory: Mapping[str, str] | None = None,
) -> Any:
    """Apply the canonical inventory/redaction boundary to structured output."""
    effective_inventory = _inventory_strings(value)
    if inventory:
        caller_provenance = sensitive_value_provenance(inventory)
        caller_values = {item.value for item in caller_provenance}
        effective_inventory = SensitiveValueInventory(
            {**effective_inventory, **inventory},
            provenance=(
                *(
                    item
                    for item in effective_inventory.provenance
                    if item.value not in caller_values
                ),
                *caller_provenance,
            ),
        )

    canonical_marker = re.compile(r"<redacted:[A-Za-z0-9_.\[\]#-]+>")

    def redact_text(text: str) -> str:
        # Canonical redaction is an output state, not a fresh source value.
        # Preserve its bounded label while continuing to inspect and redact
        # every byte around it. This keeps repeated ACP/artifact boundaries
        # deterministic without creating a marker-shaped bypass for adjacent
        # sensitive material.
        output: list[str] = []
        cursor = 0
        for match in canonical_marker.finditer(text):
            output.append(
                redact_credential_values(
                    text[cursor : match.start()],
                    effective_inventory,
                )
            )
            output.append(match.group(0))
            cursor = match.end()
        output.append(redact_credential_values(text[cursor:], effective_inventory))
        return "".join(output)

    def project(item: Any) -> Any:
        if isinstance(item, str):
            return redact_text(item)
        if isinstance(item, list):
            return [project(child) for child in item]
        if isinstance(item, tuple):
            return tuple(project(child) for child in item)
        if isinstance(item, Mapping):
            entries = [
                (
                    key,
                    (
                        redact_text(key)
                        if isinstance(key, str)
                        else key
                    ),
                    project(child),
                )
                for key, child in item.items()
            ]
            candidates: dict[Any, int] = {}
            for _, candidate, _ in entries:
                candidates[candidate] = candidates.get(candidate, 0) + 1
            reserved = set(candidates)
            allocated: dict[Any, Any] = {}
            next_suffix: dict[str, int] = {}
            for key, candidate, _ in sorted(
                entries,
                key=lambda entry: (str(entry[1]), str(entry[0])),
            ):
                if key == candidate or candidates[candidate] == 1:
                    continue
                suffix = next_suffix.get(str(candidate), 1)
                output_key = f"{candidate}#{suffix}"
                while output_key in reserved:
                    suffix += 1
                    output_key = f"{candidate}#{suffix}"
                allocated[key] = output_key
                reserved.add(output_key)
                next_suffix[str(candidate)] = suffix + 1
            output = {
                allocated.get(key, candidate): child
                for key, candidate, child in entries
            }
            return dict(sorted(output.items(), key=lambda entry: str(entry[0])))
        return item

    return project(value)


def _canonical_access_path(path: Path, *, for_write: bool) -> Path:
    try:
        if not for_write:
            return path.resolve(strict=True)
        cursor = path
        while not cursor.exists() and not cursor.is_symlink():
            parent = cursor.parent
            if parent == cursor:
                break
            cursor = parent
        cursor.resolve(strict=True)
        return path.resolve(strict=False)
    except OSError as exc:
        raise CapabilityAccessError(
            "filesystem:canonicalization",
            "path cannot be resolved safely",
        ) from exc


def _is_within(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


__all__ = [
    "ApprovalCapability",
    "CAPABILITY_POLICY_VERSION",
    "CAPABILITY_PROFILE_ENV",
    "CAPABILITY_VERSION_ENV",
    "CapabilityAccessError",
    "CapabilityBoundaryError",
    "CapabilityPolicy",
    "CapabilityPolicyError",
    "EnvironmentCapability",
    "NetworkCapability",
    "ProcessCapability",
    "ResolvedRoleCapability",
    "RoleCapability",
    "RoleName",
    "RootCapability",
    "SAFE_PROFILE",
    "SensitiveValueInventory",
    "SensitiveValueProvenance",
    "UNSAFE_DEVELOPMENT_ENV",
    "UNSAFE_DEVELOPMENT_PROFILE",
    "build_role_environment",
    "contains_semantic_credential",
    "contains_credential_token",
    "credential_source_values",
    "credential_values",
    "declared_credential_values",
    "deserialize_sensitive_value_inventory",
    "enforce_environment_credential_provenance",
    "enforce_persisted_environment_credential_provenance",
    "load_capability_policy",
    "policy_path",
    "profile_environment",
    "redact_credential_values",
    "redact_sensitive_value",
    "resolve_profile_from_environment",
    "resolve_role_capability",
    "serialize_sensitive_value_inventory",
    "is_credential_source_name",
    "sensitive_value_provenance",
    "sensitive_values",
    "validate_provider_support",
    "validate_role_environment",
]
