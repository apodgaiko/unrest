"""Finite role authority and exact known-value output protection."""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    model_validator,
)

if TYPE_CHECKING:
    from .providers import ProviderDefinition

CAPABILITY_POLICY_VERSION = 1
SAFE_PROFILE = "safe"
UNSAFE_DEVELOPMENT_PROFILE = "unsafe-development-unrestricted"
UNSAFE_DEVELOPMENT_ENV = "UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED"
CAPABILITY_PROFILE_ENV = "UNREST_CAPABILITY_PROFILE"
CAPABILITY_VERSION_ENV = "UNREST_CAPABILITY_POLICY_VERSION"
FINITE_CREDENTIAL_NAMES = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CODEX_API_KEY",
    "GLM_API_KEY",
    "OPENAI_API_KEY",
    "ZAI_API_KEY",
)

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


class StrictPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RootCapability(StrictPolicyModel):
    name: RootName
    read: StrictBool
    write: StrictBool

    @model_validator(mode="after")
    def write_requires_read(self) -> RootCapability:
        if self.write and not self.read:
            raise ValueError("write access requires read access")
        return self


class ProcessCapability(StrictPolicyModel):
    enabled: StrictBool
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
    inherit_all: StrictBool = False

    @model_validator(mode="after")
    def names_are_finite_and_deterministic(self) -> EnvironmentCapability:
        for field_name in ("forward", "credentials", "terminal_injection", "internal"):
            values = getattr(self, field_name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} names must be sorted and unique")
        if "*" in self.credentials:
            raise ValueError("'*' is forwarding authority, not credential identity")
        if self.inherit_all:
            if self.forward != ("*",) or self.terminal_injection != ("*",):
                raise ValueError("inherit_all requires wildcard forwarding authority")
        elif "*" in (*self.forward, *self.terminal_injection):
            raise ValueError("'*' is reserved for inherit_all profiles")
        if tuple(name for name in FINITE_CREDENTIAL_NAMES if name in self.credentials) != (
            self.credentials
        ):
            raise ValueError("credential names must come from the finite inventory")
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
        names = tuple(item.name for item in self.filesystem)
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


class CapabilityPolicyError(ValueError):
    """Stable, value-free provider/role/version/capability diagnostic."""

    def __init__(
        self,
        *,
        provider: str,
        role: str,
        version: int | str,
        capability: str,
        reason: str,
    ) -> None:
        self.provider = _diagnostic_identifier(
            provider, {"claude", "codex", "unresolved"}
        )
        self.role = _diagnostic_identifier(
            role,
            {"orchestrator", "worker", "validator", "terminal_reviewer", "unresolved"},
        )
        self.version = version if isinstance(version, int) else _opaque(version)
        self.capability = _diagnostic_identifier(
            capability,
            {
                CAPABILITY_PROFILE_ENV,
                CAPABILITY_VERSION_ENV,
                UNSAFE_DEVELOPMENT_ENV,
                "approvals",
                "filesystem",
                "network:allow",
                "network:deny",
                "policy-document",
                "policy-version",
                "profile:safe",
                f"profile:{UNSAFE_DEVELOPMENT_PROFILE}",
                "provider",
                "role",
                "terminal",
                "unsafe-development-opt-in",
            },
        )
        self.reason = reason
        super().__init__(
            "CAP-POLICY-001 "
            f"provider={self.provider} role={self.role} version={self.version} "
            f"capability={self.capability}: {reason}"
        )


def _opaque(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"opaque#{digest}"


def _diagnostic_identifier(value: str, allowed: set[str]) -> str:
    return value if value in allowed else _opaque(value)


class CapabilityAccessError(PermissionError):
    """A stable runtime denial raised by explicit callback authority checks."""

    def __init__(self, capability: str, reason: str) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(f"CAP-ACCESS-001 capability={capability}: {reason}")


class CapabilityBoundaryError(ValueError):
    """Stable, value-free structured-output boundary failure."""

    def __init__(self, classification: Literal["cyclic-container"]) -> None:
        self.classification = classification
        super().__init__(
            "CAP-BOUNDARY-001 "
            f"classification={classification}: output blocked before serialization"
        )


_PolicyModel = TypeVar("_PolicyModel", bound=BaseModel)


def _load_strict_policy_asset(
    path: Path,
    *,
    model: type[_PolicyModel],
) -> _PolicyModel:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate policy member")
            result[key] = value
        return result

    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        return model.model_validate(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, ValidationError) as exc:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=CAPABILITY_POLICY_VERSION,
            capability="policy-document",
            reason=f"cannot load strict policy resource {path.name}",
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
        rejected = sorted(set(names) - set(self.environment.terminal_injection))
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


def load_capability_policy(bundled_dir: Path) -> CapabilityPolicy:
    path = policy_path(bundled_dir)
    try:
        canonical_bundled_dir = bundled_dir.resolve(strict=True)
        canonical_path = path.resolve(strict=True)
        if (
            not bundled_dir.is_absolute()
            or bundled_dir != canonical_bundled_dir
            or path != canonical_path
            or not path.is_file()
        ):
            raise ValueError("capability policy path must be canonical and regular")
    except (OSError, RuntimeError, ValueError) as exc:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=CAPABILITY_POLICY_VERSION,
            capability="policy-document",
            reason=f"cannot load strict policy resource {path.name}",
        ) from exc
    return _load_strict_policy_asset(path, model=CapabilityPolicy)


def resolve_profile_from_environment(environment: Mapping[str, str]) -> tuple[int, str]:
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
            reason=f"unknown unsafe setting identifier={_opaque(suspicious[0])}",
        )
    return version, profile


def profile_environment(profile: str) -> dict[str, str]:
    if profile not in (SAFE_PROFILE, UNSAFE_DEVELOPMENT_PROFILE):
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=CAPABILITY_POLICY_VERSION,
            capability=f"profile:{profile}",
            reason="unsupported capability profile",
        )
    result = {
        CAPABILITY_PROFILE_ENV: profile,
        CAPABILITY_VERSION_ENV: str(CAPABILITY_POLICY_VERSION),
    }
    if profile == UNSAFE_DEVELOPMENT_PROFILE:
        result[UNSAFE_DEVELOPMENT_ENV] = "1"
    return result


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
    selected_credentials = tuple(
        name
        for name in role_policy.environment.credentials
        if name in provider.credential_names
    )
    return role_policy.model_copy(
        update={
            "environment": role_policy.environment.model_copy(
                update={"credentials": selected_credentials}
            )
        }
    )


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
        provider, role=role, policy=policy, profile=profile
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
            if identity not in seen:
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


@dataclass(frozen=True)
class SensitiveValueProvenance:
    """One exact known value and the explicit name that authorized it."""

    source_name: str
    value: str
    evidence: tuple[str, ...] = ("declared-credential-provenance",)
    derived: Literal[False] = False


class SensitiveValueInventory(dict[str, str]):
    """Deterministically ordered finite exact-value inventory."""

    provenance: tuple[SensitiveValueProvenance, ...]

    def __init__(
        self,
        values: Mapping[str, str] | None = None,
        *,
        provenance: Iterable[SensitiveValueProvenance] | None = None,
    ) -> None:
        finite = {
            name: value
            for name, value in sorted((values or {}).items())
            if isinstance(name, str) and isinstance(value, str) and value
        }
        super().__init__(finite)
        records = provenance
        if records is None:
            records = (
                SensitiveValueProvenance(source_name=name, value=value)
                for name, value in finite.items()
            )
        self.provenance = tuple(
            sorted(records, key=lambda item: (-len(item.value), item.source_name, item.value))
        )

    def copy(self) -> SensitiveValueInventory:
        return SensitiveValueInventory(self, provenance=self.provenance)


def credential_source_values(
    environment: Mapping[str, str],
    *,
    declared_names: Sequence[str] = (),
) -> SensitiveValueInventory:
    """Select only explicitly declared names; payload shape never grants identity."""
    declared = set(declared_names) - {"*"}
    return SensitiveValueInventory(
        {
            name: environment[name]
            for name in sorted(declared)
            if environment.get(name)
        }
    )


def declared_credential_values(
    declaration: EnvironmentCapability,
    environment: Mapping[str, str],
) -> SensitiveValueInventory:
    return credential_source_values(
        environment,
        declared_names=declaration.credentials,
    )


def credential_values(
    policy: ResolvedRoleCapability,
    environment: Mapping[str, str],
) -> SensitiveValueInventory:
    return declared_credential_values(policy.environment, environment)


def finite_credential_values(
    environment: Mapping[str, str],
) -> SensitiveValueInventory:
    """Inventory every exact ambient value in the finite credential catalog."""
    return credential_source_values(
        environment,
        declared_names=FINITE_CREDENTIAL_NAMES,
    )


def serialize_sensitive_value_inventory(inventory: Mapping[str, str]) -> bytes:
    """Serialize the explicit inventory for the private inherited-FD channel."""
    values = SensitiveValueInventory(inventory)
    return json.dumps(
        {"values": dict(values)},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def deserialize_sensitive_value_inventory(payload: bytes) -> SensitiveValueInventory:
    """Restore the bounded exact-value inventory and reject alternate shapes."""
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict) or set(decoded) != {"values"}:
        raise ValueError("sensitive inventory payload has an invalid shape")
    values = decoded["values"]
    if not isinstance(values, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in values.items()
    ):
        raise ValueError("sensitive inventory values must be strings")
    return SensitiveValueInventory(values)


def build_role_environment(
    policy: ResolvedRoleCapability,
    host_environment: Mapping[str, str],
    *,
    internal: Mapping[str, str] | None = None,
    include_credentials: bool = True,
) -> dict[str, str]:
    declaration = policy.environment
    known = finite_credential_values(host_environment)
    if declaration.inherit_all:
        result = dict(sorted(host_environment.items()))
        selected_credentials = set(declaration.credentials)
        for name in FINITE_CREDENTIAL_NAMES:
            if not include_credentials or name not in selected_credentials:
                result.pop(name, None)
        result = enforce_environment_credential_provenance(result, known)
    else:
        names = set(declaration.forward)
        if include_credentials:
            names.update(declaration.credentials)
        result = {
            name: host_environment[name]
            for name in sorted(names)
            if name in host_environment
        }
        result = enforce_environment_credential_provenance(result, known)
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
    return dict(sorted(result.items()))


def _is_token_character(character: str | None) -> bool:
    return bool(character and (character.isalnum() or character in {"_", "-", "."}))


def _requires_token_boundaries(value: str) -> bool:
    return len(value) < 8 and all(_is_token_character(character) for character in value)


def contains_credential_token(text: str, credential: str) -> bool:
    if not credential:
        return False
    if not _requires_token_boundaries(credential):
        return credential in text
    start = 0
    while (index := text.find(credential, start)) >= 0:
        end = index + len(credential)
        left = text[index - 1] if index else None
        right = text[end] if end < len(text) else None
        if not _is_token_character(left) and not _is_token_character(right):
            return True
        start = index + 1
    return False


def enforce_environment_credential_provenance(
    environment: Mapping[str, str],
    credentials: Mapping[str, str],
    *,
    inherit_all: bool = False,
) -> dict[str, str]:
    """Keep exact authorized pairs and omit exact-value aliases."""
    # Wildcard forwarding broadens names, never finite credential identity.
    # Keep the keyword for callers that describe their projection mode, but do
    # not let it bypass the exact-value provenance boundary.
    del inherit_all
    names_by_value: dict[str, set[str]] = {}
    for name, value in credentials.items():
        if value:
            names_by_value.setdefault(value, set()).add(name)
    return {
        name: value
        for name, value in sorted(environment.items())
        if name in names_by_value.get(value, set())
        or value not in names_by_value
    }


def enforce_persisted_environment_credential_provenance(
    environment: Mapping[str, str],
    credentials: Mapping[str, str],
) -> dict[str, str]:
    """Omit every known exact credential occurrence from persisted environments."""
    return {
        name: value
        for name, value in sorted(environment.items())
        if not any(contains_credential_token(value, known) for known in credentials.values())
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


def _patterns(credentials: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            {(value, name) for name, value in credentials.items() if value},
            key=lambda item: (-len(item[0]), item[1]),
        )
    )


class StreamingCredentialRedactor:
    """Remove exact values while retaining enough suffix to span chunk splits."""

    def __init__(self, credentials: Mapping[str, str]) -> None:
        self._patterns = _patterns(credentials)
        self._pending = ""
        self._left_character: str | None = None
        self._finished = False

    def feed(self, text: str, *, final: bool = False) -> str:
        if self._finished:
            if text:
                raise RuntimeError("credential redactor is already finished")
            return ""
        self._pending += text
        output: list[str] = []
        cursor = 0
        while cursor < len(self._pending):
            left = self._pending[cursor - 1] if cursor else self._left_character
            left_boundary = not _is_token_character(left)
            remainder = self._pending[cursor:]
            if not final and any(
                (left_boundary or not _requires_token_boundaries(secret))
                and len(remainder) < len(secret)
                and secret.startswith(remainder)
                for secret, _ in self._patterns
            ):
                break

            match: tuple[str, str] | None = None
            unresolved_boundary = False
            for secret, name in self._patterns:
                bounded = _requires_token_boundaries(secret)
                if (bounded and not left_boundary) or not self._pending.startswith(
                    secret, cursor
                ):
                    continue
                end = cursor + len(secret)
                if end == len(self._pending) and not final and bounded:
                    unresolved_boundary = True
                    continue
                right = self._pending[end] if end < len(self._pending) else None
                if not bounded or not _is_token_character(right):
                    match = (secret, name)
                    break
            if match:
                secret, name = match
                output.append(f"<redacted:{name}>")
                cursor += len(secret)
                self._left_character = secret[-1]
                continue
            if unresolved_boundary:
                break
            self._left_character = self._pending[cursor]
            output.append(self._pending[cursor])
            cursor += 1

        self._pending = self._pending[cursor:]
        if final:
            self._finished = True
            if self._pending:
                raise AssertionError("final credential redaction left pending text")
        return "".join(output)

    def finish(self) -> str:
        return self.feed("", final=True)


def redact_credential_values(text: str, credentials: Mapping[str, str]) -> str:
    return StreamingCredentialRedactor(credentials).feed(text, final=True)


_REDACTION_MARKER = re.compile(r"<redacted:[A-Za-z0-9_.\[\]#-]+>")


def redact_sensitive_value(
    value: Any,
    inventory: Mapping[str, str] | None = None,
) -> Any:
    """Redact exact known values recursively; never infer identity from payload."""
    known = SensitiveValueInventory(inventory)
    active: set[int] = set()

    def redact_text(text: str) -> str:
        output: list[str] = []
        cursor = 0
        for match in _REDACTION_MARKER.finditer(text):
            output.append(redact_credential_values(text[cursor : match.start()], known))
            output.append(match.group(0))
            cursor = match.end()
        output.append(redact_credential_values(text[cursor:], known))
        return "".join(output)

    def project(item: Any) -> Any:
        if isinstance(item, str):
            return redact_text(item)
        if isinstance(item, (list, tuple, Mapping)):
            identity = id(item)
            if identity in active:
                raise CapabilityBoundaryError("cyclic-container")
            active.add(identity)
            try:
                if isinstance(item, list):
                    return [project(child) for child in item]
                if isinstance(item, tuple):
                    return tuple(project(child) for child in item)
                entries = [
                    (key, redact_text(key) if isinstance(key, str) else key, project(child))
                    for key, child in item.items()
                ]
                counts: dict[Any, int] = {}
                for _, candidate, _ in entries:
                    counts[candidate] = counts.get(candidate, 0) + 1
                reserved = set(counts)
                allocated: dict[Any, Any] = {}
                next_suffix: dict[str, int] = {}
                for key, candidate, _ in sorted(
                    entries, key=lambda entry: (str(entry[1]), str(entry[0]))
                ):
                    if key == candidate or counts[candidate] == 1:
                        continue
                    suffix = next_suffix.get(str(candidate), 1)
                    output_key = f"{candidate}#{suffix}"
                    while output_key in reserved:
                        suffix += 1
                        output_key = f"{candidate}#{suffix}"
                    allocated[key] = output_key
                    reserved.add(output_key)
                    next_suffix[str(candidate)] = suffix + 1
                return dict(
                    sorted(
                        (
                            (allocated.get(key, candidate), child)
                            for key, candidate, child in entries
                        ),
                        key=lambda entry: str(entry[0]),
                    )
                )
            finally:
                active.remove(identity)
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
    "FINITE_CREDENTIAL_NAMES",
    "NetworkCapability",
    "ProcessCapability",
    "ResolvedRoleCapability",
    "RoleCapability",
    "RoleName",
    "RootCapability",
    "SAFE_PROFILE",
    "SensitiveValueInventory",
    "SensitiveValueProvenance",
    "StreamingCredentialRedactor",
    "UNSAFE_DEVELOPMENT_ENV",
    "UNSAFE_DEVELOPMENT_PROFILE",
    "build_role_environment",
    "contains_credential_token",
    "credential_source_values",
    "credential_values",
    "declared_credential_values",
    "deserialize_sensitive_value_inventory",
    "enforce_environment_credential_provenance",
    "enforce_persisted_environment_credential_provenance",
    "finite_credential_values",
    "load_capability_policy",
    "policy_path",
    "profile_environment",
    "redact_credential_values",
    "redact_sensitive_value",
    "resolve_profile_from_environment",
    "resolve_role_capability",
    "serialize_sensitive_value_inventory",
    "validate_provider_support",
    "validate_role_environment",
]
