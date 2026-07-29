"""Versioned, fail-closed role capability policy and runtime enforcement helpers."""
from __future__ import annotations

import base64
import binascii
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
from typing import TYPE_CHECKING, Any, Literal

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


class CapabilityAccessError(PermissionError):
    """A stable runtime denial raised by ACP callback enforcement."""

    def __init__(self, capability: str, reason: str) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(f"CAP-ACCESS-001 capability={capability}: {reason}")


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


def load_capability_policy(bundled_dir: Path) -> CapabilityPolicy:
    path = policy_path(bundled_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return CapabilityPolicy.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise CapabilityPolicyError(
            provider="unresolved",
            role="unresolved",
            version=CAPABILITY_POLICY_VERSION,
            capability="policy-document",
            reason=f"cannot load strict policy resource {path.name}",
        ) from exc


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
            reason=f"unknown unsafe setting: {suspicious[0]}",
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
) -> dict[str, str]:
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
_SEMANTIC_INSPECTION_MAX_DECODED_BYTES = 1024 * 1024
_SEMANTIC_INSPECTION_MAX_WORK = 2 * 1024 * 1024
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
    for unit in _credential_scan_units(value):
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
    encoded_layers: int = 0
    mapping_key: bool = False
    origin: str = "value"
    format_context_invalid: bool = False
    format_ast_component: bool = False


@dataclass(frozen=True)
class _SemanticTraversal:
    nodes: tuple[_SemanticNode, ...]
    exhausted: bool
    exhausted_with_sensitivity: bool


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


def _bounded_semantic_traversal(text: str) -> _SemanticTraversal:
    pending: deque[_SemanticNode] = deque([_SemanticNode(text, 0)])
    nodes: list[_SemanticNode] = []
    seen_strings: set[
        tuple[str, tuple[str, ...], bool, str, bool, bool]
    ] = set()
    decoded_bytes = 0
    work = 0
    exhausted = False
    exhausted_with_sensitivity = False

    while pending:
        node = pending.popleft()
        # SECURITY[SEC-SENSITIVITY-PROVENANCE-001]: Sensitivity is monotonic
        # across the traversal. A later ordinary branch may exhaust a bound,
        # but it cannot erase concrete evidence already visited elsewhere.
        exhausted_with_sensitivity = (
            exhausted_with_sensitivity
            or _node_has_sensitivity_evidence(node)
        )
        if len(nodes) >= _SEMANTIC_INSPECTION_MAX_NODES:
            exhausted = True
            exhausted_with_sensitivity = (
                exhausted_with_sensitivity
                or _node_has_sensitivity_evidence(node)
                or any(_node_has_sensitivity_evidence(item) for item in pending)
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
            work += len(value)
            if work > _SEMANTIC_INSPECTION_MAX_WORK:
                exhausted = True
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or _node_has_sensitivity_evidence(node)
                )
                break
            if node.depth >= _SEMANTIC_INSPECTION_MAX_DEPTH:
                if _looks_like_reversible_wrapper(value):
                    exhausted = True
                    exhausted_with_sensitivity = (
                        exhausted_with_sensitivity
                        or _node_has_sensitivity_evidence(node)
                    )
                continue
            if len(value) > _SEMANTIC_INSPECTION_MAX_TEXT:
                if _looks_like_reversible_wrapper(value):
                    exhausted = True
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
            pending.extend(
                _SemanticNode(
                    item,
                    node.depth + 1,
                    sensitivity_provenance=node.sensitivity_provenance,
                    encoded_layers=node.encoded_layers,
                    origin="container-item",
                    format_context_invalid=format_context_invalid,
                    format_ast_component=node.format_ast_component,
                )
                for item in normalized.container_items
            )
            pending.extend(
                _SemanticNode(
                    item.value,
                    node.depth + 1,
                    sensitivity_provenance=item.sensitivity_provenance,
                    encoded_layers=node.encoded_layers,
                    origin=item.origin,
                    format_context_invalid=format_context_invalid,
                    format_ast_component=True,
                )
                for item in normalized.format_items
            )
            for field in normalized.fields:
                pending.append(
                    _SemanticNode(
                        field.name,
                        node.depth + 1,
                        mapping_key=True,
                        origin=f"uri-{field.component}-key",
                        format_context_invalid=format_context_invalid,
                        format_ast_component=node.format_ast_component,
                    )
                )
                pending.append(
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
                        encoded_layers=node.encoded_layers,
                        origin=f"uri-{field.component}-value",
                        format_context_invalid=format_context_invalid,
                        format_ast_component=node.format_ast_component,
                    )
                )
            for decoded, encoded in _semantic_candidates(value):
                if decoded == value:
                    continue
                if isinstance(decoded, str):
                    decoded_bytes += len(decoded.encode("utf-8"))
                    if decoded_bytes > _SEMANTIC_INSPECTION_MAX_DECODED_BYTES:
                        exhausted = True
                        exhausted_with_sensitivity = (
                            exhausted_with_sensitivity
                            or _node_has_sensitivity_evidence(node)
                        )
                        pending.clear()
                        break
                pending.append(
                    _SemanticNode(
                        decoded,
                        node.depth + 1,
                        sensitivity_provenance=node.sensitivity_provenance,
                        encoded_layers=node.encoded_layers + int(encoded),
                        origin="derived",
                        format_context_invalid=(
                            format_context_invalid
                            if isinstance(decoded, str)
                            else False
                        ),
                        format_ast_component=node.format_ast_component,
                    )
                )
            continue
        if isinstance(value, Mapping):
            if node.depth >= _SEMANTIC_INSPECTION_MAX_DEPTH:
                exhausted = exhausted or bool(value)
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or bool(node.sensitivity_provenance)
                    or any(
                        isinstance(key, str) and _structured_key_is_sensitive(key)
                        for key in value
                    )
                )
                continue
            ordered_keys = sorted(
                value,
                key=lambda item: (type(item).__name__, repr(item)),
            )
            for key in ordered_keys:
                key_provenance = (
                    isinstance(key, str)
                    and _sensitive_semantic_field_provenance(key)
                )
                pending.append(
                    _SemanticNode(
                        key,
                        node.depth + 1,
                        mapping_key=True,
                        origin="structured-key",
                        format_context_invalid=node.format_context_invalid,
                        format_ast_component=node.format_ast_component,
                    )
                )
                pending.append(
                    _SemanticNode(
                        value[key],
                        node.depth + 1,
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
                    )
                )
            continue
        if isinstance(value, list):
            if node.depth >= _SEMANTIC_INSPECTION_MAX_DEPTH:
                exhausted = exhausted or bool(value)
                exhausted_with_sensitivity = (
                    exhausted_with_sensitivity
                    or bool(node.sensitivity_provenance)
                )
                continue
            pending.extend(
                _SemanticNode(
                    item,
                    node.depth + 1,
                    sensitivity_provenance=node.sensitivity_provenance,
                    origin="structured-item",
                    format_context_invalid=node.format_context_invalid,
                    format_ast_component=node.format_ast_component,
                )
                for item in value
            )

    return _SemanticTraversal(
        tuple(nodes),
        exhausted,
        exhausted_with_sensitivity,
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
    traversal = _bounded_semantic_traversal(value)
    derived: dict[str, set[str]] = {}
    templates: set[str] = set()
    allow_high_entropy = (
        "benign-family-name" not in name_evidence.benign_evidence
        or name_evidence.classified
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
    "enforce_environment_credential_provenance",
    "enforce_persisted_environment_credential_provenance",
    "load_capability_policy",
    "policy_path",
    "profile_environment",
    "redact_credential_values",
    "resolve_profile_from_environment",
    "resolve_role_capability",
    "is_credential_source_name",
    "sensitive_value_provenance",
    "sensitive_values",
    "validate_provider_support",
    "validate_role_environment",
]
