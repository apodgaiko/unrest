"""v5 HarnessConfig. See specs/memory_v2/PRODUCT.md for layout."""
from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from .capability_policy import (
    CAPABILITY_POLICY_VERSION,
    SAFE_PROFILE,
    CapabilityPolicy,
    CapabilityPolicyError,
    RoleName,
    load_capability_policy,
    resolve_profile_from_environment,
    validate_provider_support,
)
from .providers import (
    ProviderSelection,
    default_worker_provider_name,
    get_provider,
)

DEFAULT_MAX_PARALLEL_NODES = 4
DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS = 900

# codex-acp `model_reasoning_effort` values. Also a safety allowlist: the
# resolved value is spliced into a shell command line by acp_runner. Codex's
# "ultra" is deliberately excluded: it is not a reasoning tier (codex
# downgrades the request to "max" on the wire) but a switch to proactive
# multi-agent mode — a lane spawning its own agent swarm inside a harness
# that already orchestrates and validates per-lane work.
VALID_REASONING_EFFORTS = ("minimal", "low", "medium", "high", "xhigh", "max")


def _bundled_dir() -> Path:
    return (Path(__file__).resolve().parent / "bundled").resolve()


def _resolve_optional_path(value: str | None) -> Path | None:
    if not value:
        return None
    return Path(value).expanduser().resolve()


def _resolve_max_parallel(value: str | None) -> int:
    if not value:
        return DEFAULT_MAX_PARALLEL_NODES
    try:
        parsed = int(value)
    except ValueError:
        return DEFAULT_MAX_PARALLEL_NODES
    return max(1, parsed)


def _resolve_positive_seconds(value: str | None, *, env_var: str, default: int) -> int:
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{env_var} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{env_var} must be a positive integer")
    return parsed


def _resolve_reasoning_effort(value: str | None, *, env_var: str) -> str | None:
    """None passes through (provider default); anything else must be on the
    allowlist — a typo silently ignored would spend medium when the user thought
    they had dialed down."""
    if not value:
        return None
    if value not in VALID_REASONING_EFFORTS:
        raise ValueError(
            f"{env_var}={value!r} is not a valid reasoning effort; "
            f"choose one of: {', '.join(VALID_REASONING_EFFORTS)}"
        )
    return value


@dataclass(frozen=True)
class HarnessConfig:
    """Static configuration loaded from env. Per-call overrides allowed via `with_*`."""

    bundled_dir: Path
    harness_home: Path  # UNREST_HOME (default ~/.unrest)
    projects_dir: Path  # UNREST_PROJECTS_DIR (default <harness_home>/projects)
    orchestrator_provider_name: str
    worker_provider_name: str
    worker_acp_command: str | None
    validator_provider_name: str | None
    validator_acp_command: str | None
    terminal_reviewer_provider_name: str | None
    terminal_reviewer_acp_command: str | None
    max_parallel_nodes: int = DEFAULT_MAX_PARALLEL_NODES
    terminal_review_timeout_seconds: int = DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS
    # Per-role reasoning effort for providers whose ACP command accepts one
    # (codex today). None means the harness default ("medium" for codex).
    worker_reasoning_effort: str | None = None
    validator_reasoning_effort: str | None = None
    terminal_reviewer_reasoning_effort: str | None = None
    capability_policy_version: int = CAPABILITY_POLICY_VERSION
    capability_profile: str = SAFE_PROFILE

    @classmethod
    def discover(cls) -> HarnessConfig:
        capability_policy_version, capability_profile = (
            resolve_profile_from_environment(os.environ)
        )
        harness_home = (
            Path(os.environ.get("UNREST_HOME") or (Path.home() / ".unrest"))
            .expanduser()
            .resolve()
        )
        projects_dir = (
            _resolve_optional_path(os.environ.get("UNREST_PROJECTS_DIR"))
            or harness_home / "projects"
        )
        orchestrator_provider_name = os.environ.get(
            "UNREST_ORCHESTRATOR_PROVIDER", "claude"
        )
        worker_provider_name = os.environ.get(
            "UNREST_WORKER_PROVIDER"
        ) or default_worker_provider_name(orchestrator_provider_name)
        worker_acp_command = os.environ.get("UNREST_WORKER_ACP_COMMAND")
        validator_provider_name = os.environ.get("UNREST_VALIDATOR_PROVIDER")
        validator_acp_command = os.environ.get("UNREST_VALIDATOR_ACP_COMMAND")
        terminal_reviewer_provider_name = os.environ.get(
            "UNREST_TERMINAL_REVIEWER_PROVIDER"
        )
        terminal_reviewer_acp_command = os.environ.get(
            "UNREST_TERMINAL_REVIEWER_ACP_COMMAND"
        )
        return cls(
            bundled_dir=_bundled_dir(),
            harness_home=harness_home,
            projects_dir=projects_dir,
            orchestrator_provider_name=orchestrator_provider_name,
            worker_provider_name=worker_provider_name,
            worker_acp_command=worker_acp_command,
            validator_provider_name=validator_provider_name,
            validator_acp_command=validator_acp_command,
            terminal_reviewer_provider_name=terminal_reviewer_provider_name,
            terminal_reviewer_acp_command=terminal_reviewer_acp_command,
            max_parallel_nodes=_resolve_max_parallel(
                os.environ.get("UNREST_MAX_PARALLEL_NODES")
            ),
            terminal_review_timeout_seconds=_resolve_positive_seconds(
                os.environ.get("UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS"),
                env_var="UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS",
                default=DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS,
            ),
            worker_reasoning_effort=_resolve_reasoning_effort(
                os.environ.get("UNREST_WORKER_REASONING_EFFORT"),
                env_var="UNREST_WORKER_REASONING_EFFORT",
            ),
            validator_reasoning_effort=_resolve_reasoning_effort(
                os.environ.get("UNREST_VALIDATOR_REASONING_EFFORT"),
                env_var="UNREST_VALIDATOR_REASONING_EFFORT",
            ),
            terminal_reviewer_reasoning_effort=_resolve_reasoning_effort(
                os.environ.get("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT"),
                env_var="UNREST_TERMINAL_REVIEWER_REASONING_EFFORT",
            ),
            capability_policy_version=capability_policy_version,
            capability_profile=capability_profile,
        )

    # ------------------------------------------------------------------
    # Provider accessors
    # ------------------------------------------------------------------

    @property
    def orchestrator_provider(self):
        return self._provider_for_role(
            self.orchestrator_provider_name,
            "orchestrator",
        )

    @property
    def worker_provider(self):
        return self._provider_for_role(self.worker_provider_name, "worker")

    @property
    def validator_provider(self):
        return self._provider_for_role(
            self.validator_provider_name or self.worker_provider_name,
            "validator",
        )

    @property
    def terminal_reviewer_provider(self):
        name = (
            self.terminal_reviewer_provider_name
            or self.validator_provider_name
            or self.worker_provider_name
        )
        return self._provider_for_role(name, "terminal_reviewer")

    def _provider_for_role(self, name: str, role: RoleName):
        try:
            return get_provider(name)
        except ValueError as exc:
            raise CapabilityPolicyError(
                provider=name,
                role=role,
                version=self.capability_policy_version,
                capability="provider",
                reason="provider is not declared",
            ) from exc

    @property
    def resolved_worker_acp_command(self) -> str | None:
        return self.worker_acp_command or self.worker_provider.default_worker_acp_command

    @property
    def resolved_validator_acp_command(self) -> str | None:
        return (
            self.validator_acp_command
            or self.validator_provider.default_worker_acp_command
            or self.resolved_worker_acp_command
        )

    @property
    def resolved_terminal_reviewer_acp_command(self) -> str | None:
        return (
            self.terminal_reviewer_acp_command
            or self.terminal_reviewer_provider.default_worker_acp_command
            or self.resolved_validator_acp_command
        )

    @property
    def provider_selection(self) -> ProviderSelection:
        return ProviderSelection(
            orchestrator=self.orchestrator_provider,
            worker=self.worker_provider,
            validation_worker=(
                self.validator_provider
                if self.validator_provider_name
                else None
            ),
            worker_acp_command=self.worker_acp_command,
            validation_worker_acp_command=self.validator_acp_command,
            terminal_reviewer=self.terminal_reviewer_provider,
            terminal_reviewer_acp_command=self.terminal_reviewer_acp_command,
        )

    @property
    def capability_policy(self) -> CapabilityPolicy:
        policy = load_capability_policy(self.bundled_dir)
        if policy.schema_version != self.capability_policy_version:
            raise CapabilityPolicyError(
                provider="unresolved",
                role="unresolved",
                version=self.capability_policy_version,
                capability="policy-version",
                reason="does not match the bundled policy resource",
            )
        return policy

    def validate_capability_support(self) -> None:
        policy = self.capability_policy
        providers: dict[RoleName, object] = {
            "orchestrator": self.orchestrator_provider,
            "worker": self.worker_provider,
            "validator": self.validator_provider,
            "terminal_reviewer": self.terminal_reviewer_provider,
        }
        for role, provider in providers.items():
            validate_provider_support(
                provider,  # type: ignore[arg-type]
                role=role,
                policy=policy,
                profile=self.capability_profile,
            )

    # ------------------------------------------------------------------
    # Bucket paths
    # ------------------------------------------------------------------

    def bucket_root(self, project_id: str) -> Path:
        """Per-project root: parent of .unrest/ and .unrest-runtime/."""
        return self.projects_dir / project_id

    def unrest_dir(self, project_id: str) -> Path:
        """Durable, all-roles-readable record (brief, decisions, skills, missions)."""
        return self.bucket_root(project_id) / ".unrest"

    def unrest_runtime_dir(self, project_id: str) -> Path:
        """Orchestrator-only cursors (project.json, state.json, dag.json, ...)."""
        return self.bucket_root(project_id) / ".unrest-runtime"

    def skill_dirs(self, project_id: str | None = None) -> list[Path]:
        dirs: list[Path] = []
        if project_id is not None:
            dirs.append(self.unrest_dir(project_id) / "skills")
        dirs.append(self.harness_home / "skills")
        dirs.append(self.bundled_dir / "skills")
        return dirs

    # ------------------------------------------------------------------
    # Role-specialized variants
    # ------------------------------------------------------------------

    def for_role(
        self, role: Literal["worker", "validator", "terminal_reviewer"]
    ) -> HarnessConfig:
        if role == "worker":
            return self
        if role == "validator":
            return replace(
                self,
                worker_provider_name=(
                    self.validator_provider_name or self.worker_provider_name
                ),
                worker_acp_command=self.resolved_validator_acp_command,
                worker_reasoning_effort=(
                    self.validator_reasoning_effort or self.worker_reasoning_effort
                ),
            )
        if role == "terminal_reviewer":
            return replace(
                self,
                worker_provider_name=(
                    self.terminal_reviewer_provider_name
                    or self.validator_provider_name
                    or self.worker_provider_name
                ),
                worker_acp_command=self.resolved_terminal_reviewer_acp_command,
                worker_reasoning_effort=(
                    self.terminal_reviewer_reasoning_effort
                    or self.validator_reasoning_effort
                    or self.worker_reasoning_effort
                ),
            )
        raise ValueError(f"unknown role: {role}")
