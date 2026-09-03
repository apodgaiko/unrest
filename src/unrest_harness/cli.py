from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import tomllib
from collections.abc import Set as AbstractSet
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast

import click

from .assets import AssetLoader, iter_skill_directories
from .capability_policy import (
    FINITE_CREDENTIAL_NAMES,
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_PROFILE,
    CapabilityPolicyError,
    enforce_persisted_environment_credential_provenance,
    load_capability_policy,
    profile_environment,
    redact_sensitive_value,
    validate_provider_support,
)
from .config import VALID_REASONING_EFFORTS, HarnessConfig
from .envelope import render_task_list
from .providers import (
    ProviderDefinition,
    ProviderSelection,
    default_worker_provider_name,
    get_provider,
    provider_names_for_role,
)
from .storage import (
    ProjectStore,
    atomic_write_text,
    validate_atomic_write_destination,
)

RUNTIME_ENV_FORWARD_ALLOWLIST = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
    "CLAUDE_CODE_EFFORT_LEVEL",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
    "CLAUDE_CODE_SUBAGENT_MODEL",
    "GLM_BASE_URL",
    "MAX_THINKING_TOKENS",
    "UNREST_WORKER_MODEL",
    "UNREST_WORKER_REASONING_EFFORT",
    "UNREST_VALIDATOR_REASONING_EFFORT",
    "UNREST_TERMINAL_REVIEWER_REASONING_EFFORT",
    "ZAI_BASE_URL",
)

USER_SCOPE_ORCHESTRATORS = ("claude", "codex")
MANAGED_ASSET_MODE = 0o644


ManagedAssetOutcome = Literal["created", "repaired", "verified"]


@dataclass
class _ManagedAssetSummary:
    created: int = 0
    repaired: int = 0
    verified: int = 0

    def record(self, outcome: ManagedAssetOutcome) -> None:
        setattr(self, outcome, getattr(self, outcome) + 1)

    def render(self, label: str, destination: Path) -> str:
        return (
            f"Managed {label} at {destination}: created={self.created} "
            f"repaired={self.repaired} verified={self.verified}"
        )


class FiniteCredentialChoice(click.Choice):
    """Keep Click's useful choice error while protecting declared credentials."""

    def get_invalid_choice_message(
        self,
        value: object,
        ctx: click.Context | None,
    ) -> str:
        display_value = value
        if isinstance(value, str):
            inventory = {
                name: os.environ[name]
                for name in FINITE_CREDENTIAL_NAMES
                if os.environ.get(name)
            }
            display_value = redact_sensitive_value(value, inventory)
        return super().get_invalid_choice_message(value=display_value, ctx=ctx)


@click.group()
def cli() -> None:
    """Unrest CLI — set up + inspect long-running coding projects."""


# ---------------------------------------------------------------------------
# governance checks
# ---------------------------------------------------------------------------


@cli.command("check-repository")
def check_repository_cmd() -> None:
    """Validate the canonical repository contract without changing the worktree."""
    from .repository_contract import (  # Repository development code stays command-local.
        RepositoryContractError,
        check_repository,
        find_repository_root,
    )

    try:
        root = find_repository_root(Path.cwd())
        report = check_repository(root)
    except RepositoryContractError as error:
        raise click.ClickException(str(error)) from error
    click.echo(report.render(), nl=False)


@cli.command("measure-baseline")
@click.option("--protocol", required=True, type=str)
@click.option("--destination", required=True, type=click.Path(path_type=Path))
@click.option("--confirm-provider-work", is_flag=True, required=True)
def measure_baseline_cmd(
    protocol: str,
    destination: Path,
    confirm_provider_work: bool,
) -> None:
    """Run the frozen manual/provider-backed FM-010 release baseline."""
    from .measurement import MeasurementError, measure_baseline
    from .public_schema import (
        PublicSchemaValidationError,
        validate_public_request,
        validate_public_result,
    )

    try:
        validate_public_request(
            "measure-baseline",
            {
                "protocol": protocol,
                "destination": str(destination),
                "confirm_provider_work": confirm_provider_work,
            },
        )
        summary = measure_baseline(
            protocol,
            str(destination),
            confirm_provider_work,
        )
        validate_public_result("measure-baseline", summary)
    except PublicSchemaValidationError:
        raise click.ClickException("invalid argument") from None
    except MeasurementError as exc:
        raise click.ClickException(str(exc)) from None
    except RuntimeError:
        raise click.ClickException("internal error") from None
    click.echo(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    if summary["status"] != "published":
        raise click.exceptions.Exit(2)


_ADAPTER_REQUEST_LIMIT = 1_048_576


def _adapter_document(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _ADAPTER_REQUEST_LIMIT:
            raise ValueError
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise click.ClickException("invalid_argument") from None
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise click.ClickException("invalid_argument")
    return value


def _closed_adapter_mapping(
    value: object,
    *,
    required: AbstractSet[str],
    optional: AbstractSet[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - required - optional or required - set(value):
        raise click.ClickException("invalid_argument")
    return value


def _emit_adapter_result(content: bytes) -> None:
    payload = content[:-1] if content.endswith(b"\n") else content
    try:
        if json.dumps(
            json.loads(payload),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") != payload:
            raise ValueError
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, TypeError):
        raise click.ClickException("internal_error") from None
    click.echo(payload.decode("utf-8"))


def _task_request(value: object):
    from .task_adapter import TaskAdapterError, TaskBounds, TaskRequest

    document = _closed_adapter_mapping(
        value,
        required={"bounds", "brief", "idempotency_key"},
        optional={
            "consumer_id",
            "pause_reason",
            "project_id",
            "resume_after_pause",
        },
    )
    bounds = _closed_adapter_mapping(
        document["bounds"],
        required={"max_steps", "timeout_seconds"},
        optional={"max_branches"},
    )
    try:
        checked_bounds = TaskBounds(**cast(Any, bounds))
        arguments = {key: value for key, value in document.items() if key != "bounds"}
        return TaskRequest(bounds=checked_bounds, **cast(Any, arguments))
    except (TaskAdapterError, TypeError, ValueError):
        raise click.ClickException("invalid_argument") from None


@cli.command("run-task")
@click.option(
    "--request",
    "request_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
)
def run_task_cmd(request_path: Path) -> None:
    """Run one bounded task from a closed JSON request file."""

    from . import api
    from .foundation_tools import FoundationToolError
    from .task_adapter import TaskAdapterError

    request = _task_request(_adapter_document(request_path))
    try:
        result = asyncio.run(api.run_task(request))
    except (FoundationToolError, TaskAdapterError) as exc:
        raise click.ClickException(exc.code) from None
    except (OSError, RuntimeError, ValueError):
        raise click.ClickException("internal_error") from None
    _emit_adapter_result(result.canonical_bytes())


def _project_request(value: object):
    from .project_adapter import ProjectAdapterError, ProjectDag, ProjectNode

    document = _closed_adapter_mapping(
        value,
        required={"max_steps", "mission_id", "nodes", "project_id"},
    )
    nodes = document["nodes"]
    if not isinstance(nodes, list):
        raise click.ClickException("invalid_argument")
    checked_nodes = []
    required = {"body", "id"}
    optional = {"auto_merge", "needs", "result_path", "skill", "targets", "writes"}
    try:
        for item in nodes:
            node = _closed_adapter_mapping(item, required=required, optional=optional)
            arguments = dict(node)
            for key in ("needs", "targets", "writes"):
                if key in arguments:
                    sequence = arguments[key]
                    if not isinstance(sequence, list):
                        raise TypeError
                    arguments[key] = tuple(sequence)
            checked_nodes.append(ProjectNode(**cast(Any, arguments)))
        project = ProjectDag(tuple(checked_nodes))
    except (ProjectAdapterError, TypeError, ValueError):
        raise click.ClickException("invalid_argument") from None
    project_id = document["project_id"]
    mission_id = document["mission_id"]
    max_steps = document["max_steps"]
    if (
        not isinstance(project_id, str)
        or not project_id.strip()
        or not isinstance(mission_id, str)
        or not mission_id.strip()
        or isinstance(max_steps, bool)
        or not isinstance(max_steps, int)
        or max_steps <= 0
    ):
        raise click.ClickException("invalid_argument")
    return project_id, mission_id, project, max_steps


def _project_adapter_coordinator(
    project_id: str,
    mission_id: str,
    project: object,
):
    from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
    from .coordinator import MissionCoordinator
    from .project_adapter import ProjectAdapterError, ProjectDag
    from .storage import ProjectStore

    config = HarnessConfig.discover()
    store = ProjectStore(config)
    try:
        submitted = store.load_task_list(project_id, mission_id)
    except (FileNotFoundError, OSError, ValueError):
        raise ProjectAdapterError("project_prerequisite_missing") from None
    if not isinstance(project, ProjectDag) or (
        submitted.model_dump(mode="json")
        != project.task_list().model_dump(mode="json")
    ):
        raise ProjectAdapterError("project_task_list_mismatch")
    return MissionCoordinator(
        store,
        project_id,
        ACPNodeDispatcher(config),
        ACPTerminalReviewer(config),
    )


@cli.command("run-project")
@click.option(
    "--request",
    "request_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
)
def run_project_adapter_cmd(request_path: Path) -> None:
    """Run one exact, already-submitted project DAG from JSON."""

    from . import api
    from .project_adapter import ProjectAdapterError

    project_id, mission_id, project, max_steps = _project_request(
        _adapter_document(request_path)
    )
    try:
        coordinator = _project_adapter_coordinator(
            project_id,
            mission_id,
            project,
        )
        result = api.run_project(
            coordinator,
            mission_id,
            project,
            max_steps=max_steps,
        )
    except ProjectAdapterError as exc:
        raise click.ClickException(exc.code) from None
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        raise click.ClickException("invalid_argument") from None
    _emit_adapter_result(result.canonical_bytes())


def _improvement_request(value: object):
    from .evolution import CampaignFreeze, EvolutionError
    from .improve_adapter import ImprovementAdapterError, ImprovementRequest

    document = _closed_adapter_mapping(value, required={"repository", "request"})
    request = _closed_adapter_mapping(
        document["request"],
        required={
            "action",
            "author_id",
            "campaign_id",
            "candidate_id",
            "evaluation_id",
            "freeze",
            "lease_id",
            "review_id",
        },
        optional={
            "candidate_cost_steps",
            "candidate_dissent_digests",
            "evaluation_cost_steps",
            "parent_candidate_id",
        },
    )
    repository = document["repository"]
    if not isinstance(repository, str) or not repository:
        raise click.ClickException("invalid_argument")
    try:
        freeze = CampaignFreeze.from_mapping(
            _closed_adapter_mapping(
                request["freeze"],
                required={field.name for field in CampaignFreeze.__dataclass_fields__.values()},
            )
        )
        arguments = {key: item for key, item in request.items() if key != "freeze"}
        dissent = arguments.get("candidate_dissent_digests")
        if dissent is not None:
            if not isinstance(dissent, list):
                raise TypeError
            arguments["candidate_dissent_digests"] = tuple(dissent)
        checked = ImprovementRequest(freeze=freeze, **cast(Any, arguments))
    except (EvolutionError, ImprovementAdapterError, TypeError, ValueError):
        raise click.ClickException("invalid_argument") from None
    return Path(repository), checked


def _improvement_prerequisites(repository: Path, request: object) -> None:
    """Verify immutable public prerequisite records before manager construction."""

    from .canonical_identity import verify_canonical_json_bytes
    from .evolution import CampaignFreeze
    from .improve_adapter import ImprovementAdapterError, ImprovementRequest

    if not isinstance(request, ImprovementRequest):
        raise ImprovementAdapterError("invalid_argument", operation="inspect")
    freeze = request.freeze
    if not isinstance(freeze, CampaignFreeze):
        raise ImprovementAdapterError("invalid_argument", operation="inspect")

    campaign_dir = (
        repository
        / ".unrest"
        / "evolution"
        / "campaigns"
        / request.campaign_id.removeprefix("campaign:")
    )
    try:
        campaign_paths = sorted(campaign_dir.glob("*.json"))
        first = verify_canonical_json_bytes(campaign_paths[0].read_bytes())
    except (IndexError, OSError, ValueError):
        raise ImprovementAdapterError(
            "missing_campaign_freeze", operation="inspect"
        ) from None
    if (
        not isinstance(first, dict)
        or first.get("event_kind") != "campaign_opened"
        or not isinstance(first.get("payload"), dict)
        or first["payload"].get("freeze")
        != json.loads(json.dumps(asdict(freeze), sort_keys=True))
    ):
        raise ImprovementAdapterError("campaign_freeze_mismatch", operation="inspect")

    lease_dir = (
        repository
        / ".unrest"
        / "workspaces"
        / "leases"
        / request.lease_id.removeprefix("lease:")
    )
    try:
        lease_paths = sorted(lease_dir.glob("*.json"))
        lease = verify_canonical_json_bytes(lease_paths[-1].read_bytes())
    except (IndexError, OSError, ValueError):
        raise ImprovementAdapterError(
            "missing_returned_candidate_lease", operation="inspect"
        ) from None
    if (
        not isinstance(lease, dict)
        or lease.get("lease_id") != request.lease_id
        or lease.get("state") != "returned"
        or lease.get("owner_id") != request.author_id
        or lease.get("base_revision") != freeze.accepted_revision
        or not isinstance(lease.get("patch_digest"), str)
        or not isinstance(lease.get("candidate_identity_digest"), str)
    ):
        raise ImprovementAdapterError(
            "returned_candidate_lease_mismatch", operation="inspect"
        )

    candidate_payload: dict[str, object] | None = None
    try:
        for path in campaign_paths[1:]:
            event = verify_canonical_json_bytes(path.read_bytes())
            if (
                isinstance(event, dict)
                and event.get("event_kind") == "candidate_added"
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("candidate_id") == request.candidate_id
            ):
                candidate_payload = event["payload"]
                break
    except (OSError, ValueError):
        raise ImprovementAdapterError(
            "admitted_candidate_mismatch", operation="inspect"
        ) from None
    if candidate_payload is None:
        raise ImprovementAdapterError("missing_admitted_candidate", operation="inspect")
    if (
        candidate_payload.get("lease_id") != request.lease_id
        or candidate_payload.get("outcome") != "admitted"
        or candidate_payload.get("author_id") != request.author_id
        or candidate_payload.get("candidate_digest") != lease.get("patch_digest")
        or candidate_payload.get("candidate_identity_digest")
        != lease.get("candidate_identity_digest")
        or candidate_payload.get("cost_steps") != request.candidate_cost_steps
    ):
        raise ImprovementAdapterError("admitted_candidate_mismatch", operation="inspect")


@cli.command("run-improvement")
@click.option(
    "--request",
    "request_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
)
def run_improvement_cmd(request_path: Path) -> None:
    """Run one provider-free candidate through the reviewed decision boundary."""

    from . import api
    from .evolution import EvolutionError, EvolutionManager
    from .improve_adapter import ImprovementAdapterError

    repository, request = _improvement_request(_adapter_document(request_path))
    try:
        api._validate_improvement_request(request)
        resolved_repository = repository.resolve(strict=True)
        if not resolved_repository.is_dir():
            raise ValueError
        _improvement_prerequisites(resolved_repository, request)
        manager = EvolutionManager(resolved_repository)
        result = asyncio.run(api.run_improvement(manager, request))
    except ImprovementAdapterError as exc:
        raise click.ClickException(exc.code) from None
    except (EvolutionError, FileNotFoundError, OSError, RuntimeError, ValueError):
        raise click.ClickException("invalid_argument") from None
    _emit_adapter_result(result.to_json_bytes())


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--agent",
    type=FiniteCredentialChoice(provider_names_for_role("orchestrator")),
    default=None,
    help="Convenience: sets orchestrator+worker provider in one shot.",
)
@click.option(
    "--orchestrator-provider",
    type=FiniteCredentialChoice(provider_names_for_role("orchestrator")),
    default=None,
)
@click.option(
    "--worker-provider",
    type=FiniteCredentialChoice(provider_names_for_role("worker")),
    default=None,
)
@click.option("--worker-acp-command", default=None)
@click.option("--worker-model", default=None)
@click.option(
    "--validator-provider",
    type=FiniteCredentialChoice(provider_names_for_role("worker")),
    default=None,
)
@click.option("--validator-acp-command", default=None)
@click.option(
    "--terminal-reviewer-provider",
    type=FiniteCredentialChoice(provider_names_for_role("worker")),
    default=None,
)
@click.option("--terminal-reviewer-acp-command", default=None)
@click.option(
    "--worker-reasoning-effort",
    type=FiniteCredentialChoice(VALID_REASONING_EFFORTS),
    default=None,
)
@click.option(
    "--validator-reasoning-effort",
    type=FiniteCredentialChoice(VALID_REASONING_EFFORTS),
    default=None,
)
@click.option(
    "--terminal-reviewer-reasoning-effort",
    type=FiniteCredentialChoice(VALID_REASONING_EFFORTS),
    default=None,
)
@click.option(
    "--unsafe-development-unrestricted",
    is_flag=True,
    help=(
        "DANGEROUS development-only opt-in: override the safe default, disable "
        "provider sandbox/approvals, and grant unrestricted host capabilities."
    ),
)
@click.option("--unrest-home", type=click.Path(), default=None)
@click.option(
    "--scope",
    type=FiniteCredentialChoice(("project", "user")),
    default="project",
    show_default=True,
    help="Install into one project or the current user's host configuration.",
)
@click.option("--workspace-dir", "workspace_dir", type=click.Path(exists=True), default=None)
def init(
    agent: str | None,
    orchestrator_provider: str | None,
    worker_provider: str | None,
    worker_acp_command: str | None,
    worker_model: str | None,
    validator_provider: str | None,
    validator_acp_command: str | None,
    terminal_reviewer_provider: str | None,
    terminal_reviewer_acp_command: str | None,
    worker_reasoning_effort: str | None,
    validator_reasoning_effort: str | None,
    terminal_reviewer_reasoning_effort: str | None,
    unsafe_development_unrestricted: bool,
    unrest_home: str | None,
    scope: str,
    workspace_dir: str | None,
) -> None:
    """Initialize Unrest's host-agent surface.

    Project scope (the default) stages MCP config and assets in one workspace.
    User scope registers Unrest and installs its assets once for every workspace
    in Claude Code or Codex. In both scopes, the project bucket is created lazily
    by `start_project` at the first MCP call.

    Safe default: Claude permissions.defaultMode=default; Codex
    sandbox_mode=workspace-write and approval_policy=on-request. Only
    --unsafe-development-unrestricted opts into unrestricted development mode.
    """
    capability_profile = (
        UNSAFE_DEVELOPMENT_PROFILE
        if unsafe_development_unrestricted
        else SAFE_PROFILE
    )
    try:
        config = HarnessConfig.discover()
        loader = AssetLoader(config)
        selection = _resolve_selection(
            agent=agent,
            orchestrator=orchestrator_provider,
            worker=worker_provider,
            worker_acp_command=worker_acp_command,
            validator=validator_provider,
            validator_acp_command=validator_acp_command,
            terminal_reviewer=terminal_reviewer_provider,
            terminal_reviewer_acp_command=terminal_reviewer_acp_command,
        )
        policy = load_capability_policy(config.bundled_dir)
        role_providers = {
            "orchestrator": selection.orchestrator,
            "worker": selection.worker,
            "validator": selection.resolved_validation_worker,
            "terminal_reviewer": selection.resolved_terminal_reviewer,
        }
        role_policies = {
            role: validate_provider_support(
                provider,
                role=role,  # type: ignore[arg-type]
                policy=policy,
                profile=capability_profile,
            )
            for role, provider in role_providers.items()
        }
        declared_credential_names = tuple(
            sorted(
                {
                    name
                    for role_policy in role_policies.values()
                    for name in role_policy.environment.credentials
                    if name != "*"
                }
            )
        )
        credentials = {
            name: os.environ[name]
            for name in declared_credential_names
            if os.environ.get(name)
        }
        capability_env = profile_environment(capability_profile)
    except CapabilityPolicyError as exc:
        raise click.ClickException(str(exc)) from exc

    if scope == "user":
        if workspace_dir is not None:
            raise click.UsageError("--workspace-dir cannot be used with --scope user")
        if selection.orchestrator.name not in USER_SCOPE_ORCHESTRATORS:
            supported = ", ".join(USER_SCOPE_ORCHESTRATORS)
            raise click.UsageError(
                f"--scope user supports these orchestrators: {supported}; "
                f"use --scope project for {selection.orchestrator.name}"
            )
        storage_env = _storage_env(
            unrest_home=unrest_home,
            workspace=Path.cwd(),
            selection=selection,
        )
        try:
            _preflight_user_initialization(loader, selection.orchestrator)
            _write_user_provider_capability_settings(selection, capability_profile)
        except (CapabilityPolicyError, OSError) as exc:
            raise click.ClickException("provider settings configuration rejected") from exc
        _write_user_bootstrap_config(
            selection,
            {**storage_env, **capability_env},
            capability_profile,
            credentials,
        )
        _setup_user_provider_assets(loader, selection.orchestrator)
        _echo_user_next_steps(selection)
        return

    workspace = Path(os.path.abspath(workspace_dir or "."))
    try:
        _preflight_project_initialization(loader, selection, workspace)
    except OSError as exc:
        raise click.ClickException("provider settings configuration rejected") from exc

    # 1) MCP / Codex config
    storage_env = _storage_env(unrest_home=unrest_home, workspace=workspace, selection=selection)
    # Flags are sugar for the UNREST_*_REASONING_EFFORT env vars and win over
    # valid inherited shell settings. An invalid value already in the
    # environment still fails fast at discover() above — flags override
    # settings, they don't mask broken ones (the same validation would raise
    # at server launch anyway).
    effort_env = {
        var: value
        for var, value in (
            ("UNREST_WORKER_REASONING_EFFORT", worker_reasoning_effort),
            ("UNREST_VALIDATOR_REASONING_EFFORT", validator_reasoning_effort),
            ("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT", terminal_reviewer_reasoning_effort),
        )
        if value
    }
    if worker_model:
        if selection.worker.name != "codex":
            raise click.UsageError("--worker-model currently requires a Codex worker")
        effort_env["UNREST_WORKER_MODEL"] = worker_model
    try:
        _write_project_provider_capability_settings(
            workspace,
            selection.orchestrator,
            capability_profile,
        )
    except (CapabilityPolicyError, OSError) as exc:
        raise click.ClickException("provider settings configuration rejected") from exc
    _write_bootstrap_config(
        workspace,
        selection,
        storage_env,
        {**effort_env, **capability_env},
        capability_profile,
        credentials,
    )

    # 2) Per-provider agents + orchestrator prompt
    for provider in selection.providers():
        _setup_provider_assets(workspace, loader, provider)

    click.echo(
        f"\nInitialized v5 project workspace at {workspace}: "
        f"orchestrator={selection.orchestrator.name}, "
        f"worker={selection.worker.name}, "
        f"validator={selection.resolved_validation_worker.name}."
    )
    click.echo(
        "Bucket lives at $UNREST_HOME/projects/<pid>/ — created on the first "
        "`start_project(brief, workspace_dir)` call."
    )
    _echo_next_steps(selection.orchestrator)


# ---------------------------------------------------------------------------
# install-skills
# ---------------------------------------------------------------------------


@cli.command("install-skills")
@click.option("--target", type=click.Path(), required=True)
def install_skills_cmd(target: str) -> None:
    """Install bundled skills to a target directory (e.g. <ws>/.unrest/skills/)."""
    config = HarnessConfig.discover()
    loader = AssetLoader(config)
    _copy_skills(loader, Path(target).resolve())
    click.echo(f"Installed bundled skills to {target}")


# ---------------------------------------------------------------------------
# list-projects
# ---------------------------------------------------------------------------


@cli.command("list-projects")
def list_projects_cmd() -> None:
    """List all projects in HARNESS bucket."""
    store = ProjectStore(HarnessConfig.discover())
    projects = store.list_projects()
    if not projects:
        click.echo("No projects.")
        return
    for p in projects:
        click.echo(f"  {p.id}   ws={p.workspace_dir}   created={p.created_at}")


# ---------------------------------------------------------------------------
# show-project
# ---------------------------------------------------------------------------


@cli.command("show-project")
@click.argument("project_id")
def show_project_cmd(project_id: str) -> None:
    """Show envelope + compact task list for a project."""
    store = ProjectStore(HarnessConfig.discover())
    try:
        record = store.load_project(project_id)
    except FileNotFoundError:
        raise click.ClickException(f"Project not found: {project_id}")
    state = store.load_state(project_id)
    click.echo(f"id:        {record.id}")
    click.echo(f"workspace: {record.workspace_dir}")
    click.echo(f"created:   {record.created_at}")
    click.echo(f"state:     {state.state if state else 'draft'}")
    mid = record.current_mission_id
    if mid:
        click.echo(f"mission:   {mid}")
        try:
            tl = store.load_task_list(record.id, mid)
            ts = store.load_task_state(record.id, mid)
            rendered = render_task_list(tl, ts)
            if rendered:
                click.echo("")
                click.echo(rendered)
        except FileNotFoundError:
            click.echo("  (task list not yet submitted)")


# ---------------------------------------------------------------------------
# observe-project
# ---------------------------------------------------------------------------


def _observation_format(
    _ctx: click.Context,
    _param: click.Parameter,
    value: str,
) -> str:
    if value not in {"json", "text"}:
        raise click.ClickException("invalid_format")
    return value


def _stale_threshold(
    _ctx: click.Context,
    _param: click.Parameter,
    value: str,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise click.ClickException("invalid_stale_threshold") from exc
    if parsed <= 0:
        raise click.ClickException("invalid_stale_threshold")
    return parsed


def _observation_store(config: HarnessConfig) -> ProjectStore:
    """Construct the CLI observer store only from directory-shaped roots."""

    for root in (config.harness_home, config.projects_dir):
        try:
            info = root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError("invalid observation root") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("invalid observation root")
    return ProjectStore(config)


class _ObservationCommand(click.Command):
    """Keep status implementation command-local, including status help."""

    def get_help(self, ctx: click.Context) -> str:
        from . import runtime_observability as _runtime_observability  # noqa: F401

        return super().get_help(ctx)


@cli.command("observe-project", cls=_ObservationCommand)
@click.argument("project_id", required=False)
@click.option("--all", "all_projects", is_flag=True)
@click.option(
    "--strict",
    is_flag=True,
    help="With --all, exit 1 after emitting the complete payload if failures exist.",
)
@click.option(
    "--format",
    "output_format",
    default="text",
    show_default=True,
    callback=_observation_format,
)
@click.option(
    "--stale-after-seconds",
    default="3600",
    show_default=True,
    callback=_stale_threshold,
)
def observe_project_cmd(
    project_id: str | None,
    all_projects: bool,
    strict: bool,
    output_format: str,
    stale_after_seconds: int,
) -> None:
    """Print a read-only runtime snapshot for PROJECT_ID or every project.

    Capture is limited to 4 MiB per file, 16 MiB total, 4,096 selected files
    or entries, depth 6, and three snapshot attempts. Cursor limit violations
    report unsafe_cursor; an invalid projects root reports unsafe_project_path.
    """

    from .runtime_observability import (
        RuntimeObservationError,
        observe_all_projects_runtime,
        observe_project_runtime,
        observation_json,
        render_runtime_collection,
        render_runtime_observation,
        validate_project_id,
    )

    if (project_id is None) == (not all_projects) or (strict and not all_projects):
        raise click.ClickException("invalid_project_id")
    if project_id is not None and not validate_project_id(project_id):
        raise click.ClickException("invalid_project_id")
    strict_failure = False
    all_failed = False
    try:
        for path_variable in ("UNREST_HOME", "UNREST_PROJECTS_DIR"):
            ambient_path = os.environ.get(path_variable)
            if ambient_path is not None and (
                len(ambient_path) > 4096 or not ambient_path.isprintable()
            ):
                raise ValueError("invalid ambient path")
        ambient_parallelism = os.environ.get("UNREST_MAX_PARALLEL_NODES")
        if ambient_parallelism is not None:
            parsed_parallelism = int(ambient_parallelism)
            if parsed_parallelism <= 0:
                raise ValueError("invalid ambient parallelism")
        ambient_worker_model = os.environ.get("UNREST_WORKER_MODEL")
        if ambient_worker_model is not None and (
            not ambient_worker_model.strip()
            or len(ambient_worker_model) > 256
            or not ambient_worker_model.isprintable()
        ):
            raise ValueError("invalid ambient worker model")
        config = HarnessConfig.discover()
        config.validate_capability_support()
        store = _observation_store(config)
    except (OSError, RuntimeError, ValueError):
        raise click.ClickException("invalid_configuration") from None
    try:
        if all_projects:
            collection = observe_all_projects_runtime(
                store,
                stale_after_seconds=stale_after_seconds,
            )
            rendered = (
                observation_json(collection)
                if output_format == "json"
                else render_runtime_collection(collection)
            )
            strict_failure = bool(collection.failures)
            all_failed = bool(collection.failures) and not collection.projects
        else:
            assert project_id is not None
            observation = observe_project_runtime(
                store,
                project_id,
                stale_after_seconds=stale_after_seconds,
            )
            rendered = (
                observation_json(observation)
                if output_format == "json"
                else render_runtime_observation(observation)
            )
    except RuntimeObservationError as error:
        raise click.ClickException(error.code) from error
    click.echo(rendered, nl=False)
    if strict_failure and (strict or all_failed):
        raise click.exceptions.Exit(1)


# ---------------------------------------------------------------------------
# inspect-tasks
# ---------------------------------------------------------------------------


@cli.command("inspect-tasks")
@click.option("--project", "project_id", required=True)
@click.option("--mission", "mission_id", default=None)
def inspect_tasks_cmd(project_id: str, mission_id: str | None) -> None:
    """Render the compact text task list for a mission."""
    store = ProjectStore(HarnessConfig.discover())
    if mission_id is None:
        mid_list = store.list_missions(project_id)
        if not mid_list:
            raise click.ClickException("no missions in this project")
        mission_id = mid_list[-1]
    try:
        tl = store.load_task_list(project_id, mission_id)
    except FileNotFoundError:
        raise click.ClickException(f"tasks.json not found for {project_id}/{mission_id}")
    ts = store.load_task_state(project_id, mission_id)
    rendered = render_task_list(tl, ts, mode="full")
    if rendered:
        click.echo(rendered)


# ---------------------------------------------------------------------------
# abort-project
# ---------------------------------------------------------------------------


@cli.command("abort-project")
@click.argument("project_id")
@click.option("--reason", required=True)
def abort_project_cmd(project_id: str, reason: str) -> None:
    """Mark a project Aborted (CLI-side: preserves tasks.json + attempts/)."""
    from .controller import ProjectController
    from .dispatcher import MockDispatcher, MockTerminalReviewer
    from .models import TerminalReviewHandoff, WorkHandoff

    config = HarnessConfig.discover()
    controller = ProjectController(
        config,
        MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=False, report="aborted")),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    env = controller.abort_project(project_id, reason)
    click.echo(f"Aborted {project_id}: state={env.state.state}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bundled_skill_targets(loader: AssetLoader, target: Path) -> list[Path]:
    bundled = loader.bundled_skills_dir()
    if not bundled.exists():
        return []
    return [
        target / skill_dir.name / "SKILL.md"
        for skill_dir in iter_skill_directories(bundled)
    ]


def _bundled_agent_targets(
    loader: AssetLoader,
    target: Path,
    provider_name: str,
) -> list[Path]:
    bundled = loader.bundled_agents_dir(provider_name)
    if not bundled.exists():
        return []
    return [
        target / agent_file.name
        for agent_file in sorted(bundled.glob("*"))
        if agent_file.is_file()
    ]


def _preflight_target(
    target: Path,
    *,
    trusted_root: Path,
    allowed_ancestor: Path | None = None,
) -> None:
    validate_atomic_write_destination(
        target,
        trusted_root=trusted_root,
        allowed_ancestor=allowed_ancestor,
    )


def _preflight_project_initialization(
    loader: AssetLoader,
    selection: ProviderSelection,
    workspace: Path,
) -> None:
    bootstrap = (
        workspace / ".mcp.json"
        if selection.orchestrator.config_format == "mcp_json"
        else workspace / ".codex" / "config.toml"
    )
    bootstrap_root = (
        workspace
        if bootstrap.parent == workspace
        else workspace / bootstrap.relative_to(workspace).parts[0]
    )
    _preflight_target(
        bootstrap,
        trusted_root=bootstrap_root,
        allowed_ancestor=None if bootstrap_root == workspace else workspace,
    )
    if selection.orchestrator.name == "claude":
        claude_root = workspace / ".claude"
        for target in (
            claude_root / "settings.json",
            claude_root / ".unrest-managed-settings.json",
        ):
            _preflight_target(
                target,
                trusted_root=claude_root,
                allowed_ancestor=workspace,
            )

    for provider in selection.providers():
        destinations: list[Path] = []
        if provider.agent_output_dir:
            agents_dir = workspace / provider.agent_output_dir
            destinations.extend(
                _bundled_agent_targets(loader, agents_dir, provider.name)
            )
        for skill_relative in provider.skill_dirs:
            destinations.extend(
                _bundled_skill_targets(loader, workspace / skill_relative)
            )
        if provider.orchestrator_prompt_output_path:
            destinations.append(workspace / provider.orchestrator_prompt_output_path)
        for target in destinations:
            destination_relative = target.relative_to(workspace)
            trusted_root = workspace / destination_relative.parts[0]
            _preflight_target(
                target,
                trusted_root=trusted_root,
                allowed_ancestor=workspace,
            )


def _preflight_user_initialization(
    loader: AssetLoader,
    provider: ProviderDefinition,
) -> None:
    home = Path(os.path.abspath(Path.home()))
    root, config_path = _user_paths(provider)
    _preflight_target(config_path, trusted_root=home)
    if provider.name == "claude":
        for target in (
            root / "settings.json",
            root / ".unrest-managed-settings.json",
        ):
            _preflight_target(
                target,
                trusted_root=root,
                allowed_ancestor=home,
            )

    destinations = _bundled_agent_targets(loader, root / "agents", provider.name)
    destinations.extend(_bundled_skill_targets(loader, root / "skills"))
    destinations.extend(
        _bundled_skill_targets(loader, home / ".agents" / "skills")
    )
    destinations.extend(
        [
            root / "orchestrator_prompt.md",
            root / "skills" / "unrest" / "SKILL.md",
        ]
    )
    for target in destinations:
        if target.is_relative_to(home / ".agents"):
            trusted_root = home / ".agents"
        else:
            trusted_root = root
        _preflight_target(
            target,
            trusted_root=trusted_root,
            allowed_ancestor=home,
        )


def _copy_skills(
    loader: AssetLoader,
    target: Path,
    *,
    trusted_root: Path | None = None,
    allowed_ancestor: Path | None = None,
) -> _ManagedAssetSummary:
    summary = _ManagedAssetSummary()
    bundled = loader.bundled_skills_dir()
    if not bundled.exists():
        click.echo(f"warning: bundled skills not found at {bundled}", err=True)
        return summary
    for skill_dir in iter_skill_directories(bundled):
        dest = target / skill_dir.name
        source = skill_dir / "SKILL.md"
        destination = dest / "SKILL.md"
        if trusted_root is None:
            existed = destination.exists()
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            summary.record("repaired" if existed else "created")
        else:
            summary.record(
                _synchronize_managed_asset(
                    destination,
                    source.read_text(encoding="utf-8"),
                    trusted_root=trusted_root,
                    allowed_ancestor=allowed_ancestor,
                )
            )
    return summary


def _echo_user_next_steps(selection: ProviderSelection) -> None:
    provider = selection.orchestrator.name
    host = {"claude": "Claude Code", "codex": "Codex"}.get(provider, provider)
    click.echo(
        f"\nInitialized v5 user scope: orchestrator={provider}, "
        f"worker={selection.worker.name}, "
        f"validator={selection.resolved_validation_worker.name}."
    )
    click.echo("Unrest is available from every workspace for this user.")
    click.echo("")
    click.echo("Next:")
    click.echo(f"  1. Restart {host} or start a new session.")
    click.echo("  2. Run: /unrest <your instruction or query>")


def _echo_next_steps(orchestrator: ProviderDefinition) -> None:
    prompt_path = orchestrator.orchestrator_prompt_output_path
    click.echo("")
    click.echo("Next:")
    click.echo("  1. Start your agent from the initialized project workspace:")
    click.echo(f"     {orchestrator.name}")
    if prompt_path:
        click.echo("  2. Ask it:")
        click.echo(
            f"     First read {prompt_path} and treat it as your primary role, then use Unrest to run this mission."
        )
        click.echo("")
        click.echo("     <your instruction or query>")


def _resolve_selection(
    *,
    agent: str | None,
    orchestrator: str | None,
    worker: str | None,
    worker_acp_command: str | None,
    validator: str | None,
    validator_acp_command: str | None,
    terminal_reviewer: str | None,
    terminal_reviewer_acp_command: str | None,
) -> ProviderSelection:
    if agent and orchestrator and agent != orchestrator:
        raise click.UsageError("--agent conflicts with --orchestrator-provider")
    orch = orchestrator or agent or "claude"
    wrk = worker or (agent if agent in provider_names_for_role("worker") else None) or default_worker_provider_name(orch)
    return ProviderSelection(
        orchestrator=get_provider(orch),
        worker=get_provider(wrk),
        validation_worker=get_provider(validator) if validator else None,
        worker_acp_command=worker_acp_command,
        validation_worker_acp_command=validator_acp_command,
        terminal_reviewer=(
            get_provider(terminal_reviewer) if terminal_reviewer else None
        ),
        terminal_reviewer_acp_command=terminal_reviewer_acp_command,
    )


def _storage_env(
    *,
    unrest_home: str | None,
    workspace: Path,
    selection: ProviderSelection,
) -> dict[str, str]:
    env: dict[str, str] = {}
    if unrest_home:
        env["UNREST_HOME"] = str(Path(unrest_home).expanduser().resolve())
    return env


def _forwarded_runtime_env() -> dict[str, str]:
    return {
        key: value
        for key in RUNTIME_ENV_FORWARD_ALLOWLIST
        if (value := os.environ.get(key))
    }


def _mcp_server_args() -> list[str]:
    return ["--mode", "orchestrator"]


def _runtime_mcp_env() -> dict[str, str]:
    env = {
        key: value
        for key in ("PATH", "UV_CACHE_DIR")
        if (value := os.environ.get(key))
    }
    # Pin discovery from PATH; an ambient CODEX_PATH is a provider override and
    # cannot broaden or redirect a newly generated safe configuration.
    if codex_path := shutil.which("codex"):
        env["CODEX_PATH"] = codex_path
    return env


def _claude_user_paths() -> tuple[Path, Path]:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        root = Path(os.path.abspath(Path(configured).expanduser()))
        return root, root / ".claude.json"
    home = Path(os.path.abspath(Path.home()))
    return home / ".claude", home / ".claude.json"


def _codex_user_paths() -> tuple[Path, Path]:
    root = Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))
    root = Path(os.path.abspath(root.expanduser()))
    return root, root / "config.toml"


def _user_paths(provider: ProviderDefinition) -> tuple[Path, Path]:
    if provider.name == "claude":
        return _claude_user_paths()
    if provider.name == "codex":
        return _codex_user_paths()
    raise ValueError(f"user-scope paths are not defined for {provider.name}")


def _write_project_provider_capability_settings(
    workspace: Path,
    provider: ProviderDefinition,
    profile: str,
) -> None:
    if provider.name != "claude":
        return
    from .acp_runner import _ensure_claude_settings

    _ensure_claude_settings(
        workspace,
        provider,
        profile,
        role="orchestrator",
        allowed_ancestor=workspace,
    )


def _write_user_provider_capability_settings(
    selection: ProviderSelection,
    profile: str,
) -> None:
    provider = selection.orchestrator
    if provider.name != "claude":
        return
    from .acp_runner import _ensure_claude_settings

    settings_root, _ = _user_paths(provider)
    _ensure_claude_settings(
        settings_root.parent,
        provider,
        profile,
        role="orchestrator",
        settings_dir=settings_root,
        allowed_ancestor=Path.home(),
    )


def _write_text_atomic(
    path: Path,
    text: str,
    inventory: dict[str, str] | None = None,
    *,
    trusted_root: Path | None = None,
    allowed_ancestor: Path | None = None,
    mode: int | None = None,
) -> None:
    atomic_write_text(
        path,
        text,
        trusted_root=trusted_root or path.parent,
        allowed_ancestor=allowed_ancestor,
        mode=mode,
        inventory=inventory,
    )


def _synchronize_managed_asset(
    path: Path,
    authoritative_text: str,
    *,
    trusted_root: Path,
    allowed_ancestor: Path | None,
) -> ManagedAssetOutcome:
    """Make one managed text asset exactly match its bundled authority."""
    authoritative_bytes = authoritative_text.encode("utf-8")
    try:
        current = path.lstat()
    except FileNotFoundError:
        outcome: ManagedAssetOutcome = "created"
    else:
        if not stat.S_ISREG(current.st_mode):
            raise OSError(f"managed asset target must be a regular file: {path}")
        if (
            path.read_bytes() == authoritative_bytes
            and stat.S_IMODE(current.st_mode) == MANAGED_ASSET_MODE
        ):
            return "verified"
        outcome = "repaired"

    _write_text_atomic(
        path,
        authoritative_text,
        trusted_root=trusted_root,
        allowed_ancestor=allowed_ancestor,
        mode=MANAGED_ASSET_MODE,
    )
    installed = path.lstat()
    if (
        not stat.S_ISREG(installed.st_mode)
        or path.read_bytes() != authoritative_bytes
        or stat.S_IMODE(installed.st_mode) != MANAGED_ASSET_MODE
    ):
        raise OSError(f"managed asset verification failed after atomic write: {path}")
    return outcome


def _user_server_config(
    selection: ProviderSelection,
    storage_env: dict[str, str],
    credentials: dict[str, str] | None = None,
) -> dict:
    return {
        "type": "stdio",
        "command": "unrest-server",
        "args": _mcp_server_args(),
        "env": enforce_persisted_environment_credential_provenance(
            {**selection.env(), **storage_env},
            credentials or {},
        ),
    }


def _write_claude_user_config(
    path: Path,
    selection: ProviderSelection,
    storage_env: dict[str, str],
    credentials: dict[str, str],
) -> None:
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"Cannot update invalid Claude config {path}: {exc}") from exc
    else:
        existing = {}
    if not isinstance(existing, dict):
        raise click.ClickException(f"Cannot update Claude config {path}: root must be an object")
    mcp_servers = existing.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        raise click.ClickException(
            f"Cannot update Claude config {path}: mcpServers must be an object"
        )
    mcp_servers["unrest"] = _user_server_config(
        selection,
        storage_env,
        credentials,
    )
    _write_text_atomic(
        path,
        json.dumps(existing, indent=2) + "\n",
        credentials,
        trusted_root=Path.home(),
    )
    click.echo(f"Wrote {path}")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_table_path(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped.startswith("[") or stripped.startswith("[["):
        return None
    try:
        parsed = tomllib.loads(f"{stripped}\n")
    except tomllib.TOMLDecodeError:
        return None
    path: list[str] = []
    current = parsed
    while len(current) == 1:
        key, value = next(iter(current.items()))
        if not isinstance(value, dict):
            return None
        path.append(key)
        current = value
    return tuple(path) if not current else None


def _strip_toml_tables(text: str, table: tuple[str, ...]) -> str:
    kept: list[str] = []
    removing = False
    for line in text.splitlines(keepends=True):
        path = _toml_table_path(line)
        if path is not None:
            removing = path[: len(table)] == table
        if not removing:
            kept.append(line)
    return "".join(kept).rstrip()


def _parse_managed_block_lines(
    text: str,
    start: str,
    end: str,
) -> tuple[list[str], tuple[int, int] | None]:
    lines = text.splitlines(keepends=True)
    start_lines: list[int] = []
    end_lines: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == start:
            start_lines.append(index)
        elif stripped == end:
            end_lines.append(index)

    if not start_lines and not end_lines:
        return lines, None
    if len(start_lines) != 1 or len(end_lines) != 1 or start_lines[0] >= end_lines[0]:
        raise ValueError(
            "malformed Unrest managed block: expected no markers or one forward pair; "
            f"found {len(start_lines)} begin and {len(end_lines)} end markers"
        )
    return lines, (start_lines[0], end_lines[0])


_CODEX_CAPABILITY_START = "# BEGIN unrest capability policy v1"
_CODEX_CAPABILITY_END = "# END unrest capability policy v1"
_LEGACY_CODEX_PREAMBLE = (
    'model = "gpt-5.5"\n'
    'sandbox_mode = "danger-full-access"\n'
    'model_reasoning_effort = "xhigh"\n'
    "[features]\n"
    "memories = true\n"
)


def _apply_codex_capability_policy(text: str, profile: str, path: Path) -> str:
    # The old project initializer emitted this exact preamble immediately
    # before its managed MCP marker. Only that byte-identifiable legacy field
    # is migrated; similar unmanaged user settings are never silently edited.
    if _CODEX_CAPABILITY_START not in text and "# BEGIN unrest" in text:
        before, marker, after = text.partition("# BEGIN unrest")
        if before.rstrip().endswith(_LEGACY_CODEX_PREAMBLE.rstrip()):
            legacy_start = before.rstrip().rfind(_LEGACY_CODEX_PREAMBLE.rstrip())
            legacy = _LEGACY_CODEX_PREAMBLE.replace(
                'sandbox_mode = "danger-full-access"\n',
                "",
            )
            before = before.rstrip()[:legacy_start] + legacy
            text = before.rstrip() + "\n" + marker + after

    try:
        lines, span = _parse_managed_block_lines(
            text,
            _CODEX_CAPABILITY_START,
            _CODEX_CAPABILITY_END,
        )
    except ValueError as exc:
        raise click.ClickException(f"Cannot update Codex config {path}: {exc}") from exc
    unmanaged = text
    if span is not None:
        start_line, end_line = span
        unmanaged = "".join(lines[:start_line] + lines[end_line + 1 :]).lstrip("\n")
    try:
        parsed = tomllib.loads(unmanaged)
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"Cannot update invalid Codex config {path}: {exc}") from exc

    sandbox = parsed.get("sandbox_mode")
    approval = parsed.get("approval_policy")
    if profile == SAFE_PROFILE:
        if sandbox not in (None, "read-only", "workspace-write"):
            raise click.ClickException(
                f"Cannot update Codex config {path}: unmanaged sandbox_mode={sandbox!r} "
                "is not safe; remove it or use the explicit "
                "--unsafe-development-unrestricted opt-in"
            )
        if approval not in (None, "on-request", "untrusted"):
            raise click.ClickException(
                f"Cannot update Codex config {path}: unmanaged approval_policy={approval!r} "
                "is not safe"
            )
        desired_sandbox = "workspace-write"
        desired_approval = "on-request"
    else:
        if sandbox not in (None, "danger-full-access") or approval not in (None, "never"):
            raise click.ClickException(
                f"Cannot update Codex config {path}: unmanaged safe provider settings "
                "conflict with the explicit unsafe development profile"
            )
        desired_sandbox = "danger-full-access"
        desired_approval = "never"

    # Safe user-owned settings remain user-owned. Unrest owns only whichever
    # half of the required root authority pair is absent.
    managed_settings: list[tuple[str, str]] = []
    if sandbox is None:
        managed_settings.append(("sandbox_mode", desired_sandbox))
    if approval is None:
        managed_settings.append(("approval_policy", desired_approval))
    if not managed_settings:
        return unmanaged
    setting_lines = "".join(
        f"{name} = {_toml_string(value)}\n"
        for name, value in managed_settings
    )
    block = (
        f"{_CODEX_CAPABILITY_START}\n"
        f"{setting_lines}"
        f"{_CODEX_CAPABILITY_END}\n"
    )
    updated = block
    if unmanaged.strip():
        updated += "\n" + unmanaged.lstrip("\n")
    return updated


def _write_codex_user_config(
    path: Path,
    selection: ProviderSelection,
    storage_env: dict[str, str],
    capability_profile: str,
    credentials: dict[str, str],
) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    existing = _apply_codex_capability_policy(existing, capability_profile, path)
    try:
        tomllib.loads(existing)
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"Cannot update invalid Codex config {path}: {exc}") from exc

    start = "# BEGIN unrest"
    end = "# END unrest"
    try:
        existing_lines, managed_span = _parse_managed_block_lines(existing, start, end)
    except ValueError as exc:
        raise click.ClickException(f"Cannot update Codex config {path}: {exc}") from exc
    if managed_span is None:
        existing = _strip_toml_tables(existing, ("mcp_servers", "unrest"))

    server = _user_server_config(
        selection,
        storage_env,
        credentials,
    )
    env_lines = "\n".join(
        f"{key} = {_toml_string(value)}" for key, value in server["env"].items()
    )
    block = (
        f"{start}\n"
        "[mcp_servers.unrest]\n"
        'command = "unrest-server"\n'
        f"args = {json.dumps(server['args'], ensure_ascii=False)}\n"
        "startup_timeout_sec = 10\n"
        "tool_timeout_sec = 1000000\n"
        "\n"
        "[mcp_servers.unrest.env]\n"
        f"{env_lines}\n"
        f"{end}\n"
    )
    if managed_span is None:
        updated = existing.rstrip()
        if updated:
            updated += "\n\n"
        updated += block.rstrip() + "\n"
    else:
        start_line, end_line = managed_span
        updated = (
            "".join(existing_lines[:start_line])
            + block
            + "".join(existing_lines[end_line + 1 :])
        )
    try:
        tomllib.loads(updated)
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"Generated invalid Codex config for {path}: {exc}") from exc
    _write_text_atomic(path, updated, credentials, trusted_root=Path.home())
    click.echo(f"Wrote {path}")


def _write_user_bootstrap_config(
    selection: ProviderSelection,
    storage_env: dict[str, str],
    capability_profile: str,
    credentials: dict[str, str],
) -> None:
    _, config_path = _user_paths(selection.orchestrator)
    if selection.orchestrator.name == "claude":
        _write_claude_user_config(
            config_path,
            selection,
            storage_env,
            credentials,
        )
    elif selection.orchestrator.name == "codex":
        _write_codex_user_config(
            config_path,
            selection,
            storage_env,
            capability_profile,
            credentials,
        )
    else:
        raise ValueError(f"unsupported user-scope provider: {selection.orchestrator.name}")


def _unrest_skill_body(prompt_path: Path) -> str:
    return f'''---
name: unrest
description: Run a long-horizon mission through the Unrest continuous-improvement harness.
---

# /unrest

First read `{prompt_path}` and treat it as your primary role, then use the globally
registered Unrest MCP tools to run the mission supplied with this skill.

If the Unrest tools are unavailable, ask the user to restart the host or start a new
session. Do not run workspace initialization merely because the current workspace has
no local Unrest configuration; project state begins with `start_project(brief,
workspace_dir)`.
'''


def _setup_user_provider_assets(loader: AssetLoader, provider: ProviderDefinition) -> None:
    root, _ = _user_paths(provider)
    home = Path(os.path.abspath(Path.home()))
    agents_dir = root / "agents"
    agents_summary = _copy_provider_agents(
        loader,
        agents_dir,
        provider.name,
        trusted_root=root,
        allowed_ancestor=home,
    )
    click.echo(agents_summary.render(f"{provider.name} subagents", agents_dir))

    skills_dir = root / "skills"
    skills_summary = _copy_skills(
        loader,
        skills_dir,
        trusted_root=root,
        allowed_ancestor=home,
    )
    click.echo(skills_summary.render("bundled skills", skills_dir))

    shared_root = home / ".agents"
    shared_skills_dir = shared_root / "skills"
    shared_skills_summary = _copy_skills(
        loader,
        shared_skills_dir,
        trusted_root=shared_root,
        allowed_ancestor=home,
    )
    click.echo(shared_skills_summary.render("bundled skills", shared_skills_dir))

    prompt_path = root / "orchestrator_prompt.md"
    prompt = loader.load_prompt_file("orchestrator", "system_prompt.md")
    prompt_outcome = _synchronize_managed_asset(
        prompt_path,
        prompt,
        trusted_root=root,
        allowed_ancestor=home,
    )
    prompt_summary = _ManagedAssetSummary()
    prompt_summary.record(prompt_outcome)
    click.echo(prompt_summary.render("orchestrator prompt", prompt_path))

    skill_path = skills_dir / "unrest" / "SKILL.md"
    _write_text_atomic(
        skill_path,
        _unrest_skill_body(prompt_path),
        trusted_root=root,
        allowed_ancestor=home,
    )
    click.echo(f"Wrote {skill_path}")


def _write_bootstrap_config(
    workspace: Path,
    selection: ProviderSelection,
    storage_env: dict[str, str],
    cli_env: dict[str, str],
    capability_profile: str,
    credentials: dict[str, str],
) -> None:
    fmt = selection.orchestrator.config_format
    env = {
        **selection.env(),
        **storage_env,
        **_forwarded_runtime_env(),
        **_runtime_mcp_env(),
        **cli_env,
    }
    env = enforce_persisted_environment_credential_provenance(
        env,
        credentials,
    )
    server_args = _mcp_server_args()
    if fmt == "mcp_json":
        path = workspace / ".mcp.json"
        existing = (
            json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        )
        existing.setdefault("mcpServers", {})["unrest"] = {
            "type": "stdio",
            "command": "unrest-server",
            "args": server_args,
            "env": env,
        }
        _write_text_atomic(
            path,
            json.dumps(existing, indent=2) + "\n",
            credentials,
            trusted_root=workspace,
        )
        click.echo(f"Wrote {path}")
    elif fmt == "codex_config":
        config_path = workspace / ".codex" / "config.toml"
        env_lines = "\n".join(
            f"{key} = {_toml_string(value)}" for key, value in env.items()
        )
        existing_text = (
            config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        )
        existing_text = _apply_codex_capability_policy(
            existing_text,
            capability_profile,
            config_path,
        )
        block = (
            "# BEGIN unrest\n"
            "[mcp_servers.unrest]\n"
            'command = "unrest-server"\n'
            f"args = {json.dumps(server_args)}\n"
            "startup_timeout_sec = 10\n"
            "tool_timeout_sec = 1000000\n"
            "\n"
            "[mcp_servers.unrest.env]\n"
            f"{env_lines}\n"
            "# END unrest\n"
        )
        updated = _replace_managed_block_text(
            existing_text,
            "# BEGIN unrest",
            "# END unrest",
            block,
        )
        try:
            tomllib.loads(updated)
        except tomllib.TOMLDecodeError as exc:
            raise click.ClickException(
                f"Generated invalid Codex config for {config_path}: {exc}"
            ) from exc
        _write_text_atomic(
            config_path,
            updated,
            credentials,
            trusted_root=config_path.parent,
            allowed_ancestor=workspace,
        )
        click.echo(f"Wrote {config_path}")
    else:
        raise ValueError(f"unsupported config_format: {fmt}")


def _replace_managed_block_text(
    existing: str,
    start: str,
    end: str,
    block: str,
    *,
    legacy_prefix: str | None = None,
) -> str:
    lines, span = _parse_managed_block_lines(existing, start, end)
    if span is None:
        remaining = existing
    else:
        start_line, end_line = span
        remaining = "".join(lines[:start_line] + lines[end_line + 1 :])
    if legacy_prefix and remaining.rstrip().endswith(legacy_prefix.rstrip()):
        remaining = remaining.rstrip()[: -len(legacy_prefix.rstrip())]
    updated = remaining.rstrip()
    if updated:
        updated += "\n\n"
    updated += block.rstrip() + "\n"
    return updated


def _replace_managed_block(
    path: Path,
    start: str,
    end: str,
    block: str,
    *,
    legacy_prefix: str | None = None,
) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    updated = _replace_managed_block_text(
        existing,
        start,
        end,
        block,
        legacy_prefix=legacy_prefix,
    )
    path.write_text(updated, encoding="utf-8")


def _setup_provider_assets(
    workspace: Path,
    loader: AssetLoader,
    provider: ProviderDefinition,
) -> None:
    if provider.agent_output_dir:
        agents_dir = workspace / provider.agent_output_dir
        trusted_root = workspace / Path(provider.agent_output_dir).parts[0]
        agents_summary = _copy_provider_agents(
            loader,
            agents_dir,
            provider.name,
            trusted_root=trusted_root,
            allowed_ancestor=workspace,
        )
        click.echo(agents_summary.render(f"{provider.name} subagents", agents_dir))
    # Install bundled skills into the host-agent skill surface so the
    # orchestrator can discover playbooks/skills at startup — `start_project`
    # runs only after the host agent is already up, so the surface must exist
    # before the first MCP call. `start_project` later merges bucket skills
    # (including project-authored ones) into these dirs.
    for rel in provider.skill_dirs:
        dest = workspace / rel
        trusted_root = workspace / Path(rel).parts[0]
        skills_summary = _copy_skills(
            loader,
            dest,
            trusted_root=trusted_root,
            allowed_ancestor=workspace,
        )
        click.echo(skills_summary.render("bundled skills", dest))
    if provider.orchestrator_prompt_output_path:
        path = workspace / provider.orchestrator_prompt_output_path
        body = loader.load_prompt_file("orchestrator", "system_prompt.md")
        trusted_root = workspace / Path(
            provider.orchestrator_prompt_output_path
        ).parts[0]
        outcome = _synchronize_managed_asset(
            path,
            body,
            trusted_root=trusted_root,
            allowed_ancestor=workspace,
        )
        summary = _ManagedAssetSummary()
        summary.record(outcome)
        click.echo(summary.render("orchestrator prompt", path))


def _copy_provider_agents(
    loader: AssetLoader,
    target: Path,
    provider_name: str,
    *,
    trusted_root: Path | None = None,
    allowed_ancestor: Path | None = None,
) -> _ManagedAssetSummary:
    summary = _ManagedAssetSummary()
    bundled = loader.bundled_agents_dir(provider_name)
    if not bundled.exists():
        return summary
    for agent_file in sorted(bundled.glob("*")):
        if agent_file.is_file():
            destination = target / agent_file.name
            if trusted_root is None:
                existed = destination.exists()
                target.mkdir(parents=True, exist_ok=True)
                shutil.copy2(agent_file, destination)
                summary.record("repaired" if existed else "created")
            else:
                summary.record(_synchronize_managed_asset(
                    destination,
                    agent_file.read_text(encoding="utf-8"),
                    trusted_root=trusted_root,
                    allowed_ancestor=allowed_ancestor,
                ))
    return summary
