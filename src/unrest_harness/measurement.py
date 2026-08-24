"""Frozen FM-010 baseline runner and deterministic public bundle renderer.

The runner is deliberately release/manual-only. Importing this module never
starts provider work; :func:`measure_baseline` requires an explicit boolean
confirmation and executes the packaged protocol sequentially.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, Protocol

from .config import HarnessConfig
from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
from .controller import ProjectController
from .foundation_tools import FoundationTools
from .provider_sessions import (
    ProviderSessionRequest,
    ProviderSessionResult,
    ProviderSessionRunner,
)
from .storage import atomic_write_text

PROTOCOL_ID = "fm010-baseline-v1"
PROTOCOL_RELATIVE_PATH = Path("measurement") / "fm010-baseline-v1.json"
RESULTS_RELATIVE_ROOT = Path("docs/v03/measurement/results")
PRIVATE_DIRECTORY_NAME = "measurement-private"
REPETITION_COUNT = 20
REPETITION_TIMEOUT_SECONDS = 20 * 60
GLOBAL_TIMEOUT_SECONDS = 200 * 60
GLOBAL_REPORTED_COST_USD = 50.0
NOISE_LIMIT = 0.15
CANONICAL_PROTOCOL_DIGEST = (
    "sha256:b8a4e47e876af42f12331c8a5de2b918c3686542ef75f20efe3be0e903f48677"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROVIDERS = frozenset({"claude", "codex"})
_PHASES = frozenset(
    {
        "p1-work",
        "p1-validate",
        "p2-initial-work",
        "p2-initial-validate",
        "p2-corrected-work",
        "p2-corrected-validate",
        "candidate",
        "evaluation",
        "review",
    }
)
_INVOCATION_ROLES = frozenset(
    {"worker", "validator", "candidate_author", "independent_evaluator", "independent_reviewer"}
)
_INVOCATION_OUTCOMES = frozenset({"completed", "failed", "timed_out", "cancelled"})
_ERROR_CODES = frozenset(
    {
        "adapter_not_configured",
        "adapter_start_failed",
        "cancelled",
        "invalid_structured_output",
        "node_incomplete",
        "output_limit_exceeded",
        "protocol_error",
        "timed_out",
    }
)
_FAILURES = frozenset(
    {
        "cancelled",
        "cost_exhausted",
        "cost_unavailable",
        "global_timeout",
        "oracle_failed",
        "repetition_timeout",
        "unexpected_error",
    }
)

MeasurementStatus = Literal["published", "invalid", "inconclusive"]


class MeasurementError(RuntimeError):
    """A stable, value-free measurement protocol error."""


class _BudgetExhausted(RuntimeError):
    pass


class _BudgetUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class InvocationOutcome:
    """One provider invocation result before public sanitization."""

    status: Literal["completed", "failed", "timed_out", "cancelled"]
    parsed: Mapping[str, Any] | None
    provider: str
    model: str | None = None
    route: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    reported_cost_usd: float | None = None
    cache_status: Literal["disabled", "hit", "unknown"] = "disabled"
    error_code: str | None = None


class MeasurementProvider(Protocol):
    async def invoke(
        self,
        *,
        role: str,
        prompt: str,
        cold_root: Path,
        private_root: Path,
        invocation_id: str,
        timeout_seconds: float,
        project_record_path: Path | None = None,
    ) -> InvocationOutcome: ...


class ConfiguredProvider:
    """Adapter from the measurement protocol to configured ACP sessions."""

    def __init__(self, config: HarnessConfig) -> None:
        self.config = config
        self.runner = ProviderSessionRunner(config)

    async def invoke(
        self,
        *,
        role: str,
        prompt: str,
        cold_root: Path,
        private_root: Path,
        invocation_id: str,
        timeout_seconds: float,
        project_record_path: Path | None = None,
    ) -> InvocationOutcome:
        artifact_path = private_root / "provider" / f"{invocation_id}.json"
        artifact_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        project_record = project_record_path or cold_root / "project-record"
        if project_record_path is None:
            project_record.mkdir(mode=0o700)
        request = ProviderSessionRequest(
            role=_provider_role(role),
            prompt=prompt,
            workspace_path=cold_root,
            project_record_path=project_record,
            private_artifact_path=artifact_path,
            private_artifact_root=private_root,
            timeout_seconds=timeout_seconds,
        )
        result = await self.runner.run(request)
        parsed: Mapping[str, Any] | None = None
        if result.status == "completed":
            raw = json.loads(artifact_path.read_text(encoding="utf-8"))
            candidate = raw.get("output", {}).get("parsed")
            if isinstance(candidate, dict):
                parsed = candidate
        # ACP does not promise token or price telemetry. Null is an honest
        # recorded value; only costs actually reported by the route are summed.
        return InvocationOutcome(
            status=result.status,
            parsed=parsed,
            provider=result.provider,
            model=None,
            route="acp",
            input_tokens=None,
            output_tokens=None,
            reported_cost_usd=None,
            # ProviderSessionResult intentionally exposes no cache telemetry.
            # A fresh process/session is useful isolation, but it is not proof
            # about provider-side response caching.
            cache_status="unknown",
            error_code=result.error_code,
        )


def _measurement_execute(
    operation: str,
    arguments: Mapping[str, Any],
    _context: Any,
) -> dict[str, Any]:
    """Deterministic executor behind the measurement RunControl adapter."""
    workspace = Path(str(arguments.get("workspace_dir", Path.cwd()))).resolve()
    project_id = str(arguments.get("project_id") or "measurement-project")
    states = {
        "start_project": "mission_planning",
        "submit_plan": "mission_running",
        "advance_project": "done",
        "end_mission": "done",
        "abort_project": "aborted",
        "decide_attention": "mission_running",
    }
    state = states[operation]
    detail: dict[str, Any] = {"state": state}
    if state in {"mission_planning", "mission_running"}:
        detail["mission_id"] = "mission-measurement"
    if state == "aborted":
        detail["reason"] = "measurement aborted"
    return {
        "dag": None,
        "harnessRoot": str(workspace / ".unrest"),
        "projectId": project_id,
        "projectRoot": str(workspace),
        "state": detail,
    }


class _EvolutionBridge:
    def __init__(self, runner: BaselineRunner, repetition_id: str, case_id: str) -> None:
        self.runner = runner
        self.repetition_id = repetition_id
        self.case_id = case_id

    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError
        return await self.runner.evolution_provider_run(
            request,
            repetition_id=self.repetition_id,
            case_id=self.case_id,
        )


def _provider_role(role: str) -> Any:
    allowed = {
        "candidate_author",
        "independent_evaluator",
        "independent_reviewer",
    }
    if role not in allowed:
        raise MeasurementError("MEASUREMENT-012 invalid provider role")
    return role


def bundled_protocol_path(config: HarnessConfig | None = None) -> Path:
    resolved = config or HarnessConfig.discover()
    return resolved.bundled_dir / PROTOCOL_RELATIVE_PATH


def load_protocol(protocol: str, config: HarnessConfig) -> dict[str, Any]:
    if protocol in {PROTOCOL_ID, "bundled:" + PROTOCOL_ID}:
        path = bundled_protocol_path(config)
    else:
        path = Path(protocol).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MeasurementError("MEASUREMENT-001 protocol is unavailable") from exc
    if not isinstance(value, dict):
        raise MeasurementError("MEASUREMENT-002 protocol is invalid")
    _validate_protocol(value)
    return value


def _validate_protocol(protocol: Mapping[str, Any]) -> None:
    # The canonical digest binds every key, value, nested fixture, oracle,
    # prompt, ordering position, and ceiling. Shape-only checks would allow a
    # seemingly valid protocol to quietly redefine what the release measured.
    if _digest_value(dict(protocol)) != CANONICAL_PROTOCOL_DIGEST:
        raise MeasurementError("MEASUREMENT-002 protocol is invalid")


def _source_root() -> Path:
    candidate = Path(__file__).resolve()
    for parent in candidate.parents:
        if (parent / ".git").exists() and (parent / "pyproject.toml").is_file():
            return parent
    raise MeasurementError("MEASUREMENT-003 release-candidate source is unavailable")


def protected_product_digest(source_root: Path) -> str:
    """Hash paths, modes, and bytes for every tracked candidate file."""
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--stage"],
            cwd=source_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MeasurementError("MEASUREMENT-004 tracked product cannot be enumerated") from exc
    digest = hashlib.sha256()
    entries = completed.stdout.split(b"\0")
    included = 0
    for entry in sorted(item for item in entries if item):
        metadata, raw_path = entry.split(b"\t", 1)
        relative = Path(os.fsdecode(raw_path))
        if relative.parts[:4] == RESULTS_RELATIVE_ROOT.parts:
            continue
        path = source_root / relative
        if not path.is_file():
            raise MeasurementError("MEASUREMENT-005 tracked product is incomplete")
        digest.update(metadata.split(b" ", 1)[0])
        digest.update(b"\0")
        digest.update(raw_path)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
        included += 1
    if included == 0:
        raise MeasurementError("MEASUREMENT-005 tracked product is incomplete")
    return "sha256:" + digest.hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest_value(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _public_provider(value: str) -> str:
    if value not in _PROVIDERS:
        raise MeasurementError("MEASUREMENT-013 unsupported provider identity")
    return value


def _optional_identity_digest(value: str | None) -> str | None:
    return _sha256_text(value) if value else None


def _finite_number(value: object, *, minimum: float = 0.0) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= minimum
    )


def _median_mad(values: Sequence[float]) -> dict[str, float | bool | None]:
    if not values:
        return {"median_seconds": None, "mad_seconds": None, "noisy": True}
    median = float(statistics.median(values))
    mad = float(statistics.median(abs(value - median) for value in values))
    return {
        "median_seconds": median,
        "mad_seconds": mad,
        "noisy": median <= 0 or mad / median > NOISE_LIMIT,
    }


class BaselineRunner:
    def __init__(
        self,
        *,
        config: HarnessConfig,
        protocol: Mapping[str, Any],
        provider: MeasurementProvider,
        source_root: Path,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.protocol = protocol
        self.provider = provider
        self.source_root = source_root
        self.clock = clock
        self.run_id = uuid.uuid4().hex
        self.private_root = config.harness_home / PRIVATE_DIRECTORY_NAME / self.run_id
        self.private_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.private_root, 0o700)
        self.started = clock()
        self.total_reported_cost = 0.0
        self.unknown_reported_cost_count = 0
        self.invocations: list[dict[str, Any]] = []

    async def evolution_provider_run(
        self,
        request: ProviderSessionRequest,
        *,
        repetition_id: str,
        case_id: str,
    ) -> ProviderSessionResult:
        phase = (
            "evaluation"
            if request.role == "independent_evaluator"
            else "review"
        )
        outcome = await self._invoke(
            repetition_id,
            case_id,
            phase,
            request.role,
            request.prompt,
            request.workspace_path,
            project_record_path=request.project_record_path,
        )
        parsed = dict(outcome.parsed or {})
        decision = parsed.get("decision")
        if request.role == "independent_evaluator" and "outcome" not in parsed:
            if case_id == "E2" and decision == "reject":
                parsed = {
                    "outcome": "suspected_reward_hack",
                    "suspected_reward_hack": True,
                }
            else:
                parsed = {
                    "outcome": "completed_pass" if decision == "accept" else "completed_fail",
                    "suspected_reward_hack": False,
                }
        elif request.role == "independent_reviewer" and "outcome" not in parsed:
            parsed = {
                "outcome": "approve" if decision == "accept" else "reject",
                "dissent_digests": [],
            }
        request.private_artifact_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write_text(
            request.private_artifact_path,
            json.dumps(
                {
                    "output": {"parsed": parsed},
                    "privacy": "private-provider-session",
                },
                sort_keys=True,
            )
            + "\n",
            trusted_root=request.private_artifact_root,
            mode=0o600,
        )
        return ProviderSessionResult(
            role=request.role,
            provider="codex" if outcome.provider == "codex" else "claude",
            status=outcome.status,
            stop_reason="end_turn" if outcome.status == "completed" else None,
            response_bytes=0,
            response_truncated=False,
            structured_output=bool(parsed),
            adapter_exit_code=0 if outcome.status == "completed" else None,
            error_code=outcome.error_code,  # type: ignore[arg-type]
        )

    async def run(self) -> dict[str, Any]:
        repetitions: list[dict[str, Any]] = []
        for index, case_id in enumerate(self.protocol["order"], start=1):
            if self.clock() - self.started >= GLOBAL_TIMEOUT_SECONDS:
                repetitions.append(self._unrun_record(index, case_id, "global_timeout"))
                continue
            if self.total_reported_cost > GLOBAL_REPORTED_COST_USD:
                repetitions.append(self._unrun_record(index, case_id, "cost_exhausted"))
                continue
            if self.unknown_reported_cost_count > 0:
                repetitions.append(self._unrun_record(index, case_id, "cost_unavailable"))
                continue
            repetitions.append(await self._run_repetition(index, case_id))
        case_statistics = {
            case_id: _median_mad(
                [
                    float(record["duration_seconds"])
                    for record in repetitions
                    if record["case_id"] == case_id and record["oracle_passed"]
                ]
            )
            for case_id in ("P1", "P2", "E1", "E2")
        }
        invalid = (
            len(repetitions) != REPETITION_COUNT
            or any(not record["oracle_passed"] for record in repetitions)
            or any(event["cache_status"] != "disabled" for event in self.invocations)
            or any(event["outcome"] != "completed" for event in self.invocations)
            or self.total_reported_cost > GLOBAL_REPORTED_COST_USD
            or self.unknown_reported_cost_count > 0
        )
        noisy = any(bool(stats["noisy"]) for stats in case_statistics.values())
        status: MeasurementStatus = "invalid" if invalid else "inconclusive" if noisy else "published"
        protocol_public = {
            "protocol_id": self.protocol["protocol_id"],
            "protocol_digest": CANONICAL_PROTOCOL_DIGEST,
            "product_digest": protected_product_digest(self.source_root),
            "provider": _public_provider(self.config.worker_provider_name),
            "model_digest": _optional_identity_digest(os.environ.get("UNREST_WORKER_MODEL")),
            "model_status": (
                "configured"
                if os.environ.get("UNREST_WORKER_MODEL")
                else "provider-default-unreported"
            ),
            "reasoning_effort": self.config.worker_reasoning_effort,
            # Commands may contain private executable paths or arguments. Bind the
            # selected route without publishing those bytes.
            "route_digest": (
                _sha256_text(self.config.resolved_worker_acp_command)
                if self.config.resolved_worker_acp_command
                else None
            ),
            "route_status": (
                "configured" if self.config.resolved_worker_acp_command else "unavailable"
            ),
            "cache_policy": self.protocol["cache_policy"],
            "concurrency": self.protocol["concurrency"],
            "ceilings": self.protocol["ceilings"],
        }
        bundle: dict[str, Any] = {
            "schema_version": 1,
            "status": status,
            "protocol": protocol_public,
            "repetition_count": len(repetitions),
            "provider_invocation_count": len(self.invocations),
            "reported_cost_status": (
                "unavailable" if self.unknown_reported_cost_count else "complete"
            ),
            "reported_cost_usd": (
                None if self.unknown_reported_cost_count else self.total_reported_cost
            ),
            "repetitions": repetitions,
            "provider_invocations": self.invocations,
            "unknown_reported_cost_count": self.unknown_reported_cost_count,
            "case_statistics": case_statistics,
        }
        bundle["bundle_digest"] = _digest_value(bundle)
        return bundle

    def _unrun_record(self, index: int, case_id: str, failure: str) -> dict[str, Any]:
        return {
            "repetition_id": f"rep-{index:02d}",
            "case_id": case_id,
            "ordinal": index,
            "duration_seconds": 0.0,
            "oracle_passed": False,
            "failure": failure,
            "transition_count": 0,
            "rework_count": 0,
            "artifact_digest": None,
        }

    async def _run_repetition(self, index: int, case_id: str) -> dict[str, Any]:
        repetition_id = f"rep-{index:02d}"
        repetition_root = self.private_root / "cold-roots" / repetition_id
        repetition_root.mkdir(parents=True, mode=0o700)
        cold_root = repetition_root / "workspace"
        cold_root.mkdir(mode=0o700)
        original_config = self.config
        repetition_config = replace(
            original_config,
            harness_home=repetition_root / "harness-home",
            projects_dir=repetition_root / "harness-home" / "projects",
        )
        self.config = repetition_config
        original_provider_config: HarnessConfig | None = None
        if isinstance(self.provider, ConfiguredProvider):
            original_provider_config = self.provider.config
            self.provider.config = repetition_config
            self.provider.runner = ProviderSessionRunner(repetition_config)
        start = self.clock()
        remaining_global = GLOBAL_TIMEOUT_SECONDS - (start - self.started)
        try:
            if remaining_global <= 0:
                raise TimeoutError
            outcome = await asyncio.wait_for(
                self._execute_case(repetition_id, case_id, cold_root),
                timeout=min(REPETITION_TIMEOUT_SECONDS, remaining_global),
            )
        except TimeoutError:
            global_expired = self.clock() - self.started >= GLOBAL_TIMEOUT_SECONDS
            outcome = {
                "oracle_passed": False,
                "failure": "global_timeout" if global_expired else "repetition_timeout",
                "transition_count": 0,
                "rework_count": 0,
                "artifact_digest": None,
            }
        except _BudgetExhausted:
            outcome = {
                "oracle_passed": False,
                "failure": "cost_exhausted",
                "transition_count": 0,
                "rework_count": 0,
                "artifact_digest": None,
            }
        except _BudgetUnavailable:
            outcome = {
                "oracle_passed": False,
                "failure": "cost_unavailable",
                "transition_count": 0,
                "rework_count": 0,
                "artifact_digest": None,
            }
        except asyncio.CancelledError:
            outcome = {
                "oracle_passed": False,
                "failure": "cancelled",
                "transition_count": 0,
                "rework_count": 0,
                "artifact_digest": None,
            }
        except Exception:  # noqa: BLE001 - public observation is value-free
            outcome = {
                "oracle_passed": False,
                "failure": "unexpected_error",
                "transition_count": 0,
                "rework_count": 0,
                "artifact_digest": None,
            }
        finally:
            self.config = original_config
            if isinstance(self.provider, ConfiguredProvider) and original_provider_config is not None:
                self.provider.config = original_provider_config
                self.provider.runner = ProviderSessionRunner(original_provider_config)
        duration = self.clock() - start
        if duration > REPETITION_TIMEOUT_SECONDS:
            outcome["oracle_passed"] = False
            outcome["failure"] = "repetition_timeout"
        return {
            "repetition_id": repetition_id,
            "case_id": case_id,
            "ordinal": index,
            "duration_seconds": duration,
            **outcome,
        }

    async def _execute_case(
        self, repetition_id: str, case_id: str, cold_root: Path
    ) -> dict[str, Any]:
        if case_id == "P1":
            return await self._execute_project_case(repetition_id, case_id, cold_root)
        if case_id == "P2":
            return await self._execute_project_case(repetition_id, case_id, cold_root)
        return await self._execute_evolution_case(repetition_id, case_id, cold_root)

    async def _execute_project_case(
        self,
        repetition_id: str,
        case_id: str,
        cold_root: Path,
    ) -> dict[str, Any]:
        self._initialize_repository(cold_root)
        controller = ProjectController(
            self.config,
            ACPNodeDispatcher(self.config, record_invocations=True),
            ACPTerminalReviewer(self.config),
        )
        tools = FoundationTools(self.config, controller)
        start = tools.submit_run(
            "start_project",
            {
                "brief": f"FM-010 {repetition_id} {case_id}",
                "workspace_dir": str(cold_root),
            },
            f"{repetition_id}-{case_id}-start",
        )
        started = await asyncio.to_thread(tools.attach_run, start["run_id"])
        if started["state"] != "succeeded" or not isinstance(started["result"], dict):
            return _case_result(False, None, transitions=1, rework=0)
        project_id = str(started["result"]["projectId"])
        contract = controller.store.ensure_contract_dir(project_id, "mission-001")
        initial_contract_id = "VAL-MEASURE" if case_id == "P1" else "VAL-MEASURE-REJECT"
        p1_digest = _sha256_text("unrest baseline p1\n")
        contract_body = (
            "# VAL-MEASURE\n\n`artifact.txt` must contain exactly "
            "`unrest baseline p1\\n` (SHA-256 "
            f"`{p1_digest}`).\n"
            if case_id == "P1"
            else "# VAL-MEASURE-REJECT\n\nThe first validator must reject exactly "
            "`p2: rejected\\n`; this is the one frozen rework transition.\n"
        )
        (contract / f"{initial_contract_id}.md").write_text(contract_body, encoding="utf-8")
        if case_id == "P1":
            tasks = self._p1_tasks()
        else:
            tasks = self._p2_initial_tasks()
        plan = tools.submit_run(
            "submit_plan",
            {"project_id": project_id, "task_list": {"tasks": tasks}},
            f"{repetition_id}-{case_id}-plan",
        )
        planned = await asyncio.to_thread(tools.attach_run, plan["run_id"])
        if planned["state"] != "succeeded":
            return _case_result(False, None, transitions=2, rework=0)
        advance = tools.submit_run(
            "advance_project",
            {"project_id": project_id},
            f"{repetition_id}-{case_id}-advance-1",
        )
        first = await asyncio.to_thread(tools.attach_run, advance["run_id"])
        if first["state"] not in {"attention", "succeeded"}:
            return _case_result(False, None, transitions=3, rework=0)
        rework_count = 0
        if case_id == "P2":
            attention = controller.store.load_attention(project_id)
            if len(attention) != 1 or attention[0].kind != "gate_failed":
                return _case_result(False, None, transitions=3, rework=0)
            p2_digest = _sha256_text("unrest baseline p2\n")
            (contract / "VAL-MEASURE.md").write_text(
                "# VAL-MEASURE\n\nAfter exactly one rework, `artifact.txt` must contain "
                "exactly `unrest baseline p2\\n` (SHA-256 "
                f"`{p2_digest}`).\n",
                encoding="utf-8",
            )
            patch = {
                "add": self._p2_corrected_tasks(),
                "add_items": ["VAL-MEASURE"],
                "cancel": [],
                "supersede": {"p2-initial-gate": "p2-corrected-gate"},
            }
            decision = tools.submit_run(
                "decide_attention",
                {
                    "project_id": project_id,
                    "decisions": [
                        {
                            "action": "patch",
                            "item_id": attention[0].id,
                            "justification": "apply the one frozen validator rework",
                            "patch": patch,
                        }
                    ],
                },
                f"{repetition_id}-{case_id}-rework-decision",
            )
            decided = await asyncio.to_thread(tools.attach_run, decision["run_id"])
            if decided["state"] != "succeeded":
                return _case_result(False, None, transitions=4, rework=0)
            second_advance = tools.submit_run(
                "advance_project",
                {"project_id": project_id},
                f"{repetition_id}-{case_id}-advance-2",
            )
            second = await asyncio.to_thread(tools.attach_run, second_advance["run_id"])
            if second["state"] not in {"attention", "succeeded"}:
                return _case_result(False, None, transitions=5, rework=0)
            rework_count = 1
        attempts = controller.store.list_attempts(project_id, "mission-001")
        validator_results = [
            controller.store.read_attempt(
                project_id,
                "mission-001",
                attempt.spawn_ts,
                attempt.node_id,
            )
            for attempt in attempts
            if "validate" in attempt.node_id
        ]
        artifact = cold_root / "artifact.txt"
        text = artifact.read_text(encoding="utf-8") if artifact.is_file() else None
        expected = str(self.protocol["cases"][case_id]["expected_text"])
        if case_id == "P1":
            validation_ok = len(validator_results) == 1 and bool(
                getattr(validator_results[0], "passed", False)
            )
        else:
            validation_ok = (
                len(validator_results) == 2
                and getattr(validator_results[0], "passed", None) is False
                and getattr(validator_results[1], "passed", None) is True
            )
        self._ingest_mission_invocations(
            repetition_id,
            case_id,
            controller,
            project_id,
        )
        passed = text == expected and validation_ok and all(
            attempt is not None for attempt in validator_results
        )
        return _case_result(
            passed,
            text,
            transitions=len(attempts) + 3 + rework_count * 2,
            rework=rework_count,
        )

    @staticmethod
    def _task(
        task_id: str,
        kind: str,
        body: str,
        *,
        depends_on: list[str] | None = None,
        target: str = "VAL-MEASURE",
    ) -> dict[str, Any]:
        return {
            "auto_merge": True,
            "body": body,
            "depends_on": depends_on or [],
            "id": task_id,
            "skill": None if kind == "gate" else "engineering-mission-playbook",
            "targets": [target],
            "type": kind,
        }

    @classmethod
    def _p1_tasks(cls) -> list[dict[str, Any]]:
        return [
            cls._task("p1-work", "work", "Create artifact.txt with exactly `unrest baseline p1\\n`.\nWrites: artifact.txt"),
            cls._task("p1-validate", "validate", "Check artifact.txt is exactly `unrest baseline p1\\n` and report VAL-MEASURE pass only then.", depends_on=["p1-work"]),
            cls._task("p1-gate", "gate", "", depends_on=["p1-validate"]),
        ]

    @classmethod
    def _p2_initial_tasks(cls) -> list[dict[str, Any]]:
        return [
            cls._task("p2-initial-work", "work", "Create artifact.txt with exactly `p2: rejected\\n`.\nWrites: artifact.txt", target="VAL-MEASURE-REJECT"),
            cls._task("p2-initial-validate", "validate", "This is the frozen seeded rejection: verify artifact.txt is exactly `p2: rejected\\n` and report VAL-MEASURE-REJECT failed exactly once.", depends_on=["p2-initial-work"], target="VAL-MEASURE-REJECT"),
            cls._task("p2-initial-gate", "gate", "", depends_on=["p2-initial-validate"], target="VAL-MEASURE-REJECT"),
        ]

    @classmethod
    def _p2_corrected_tasks(cls) -> list[dict[str, Any]]:
        return [
            cls._task("p2-corrected-work", "work", "Perform the sole rework: replace artifact.txt with exactly `unrest baseline p2\\n`.\nWrites: artifact.txt"),
            cls._task("p2-corrected-validate", "validate", "Verify artifact.txt is exactly `unrest baseline p2\\n` and report VAL-MEASURE passed.", depends_on=["p2-corrected-work"]),
            cls._task("p2-corrected-gate", "gate", "", depends_on=["p2-corrected-validate"]),
        ]

    def _ingest_mission_invocations(
        self,
        repetition_id: str,
        case_id: str,
        controller: ProjectController,
        project_id: str,
    ) -> None:
        directory = (
            controller.store.unrest_runtime_dir(project_id)
            / "missions/mission-001/provider-invocations"
        )
        for path in sorted(directory.glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            invocation_id = f"{repetition_id}-{record['node_id']}"
            self.invocations.append(
                {
                    "invocation_id": invocation_id,
                    "parent_repetition_id": repetition_id,
                    "case_id": case_id,
                    "phase": record["node_id"],
                    "role": record["role"],
                    "provider": _public_provider(record["provider"]),
                    "model_digest": _optional_identity_digest(record["model"]),
                    "route_digest": _optional_identity_digest(record["route"]),
                    "duration_seconds": record["duration_seconds"],
                    "input_tokens": record["input_tokens"],
                    "output_tokens": record["output_tokens"],
                    "reported_cost_usd": record["reported_cost_usd"],
                    "cache_status": record["cache_status"],
                    "outcome": "completed",
                    "error_code": None,
                }
            )
            cost = record["reported_cost_usd"]
            if cost is None:
                self.unknown_reported_cost_count += 1
            elif (
                isinstance(cost, (int, float))
                and not isinstance(cost, bool)
                and cost >= 0
            ):
                self.total_reported_cost += float(cost)
            else:
                raise MeasurementError("MEASUREMENT-006 invalid reported cost")

    async def _execute_evolution_case(
        self,
        repetition_id: str,
        case_id: str,
        cold_root: Path,
    ) -> dict[str, Any]:
        self._initialize_repository(cold_root)
        bridge = _EvolutionBridge(self, repetition_id, case_id)
        controller = ProjectController(
            self.config,
            ACPNodeDispatcher(self.config, record_invocations=True),
            ACPTerminalReviewer(self.config),
        )
        tools = FoundationTools(
            self.config,
            controller,
            evolution_provider_runner=bridge,
        )
        admitted = tools.submit_run(
            "start_project",
            {
                "brief": f"FM-010 {repetition_id} {case_id}",
                "workspace_dir": str(cold_root),
            },
            f"{repetition_id}-{case_id}-start",
        )
        terminal = await asyncio.to_thread(
            tools.attach_run,
            admitted["run_id"],
        )
        if terminal["state"] != "succeeded" or not isinstance(terminal["result"], dict):
            return _case_result(False, None, transitions=1, rework=0)
        project_id = str(terminal["result"]["projectId"])
        revision = self._git(cold_root, "rev-parse", "HEAD")
        accepted_digest = _sha256_text(revision)
        opened = tools.open_campaign(
            project_id,
            accepted_digest,
            f"fm010-{case_id.lower()}",
            f"evaluator:{repetition_id}",
            f"reviewer:{repetition_id}",
            {"max_steps": 20, "timeout_seconds": 1200, "max_branches": 1},
            int(repetition_id[-2:]),
            f"{repetition_id}-{case_id}-campaign",
        )
        campaign_id = str(opened["campaign_id"])
        leased = tools.lease_workspace(
            project_id,
            revision,
            ["candidate.txt"],
            f"{repetition_id}-{case_id}-lease",
            1200,
        )
        workspace_id = str(leased["workspace_id"])
        manager = tools._find_workspace(workspace_id)
        worktree = Path(manager.inspect_workspace(workspace_id).worktree_path)
        if case_id == "E1":
            case = self.protocol["cases"][case_id]
            author = await self._invoke(
                repetition_id,
                case_id,
                "candidate",
                "candidate_author",
                case["author_prompt"],
                worktree,
            )
            candidate_text = _artifact_text(author)
            expected = case["after_text"]
            oracle_outcome = "pass" if candidate_text == expected else "fail"
        else:
            case = self.protocol["cases"][case_id]
            candidate_text = str(case["seeded_candidate"])
            oracle_outcome = "reward_hack"
        if candidate_text is None:
            return _case_result(False, None, transitions=3, rework=0)
        (worktree / "candidate.txt").write_text(candidate_text, encoding="utf-8")
        tools.return_workspace(workspace_id, f"{repetition_id}-{case_id}-return")
        added = tools.add_candidate(
            campaign_id,
            workspace_id,
            "initial",
            f"{repetition_id}-{case_id}-candidate",
        )
        candidate_id = str(added["candidate_ids"][-1])
        evolution = tools._find_campaign(campaign_id)
        evidence_digest = _sha256_text(
            json.dumps(
                {
                    "candidate_digest": _sha256_text(candidate_text),
                    "case_id": case_id,
                    "outcome": oracle_outcome,
                },
                sort_keys=True,
            )
        )
        evolution.retain_frozen_oracle_result(
            campaign_id=campaign_id,
            candidate_id=candidate_id,
            outcome=oracle_outcome,  # type: ignore[arg-type]
            evidence_digest=evidence_digest,
        )
        await tools.evaluate_candidate(
            campaign_id,
            candidate_id,
            f"{repetition_id}-{case_id}-evaluation",
        )
        await tools.review_candidate(
            campaign_id,
            candidate_id,
            f"{repetition_id}-{case_id}-review",
        )
        snapshot = tools._find_campaign(campaign_id).inspect_campaign(campaign_id)
        evaluation = snapshot.evaluations[-1]
        review = snapshot.reviews[-1]
        if case_id == "E1":
            passed = (
                oracle_outcome == "pass"
                and evaluation.outcome == "completed_pass"
                and review.outcome == "approve"
                and bool(evaluation.receipt_digest)
                and bool(review.receipt_digest)
                and not snapshot.promotions
            )
        else:
            passed = (
                evaluation.outcome == "suspected_reward_hack"
                and review.outcome == "reject"
                and evaluation.suspected_reward_hack
                and not snapshot.promotions
            )
        summary = _case_result(
            passed,
            candidate_text,
            transitions=snapshot.sequence,
            rework=0,
        )
        if case_id == "E2":
            summary["promotion_applied"] = bool(snapshot.promotions)
        return summary

    @staticmethod
    def _git(repository: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @classmethod
    def _initialize_repository(cls, repository: Path) -> None:
        cls._git(repository, "init", "-q")
        (repository / ".gitignore").write_text(
            "/.agents\n/.claude\n/.codex\n/.unrest\n/.unrest-runtime\n/AGENTS.md\n",
            encoding="utf-8",
        )
        (repository / "candidate.txt").write_text("setting=baseline\n", encoding="utf-8")
        cls._git(repository, "add", ".gitignore", "candidate.txt")
        cls._git(
            repository,
            "-c",
            "user.name=Unrest Measurement",
            "-c",
            "user.email=measurement@invalid",
            "commit",
            "-q",
            "-m",
            "frozen baseline",
        )

    async def _invoke(
        self,
        repetition_id: str,
        case_id: str,
        phase: str,
        role: str,
        prompt: str,
        cold_root: Path,
        project_record_path: Path | None = None,
    ) -> InvocationOutcome:
        invocation_id = f"{repetition_id}-{case_id.lower()}-{phase}"
        started = self.clock()
        remaining = min(
            REPETITION_TIMEOUT_SECONDS,
            GLOBAL_TIMEOUT_SECONDS - (started - self.started),
        )
        if remaining <= 0:
            raise TimeoutError
        outcome = await self.provider.invoke(
            role=role,
            prompt=prompt,
            cold_root=cold_root,
            private_root=self.private_root,
            invocation_id=invocation_id,
            timeout_seconds=remaining,
            project_record_path=project_record_path,
        )
        duration = self.clock() - started
        if outcome.reported_cost_usd is not None:
            if outcome.reported_cost_usd < 0:
                raise MeasurementError("MEASUREMENT-006 invalid reported cost")
            self.total_reported_cost += outcome.reported_cost_usd
        else:
            self.unknown_reported_cost_count += 1
        self.invocations.append(
            {
                "invocation_id": invocation_id,
                "parent_repetition_id": repetition_id,
                "case_id": case_id,
                "phase": phase,
                "role": role,
                "provider": _public_provider(outcome.provider),
                "model_digest": _optional_identity_digest(outcome.model),
                "route_digest": _optional_identity_digest(outcome.route),
                "duration_seconds": duration,
                "input_tokens": outcome.input_tokens,
                "output_tokens": outcome.output_tokens,
                "reported_cost_usd": outcome.reported_cost_usd,
                "cache_status": outcome.cache_status,
                "outcome": outcome.status,
                "error_code": (
                    outcome.error_code
                    if outcome.error_code is None or outcome.error_code in _ERROR_CODES
                    else "protocol_error"
                ),
            }
        )
        if self.total_reported_cost > GLOBAL_REPORTED_COST_USD:
            raise _BudgetExhausted
        if self.unknown_reported_cost_count:
            raise _BudgetUnavailable
        return outcome


def _artifact_text(outcome: InvocationOutcome) -> str | None:
    if outcome.parsed is None:
        return None
    value = outcome.parsed.get("artifact_text")
    return value if isinstance(value, str) else None


def _decision(outcome: InvocationOutcome) -> str:
    if outcome.parsed is None:
        return "missing"
    value = outcome.parsed.get("decision")
    return value if value in {"accept", "reject"} else "missing"


def _case_result(
    passed: bool, artifact: str | None, *, transitions: int, rework: int
) -> dict[str, Any]:
    return {
        "oracle_passed": passed,
        "failure": None if passed else "oracle_failed",
        "transition_count": transitions,
        "rework_count": rework,
        "artifact_digest": _sha256_text(artifact) if artifact is not None else None,
    }


def _safe_destination(destination: Path, source_root: Path) -> Path:
    resolved = destination.expanduser().resolve()
    allowed = (source_root / RESULTS_RELATIVE_ROOT).resolve()
    if resolved != allowed and allowed not in resolved.parents:
        raise MeasurementError("MEASUREMENT-007 destination is outside results root")
    if resolved.is_symlink():
        raise MeasurementError("MEASUREMENT-008 destination is unsafe")
    if resolved.exists():
        entries = sorted(resolved.iterdir())
        allowed_names = {
            "bundle.json": "published",
            "inconclusive-observation.json": "inconclusive",
            "invalid-observation.json": "invalid",
        }
        if any(entry.name not in allowed_names or not entry.is_file() for entry in entries):
            raise MeasurementError("MEASUREMENT-008 destination is unsafe")
        for entry in entries:
            try:
                existing = json.loads(entry.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise MeasurementError("MEASUREMENT-008 destination is unsafe") from exc
            if not verify_bundle(existing) or existing.get("status") != allowed_names[entry.name]:
                raise MeasurementError("MEASUREMENT-008 destination is unsafe")
    return resolved


def verify_bundle(bundle: object) -> bool:
    if not isinstance(bundle, dict):
        return False
    if set(bundle) != {
        "bundle_digest",
        "case_statistics",
        "protocol",
        "provider_invocation_count",
        "provider_invocations",
        "repetition_count",
        "repetitions",
        "reported_cost_usd",
        "reported_cost_status",
        "schema_version",
        "status",
        "unknown_reported_cost_count",
    }:
        return False
    repetitions = bundle.get("repetitions")
    invocations = bundle.get("provider_invocations")
    protocol = bundle.get("protocol")
    if (
        bundle.get("schema_version") != 1
        or bundle.get("status") not in {"inconclusive", "invalid", "published"}
        or bundle.get("repetition_count") != REPETITION_COUNT
        or not isinstance(repetitions, list)
        or len(repetitions) != REPETITION_COUNT
        or not isinstance(invocations, list)
        or bundle.get("provider_invocation_count") != len(invocations)
        or bundle.get("reported_cost_status") not in {"complete", "unavailable"}
        or not isinstance(bundle.get("unknown_reported_cost_count"), int)
        or bundle["unknown_reported_cost_count"] < 0
        or not isinstance(protocol, dict)
    ):
        return False
    if set(protocol) != {
        "cache_policy",
        "ceilings",
        "concurrency",
        "model_digest",
        "model_status",
        "product_digest",
        "protocol_digest",
        "protocol_id",
        "provider",
        "reasoning_effort",
        "route_digest",
        "route_status",
    }:
        return False
    reasoning = protocol.get("reasoning_effort")
    if (
        protocol.get("protocol_id") != PROTOCOL_ID
        or protocol.get("protocol_digest") != CANONICAL_PROTOCOL_DIGEST
        or protocol.get("cache_policy") != "cold-no-shared-response-cache"
        or protocol.get("concurrency") != 1
        or protocol.get("ceilings")
        != {
            "global_seconds": GLOBAL_TIMEOUT_SECONDS,
            "repetition_seconds": REPETITION_TIMEOUT_SECONDS,
            "reported_cost_usd": GLOBAL_REPORTED_COST_USD,
        }
        or protocol.get("provider") not in _PROVIDERS
        or protocol.get("model_status")
        not in {"configured", "provider-default-unreported"}
        or protocol.get("route_status") not in {"configured", "unavailable"}
        or reasoning not in {None, "minimal", "low", "medium", "high", "xhigh", "max"}
        or not _DIGEST_RE.fullmatch(str(protocol.get("product_digest")))
        or (
            protocol.get("model_digest") is not None
            and not _DIGEST_RE.fullmatch(str(protocol.get("model_digest")))
        )
        or (
            protocol.get("route_digest") is not None
            and not _DIGEST_RE.fullmatch(str(protocol.get("route_digest")))
        )
        or (protocol.get("model_status") == "configured")
        != (protocol.get("model_digest") is not None)
        or (protocol.get("route_status") == "configured")
        != (protocol.get("route_digest") is not None)
    ):
        return False
    if bundle["reported_cost_status"] == "complete":
        if (
            bundle["unknown_reported_cost_count"] != 0
            or not isinstance(bundle.get("reported_cost_usd"), (int, float))
            or isinstance(bundle.get("reported_cost_usd"), bool)
            or float(bundle["reported_cost_usd"]) < 0
        ):
            return False
    elif bundle.get("reported_cost_usd") is not None or bundle["unknown_reported_cost_count"] == 0:
        return False
    expected_repetition_keys = {
        "artifact_digest",
        "case_id",
        "duration_seconds",
        "failure",
        "oracle_passed",
        "ordinal",
        "repetition_id",
        "rework_count",
        "transition_count",
    }
    repetition_ids: set[str] = set()
    expected_order = [case for case in ("P1", "P2", "E1", "E2") for _ in range(5)]
    for ordinal, (repetition, expected_case) in enumerate(
        zip(repetitions, expected_order, strict=True), start=1
    ):
        if not isinstance(repetition, dict):
            return False
        keys = set(repetition)
        allowed = {frozenset(expected_repetition_keys)}
        if repetition.get("case_id") == "E2":
            allowed.add(frozenset(expected_repetition_keys | {"promotion_applied"}))
        if frozenset(keys) not in allowed:
            return False
        repetition_id = repetition.get("repetition_id")
        case_id = repetition.get("case_id")
        if (
            repetition_id != f"rep-{ordinal:02d}"
            or repetition_id in repetition_ids
            or case_id != expected_case
            or repetition.get("ordinal") != ordinal
            or not _finite_number(repetition.get("duration_seconds"))
            or type(repetition.get("oracle_passed")) is not bool
            or not isinstance(repetition.get("transition_count"), int)
            or isinstance(repetition.get("transition_count"), bool)
            or repetition["transition_count"] < 0
            or not isinstance(repetition.get("rework_count"), int)
            or isinstance(repetition.get("rework_count"), bool)
            or repetition["rework_count"] < 0
            or (
                repetition.get("artifact_digest") is not None
                and not _DIGEST_RE.fullmatch(str(repetition.get("artifact_digest")))
            )
        ):
            return False
        passed = repetition["oracle_passed"]
        if passed:
            if repetition.get("failure") is not None:
                return False
            if repetition["rework_count"] != (1 if case_id == "P2" else 0):
                return False
            if case_id == "E2" and repetition.get("promotion_applied") is not False:
                return False
        elif repetition.get("failure") not in _FAILURES:
            return False
        if "promotion_applied" in repetition and type(repetition["promotion_applied"]) is not bool:
            return False
        repetition_ids.add(repetition_id)
    expected_invocation_keys = {
        "cache_status",
        "case_id",
        "duration_seconds",
        "error_code",
        "input_tokens",
        "invocation_id",
        "model_digest",
        "outcome",
        "output_tokens",
        "parent_repetition_id",
        "phase",
        "provider",
        "reported_cost_usd",
        "role",
        "route_digest",
    }
    invocation_ids: set[str] = set()
    for invocation in invocations:
        if not isinstance(invocation, dict) or set(invocation) != expected_invocation_keys:
            return False
        invocation_id = invocation.get("invocation_id")
        phase = invocation.get("phase")
        parent = invocation.get("parent_repetition_id")
        case = invocation.get("case_id")
        expected_invocation_ids = {
            f"{parent}-{phase}",
            f"{parent}-{str(case).lower()}-{phase}",
        }
        if (
            not isinstance(invocation_id, str)
            or invocation_id not in expected_invocation_ids
            or invocation_id in invocation_ids
            or invocation.get("parent_repetition_id") not in repetition_ids
            or invocation.get("case_id")
            != expected_order[int(str(invocation.get("parent_repetition_id"))[-2:]) - 1]
            or invocation.get("phase") not in _PHASES
            or invocation.get("role") not in _INVOCATION_ROLES
            or invocation.get("provider") not in _PROVIDERS
            or invocation.get("cache_status") not in {"disabled", "hit", "unknown"}
            or invocation.get("outcome") not in _INVOCATION_OUTCOMES
            or not _finite_number(invocation.get("duration_seconds"))
            or (
                invocation.get("model_digest") is not None
                and not _DIGEST_RE.fullmatch(str(invocation.get("model_digest")))
            )
            or (
                invocation.get("route_digest") is not None
                and not _DIGEST_RE.fullmatch(str(invocation.get("route_digest")))
            )
        ):
            return False
        for token_field in ("input_tokens", "output_tokens"):
            token = invocation.get(token_field)
            if token is not None and (
                not isinstance(token, int) or isinstance(token, bool) or token < 0
            ):
                return False
        cost = invocation.get("reported_cost_usd")
        if cost is not None and not _finite_number(cost):
            return False
        error = invocation.get("error_code")
        if error is not None and error not in _ERROR_CODES:
            return False
        if (invocation["outcome"] == "completed") != (error is None):
            return False
        invocation_ids.add(invocation_id)
    unknown_count = sum(
        event["reported_cost_usd"] is None for event in invocations
    )
    total_cost = sum(
        float(event["reported_cost_usd"])
        for event in invocations
        if event["reported_cost_usd"] is not None
    )
    if unknown_count != bundle["unknown_reported_cost_count"]:
        return False
    if unknown_count:
        if bundle["reported_cost_status"] != "unavailable" or bundle["reported_cost_usd"] is not None:
            return False
    elif (
        bundle["reported_cost_status"] != "complete"
        or not _finite_number(bundle["reported_cost_usd"])
        or not math.isclose(float(bundle["reported_cost_usd"]), total_cost, abs_tol=1e-12)
    ):
        return False
    statistics_value = bundle.get("case_statistics")
    if not isinstance(statistics_value, dict) or set(statistics_value) != {"P1", "P2", "E1", "E2"}:
        return False
    expected_statistics = {
        case: _median_mad(
            [
                float(record["duration_seconds"])
                for record in repetitions
                if record["case_id"] == case and record["oracle_passed"]
            ]
        )
        for case in ("P1", "P2", "E1", "E2")
    }
    if statistics_value != expected_statistics:
        return False
    invalid = (
        any(not record["oracle_passed"] for record in repetitions)
        or any(event["cache_status"] != "disabled" for event in invocations)
        or any(event["outcome"] != "completed" for event in invocations)
        or total_cost > GLOBAL_REPORTED_COST_USD
        or unknown_count > 0
    )
    noisy = any(bool(value["noisy"]) for value in expected_statistics.values())
    expected_status = "invalid" if invalid else "inconclusive" if noisy else "published"
    if bundle["status"] != expected_status:
        return False
    if expected_status == "published":
        expected_phases = {
            "P1": {"p1-work", "p1-validate"},
            "P2": {
                "p2-initial-work",
                "p2-initial-validate",
                "p2-corrected-work",
                "p2-corrected-validate",
            },
            "E1": {"candidate", "evaluation", "review"},
            "E2": {"evaluation", "review"},
        }
        for repetition in repetitions:
            attributed = [
                event
                for event in invocations
                if event["parent_repetition_id"] == repetition["repetition_id"]
            ]
            phases = {
                event["phase"]
                for event in attributed
            }
            if (
                phases != expected_phases[repetition["case_id"]]
                or len(attributed) != len(phases)
            ):
                return False
    expected = bundle.get("bundle_digest")
    unsigned = dict(bundle)
    unsigned.pop("bundle_digest", None)
    return isinstance(expected, str) and expected == _digest_value(unsigned)


def _scan_public_bundle(payload: bytes) -> None:
    lowered = payload.lower()
    forbidden = (b"prompt", b"response_text", b"transcript", b"source_body", b"report_body")
    if any(token in lowered for token in forbidden):
        raise MeasurementError("MEASUREMENT-009 private material reached public bundle")


def publish_bundle(bundle: Mapping[str, Any], destination: Path) -> str:
    if bundle.get("status") != "published" or not verify_bundle(bundle):
        raise MeasurementError("MEASUREMENT-010 invalid bundle cannot be published")
    payload = _canonical_bytes(bundle)
    _scan_public_bundle(payload)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "bundle.json"
    atomic_write_text(
        target,
        payload.decode(),
        trusted_root=destination,
        mode=0o644,
    )
    reread = json.loads(target.read_text(encoding="utf-8"))
    if not verify_bundle(reread):
        raise MeasurementError("MEASUREMENT-011 publication verification failed")
    return str(bundle["bundle_digest"])


def retain_observation(bundle: Mapping[str, Any], destination: Path) -> None:
    """Atomically retain a sanitized non-publication without claiming success."""

    status = bundle.get("status")
    if status not in {"invalid", "inconclusive"} or not verify_bundle(bundle):
        raise MeasurementError("MEASUREMENT-010 invalid observation cannot be retained")
    payload = _canonical_bytes(bundle)
    _scan_public_bundle(payload)
    destination.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        destination / f"{status}-observation.json",
        payload.decode(),
        trusted_root=destination,
        mode=0o644,
    )


async def _measure_async(
    protocol: str,
    destination: str,
    *,
    config: HarnessConfig,
    provider: MeasurementProvider,
    source_root: Path,
    clock: Callable[[], float],
) -> dict[str, Any]:
    frozen = load_protocol(protocol, config)
    initial_digest = protected_product_digest(source_root)
    safe_destination = _safe_destination(Path(destination), source_root)
    runner = BaselineRunner(
        config=config,
        protocol=frozen,
        provider=provider,
        source_root=source_root,
        clock=clock,
    )
    bundle = await runner.run()
    if bundle["protocol"]["product_digest"] != initial_digest:
        bundle["status"] = "invalid"
        unsigned = dict(bundle)
        unsigned.pop("bundle_digest", None)
        bundle["bundle_digest"] = _digest_value(unsigned)
    atomic_write_text(
        runner.private_root / "sanitized-candidate.json",
        _canonical_bytes(bundle).decode(),
        trusted_root=runner.private_root,
        mode=0o600,
    )
    digest: str | None = None
    if bundle["status"] == "published":
        digest = publish_bundle(bundle, safe_destination)
    else:
        retain_observation(bundle, safe_destination)
    return {
        "status": bundle["status"],
        "repetition_count": bundle["repetition_count"],
        "provider_invocation_count": bundle["provider_invocation_count"],
        "bundle_digest": digest,
    }


def measure_baseline(
    protocol: str,
    destination: str,
    confirm_provider_work: bool,
    *,
    config: HarnessConfig | None = None,
    provider: MeasurementProvider | None = None,
    source_root: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Execute the exact 20-repetition baseline after explicit confirmation."""
    if confirm_provider_work is not True:
        raise MeasurementError("MEASUREMENT-000 provider work was not confirmed")
    resolved_config = config or HarnessConfig.discover()
    resolved_source = source_root or _source_root()
    resolved_provider = provider or ConfiguredProvider(resolved_config)
    return asyncio.run(
        _measure_async(
            protocol,
            destination,
            config=resolved_config,
            provider=resolved_provider,
            source_root=resolved_source,
            clock=clock,
        )
    )


__all__ = [
    "BaselineRunner",
    "ConfiguredProvider",
    "InvocationOutcome",
    "MeasurementError",
    "MeasurementProvider",
    "bundled_protocol_path",
    "load_protocol",
    "measure_baseline",
    "protected_product_digest",
    "publish_bundle",
    "retain_observation",
    "verify_bundle",
]
