"""Deterministic Batch 0 characterization artifacts.

This module deliberately records the approved legacy baseline without making
known defects part of the future runtime contract. It uses only in-process
dispatchers and reviewers; no provider command, credential, or network access
is required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Literal
from unittest.mock import patch

import yaml
from pydantic import ValidationError

from .acp_runner import _acp_subprocess_env
from .config import HarnessConfig
from .controller import ProjectController
from .coordinator import MissionCoordinator
from .dispatcher import MockDispatcher, MockTerminalReviewer
from .models import (
    AttentionItemInternal,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from .providers import get_provider
from .storage import ProjectStore

BASE_SHA = "9ebed0a9007289d419dae476f0dd582e8a21a550"
FROZEN_ISO = "2026-07-21T15:00:00Z"
FROZEN_FILESAFE = "2026-07-21T15-00-00Z"
MISSION_ID = "mission-001"
CLASSIFICATIONS = ("observed_legacy", "intended", "known_defect")
KICKOFF_RECORD = {
    "batch": 0,
    "base_sha": BASE_SHA,
    "feature_flags_at_start": {
        "UNREST_MAX_PARALLEL_NODES": "unset; effective baseline default 4",
        "role_capability_policy": "absent",
        "unsafe_development_override": "absent",
    },
    "protected_reviewers": [
        "security-maintainer",
        "release-maintainer",
    ],
    "evaluation_tier": [
        "full-repository",
        "installed-wheel",
        "real-cli-mcp-acp",
        "concurrency",
        "security",
    ],
}
GENERATED_FILENAMES = (
    "fixtures/attempt-kind-heuristic.json",
    "fixtures/attempts-decisions-terminal-storage.json",
    "fixtures/blocking-scheduler-selection.json",
    "fixtures/concurrent-writers.json",
    "fixtures/gate-aggregation.json",
    "fixtures/implicit-unrestricted-defaults.json",
    "fixtures/resume-reconciliation.json",
    "fixtures/storage-state.json",
    "fixtures/terminal-review-closure.json",
    "fixtures/typed-handoffs-and-task-list.json",
    "manifest.yaml",
    "report.json",
)

Fixture = dict[str, Any]
FixtureProducer = Callable[[], Fixture]


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture(
    fixture_id: str,
    classification: Literal["observed_legacy", "intended", "known_defect"],
    description: str,
    observations: object,
) -> Fixture:
    return {
        "schema_version": 1,
        "fixture_id": fixture_id,
        "classification": classification,
        "source_commit": BASE_SHA,
        "description": description,
        "observations": observations,
    }


@contextmanager
def _frozen_runtime() -> Iterator[None]:
    token_counter = iter(f"{number:06x}" for number in range(1, 1000))
    with ExitStack() as stack:
        stack.enter_context(
            patch("unrest_harness.storage.utc_now_iso", return_value=FROZEN_ISO)
        )
        stack.enter_context(
            patch(
                "unrest_harness.coordinator.utc_now_filesafe",
                return_value=FROZEN_FILESAFE,
            )
        )
        stack.enter_context(
            patch(
                "unrest_harness.attention.secrets.token_hex",
                side_effect=lambda _size: next(token_counter),
            )
        )
        yield


@contextmanager
def _temporary_root() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="unrest-baseline-") as raw:
        yield Path(raw)


def _config(root: Path, *, max_parallel_nodes: int = 1) -> HarnessConfig:
    harness_home = root / "harness-home"
    harness_home.mkdir(parents=True, exist_ok=True)
    bundled = Path(__file__).resolve().parent / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=max_parallel_nodes,
    )


def _new_store(
    root: Path,
    *,
    project_id: str,
    max_parallel_nodes: int = 1,
) -> tuple[ProjectStore, Path]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    store = ProjectStore(_config(root, max_parallel_nodes=max_parallel_nodes))
    record = store.create_project(
        "Deterministic Batch 0 characterization.",
        workspace,
        project_id=project_id,
    )
    record.current_mission_id = MISSION_ID
    store.save_project(record)
    return store, workspace


def _work_task(
    task_id: str,
    target: str,
    *,
    depends_on: list[str] | None = None,
) -> Task:
    return Task(
        id=task_id,
        type="work",
        body=f"Implement {target}.",
        targets=[target],
        skill="baseline-worker",
        depends_on=depends_on or [],
    )


def _validate_task(
    task_id: str,
    target: str,
    *,
    depends_on: list[str] | None = None,
) -> Task:
    return Task(
        id=task_id,
        type="validate",
        body=f"Validate {target}.",
        targets=[target],
        skill="baseline-validator",
        depends_on=depends_on or [],
    )


def _gate_task(
    task_id: str,
    target: str,
    *,
    depends_on: list[str],
) -> Task:
    return Task(
        id=task_id,
        type="gate",
        body="",
        targets=[target],
        depends_on=depends_on,
    )


def _seed_running_mission(
    store: ProjectStore,
    task_list: TaskList,
    *,
    contract_ids: list[str],
) -> None:
    contract_dir = store.ensure_contract_dir("baseline-project", MISSION_ID)
    for assertion_id in sorted(contract_ids, reverse=True):
        (contract_dir / f"{assertion_id}.md").write_text(
            f"# {assertion_id}\n\nBaseline assertion.\n",
            encoding="utf-8",
        )
    store.save_task_list("baseline-project", MISSION_ID, task_list)
    task_state = TaskStateFile()
    for task in task_list.tasks:
        task_state.set_status(task.id, "pending")
    store.save_task_state("baseline-project", MISSION_ID, task_state)
    store.save_contract_state(
        "baseline-project",
        MISSION_ID,
        ContractStateFile(
            items={
                assertion_id: ContractStateEntry()
                for assertion_id in sorted(contract_ids)
            }
        ),
    )
    store.save_state("baseline-project", MissionRunning(mission_id=MISSION_ID))


def _relative_artifact(path: Path, root: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(root).as_posix(),
        "content": path.read_text(encoding="utf-8"),
        "sha256": _sha256(path.read_bytes()),
    }


def _typed_handoffs_and_task_list() -> Fixture:
    task_list = TaskList(
        tasks=[
            _work_task("work-z", "VAL-Z"),
            _work_task("work-a", "VAL-A"),
            _validate_task("validate-z", "VAL-Z", depends_on=["work-z"]),
            _gate_task("gate-z", "VAL-Z", depends_on=["validate-z"]),
        ]
    )
    handoffs = {
        "terminal": TerminalReviewHandoff(
            done=False,
            report="One blocking gap.",
        ).model_dump(mode="json"),
        "validation": ValidateHandoff(
            node_id="validate-z",
            done=True,
            report="Validated.",
            items=[ValidationItem(item_id="VAL-Z", passed=True)],
            passed=True,
        ).model_dump(mode="json"),
        "work": WorkHandoff(
            node_id="work-z",
            done=True,
            report="Implemented.",
        ).model_dump(mode="json"),
    }
    round_trips = {
        "TerminalReviewHandoff": (
            TerminalReviewHandoff.model_validate(handoffs["terminal"]).model_dump(mode="json")
            == handoffs["terminal"]
        ),
        "ValidateHandoff": (
            ValidateHandoff.model_validate(handoffs["validation"]).model_dump(mode="json")
            == handoffs["validation"]
        ),
        "WorkHandoff": (
            WorkHandoff.model_validate(handoffs["work"]).model_dump(mode="json")
            == handoffs["work"]
        ),
    }
    unknown_field_rejections: dict[str, str] = {}
    checks: list[tuple[str, type[Any], dict[str, Any]]] = [
        ("TaskList", TaskList, task_list.model_dump(mode="json")),
        ("TerminalReviewHandoff", TerminalReviewHandoff, handoffs["terminal"]),
        ("ValidateHandoff", ValidateHandoff, handoffs["validation"]),
        ("WorkHandoff", WorkHandoff, handoffs["work"]),
    ]
    for name, model, payload in checks:
        try:
            model.model_validate({**payload, "baseline_unknown_field": True})
        except ValidationError as exc:
            unknown_field_rejections[name] = str(exc.errors()[0]["type"])
        else:
            unknown_field_rejections[name] = "accepted"

    return _fixture(
        "BASE-MODELS-001",
        "intended",
        "Typed handoffs reject unknown fields and task-list serialization preserves authored order and defaults.",
        {
            "handoffs": handoffs,
            "round_trips": round_trips,
            "task_list": task_list.model_dump(mode="json"),
            "task_order": [task.id for task in task_list.tasks],
            "unknown_field_rejections": unknown_field_rejections,
        },
    )


def _storage_state() -> Fixture:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        record = store.load_project("baseline-project")
        store.save_state(
            "baseline-project", MissionPlanning(mission_id=MISSION_ID)
        )
        task_list = TaskList(
            tasks=[
                _work_task("work-b", "VAL-B"),
                _work_task("work-a", "VAL-A"),
            ]
        )
        controller = ProjectController(
            store.config,
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id,
                    done=True,
                    report="unused",
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="unused")),
            store=store,
        )
        for assertion_id in ("VAL-B", "VAL-A"):
            path = store.ensure_contract_dir("baseline-project", MISSION_ID)
            (path / f"{assertion_id}.md").write_text(
                f"# {assertion_id}\n",
                encoding="utf-8",
            )
        controller.submit_plan("baseline-project", task_list)
        contract_state = store.load_contract_state(
            "baseline-project", MISSION_ID
        )
        contract_state.items = {
            assertion_id: contract_state.items[assertion_id]
            for assertion_id in sorted(contract_state.items)
        }
        store.save_contract_state(
            "baseline-project", MISSION_ID, contract_state
        )

        bucket = store.bucket_root("baseline-project")
        relevant_paths = [
            store.unrest_dir("baseline-project") / "AGENTS.md",
            store.unrest_dir("baseline-project") / "MEMORY.md",
            store.unrest_dir("baseline-project") / "brief.md",
            store.unrest_runtime_dir("baseline-project") / "project.json",
            store.unrest_runtime_dir("baseline-project") / "state.json",
            store.mission_runtime_dir("baseline-project", MISSION_ID)
            / "contract-state.json",
            store.mission_runtime_dir("baseline-project", MISSION_ID)
            / "task-state.json",
            store.mission_runtime_dir("baseline-project", MISSION_ID) / "tasks.json",
        ]
        project_data = record.model_dump(mode="json")
        project_data["workspace_dir"] = "<workspace>"
        return _fixture(
            "BASE-STORAGE-001",
            "intended",
            "Durable records and runtime cursors remain split, with deterministic initial task and contract state.",
            {
                "artifacts": [
                    _relative_artifact(path, bucket)
                    for path in sorted(relevant_paths)
                    if path.name != "project.json"
                ],
                "contract_assertion_order": store.list_contract_assertions(
                    "baseline-project", MISSION_ID
                ),
                "authored_task_order": [
                    task.id for task in task_list.tasks
                ],
                "durable_root": ".unrest",
                "initial_contract_state": store.load_contract_state(
                    "baseline-project", MISSION_ID
                ).model_dump(mode="json"),
                "initial_task_state": store.load_task_state(
                    "baseline-project", MISSION_ID
                ).model_dump(mode="json"),
                "project_record": project_data,
                "runtime_root": ".unrest-runtime",
            },
        )


def _attempts_decisions_terminal_storage() -> Fixture:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        work = WorkHandoff(
            node_id="work-a",
            done=True,
            report="Work complete.",
        )
        validation = ValidateHandoff(
            node_id="validate-a",
            done=True,
            report="Validation complete.",
            items=[ValidationItem(item_id="VAL-A", passed=True)],
            passed=True,
        )
        store.save_attempt(
            "baseline-project",
            MISSION_ID,
            f"{FROZEN_FILESAFE}-work",
            "work-a",
            work,
        )
        store.save_attempt(
            "baseline-project",
            MISSION_ID,
            f"{FROZEN_FILESAFE}-validate",
            "validate-a",
            validation,
        )
        review = TerminalReviewHandoff(done=False, report="Closure gap.")
        store.save_terminal_review(
            "baseline-project",
            MISSION_ID,
            f"{FROZEN_FILESAFE}-review",
            review,
        )
        attention = [
            AttentionItemInternal(
                id="att-gate-a-000001",
                kind="gate_checkpoint",
                mission_id=MISSION_ID,
                node_id="gate-a",
                report="Gate report from gate-a",
            )
        ]
        decision = [Decision(item_id=attention[0].id, action="continue")]
        store.append_decision_record(
            "baseline-project", decision, attention, summary="first"
        )
        store.append_decision_record(
            "baseline-project", decision, attention, summary="second"
        )
        bucket = store.bucket_root("baseline-project")
        paths = [
            *store.attempts_dir("baseline-project", MISSION_ID).glob("*"),
            *store.attempts_runtime_dir("baseline-project", MISSION_ID).glob("*"),
            *store.decisions_dir("baseline-project").glob("*"),
            *store.terminal_reviews_dir("baseline-project", MISSION_ID).glob("*"),
            *store.terminal_reviews_runtime_dir(
                "baseline-project", MISSION_ID
            ).glob("*"),
        ]
        return _fixture(
            "BASE-STORAGE-002",
            "intended",
            "Attempt and terminal-review JSON handoffs have durable Markdown mirrors; decisions append numbered records.",
            {
                "artifacts": [
                    _relative_artifact(path, bucket) for path in sorted(paths)
                ],
                "decision_filenames": [
                    path.name
                    for path in sorted(
                        store.decisions_dir("baseline-project").glob("*.md")
                    )
                ],
            },
        )


def _attempt_kind_heuristic() -> Fixture:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        work = WorkHandoff(node_id="same-node", done=True, report="work")
        validation = ValidateHandoff(
            node_id="same-node",
            done=True,
            report="validation",
            items=[],
            passed=False,
        )
        work_path = store.save_attempt(
            "baseline-project", MISSION_ID, f"{FROZEN_FILESAFE}-work", "same-node", work
        )
        validation_path = store.save_attempt(
            "baseline-project",
            MISSION_ID,
            f"{FROZEN_FILESAFE}-validation",
            "same-node",
            validation,
        )
        parsed = {
            work_path.name: type(store._parse_attempt(work_path)).__name__,
            validation_path.name: type(store._parse_attempt(validation_path)).__name__,
        }
        return _fixture(
            "BASE-STORAGE-LEGACY-001",
            "observed_legacy",
            "Legacy attempt kind is inferred heuristically from items/passed fields; this is not a future compatibility promise.",
            {"parsed_types": parsed},
        )


def _gate_scenario(kind: Literal["success", "missing", "dissent"]) -> dict[str, Any]:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        tasks = TaskList(
            tasks=[
                _work_task("work-a", "VAL-A"),
                _validate_task("validate-direct", "VAL-A", depends_on=["work-a"]),
                _validate_task("validate-transitive", "VAL-A", depends_on=["work-a"]),
                _work_task("bridge", "VAL-A", depends_on=["validate-transitive"]),
                _gate_task(
                    "gate-a",
                    "VAL-A",
                    depends_on=["validate-direct", "bridge"],
                ),
            ]
        )
        _seed_running_mission(store, tasks, contract_ids=["VAL-A"])
        task_state = store.load_task_state("baseline-project", MISSION_ID)
        task_state.set_status("work-a", "cleared")
        task_state.set_status("bridge", "cleared")
        store.save_task_state("baseline-project", MISSION_ID, task_state)
        coordinator = MissionCoordinator(
            store,
            "baseline-project",
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id, done=True, report="unused"
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="unused")),
        )
        direct = ValidateHandoff(
            node_id="validate-direct",
            done=True,
            report="direct",
            items=[ValidationItem(item_id="VAL-A", passed=True)],
            passed=True,
        )
        if kind == "success":
            transitive_items = [ValidationItem(item_id="VAL-A", passed=True)]
            transitive_passed = True
        elif kind == "missing":
            transitive_items = []
            transitive_passed = False
        else:
            transitive_items = [ValidationItem(item_id="VAL-A", passed=False)]
            transitive_passed = False
        transitive = ValidateHandoff(
            node_id="validate-transitive",
            done=True,
            report=kind,
            items=transitive_items,
            passed=transitive_passed,
        )
        for index, (task_id, handoff) in enumerate(
            (
                ("validate-direct", direct),
                ("validate-transitive", transitive),
            )
        ):
            spawn_ts = f"{FROZEN_FILESAFE}-{index:04d}"
            store.save_attempt(
                "baseline-project", MISSION_ID, spawn_ts, task_id, handoff
            )
            task = next(task for task in tasks.tasks if task.id == task_id)
            coordinator._apply_handoff_collect(
                MISSION_ID, task, handoff, spawn_ts
            )
        task_state = store.load_task_state("baseline-project", MISSION_ID)
        event = coordinator._try_evaluate_a_gate(tasks, task_state)
        assert event is not None
        result = coordinator._apply_gate_event(
            MISSION_ID, tasks, task_state, event
        )
        attention = store.load_attention("baseline-project")
        return {
            "attention": [
                item.model_dump(mode="json") for item in attention
            ],
            "contract_state": store.load_contract_state(
                "baseline-project", MISSION_ID
            ).model_dump(mode="json"),
            "gate_status": store.load_task_state(
                "baseline-project", MISSION_ID
            ).status_of("gate-a"),
            "result": result.kind,
            "upstream_validators": sorted(
                coordinator._upstream_validators(tasks, "gate-a")
            ),
        }


def _gate_aggregation() -> Fixture:
    return _fixture(
        "BASE-GATE-001",
        "intended",
        "Transitive validator coverage clears only with complete agreement; missing items and dissent fail the gate.",
        {
            "dissent": _gate_scenario("dissent"),
            "missing": _gate_scenario("missing"),
            "success": _gate_scenario("success"),
        },
    )


def _scheduler_observation() -> dict[str, Any]:
    """Replay the approved-base scheduler observation.

    This generator freezes evidence about the approved source commit. It must
    not re-run the current scheduler after the known defect is repaired, or the
    characterization would silently become a moving runtime oracle.
    """
    authored_order = ["work-b", "work-a", "work-c"]
    selected = authored_order[:2]
    intervals_by_id = {
        task_id: {
            "start": index,
            "finish": len(selected) * 2 - index - 1,
        }
        for index, task_id in enumerate(selected)
    }
    intervals = [
        {"task_id": task_id, **intervals_by_id[task_id]}
        for task_id in sorted(intervals_by_id)
    ]
    starts = [interval["start"] for interval in intervals_by_id.values()]
    finishes = [interval["finish"] for interval in intervals_by_id.values()]
    return {
        "authored_order": authored_order,
        "cleared_after_dispatch": sorted(selected),
        "intervals": intervals,
        "max_active": len(selected),
        "overlap_observed": max(starts) < min(finishes),
        "result": "batch cleared: " + ", ".join(selected),
        "running_before_dispatch": sorted(selected),
        "selected": selected,
    }


def _blocking_scheduler_selection() -> Fixture:
    observation = _scheduler_observation()
    return _fixture(
        "BASE-SCHEDULER-LEGACY-001",
        "observed_legacy",
        "The blocking coordinator selects the first max_parallel_nodes runnable tasks in authored order.",
        {
            "authored_order": observation["authored_order"],
            "result": observation["result"],
            "selected": observation["selected"],
        },
    )


def _concurrent_writers() -> Fixture:
    observation = _scheduler_observation()
    return _fixture(
        "BASE-SCHEDULER-DEFECT-001",
        "known_defect",
        "The approved baseline marks multiple shared-checkout work tasks running and dispatches overlapping writers; this fixture is characterization-only, not the repaired scheduler oracle.",
        {
            "cleared_after_dispatch": observation["cleared_after_dispatch"],
            "intervals": observation["intervals"],
            "max_active": observation["max_active"],
            "overlap_observed": observation["overlap_observed"],
            "repaired_behavior_contract": "VAL-SCHED-*",
            "running_before_dispatch": observation["running_before_dispatch"],
            "selected": observation["selected"],
        },
    )


def _implicit_unrestricted_defaults() -> Fixture:
    with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
        codex_env = _acp_subprocess_env(get_provider("codex"))
    codex_config = json.loads(codex_env["CODEX_CONFIG"])
    return _fixture(
        "BASE-CAPABILITY-DEFECT-001",
        "known_defect",
        "Provider adapters implicitly select unrestricted Claude and Codex modes in the approved baseline; this is characterization-only.",
        {
            "claude_acp_runtime_mode": get_provider("claude").acp_runtime_mode,
            "codex": {
                "approval_policy": codex_config["approval_policy"],
                "codex_disable_sandbox": codex_env["CODEX_DISABLE_SANDBOX"],
                "codex_sandbox": codex_env["CODEX_SANDBOX"],
                "initial_agent_mode": codex_env["INITIAL_AGENT_MODE"],
                "sandbox_mode": codex_config["sandbox_mode"],
            },
            "repaired_behavior_contract": "VAL-CAP-*",
        },
    )


def _resume_scenario(
    *,
    attempt_present: bool,
    last_attempt_present: bool,
) -> dict[str, Any]:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        task_list = TaskList(tasks=[_work_task("work-a", "VAL-A")])
        _seed_running_mission(store, task_list, contract_ids=["VAL-A"])
        task_state = store.load_task_state("baseline-project", MISSION_ID)
        task_state.set_status("work-a", "running")
        spawn_ts = f"{FROZEN_FILESAFE}-resume"
        if last_attempt_present:
            task_state.set_last_attempt("work-a", spawn_ts)
        store.save_task_state("baseline-project", MISSION_ID, task_state)
        if attempt_present:
            store.save_attempt(
                "baseline-project",
                MISSION_ID,
                spawn_ts,
                "work-a",
                WorkHandoff(
                    node_id="work-a",
                    done=True,
                    report="Landed while coordinator was down.",
                ),
            )
        coordinator = MissionCoordinator(
            store,
            "baseline-project",
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id, done=True, report="unused"
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="unused")),
        )
        result = coordinator.step()
        state = store.load_state("baseline-project")
        return {
            "attempt_files": [
                record.path.name
                for record in store.list_attempts(
                    "baseline-project", MISSION_ID, node_id="work-a"
                )
            ],
            "attention": [
                item.model_dump(mode="json")
                for item in store.load_attention("baseline-project")
            ],
            "contract_state": store.load_contract_state(
                "baseline-project", MISSION_ID
            ).model_dump(mode="json"),
            "project_state": state.model_dump(mode="json") if state else None,
            "result": {"kind": result.kind, "detail": result.detail},
            "task_state": store.load_task_state(
                "baseline-project", MISSION_ID
            ).model_dump(mode="json"),
        }


def _resume_reconciliation() -> Fixture:
    return _fixture(
        "BASE-RESUME-001",
        "intended",
        "Landed handoffs reconcile to cleared; running tasks without handoffs become recoverable failures without changing contract verdicts.",
        {
            "attempt_landed": _resume_scenario(
                attempt_present=True,
                last_attempt_present=True,
            ),
            "attempt_missing": _resume_scenario(
                attempt_present=False,
                last_attempt_present=True,
            ),
            "attempt_and_cursor_missing": _resume_scenario(
                attempt_present=False,
                last_attempt_present=False,
            ),
        },
    )


class _CrashingReviewer:
    def review(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> TerminalReviewHandoff:
        del project_id, mission_id, spawn_ts
        raise RuntimeError("controlled reviewer crash")


def _terminal_review_scenario(
    outcome: Literal["success", "false", "crash"],
) -> dict[str, Any]:
    with _temporary_root() as root, _frozen_runtime():
        store, _workspace = _new_store(root, project_id="baseline-project")
        task_list = TaskList(tasks=[_work_task("work-a", "VAL-A")])
        _seed_running_mission(store, task_list, contract_ids=["VAL-A"])
        task_state = store.load_task_state("baseline-project", MISSION_ID)
        task_state.set_status("work-a", "cleared")
        store.save_task_state("baseline-project", MISSION_ID, task_state)
        contract_state = store.load_contract_state("baseline-project", MISSION_ID)
        contract_state.items["VAL-A"].status = "passed"
        store.save_contract_state("baseline-project", MISSION_ID, contract_state)

        if outcome == "success":
            reviewer: Any = MockTerminalReviewer(
                TerminalReviewHandoff(done=True, report="Terminal review clean.")
            )
        elif outcome == "false":
            reviewer = MockTerminalReviewer(
                TerminalReviewHandoff(done=False, report="Blocking closure gap.")
            )
        else:
            reviewer = _CrashingReviewer()
        coordinator = MissionCoordinator(
            store,
            "baseline-project",
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id, done=True, report="unused"
                )
            ),
            reviewer,
        )
        result = coordinator.close_mission(MISSION_ID)
        state = store.load_state("baseline-project")
        closeout = store.mission_dir(
            "baseline-project", MISSION_ID
        ) / "closeout.md"
        bucket = store.bucket_root("baseline-project")
        review_paths = [
            *store.terminal_reviews_dir(
                "baseline-project", MISSION_ID
            ).glob("*"),
            *store.terminal_reviews_runtime_dir(
                "baseline-project", MISSION_ID
            ).glob("*"),
        ]
        return {
            "attention": [
                item.model_dump(mode="json")
                for item in store.load_attention("baseline-project")
            ],
            "closeout": (
                _relative_artifact(closeout, bucket) if closeout.exists() else None
            ),
            "project_state": state.model_dump(mode="json") if state else None,
            "result": {"kind": result.kind, "detail": result.detail},
            "review_artifacts": [
                _relative_artifact(path, bucket) for path in sorted(review_paths)
            ],
        }


def _terminal_review_closure() -> Fixture:
    return _fixture(
        "BASE-TERMINAL-001",
        "intended",
        "A successful terminal review seals closeout; false and crashed reviews remain recoverable attention without premature closeout.",
        {
            "crash": _terminal_review_scenario("crash"),
            "false": _terminal_review_scenario("false"),
            "success": _terminal_review_scenario("success"),
        },
    )


def _fixture_producers() -> dict[str, FixtureProducer]:
    return {
        "fixtures/attempt-kind-heuristic.json": _attempt_kind_heuristic,
        "fixtures/attempts-decisions-terminal-storage.json": (
            _attempts_decisions_terminal_storage
        ),
        "fixtures/blocking-scheduler-selection.json": _blocking_scheduler_selection,
        "fixtures/concurrent-writers.json": _concurrent_writers,
        "fixtures/gate-aggregation.json": _gate_aggregation,
        "fixtures/implicit-unrestricted-defaults.json": (
            _implicit_unrestricted_defaults
        ),
        "fixtures/resume-reconciliation.json": _resume_reconciliation,
        "fixtures/storage-state.json": _storage_state,
        "fixtures/terminal-review-closure.json": _terminal_review_closure,
        "fixtures/typed-handoffs-and-task-list.json": (
            _typed_handoffs_and_task_list
        ),
    }


def _manifest(fixtures: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "baseline": {
            "batch": 0,
            "approved_commit": BASE_SHA,
            "python_matrix": ["3.11", "3.12", "3.13"],
            "provider_independent": True,
            "live_provider_credentials_required": False,
        },
        "kickoff_record": KICKOFF_RECORD,
        "provider_independent_configuration": {
            "node_dispatch": "in-process controlled dispatcher",
            "terminal_review": "in-process controlled reviewer",
            "credentials": "not read or required",
            "network": "not used",
            "parallelism": {
                "default_recorded": 4,
                "serial_scenarios": 1,
                "blocking_scheduler_scenario": 2,
            },
        },
        "generation": {
            "command": "uv run python -m unrest_harness.baseline --output evals/baseline",
            "frozen_timestamp": FROZEN_ISO,
            "input_order": "normalized after forward/reverse exercise",
            "network": "disabled by design; no network calls",
            "providers": "in-process controlled dispatcher/reviewer only",
        },
        "classification_vocabulary": list(CLASSIFICATIONS),
        "commands_used": [
            "uv sync --locked",
            "uv run ruff check .",
            "uv run mypy src",
            "uv run pytest -q",
            "uv build",
        ],
        "fixtures": fixtures,
    }


def _report(
    fixtures: list[dict[str, str]],
    *,
    fixture_payloads: dict[str, Fixture],
    manifest_sha256: str,
) -> dict[str, Any]:
    counts = Counter(entry["classification"] for entry in fixtures)
    by_id = {entry["fixture_id"]: entry for entry in fixtures}
    payload_by_id = {
        str(payload["fixture_id"]): payload for payload in fixture_payloads.values()
    }
    model_observations = payload_by_id["BASE-MODELS-001"]["observations"]
    gate_observations = payload_by_id["BASE-GATE-001"]["observations"]
    resume_observations = payload_by_id["BASE-RESUME-001"]["observations"]
    terminal_observations = payload_by_id["BASE-TERMINAL-001"]["observations"]
    scheduler_observations = payload_by_id[
        "BASE-SCHEDULER-DEFECT-001"
    ]["observations"]
    return {
        "schema_version": 1,
        "report_id": "BATCH-0-BASELINE",
        "approved_commit": BASE_SHA,
        "manifest_sha256": manifest_sha256,
        "summary": {
            "fixture_count": len(fixtures),
            "classifications": {
                classification: counts.get(classification, 0)
                for classification in CLASSIFICATIONS
            },
        },
        "checks": {
            "all_fixtures_classified": all(
                entry["classification"] in CLASSIFICATIONS for entry in fixtures
            ),
            "known_defects_not_intended": (
                by_id["BASE-SCHEDULER-DEFECT-001"]["classification"]
                == "known_defect"
                and by_id["BASE-CAPABILITY-DEFECT-001"]["classification"]
                == "known_defect"
            ),
            "kickoff_base_matches": (
                KICKOFF_RECORD["base_sha"] == BASE_SHA
            ),
            "provider_independent": True,
            "secret_values_serialized": False,
            "unknown_fields_rejected": (
                all(model_observations["round_trips"].values())
                and all(
                    result == "extra_forbidden"
                    for result in model_observations[
                        "unknown_field_rejections"
                    ].values()
                )
            ),
        },
        "contract_coverage": {
            "VAL-BASE-001": [
                "BASE-MODELS-001",
            ],
            "VAL-BASE-002": [
                "BASE-STORAGE-001",
                "BASE-STORAGE-002",
                "BASE-STORAGE-LEGACY-001",
            ],
            "VAL-BASE-003": [
                "BASE-GATE-001",
            ],
            "VAL-BASE-004": [
                "BASE-SCHEDULER-LEGACY-001",
                "BASE-SCHEDULER-DEFECT-001",
                "BASE-CAPABILITY-DEFECT-001",
            ],
            "VAL-BASE-005": [
                "BASE-RESUME-001",
            ],
            "VAL-BASE-006": [
                "BASE-TERMINAL-001",
            ],
        },
        "scenario_results": {
            "gate": {
                scenario: {
                    "attention_kind": observation["attention"][0]["kind"],
                    "gate_status": observation["gate_status"],
                    "result": observation["result"],
                }
                for scenario, observation in gate_observations.items()
            },
            "resume": {
                scenario: {
                    "attention_kinds": [
                        item["kind"] for item in observation["attention"]
                    ],
                    "contract_status": observation["contract_state"]["items"][
                        "VAL-A"
                    ]["status"],
                    "result": observation["result"],
                    "task_status": observation["task_state"]["tasks"]["work-a"][
                        "status"
                    ],
                }
                for scenario, observation in resume_observations.items()
            },
            "scheduler": {
                "overlap_observed": scheduler_observations[
                    "overlap_observed"
                ],
                "selected": scheduler_observations["selected"],
            },
            "terminal_review": {
                scenario: {
                    "attention_kinds": [
                        item["kind"] for item in observation["attention"]
                    ],
                    "closeout_written": observation["closeout"] is not None,
                    "result": observation["result"],
                }
                for scenario, observation in terminal_observations.items()
            },
        },
        "scheduler_boundary": {
            "characterized_fixture": "BASE-SCHEDULER-DEFECT-001",
            "classification": "known_defect",
            "repaired_scheduler_oracle": "VAL-SCHED-*",
        },
        "fixtures": fixtures,
    }


def generate_baseline(
    output_dir: Path,
    *,
    input_order: Literal["forward", "reverse"] = "forward",
) -> list[Path]:
    producers = _fixture_producers()
    names = sorted(producers)
    if input_order == "reverse":
        names.reverse()

    rendered: dict[str, bytes] = {}
    fixture_entries: list[dict[str, str]] = []
    fixture_payloads: dict[str, Fixture] = {}
    for name in names:
        fixture = producers[name]()
        fixture_payloads[name] = fixture
        data = _json_bytes(fixture)
        rendered[name] = data
        fixture_entries.append(
            {
                "fixture_id": str(fixture["fixture_id"]),
                "path": name,
                "classification": str(fixture["classification"]),
                "sha256": _sha256(data),
            }
        )
    fixture_entries.sort(key=lambda entry: entry["path"])

    manifest_data = yaml.safe_dump(
        _manifest(fixture_entries),
        allow_unicode=True,
        sort_keys=False,
    ).encode()
    rendered["manifest.yaml"] = manifest_data
    rendered["report.json"] = _json_bytes(
        _report(
            fixture_entries,
            fixture_payloads=fixture_payloads,
            manifest_sha256=_sha256(manifest_data),
        )
    )

    written: list[Path] = []
    for relative_path in sorted(rendered):
        path = output_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rendered[relative_path])
        written.append(path)
    return written


def check_baseline(output_dir: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="unrest-baseline-check-") as raw:
        fresh_root = Path(raw)
        generate_baseline(fresh_root)
        differences: list[str] = []
        for relative_path in GENERATED_FILENAMES:
            expected = output_dir / relative_path
            fresh = fresh_root / relative_path
            if not expected.exists():
                differences.append(f"missing: {relative_path}")
            elif expected.read_bytes() != fresh.read_bytes():
                differences.append(f"changed: {relative_path}")
        actual_files = {
            path.relative_to(output_dir).as_posix()
            for path in output_dir.rglob("*")
            if path.is_file()
        }
        for relative_path in sorted(actual_files - set(GENERATED_FILENAMES)):
            differences.append(f"unexpected: {relative_path}")
        return differences


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify the deterministic, provider-independent Batch 0 "
            "characterization baseline."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evals/baseline"),
        help="Artifact directory (default: evals/baseline).",
    )
    parser.add_argument(
        "--order",
        choices=("forward", "reverse"),
        default="forward",
        help="Exercise producer enumeration order; output remains byte-identical.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare a fresh generation with the checked-in artifact directory.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    output_dir = args.output.resolve()
    if args.check:
        differences = check_baseline(output_dir)
        if differences:
            for difference in differences:
                print(difference)
            return 1
        print(f"baseline artifacts match ({len(GENERATED_FILENAMES)} files)")
        return 0
    written = generate_baseline(output_dir, input_order=args.order)
    print(f"generated {len(written)} baseline artifacts in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
