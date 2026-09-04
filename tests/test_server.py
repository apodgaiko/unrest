"""MCP server tests — tool surface per mode + in-process integration."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Iterator

import pytest

import unrest_harness.acp_runner as acp_runner
import unrest_harness.api as api_module
import unrest_harness.server as server_module
from unrest_harness.capability_policy import (
    UNSAFE_DEVELOPMENT_PROFILE,
    credential_source_values,
)
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
)
from unrest_harness.evolution import CampaignFreeze, EvolutionManager
from unrest_harness.foundation_tools import FoundationTools
from unrest_harness.models import (
    AttentionItemInternal,
    AttentionNeeded,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    MissionRunning,
    SteeringRequest,
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from unrest_harness.public_schema import (
    PublicSchemaValidationError,
    public_input_schema,
    public_output_schema,
    public_surface_catalog,
    validate_public_request,
    validate_public_result,
)
from unrest_harness.server import (
    create_orchestrator_server,
    create_terminal_reviewer_server,
    create_validator_server,
    create_worker_server,
)
from unrest_harness.storage import ProjectStore
from unrest_harness.supervision import (
    load_policy_state,
    load_snapshot,
    save_snapshot,
    terminal_snapshot,
)
from unrest_harness.workspaces import ResourceBudget, WorkspaceManager


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
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
        max_parallel_nodes=1,
    )


def _completion_oracle(
    *,
    workspace: Path,
    attempt_id: str,
    task_type: str,
    targets: list[str],
    done: bool,
    items: list[ValidationItem],
) -> dict[str, object]:
    """Independent contract oracle; never calls a production carrier helper."""
    if task_type == "work":
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return_ref = f"git:{revision}"
        statuses = {
            target: "completed" if done else "blocked" for target in targets
        }
    else:
        rows = sorted([item.item_id, item.passed] for item in items)
        verdict_bytes = (
            json.dumps(rows, separators=(",", ":")) + "\n"
        ).encode("ascii")
        return_ref = f"verdict:sha256:{hashlib.sha256(verdict_bytes).hexdigest()}"
        statuses = {
            target_id: "passed" if passed else "failed"
            for target_id, passed in rows
        }
    target_rows: list[dict[str, object]] = []
    for target_id in sorted(targets):
        status = statuses[target_id]
        evidence_preimage = {
            "attempt_id": attempt_id,
            "return_ref": return_ref,
            "status": status,
            "target_id": target_id,
        }
        evidence_bytes = (
            json.dumps(evidence_preimage, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
        target_rows.append(
            {
                "target_id": target_id,
                "status": status,
                "return_ref": return_ref,
                "evidence_refs": [
                    f"evidence:sha256:{hashlib.sha256(evidence_bytes).hexdigest()}"
                ],
            }
        )
    return {
        "schema": "unrest.v045.node-completion.v1",
        "attempt_id": attempt_id,
        "task_type": task_type,
        "targets": target_rows,
        "scope_status": "in_scope",
        "blocker_code": None,
    }


async def _tool_names(server) -> set[str]:
    return {t.name for t in await server.list_tools()}


async def _tool_contract(server, name: str) -> tuple[str | None, dict[str, object]]:
    tool = next(tool for tool in await server.list_tools() if tool.name == name)
    return tool.description, tool.parameters


def _resolve_local_schema_references(schema: object, definitions: dict[str, object]) -> object:
    if isinstance(schema, list):
        return [_resolve_local_schema_references(item, definitions) for item in schema]
    if not isinstance(schema, dict):
        return schema
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/definitions/"):
        name = reference.removeprefix("#/definitions/")
        return _resolve_local_schema_references(definitions[name], definitions)
    return {
        key: _resolve_local_schema_references(value, definitions)
        for key, value in schema.items()
        if key != "definitions"
    }


def _valid_public_requests() -> dict[str, dict[str, object]]:
    budget = {"max_steps": 1, "timeout_seconds": 1}
    action = {"campaign_id": "campaign:1", "candidate_id": "candidate:1", "idempotency_key": "idem:1"}
    return {
        "add_candidate": {
            "campaign_id": "campaign:1",
            "artifact_id": "artifact:1",
            "action": "initial",
            "idempotency_key": "idem:1",
        },
        "advance_inquiry": {"inquiry_id": "inquiry:1", "idempotency_key": "idem:1"},
        "attach_run": {"run_id": "run:1"},
        "cancel_inquiry": {
            "inquiry_id": "inquiry:1",
            "reason": "done",
            "idempotency_key": "idem:1",
        },
        "cancel_run": {"run_id": "run:1", "reason": "done", "idempotency_key": "idem:1"},
        "cleanup_workspace": {"workspace_id": "lease:1", "idempotency_key": "idem:1"},
        "evaluate_candidate": dict(action),
        "handoff_inquiry": {
            "inquiry_id": "inquiry:1",
            "consumer_id": "consumer:1",
            "idempotency_key": "idem:1",
        },
        "inspect_campaign": {"campaign_id": "campaign:1"},
        "inspect_inquiry": {"inquiry_id": "inquiry:1"},
        "inspect_run": {"run_id": "run:1"},
        "inspect_workspace": {"workspace_id": "lease:1"},
        "integrate_workspace": {
            "workspace_id": "lease:1",
            "human_grant_id": "grant:1",
            "idempotency_key": "idem:1",
        },
        "lease_workspace": {
            "project_id": "project:1",
            "base_revision": "0" * 40,
            "write_paths": ["src"],
            "idempotency_key": "idem:1",
            "lease_seconds": 1,
        },
        "open_campaign": {
            "project_id": "project:1",
            "accepted_point_digest": "sha256:" + "0" * 64,
            "workload_id": "workload:1",
            "evaluator_id": "evaluator:1",
            "reviewer_id": "reviewer:1",
            "budget": budget,
            "seed": 0,
            "idempotency_key": "idem:1",
        },
        "open_inquiry": {
            "question": "Why?",
            "budget": budget,
            "idempotency_key": "idem:1",
        },
        "pause_inquiry": {
            "inquiry_id": "inquiry:1",
            "reason": "wait",
            "idempotency_key": "idem:1",
        },
        "promote_candidate": {
            **action,
            "human_grant_id": "grant:1",
        },
        "resume_inquiry": {"inquiry_id": "inquiry:1", "idempotency_key": "idem:1"},
        "return_workspace": {"workspace_id": "lease:1", "idempotency_key": "idem:1"},
        "review_candidate": dict(action),
        "rollback_promotion": {
            "campaign_id": "campaign:1",
            "promotion_receipt_id": "receipt:1",
            "human_grant_id": "grant:1",
            "idempotency_key": "idem:1",
        },
        "submit_run": {
            "operation": "start_project",
            "arguments": {"brief": "Ship", "workspace_dir": "/workspace"},
            "idempotency_key": "idem:1",
        },
        "steer_attempt": {
            "run_id": "run:1",
            "request": {
                "project_id": "project:1",
                "mission_id": "mission-001",
                "node_id": "worker-1",
                "terminal_review_id": None,
                "attempt_id": "attempt-1",
                "checkpoint_sequence": 1,
                "action": "continue",
                "actor": "orchestrator",
            },
        },
    }


def _valid_public_results() -> dict[str, dict[str, object]]:
    timestamp = "2026-08-24T12:34:56Z"
    return {
        "campaign_summary": {
            "campaign_id": "campaign:1",
            "state": "open",
            "candidate_ids": [],
            "receipt_id": None,
        },
        "handoff_summary": {
            "handoff_id": "handoff:1",
            "inquiry_id": "inquiry:1",
            "consumer_id": "consumer:1",
            "receipt_id": "receipt:1",
        },
        "inquiry_summary": {
            "answer": None,
            "inquiry_id": "inquiry:1",
            "state": "open",
            "branch_outcomes": {},
            "diagnostics": {
                "aggregate_known_steps": 0,
                "branch_attempts": 0,
                "branch_steps_used": {},
                "error_codes": {"synthesis": None},
                "synthesis_attempts": 0,
                "synthesis_steps_used": None,
                "unknown_step_attempts": 0,
            },
            "receipt_id": None,
        },
        "queued_run_summary": {
            "run_id": "run:1",
            "operation": "start_project",
            "state": "queued",
            "resource_key": "workspace:/workspace",
            "idempotency_key": "idem:1",
            "project_id": None,
            "created_at": timestamp,
            "updated_at": timestamp,
            "result": None,
            "error": None,
            "receipt_id": None,
            "active_attempts": [],
        },
        "run_summary": {
            "run_id": "run:1",
            "operation": "start_project",
            "state": "running",
            "resource_key": "workspace:/workspace",
            "idempotency_key": "idem:1",
            "project_id": None,
            "created_at": timestamp,
            "updated_at": timestamp,
            "result": None,
            "error": None,
            "receipt_id": None,
            "active_attempts": [],
        },
        "supervision_receipt": {
            "project_id": "project:1",
            "mission_id": "mission-001",
            "node_id": "worker-1",
            "terminal_review_id": None,
            "attempt_id": "attempt-1",
            "receipt_sequence": 1,
            "checkpoint_sequence": 1,
            "action": "continue",
            "actor": "orchestrator",
            "body_byte_count": 0,
            "body_sha256": None,
            "delivery_status": "not_applicable",
            "code": "continued",
        },
        "workspace_summary": {
            "workspace_id": "lease:1",
            "state": "leased",
            "base_revision": "0" * 40,
            "lease_expires_at": timestamp,
            "patch_id": None,
            "receipt_id": None,
        },
    }


# ---------------------------------------------------------------------------
# Tool surface per mode (structural isolation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_tools_registered(config: HarnessConfig) -> None:
    server = create_orchestrator_server(config)
    names = await _tool_names(server)
    catalog = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "v03"
            / "v0.3.1"
            / "public-surface.v1.json"
        ).read_text(encoding="utf-8")
    )
    additive = {method["name"] for method in catalog["mcp_methods"]}
    assert names == additive | {
        "start_project",
        "submit_plan",
        "advance_project",
        "end_mission",
        "decide_attention",
        "inspect_project",
        "abort_project",
    }


def test_api_export_inventory_keeps_steering_callable_but_unexported() -> None:
    assert len(api_module.__all__) == 27
    assert "steer_attempt" not in api_module.__all__
    assert callable(api_module.steer_attempt)


@pytest.mark.asyncio
async def test_original_mcp_schemas_equal_frozen_v030_fixture(
    config: HarnessConfig,
) -> None:
    fixture = json.loads(
        (
            Path(__file__).parent
            / "fixtures/v031_compatibility/v030-mcp-schemas.v1.json"
        ).read_text(encoding="utf-8")
    )
    schemas = fixture["schemas"]
    canonical = json.dumps(
        schemas,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert fixture["source_tag"] == "v0.3.0"
    assert fixture["schema_sha256"] == "sha256:" + hashlib.sha256(canonical).hexdigest()

    tools = {
        tool.name: {
            "input_schema": tool.parameters,
            "output_schema": tool.output_schema,
        }
        for tool in await create_orchestrator_server(config).list_tools()
        if tool.name in schemas
    }
    assert tools == schemas


@pytest.mark.asyncio
async def test_additive_mcp_schemas_are_exactly_catalog_backed(
    config: HarnessConfig,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    documented = (
        repository_root / "docs/v03/v0.3.1/public-surface.v1.json"
    ).read_bytes()
    packaged = (
        repository_root
        / "src/unrest_harness/bundled/foundation/public-surface.v1.json"
    ).read_bytes()
    assert packaged == documented

    catalog = json.loads(documented)
    methods = {method["name"]: method for method in catalog["mcp_methods"]}
    tools = {
        tool.name: tool
        for tool in await create_orchestrator_server(config).list_tools()
        if tool.name in methods
    }
    assert set(tools) == set(methods)

    for name, method in methods.items():
        tool = tools[name]
        expected_input = public_input_schema(name)
        assert _resolve_local_schema_references(
            tool.parameters,
            tool.parameters.get("definitions", {}),
        ) == _resolve_local_schema_references(
            expected_input,
            expected_input.get("definitions", {}),
        )
        expected_output = public_output_schema(name)
        assert _resolve_local_schema_references(
            tool.output_schema,
            tool.output_schema.get("definitions", {}),
        ) == _resolve_local_schema_references(
            expected_output,
            expected_output.get("definitions", {}),
        )

        request_name = method["args_schema"].removeprefix("#/definitions/")
        request = _resolve_local_schema_references(
            tool.parameters,
            tool.parameters.get("definitions", {}),
        )
        expected_request = _resolve_local_schema_references(
            catalog["definitions"][request_name],
            catalog["definitions"],
        )
        assert request == expected_request

        result_name = method["result_schema"].removeprefix("#/definitions/")
        output = _resolve_local_schema_references(
            tool.output_schema,
            tool.output_schema.get("definitions", {}),
        )
        expected = _resolve_local_schema_references(
            {
                "oneOf": [
                    catalog["definitions"][result_name],
                    catalog["definitions"]["error_envelope"],
                ],
                "type": "object",
            },
            catalog["definitions"],
        )
        assert output == expected

    submit = tools["submit_run"].parameters
    assert len(submit["allOf"]) == 6
    assert submit["properties"]["arguments"] == {"type": "object"}
    assert tools["lease_workspace"].parameters["properties"]["write_paths"][
        "uniqueItems"
    ] is True
    for name in ("open_inquiry", "add_candidate"):
        nullable_name = "project_id" if name == "open_inquiry" else "parent_candidate_id"
        assert tools[name].parameters["properties"][nullable_name]["type"] == [
            "string",
            "null",
        ]


def test_public_validator_covers_every_method_request_and_result() -> None:
    catalog = public_surface_catalog()
    requests = _valid_public_requests()
    methods = {method["name"]: method for method in catalog["mcp_methods"]}
    assert set(requests) == set(methods)

    results = _valid_public_results()
    for name, request in requests.items():
        validate_public_request(name, request)
        with pytest.raises(PublicSchemaValidationError):
            validate_public_request(name, {**request, "unexpected": True})

        result_name = methods[name]["result_schema"].removeprefix("#/definitions/")
        result = results[result_name]
        validate_public_result(name, result)
        validate_public_result(
            name,
            {"error": {"code": "invalid_argument", "message": "invalid argument"}},
        )
        with pytest.raises(PublicSchemaValidationError):
            validate_public_result(name, {**result, "unexpected": True})
        with pytest.raises(PublicSchemaValidationError):
            validate_public_result(
                name,
                {"error": {"code": "not_a_public_code", "message": "no"}},
            )


def test_inquiry_result_schema_is_closed_through_nested_diagnostics() -> None:
    result = _valid_public_results()["inquiry_summary"]
    validate_public_result("inspect_inquiry", result)
    answered = json.loads(json.dumps(result))
    answered["answer"] = "bounded answer"
    answered["state"] = "answered"
    validate_public_result("inspect_inquiry", answered)
    for state in ("failed", "paused", "exploring"):
        lifecycle = json.loads(json.dumps(result))
        lifecycle["state"] = state
        validate_public_result("inspect_inquiry", lifecycle)

    for mutation in (
        lambda value: value.pop("answer"),
        lambda value: value["branch_outcomes"].__setitem__("unknown", "answered"),
        lambda value: value["diagnostics"].__setitem__("unknown", 0),
        lambda value: value["diagnostics"]["branch_steps_used"].__setitem__("unknown", 0),
        lambda value: value["diagnostics"]["error_codes"].__setitem__("unknown", None),
        lambda value: value["diagnostics"].__setitem__("branch_attempts", True),
    ):
        invalid = json.loads(json.dumps(result))
        mutation(invalid)
        with pytest.raises(PublicSchemaValidationError):
            validate_public_result("inspect_inquiry", invalid)


def test_project_lineage_schema_closes_entries_and_nested_identities() -> None:
    run = _valid_public_results()["run_summary"]
    envelope = {
        "active_attempts": [],
        "dag": None,
        "frontier": None,
        "harnessRoot": "/public/harness",
        "next_action": "advance_project",
        "projectId": "project:1",
        "projectRoot": "/public/project",
        "state": {"mission_id": "mission-001", "state": "mission_running"},
        "supersession_lineage": [
            {
                "current": {"mission_id": "mission-001", "node_id": "work-2"},
                "superseded": [
                    {"mission_id": "mission-001", "node_id": "work-1"}
                ],
            }
        ],
    }
    valid = {**run, "result": envelope}
    validate_public_result("inspect_run", valid)

    mutations = (
        lambda value: value["result"]["supersession_lineage"][0].__setitem__(
            "unknown", True
        ),
        lambda value: value["result"]["supersession_lineage"][0]["current"].__setitem__(
            "unknown", True
        ),
        lambda value: value["result"]["supersession_lineage"][0]["superseded"][0].__setitem__(
            "unknown", True
        ),
        lambda value: value["result"]["supersession_lineage"][0].pop("current"),
        lambda value: value["result"]["supersession_lineage"][0].pop("superseded"),
        lambda value: value["result"]["supersession_lineage"][0]["current"].pop(
            "mission_id"
        ),
        lambda value: value["result"]["supersession_lineage"][0]["superseded"][0].__setitem__(
            "node_id", None
        ),
        lambda value: value["result"].__setitem__("supersession_lineage", None),
    )
    for mutation in mutations:
        invalid = json.loads(json.dumps(valid))
        mutation(invalid)
        with pytest.raises(PublicSchemaValidationError):
            validate_public_result("inspect_run", invalid)


@pytest.mark.asyncio
async def test_lineage_is_byte_identical_through_direct_and_mcp_inspection(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    project_id = controller.start_project("lineage", str(workspace)).projectId
    store = controller.store
    contract = store.ensure_contract_dir(project_id, "mission-001") / "VAL-X.md"
    contract.write_text("# VAL-X\n", encoding="utf-8")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="work-1",
                    type="work",
                    body="work",
                    targets=["VAL-X"],
                    skill="worker",
                )
            ]
        ),
    )
    task_state = TaskStateFile()
    task_state.set_status("work-1", "failed")
    store.save_task_state(project_id, "mission-001", task_state)
    store.save_contract_state(
        project_id,
        "mission-001",
        ContractStateFile(items={"VAL-X": ContractStateEntry()}),
    )
    item = AttentionItemInternal(
        id="attention-1",
        report="private",
        kind="node_failed",
        mission_id="mission-001",
        node_id="work-1",
    )
    store.save_attention(project_id, [item])
    store.save_state(project_id, AttentionNeeded(items=[item]))
    controller.decide_attention(
        project_id,
        [
            Decision(
                item_id="attention-1",
                action="patch",
                patch=TaskListPatch(
                    add=[
                        Task(
                            id="work-2",
                            type="work",
                            body="replacement",
                            targets=["VAL-X"],
                            skill="worker",
                        )
                    ],
                    supersede={"work-1": "work-2"},
                ),
            )
        ],
    )

    direct = controller.inspect_project(project_id).model_dump(mode="json")
    mcp = await create_orchestrator_server(config, controller).call_tool(
        "inspect_project", {"project_id": project_id}
    )
    assert json.dumps(direct, sort_keys=True, separators=(",", ":")) == json.dumps(
        mcp.structured_content, sort_keys=True, separators=(",", ":")
    )
    assert direct["supersession_lineage"] == [
        {
            "current": {"mission_id": "mission-001", "node_id": "work-2"},
            "superseded": [
                {"mission_id": "mission-001", "node_id": "work-1"}
            ],
        }
    ]


def _fresh_process_project_projection(
    config: HarnessConfig, project_id: str
) -> dict[str, object]:
    script = """
import json
import sys
from pathlib import Path

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff

bundled = Path(sys.argv[1])
home = Path(sys.argv[2])
projects = Path(sys.argv[3])
project_id = sys.argv[4]
config = HarnessConfig(
    bundled_dir=bundled,
    harness_home=home,
    projects_dir=projects,
    orchestrator_provider_name="claude",
    worker_provider_name="claude",
    worker_acp_command=None,
    validator_provider_name=None,
    validator_acp_command=None,
    terminal_reviewer_provider_name=None,
    terminal_reviewer_acp_command=None,
    max_parallel_nodes=1,
)
controller = ProjectController(
    config,
    MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
    MockTerminalReviewer(TerminalReviewHandoff(done=True)),
)
print(json.dumps(controller.inspect_project(project_id).model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(config.bundled_dir),
            str(config.harness_home),
            str(config.projects_dir),
            project_id,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def _canonical_projection(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _seed_identity_project(
    config: HarnessConfig,
    workspace: Path,
    *,
    reviewer: object | None = None,
) -> tuple[ProjectController, str]:
    def dispatch(request: DispatchRequest) -> WorkHandoff | ValidateHandoff:
        if request.task.type == "work":
            return WorkHandoff(
                node_id=request.task.id,
                attempt_id=request.spawn_ts,
                done=True,
                report="complete",
            )
        return ValidateHandoff(
            node_id=request.task.id,
            attempt_id=request.spawn_ts,
            done=True,
            report="passed",
            items=[ValidationItem(item_id="VAL-IDENTITY", passed=True)],
            passed=True,
        )

    controller = ProjectController(
        config,
        MockDispatcher(dispatch),
        reviewer or MockTerminalReviewer(TerminalReviewHandoff(done=True)),  # type: ignore[arg-type]
    )
    project_id = controller.start_project("identity", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-IDENTITY.md").write_text("# VAL-IDENTITY\n", encoding="utf-8")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="worker-1",
                    type="work",
                    body="work",
                    targets=["VAL-IDENTITY"],
                    skill="worker",
                ),
                Task(
                    id="validator-1",
                    type="validate",
                    body="validate",
                    targets=["VAL-IDENTITY"],
                    skill="validator",
                    depends_on=["worker-1"],
                ),
                Task(
                    id="gate-1",
                    type="gate",
                    body="",
                    targets=["VAL-IDENTITY"],
                    depends_on=["validator-1"],
                ),
            ]
        ),
    )
    return controller, project_id


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True], ids=["negative", "runtime-failure"])
async def test_terminal_review_generation_identity_matches_direct_mcp_and_restart(
    config: HarnessConfig,
    workspace: Path,
    failure: bool,
) -> None:
    class BranchReviewer:
        spawn_ts: str | None = None

        def review(
            self, project_id: str, mission_id: str, spawn_ts: str
        ) -> TerminalReviewHandoff:
            del project_id, mission_id
            self.spawn_ts = spawn_ts
            if failure:
                raise RuntimeError("PRIVATE-REVIEW-RUNTIME-CANARY")
            return TerminalReviewHandoff(
                done=False, report="PRIVATE-NEGATIVE-REVIEW-CANARY"
            )

    reviewer = BranchReviewer()
    controller, project_id = _seed_identity_project(
        config, workspace, reviewer=reviewer
    )
    gate_result = controller.advance_project(project_id)
    assert gate_result.state.state == "attention_needed"
    gate_attention = controller.store.load_attention(project_id)
    assert [item.kind for item in gate_attention] == ["gate_checkpoint"]
    controller.decide_attention(
        project_id,
        [Decision(item_id=gate_attention[0].id, action="continue")],
    )

    result = controller.end_mission(project_id)
    assert result.state.state == "attention_needed"
    assert reviewer.spawn_ts is not None
    attention = controller.store.load_attention(project_id)
    assert len(attention) == 1
    identity = {
        "kind": attention[0].kind,
        "mission_id": attention[0].mission_id,
        "node_id": attention[0].node_id,
        "attempt_id": attention[0].attempt_id,
        "terminal_review_id": attention[0].terminal_review_id,
    }
    assert identity == {
        "kind": "terminal_review",
        "mission_id": "mission-001",
        "node_id": None,
        "attempt_id": None,
        "terminal_review_id": reviewer.spawn_ts,
    }

    review_path = controller.store.terminal_review_path(
        project_id, "mission-001", reviewer.spawn_ts
    )
    review_bytes = review_path.read_bytes()
    review_hash = hashlib.sha256(review_bytes).hexdigest()
    persisted_review = TerminalReviewHandoff.model_validate_json(review_bytes)
    assert persisted_review.done is False
    if failure:
        assert persisted_review.report.startswith("Terminal reviewer runtime failure")
    else:
        assert persisted_review.report == "PRIVATE-NEGATIVE-REVIEW-CANARY"
    attention_path = controller.store.unrest_runtime_dir(project_id) / "attention.json"
    attention_hash = hashlib.sha256(attention_path.read_bytes()).hexdigest()

    direct = controller.inspect_project(project_id).model_dump(mode="json")
    remote = await create_orchestrator_server(config, controller).call_tool(
        "inspect_project", {"project_id": project_id}
    )
    fresh = _fresh_process_project_projection(config, project_id)
    assert (
        _canonical_projection(direct)
        == _canonical_projection(remote.structured_content)
        == _canonical_projection(fresh)
    )
    projected_item = direct["state"]["items"][0]
    assert {
        key: projected_item[key]
        for key in (
            "kind",
            "mission_id",
            "node_id",
            "attempt_id",
            "terminal_review_id",
        )
    } == identity
    assert b"PRIVATE-NEGATIVE-REVIEW-CANARY" not in _canonical_projection(direct)
    assert b"PRIVATE-REVIEW-RUNTIME-CANARY" not in _canonical_projection(direct)
    assert hashlib.sha256(review_path.read_bytes()).hexdigest() == review_hash
    assert hashlib.sha256(attention_path.read_bytes()).hexdigest() == attention_hash


@pytest.mark.asyncio
@pytest.mark.parametrize("task_type", ["work", "validate"], ids=["worker", "validator"])
async def test_malformed_handoff_retains_dispatch_identity_across_mcp_and_restart(
    config: HarnessConfig,
    workspace: Path,
    task_type: str,
) -> None:
    controller, project_id = _seed_identity_project(config, workspace)
    node_id = "worker-1" if task_type == "work" else "validator-1"
    generation = f"dispatch-generation-{task_type}"
    task_state = controller.store.load_task_state(project_id, "mission-001")
    task_state.set_status(node_id, "running")
    task_state.set_last_attempt(node_id, generation)
    controller.store.save_task_state(project_id, "mission-001", task_state)
    controller.store.save_state(project_id, MissionRunning(mission_id="mission-001"))
    malformed_path = controller.store.attempt_path(
        project_id, "mission-001", generation, node_id
    )
    malformed_bytes = (
        b'{"malformed":"PRIVATE-HANDOFF-CANARY-' + task_type.encode("ascii")
    )
    malformed_path.parent.mkdir(parents=True, exist_ok=True)
    malformed_path.write_bytes(malformed_bytes)
    malformed_hash = hashlib.sha256(malformed_bytes).hexdigest()

    restarted = ProjectController(
        config, controller.dispatcher, controller.terminal_reviewer
    )
    result = restarted.advance_project(project_id, max_steps=1)
    assert result.state.state == "attention_needed"
    attention = restarted.store.load_attention(project_id)
    assert len(attention) == 1
    identity = {
        "kind": attention[0].kind,
        "mission_id": attention[0].mission_id,
        "node_id": attention[0].node_id,
        "attempt_id": attention[0].attempt_id,
        "terminal_review_id": attention[0].terminal_review_id,
    }
    assert identity == {
        "kind": "node_failed" if task_type == "work" else "node_attention",
        "mission_id": "mission-001",
        "node_id": node_id,
        "attempt_id": generation,
        "terminal_review_id": None,
    }
    persisted_state = restarted.store.load_task_state(project_id, "mission-001")
    assert persisted_state.tasks[node_id].last_attempt == generation
    assert malformed_path.read_bytes() == malformed_bytes
    assert hashlib.sha256(malformed_path.read_bytes()).hexdigest() == malformed_hash
    attempts = restarted.store.attempts_runtime_dir(project_id, "mission-001")
    assert all("-rejected" not in path.name for path in attempts.iterdir())
    attention_path = restarted.store.unrest_runtime_dir(project_id) / "attention.json"
    attention_hash = hashlib.sha256(attention_path.read_bytes()).hexdigest()

    direct = restarted.inspect_project(project_id).model_dump(mode="json")
    remote = await create_orchestrator_server(config, restarted).call_tool(
        "inspect_project", {"project_id": project_id}
    )
    fresh = _fresh_process_project_projection(config, project_id)
    assert (
        _canonical_projection(direct)
        == _canonical_projection(remote.structured_content)
        == _canonical_projection(fresh)
    )
    projected_item = direct["state"]["items"][0]
    assert {
        key: projected_item[key]
        for key in (
            "kind",
            "mission_id",
            "node_id",
            "attempt_id",
            "terminal_review_id",
        )
    } == identity
    assert b"PRIVATE-HANDOFF-CANARY" not in _canonical_projection(direct)
    assert malformed_path.read_bytes() == malformed_bytes
    assert hashlib.sha256(malformed_path.read_bytes()).hexdigest() == malformed_hash
    assert hashlib.sha256(attention_path.read_bytes()).hexdigest() == attention_hash


def test_public_validator_exercises_defaults_conditionals_and_boundaries() -> None:
    requests = _valid_public_requests()

    # Omitted defaults are accepted; explicit nullable fields remain nullable.
    validate_public_request("open_inquiry", requests["open_inquiry"])
    validate_public_request(
        "open_inquiry", {**requests["open_inquiry"], "project_id": None}
    )
    add = requests["add_candidate"]
    validate_public_request("add_candidate", {**add, "parent_candidate_id": None})

    lease = requests["lease_workspace"]
    validate_public_request("lease_workspace", {key: value for key, value in lease.items() if key != "lease_seconds"})
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request("lease_workspace", {**lease, "write_paths": []})
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request("lease_workspace", {**lease, "write_paths": ["src", "src"]})
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request("lease_workspace", {**lease, "base_revision": "x" * 40})

    campaign = requests["open_campaign"]
    validate_public_request(
        "open_campaign",
        {**campaign, "budget": {"max_steps": 1, "timeout_seconds": 1, "max_branches": 4}},
    )
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request(
            "open_campaign",
            {**campaign, "budget": {"max_steps": 1, "timeout_seconds": 1, "max_branches": 5}},
        )

    run_arguments: dict[str, dict[str, object]] = {
        "abort_project": {"project_id": "project:1", "reason": "done"},
        "advance_project": {"project_id": "project:1", "max_steps": 1},
        "decide_attention": {
            "project_id": "project:1",
            "decisions": [{"item_id": "attention:1", "action": "continue"}],
        },
        "end_mission": {"project_id": "project:1", "deliverable_roots": None},
        "start_project": {"brief": "Ship", "workspace_dir": "/workspace"},
        "submit_plan": {"project_id": "project:1", "task_list": {}},
    }
    for operation, arguments in run_arguments.items():
        validate_public_request(
            "submit_run",
            {"operation": operation, "arguments": arguments, "idempotency_key": operation},
        )
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request(
            "submit_run",
            {
                "operation": "abort_project",
                "arguments": run_arguments["start_project"],
                "idempotency_key": "mismatch",
            },
        )

    patch_decision = {
        "project_id": "project:1",
        "decisions": [{"item_id": "attention:1", "action": "patch", "patch": {}}],
    }
    validate_public_request(
        "submit_run",
        {"operation": "decide_attention", "arguments": patch_decision, "idempotency_key": "patch"},
    )
    with pytest.raises(PublicSchemaValidationError):
        validate_public_request(
            "submit_run",
            {
                "operation": "decide_attention",
                "arguments": {
                    "project_id": "project:1",
                    "decisions": [{"item_id": "attention:1", "action": "patch"}],
                },
                "idempotency_key": "missing-patch",
            },
        )

    run_result = _valid_public_results()["run_summary"]
    with pytest.raises(PublicSchemaValidationError):
        validate_public_result(
            "inspect_run", {**run_result, "created_at": "2026-08-24 12:34:56"}
        )


@pytest.mark.asyncio
async def test_additive_handlers_enforce_catalog_constraints(
    config: HarnessConfig,
) -> None:
    server = create_orchestrator_server(config)
    mismatched = await server.call_tool(
        "submit_run",
        {
            "operation": "abort_project",
            "arguments": {"brief": "wrong operation", "workspace_dir": "/tmp"},
            "idempotency_key": "schema:mismatch",
        },
    )
    assert mismatched.structured_content == {
        "error": {"code": "invalid_argument", "message": "invalid argument"}
    }

    duplicate_paths = await server.call_tool(
        "lease_workspace",
        {
            "project_id": "project:missing",
            "base_revision": "0" * 40,
            "write_paths": ["src", "src"],
            "idempotency_key": "schema:duplicates",
        },
    )
    assert duplicate_paths.structured_content == {
        "error": {"code": "invalid_argument", "message": "invalid argument"}
    }


@pytest.mark.parametrize("field", ("max_steps", "timeout_seconds", "max_branches"))
@pytest.mark.parametrize("value", (True, "1", 1.0))
def test_foundation_budget_does_not_coerce_non_integer_values(
    field: str,
    value: object,
) -> None:
    budget: dict[str, object] = {
        "max_steps": 1,
        "timeout_seconds": 1,
        "max_branches": 1,
    }
    budget[field] = value
    with pytest.raises(ValueError):
        server_module._FoundationBudget.model_validate(budget)


@pytest.mark.asyncio
async def test_catalog_validation_precedes_effect_and_invalid_output_fails_closed(
    config: HarnessConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ProbeTools:
        calls = 0

        def lease_workspace(self, *args: object) -> dict[str, object]:
            self.calls += 1
            raise AssertionError("invalid request reached effect")

        def inspect_run(self, run_id: str) -> dict[str, object]:
            self.calls += 1
            return {"private_source_body": "do not disclose"}

        def inspect_workspace(self, workspace_id: str) -> dict[str, object]:
            self.calls += 1
            return _valid_public_results()["workspace_summary"]

    probe = ProbeTools()
    monkeypatch.setattr(server_module, "FoundationTools", lambda *args: probe)
    server = create_orchestrator_server(config)

    rejected = await server.call_tool(
        "lease_workspace",
        {
            "project_id": "project:1",
            "base_revision": "0" * 40,
            "write_paths": ["src", "src"],
            "idempotency_key": "duplicate",
        },
    )
    assert rejected.structured_content == {
        "error": {"code": "invalid_argument", "message": "invalid argument"}
    }
    assert probe.calls == 0

    invalid_output = await server.call_tool("inspect_run", {"run_id": "run:1"})
    assert invalid_output.structured_content == {
        "error": {"code": "internal_error", "message": "internal error"}
    }
    assert "private_source_body" not in str(invalid_output)

    valid_output = await server.call_tool(
        "inspect_workspace", {"workspace_id": "lease:1"}
    )
    assert valid_output.structured_content == _valid_public_results()["workspace_summary"]
    assert probe.calls == 2


@pytest.mark.asyncio
async def test_real_run_inquiry_workspace_and_campaign_results_cross_validator(
    config: HarnessConfig,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init")
    git("config", "user.name", "Schema Validator")
    git("config", "user.email", "schema@example.test")
    (repository / ".gitignore").write_text(
        "/.agents\n/.claude\n/.codex\n/.unrest\n/.unrest-runtime\n/AGENTS.md\n",
        encoding="utf-8",
    )
    (repository / "artifact.txt").write_text("accepted\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "base")

    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    envelope = controller.start_project("schema result probe", str(repository))
    server = create_orchestrator_server(config, controller)
    mission_before = controller.store.load_state(envelope.projectId)

    inquiry = await server.call_tool(
        "open_inquiry",
        {
            "question": "What is bounded?",
            "budget": {"max_steps": 1, "timeout_seconds": 1},
            "idempotency_key": "real-inquiry",
        },
    )
    validate_public_result("open_inquiry", inquiry.structured_content)
    assert "error" not in inquiry.structured_content
    direct = FoundationTools(config, controller).open_inquiry(
        "What is bounded?",
        {"max_steps": 1, "timeout_seconds": 1},
        "real-inquiry",
    )
    assert json.dumps(direct, sort_keys=True, separators=(",", ":")) == json.dumps(
        inquiry.structured_content,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert controller.store.load_state(envelope.projectId) == mission_before

    base_revision = git("rev-parse", "HEAD")
    workspace_manager = WorkspaceManager(repository)
    lease = workspace_manager.lease_workspace(
        base_revision=base_revision,
        owner_id="worker:schema-probe",
        declared_write_paths=("artifact.txt",),
        capability_policy_digest="sha256:" + "2" * 64,
        duration_seconds=60,
        lease_id="lease:schema-probe",
        resource_budget=ResourceBudget(),
    )
    workspace_result = await server.call_tool(
        "inspect_workspace", {"workspace_id": lease.lease_id}
    )
    validate_public_result("inspect_workspace", workspace_result.structured_content)
    assert "error" not in workspace_result.structured_content

    evolution = EvolutionManager(repository)

    def digest(character: str) -> str:
        return "sha256:" + character * 64

    evolution.open_campaign(
        campaign_id="campaign:schema-probe",
        freeze=CampaignFreeze(
            accepted_revision=base_revision,
            accepted_working_point_digest=digest("a"),
            workload_digest=digest("b"),
            oracle_digest=digest("c"),
            author_policy_digest=digest("d"),
            evaluator_policy_digest=digest("e"),
            reviewer_policy_digest=digest("f"),
            capability_policy_digest=digest("1"),
            provider_configuration_digest=digest("2"),
            route_profile_digest=digest("3"),
            context_digest=digest("4"),
            environment_digest=digest("5"),
            secret_set_version_id="secret-set:schema:v1",
            author_id="worker:schema-author",
            evaluator_id="validator:schema-evaluator",
            reviewer_id="reviewer:schema-reviewer",
            budget_steps=1,
            seed=1,
            stopping_rule_digest=digest("6"),
            promotion_rule_digest=digest("7"),
            protected_paths=(".git", ".unrest", ".unrest-runtime"),
        ),
    )
    campaign = await server.call_tool(
        "inspect_campaign", {"campaign_id": "campaign:schema-probe"}
    )
    validate_public_result("inspect_campaign", campaign.structured_content)
    assert "error" not in campaign.structured_content

    async_workspace = tmp_path / "async-workspace"
    async_workspace.mkdir()
    queued = await server.call_tool(
        "submit_run",
        {
            "operation": "start_project",
            "arguments": {
                "brief": "async schema result probe",
                "workspace_dir": str(async_workspace),
            },
            "idempotency_key": "real-run",
        },
    )
    validate_public_result("submit_run", queued.structured_content)
    assert queued.structured_content["state"] == "queued"


@pytest.mark.asyncio
async def test_validator_has_role_specific_identity_and_shared_strict_protocol() -> None:
    worker = create_worker_server()
    validator = create_validator_server()

    assert worker.name == "unrest-worker"
    assert worker.instructions is not None
    assert "Mode: worker" in worker.instructions
    assert validator.name == "unrest-validator"
    assert validator.instructions is not None
    assert "Mode: validator" in validator.instructions
    assert "Mode: worker" not in validator.instructions
    assert await _tool_names(validator) == {
        "end_node",
        "report_supervision_checkpoint",
    }
    assert await _tool_contract(validator, "end_node") == await _tool_contract(
        worker, "end_node"
    )


@pytest.mark.asyncio
async def test_start_project_persists_validated_worker_overrides(
    config: HarnessConfig, workspace: Path
) -> None:
    config = replace(
        config,
        worker_provider_name="codex",
        worker_acp_command="codex-acp",
    )
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)

    await server.call_tool(
        "start_project",
        {
            "brief": "Ship it.",
            "workspace_dir": str(workspace),
            "worker_model": "gpt-test",
            "worker_reasoning_effort": "high",
        },
    )

    record = controller.store.list_projects()[0]
    assert record.worker_model == "gpt-test"
    assert record.worker_reasoning_effort == "high"


def test_start_project_rejects_override_for_non_codex_worker_without_persisting(
    config: HarnessConfig, workspace: Path
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )

    with pytest.raises(ToolError, match="invalid_worker_override_provider"):
        controller.start_project(
            "Ship it.",
            str(workspace),
            worker_reasoning_effort="high",
        )
    assert controller.store.list_projects() == []


def test_start_project_rejects_invalid_codex_worker_effort_without_persisting(
    config: HarnessConfig, workspace: Path
) -> None:
    config = replace(
        config,
        worker_provider_name="codex",
        worker_acp_command="codex-acp",
    )
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )

    with pytest.raises(ToolError, match="invalid_worker_reasoning_effort"):
        controller.start_project(
            "Ship it.",
            str(workspace),
            worker_reasoning_effort="ultra",
        )
    assert controller.store.list_projects() == []


@pytest.mark.asyncio
async def test_worker_tool_isolated() -> None:
    server = create_worker_server()
    assert await _tool_names(server) == {
        "end_node",
        "report_supervision_checkpoint",
    }


@pytest.mark.asyncio
async def test_terminal_reviewer_tool_isolated() -> None:
    server = create_terminal_reviewer_server()
    assert await _tool_names(server) == {
        "report_supervision_checkpoint",
        "submit_terminal_review",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["worker", "validator", "terminal_reviewer"])
async def test_all_role_checkpoint_tools_share_exact_controller_binding(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    project_id = controller.start_project("checkpoint", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-CHECKPOINT.md").write_text("# VAL-CHECKPOINT\n")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="worker-1",
                    type="work",
                    body="work",
                    targets=["VAL-CHECKPOINT"],
                    skill="worker",
                ),
                Task(
                    id="validator-1",
                    type="validate",
                    body="validate",
                    targets=["VAL-CHECKPOINT"],
                    skill="validator",
                    depends_on=["worker-1"],
                ),
            ]
        ),
    )
    attempt_id = "attempt-1"
    node_id = None if role == "terminal_reviewer" else f"{role}-1"
    terminal_review_id = attempt_id if role == "terminal_reviewer" else None
    monkeypatch.setenv("UNREST_HOME", str(config.harness_home))
    monkeypatch.setenv("UNREST_PROJECTS_DIR", str(config.projects_dir))
    monkeypatch.setenv("UNREST_PROJECT_ID", project_id)
    monkeypatch.setenv("UNREST_MISSION_ID", "mission-001")
    if node_id is not None:
        monkeypatch.setenv("UNREST_NODE_ID", node_id)
        monkeypatch.setenv(
            "UNREST_HANDOFF_PATH",
            str(controller.store.attempt_path(project_id, "mission-001", attempt_id, node_id)),
        )
    else:
        monkeypatch.setenv(
            "UNREST_TERMINAL_REVIEW_PATH",
            str(controller.store.terminal_review_path(project_id, "mission-001", attempt_id)),
        )
    snapshot = {
        "attempt_id": attempt_id,
        "blocker_code": None,
        "checkpoint_requests": 0,
        "checkpoint_sequence": 1,
        "completed_target_ids": [],
        "elapsed_nanoseconds": 0,
        "last_effect_sequence": 0,
        "mission_id": "mission-001",
        "node_id": node_id,
        "phase": "waiting_at_checkpoint",
        "project_id": project_id,
        "remaining_target_ids": ["VAL-CHECKPOINT"],
        "role": role,
        "scope_status": "in_scope",
        "supervision_status": "waiting",
        "terminal_review_id": terminal_review_id,
    }
    server = {
        "worker": create_worker_server,
        "validator": create_validator_server,
        "terminal_reviewer": create_terminal_reviewer_server,
    }[role]()
    MissionCoordinator(
        controller.store,
        project_id,
        controller.dispatcher,
        controller.terminal_reviewer,
    )._begin_supervision_attempt(
        "mission-001",
        attempt_id=attempt_id,
        role=role,
        assigned_target_ids=["VAL-CHECKPOINT"],
        node_id=node_id,
        started_nanoseconds=0,
    )
    pending = asyncio.create_task(
        server.call_tool("report_supervision_checkpoint", {"snapshot": snapshot})
    )
    for _ in range(100):
        active = controller.inspect_project(project_id).active_attempts
        if active and active[0].checkpoint_sequence == 1:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("checkpoint was not published")
    controller.steer_attempt(
        SteeringRequest(
            project_id=project_id,
            mission_id="mission-001",
            node_id=node_id,
            terminal_review_id=terminal_review_id,
            attempt_id=attempt_id,
            checkpoint_sequence=1,
            action="continue",
            actor="orchestrator",
        )
    )
    assert (await pending).structured_content == {
        "action": "continue",
        "body": None,
        "code": "continued",
    }


@pytest.mark.asyncio
async def test_end_node_refuses_one_invalid_completion_then_accepts_same_attempt(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    project_id = controller.start_project("completion", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-COMPLETION.md").write_text("# VAL-COMPLETION\n")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="validator-1",
                    type="validate",
                    body="validate",
                    targets=["VAL-COMPLETION"],
                    skill="validator",
                ),
                Task(
                    id="worker-owner",
                    type="work",
                    body="work",
                    targets=["VAL-COMPLETION"],
                    skill="worker",
                ),
            ]
        ),
    )
    attempt_id = "attempt-completion"
    handoff_path = controller.store.attempt_path(
        project_id, "mission-001", attempt_id, "validator-1"
    )
    monkeypatch.setenv("UNREST_HOME", str(config.harness_home))
    monkeypatch.setenv("UNREST_PROJECTS_DIR", str(config.projects_dir))
    monkeypatch.setenv("UNREST_PROJECT_ID", project_id)
    monkeypatch.setenv("UNREST_MISSION_ID", "mission-001")
    monkeypatch.setenv("UNREST_NODE_ID", "validator-1")
    monkeypatch.setenv("UNREST_NODE_TYPE", "validate")
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    server = create_validator_server()
    arguments = {
        "done": True,
        "report": "content is deliberately not inspected",
        "items": [{"item_id": "VAL-COMPLETION", "passed": True}],
        "passed": True,
    }
    refused = await server.call_tool(
        "end_node", {**arguments, "completion": {}}
    )
    assert refused.structured_content == {
        "recorded": False,
        "code": "completion_refused",
        "fields": [
            "attempt_id",
            "blocker_code",
            "schema",
            "scope_status",
            "targets",
            "task_type",
        ],
    }
    assert not handoff_path.exists()
    refusal_paths = list(
        controller.store.mission_runtime_dir(project_id, "mission-001").glob(
            "completion-refusals/*.json"
        )
    )
    assert len(refusal_paths) == 1
    refusal = json.loads(refusal_paths[0].read_text(encoding="utf-8"))
    assert refusal == {
        "attempt_id": attempt_id,
        "carrier_schema": "unrest.v045.node-completion.v1",
        "consumed": True,
        "mission_id": "mission-001",
        "node_id": "validator-1",
        "project_id": project_id,
        "schema": "unrest.v045.completion-refusal.v1",
    }
    assert refusal_paths[0].stat().st_mode & 0o777 == 0o600
    assert "content is deliberately not inspected" not in refusal_paths[0].read_text(
        encoding="utf-8"
    )
    accepted = await server.call_tool("end_node", arguments)
    assert accepted.structured_content["recorded"] is True
    assert not refusal_paths[0].exists()
    handoff = controller.store.read_attempt(
        project_id, "mission-001", attempt_id, "validator-1"
    )
    assert isinstance(handoff, ValidateHandoff)
    assert handoff.done is True and handoff.passed is True

    explicit_attempt = "attempt-explicit"
    explicit_path = controller.store.attempt_path(
        project_id, "mission-001", explicit_attempt, "validator-1"
    )
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(explicit_path))
    verdict_digest = hashlib.sha256(
        b'[["VAL-COMPLETION",true]]\n'
    ).hexdigest()
    return_ref = f"verdict:sha256:{verdict_digest}"
    evidence_digest = hashlib.sha256(
        (
            json.dumps(
                {
                    "attempt_id": explicit_attempt,
                    "return_ref": return_ref,
                    "status": "passed",
                    "target_id": "VAL-COMPLETION",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()
    explicit = {
        "schema": "unrest.v045.node-completion.v1",
        "attempt_id": explicit_attempt,
        "task_type": "validate",
        "targets": [
            {
                "target_id": "VAL-COMPLETION",
                "status": "passed",
                "return_ref": return_ref,
                "evidence_refs": [f"evidence:sha256:{evidence_digest}"],
            }
        ],
        "scope_status": "in_scope",
        "blocker_code": None,
    }
    explicit_result = await create_validator_server().call_tool(
        "end_node", {**arguments, "completion": explicit}
    )
    assert explicit_result.structured_content["recorded"] is True

    failed_attempt = "attempt-double-invalid"
    failed_path = controller.store.attempt_path(
        project_id, "mission-001", failed_attempt, "validator-1"
    )
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(failed_path))
    first_invalid = await create_validator_server().call_tool(
        "end_node", {**arguments, "completion": {}}
    )
    assert first_invalid.structured_content["recorded"] is False
    second_invalid = await create_validator_server().call_tool(
        "end_node", {**arguments, "completion": {}}
    )
    assert second_invalid.structured_content["recorded"] is True
    failed_handoff = controller.store.read_attempt(
        project_id, "mission-001", failed_attempt, "validator-1"
    )
    assert isinstance(failed_handoff, ValidateHandoff)
    assert failed_handoff.done is False
    assert failed_handoff.request_attention is True
    assert not list(
        controller.store.mission_runtime_dir(project_id, "mission-001").glob(
            "completion-refusals/*.json"
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "runtime_assignment",
    (
        "not-json",
        '{"task_type":"validate","targets":["VAL-OTHER"]}',
        '{"extra":true,"task_type":"work","targets":["VAL-OTHER"]}',
    ),
    ids=("malformed", "mismatched", "generic"),
)
async def test_canonical_task_truth_ignores_runtime_assignment_envelope(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_assignment: str,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"],
        cwd=workspace,
        check=True,
    )
    store = ProjectStore(config)
    project_id = "canonical-assignment"
    store.create_project("canonical assignment", workspace, project_id=project_id)
    task = Task(
        id="worker-node",
        type="work",
        body="canonical",
        targets=["VAL-CANONICAL"],
        skill="test",
    )
    store.save_task_list(project_id, "mission-001", TaskList(tasks=[task]))
    attempt_id = "canonical-attempt"
    handoff_path = store.attempt_path(
        project_id, "mission-001", attempt_id, task.id
    )
    for key, value in {
        "UNREST_HOME": str(config.harness_home),
        "UNREST_PROJECTS_DIR": str(config.projects_dir),
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": task.id,
        "UNREST_NODE_TYPE": task.type,
        "UNREST_HANDOFF_PATH": str(handoff_path),
        "UNREST_NODE_ASSIGNMENT": runtime_assignment,
    }.items():
        monkeypatch.setenv(key, value)

    result = await create_worker_server().call_tool(
        "end_node", {"done": True, "report": "canonical truth won"}
    )

    assert result.structured_content["recorded"] is True
    handoff = store.read_attempt(
        project_id, "mission-001", attempt_id, task.id
    )
    assert isinstance(handoff, WorkHandoff)
    assert handoff.done is True
    assert handoff.report == "canonical truth won"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("runtime_assignment", "expected_field"),
    (
        ("not-json", "targets"),
        ('{"task_type":"validate","targets":["VAL-A"]}', "task_type"),
        ('{"extra":true,"task_type":"work","targets":["VAL-A"]}', "targets"),
        ('{"task_type":"work","targets":["VAL-B","VAL-A"]}', "targets"),
        ('{"task_type":"work","targets":["VAL-A","VAL-A"]}', "targets"),
    ),
    ids=("malformed", "mismatched", "generic", "unsorted", "duplicate"),
)
async def test_missing_task_truth_strictly_validates_runtime_assignment(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_assignment: str,
    expected_field: str,
) -> None:
    store = ProjectStore(config)
    project_id = "fallback-assignment"
    store.create_project("fallback assignment", workspace, project_id=project_id)
    attempt_id = "fallback-attempt"
    node_id = "worker-node"
    handoff_path = store.attempt_path(
        project_id, "mission-001", attempt_id, node_id
    )
    for key, value in {
        "UNREST_HOME": str(config.harness_home),
        "UNREST_PROJECTS_DIR": str(config.projects_dir),
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": "work",
        "UNREST_HANDOFF_PATH": str(handoff_path),
        "UNREST_NODE_ASSIGNMENT": runtime_assignment,
    }.items():
        monkeypatch.setenv(key, value)

    result = await create_worker_server().call_tool(
        "end_node", {"done": True, "report": "must not hand off"}
    )

    assert result.structured_content == {
        "recorded": False,
        "code": "completion_refused",
        "fields": [expected_field],
    }
    assert not handoff_path.exists()


def test_missing_task_truth_derives_exact_work_completion_from_closed_envelope(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"],
        cwd=workspace,
        check=True,
    )
    store = ProjectStore(config)
    project_id = "derived-assignment"
    store.create_project("derived assignment", workspace, project_id=project_id)
    attempt_id = "derived-attempt"
    node_id = "worker-node"
    handoff_path = store.attempt_path(
        project_id, "mission-001", attempt_id, node_id
    )
    for key, value in {
        "UNREST_HOME": str(config.harness_home),
        "UNREST_PROJECTS_DIR": str(config.projects_dir),
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": "work",
        "UNREST_HANDOFF_PATH": str(handoff_path),
        "UNREST_NODE_ASSIGNMENT": '{"targets":["VAL-A","VAL-B"],"task_type":"work"}',
    }.items():
        monkeypatch.setenv(key, value)

    derived, derived_store = server_module._completion_context(
        node_id=node_id,
        node_type="work",
        attempt_id=attempt_id,
        handoff_path=str(handoff_path),
        items=[],
        done=True,
    )

    assert derived_store is not None
    assert derived is not None
    assert derived.model_dump(mode="json", by_alias=True) == _completion_oracle(
        workspace=workspace,
        attempt_id=attempt_id,
        task_type="work",
        targets=["VAL-A", "VAL-B"],
        items=[],
        done=True,
    )


def test_real_worker_mcp_refuses_missing_task_truth_without_git_carrier(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    store = ProjectStore(config)
    project_id = "real-fallback-assignment"
    store.create_project("real fallback assignment", workspace, project_id=project_id)
    attempt_id = "real-fallback-attempt"
    node_id = "worker-node"
    handoff_path = store.attempt_path(
        project_id, "mission-001", attempt_id, node_id
    )
    role_environment = {
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": "work",
        "UNREST_HANDOFF_PATH": str(handoff_path),
        "UNREST_NODE_ASSIGNMENT": '{"targets":["VAL-A"],"task_type":"work"}',
    }

    with _http_server_process(
        config,
        workspace,
        mode="worker",
        role_environment=role_environment,
    ) as (process, url):
        result = _call_process_mcp(
            url, "end_node", {"done": True, "report": "must derive or refuse"}
        )
        assert process.poll() is None

    assert result == {
        "recorded": False,
        "code": "completion_refused",
        "fields": ["return_ref"],
    }
    assert not handoff_path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["work", "validate"])
@pytest.mark.parametrize(
    ("case", "expected_fields"),
    [
        ("missing", ["schema"]),
        ("unknown", ["completion"]),
        ("null", ["scope_status"]),
        ("wrong_type", ["completion"]),
        ("order", ["targets"]),
        ("duplicate", ["targets"]),
        ("coverage", ["targets"]),
        ("status", ["status"]),
        ("attempt", ["attempt_id"]),
        ("return", ["return_ref"]),
        ("return_uppercase", ["return_ref"]),
        ("evidence", ["evidence_refs"]),
        ("evidence_locator", ["evidence_refs"]),
        ("evidence_multiple", ["evidence_refs"]),
        ("scope", ["request_attention"]),
        ("blocker", ["request_attention"]),
        ("items", ["items"]),
        ("passed", ["passed"]),
        ("done", ["done", "status"]),
    ],
)
async def test_completion_carrier_exhaustive_structural_matrix(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    case: str,
    expected_fields: list[str],
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"],
        cwd=workspace,
        check=True,
    )
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    project_id = controller.start_project(f"matrix-{role}-{case}", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    for target in ("VAL-A", "VAL-B"):
        (contract / f"{target}.md").write_text(f"# {target}\n", encoding="utf-8")
    node_id = f"{role}-node"
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id=node_id,
                    type=role,  # type: ignore[arg-type]
                    body="matrix",
                    targets=["VAL-A", "VAL-B"],
                    skill="test",
                ),
                *(
                    [
                        Task(
                            id="work-owner",
                            type="work",
                            body="owner",
                            targets=["VAL-A", "VAL-B"],
                            skill="test",
                        )
                    ]
                    if role == "validate"
                    else [
                        Task(
                            id="validator-owner",
                            type="validate",
                            body="validator",
                            targets=["VAL-A", "VAL-B"],
                            skill="test",
                        )
                    ]
                ),
            ]
        ),
    )
    attempt_id = f"attempt-{role}-{case}"
    handoff_path = controller.store.attempt_path(
        project_id, "mission-001", attempt_id, node_id
    )
    for key, value in {
        "UNREST_HOME": str(config.harness_home),
        "UNREST_PROJECTS_DIR": str(config.projects_dir),
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": role,
        "UNREST_HANDOFF_PATH": str(handoff_path),
    }.items():
        monkeypatch.setenv(key, value)
    items = [
        ValidationItem(item_id="VAL-A", passed=True),
        ValidationItem(item_id="VAL-B", passed=False),
    ] if role == "validate" else []
    completion: object = _completion_oracle(
        workspace=workspace,
        attempt_id=attempt_id,
        task_type=role,
        targets=["VAL-A", "VAL-B"],
        items=items,
        done=True,
    )
    arguments: dict[str, object] = {
        "done": True,
        "report": "PROSE_CANARY_never_structurally_read",
        "completion": completion,
    }
    if role == "validate":
        arguments.update(
            items=[item.model_dump(mode="json") for item in items],
            passed=False,
        )
    carrier = completion
    assert isinstance(carrier, dict)
    if case == "missing":
        carrier.pop("schema")
    elif case == "unknown":
        carrier["unexpected"] = "value"
    elif case == "null":
        carrier["scope_status"] = None
    elif case == "wrong_type":
        arguments["completion"] = []
    elif case == "order":
        carrier["targets"].reverse()
    elif case == "duplicate":
        carrier["targets"].append(dict(carrier["targets"][0]))
    elif case == "coverage":
        carrier["targets"].pop()
        if role == "validate":
            expected_fields = ["passed", "targets"]
    elif case == "status":
        carrier["targets"][0]["status"] = (
            "failed" if carrier["targets"][0]["status"] != "failed" else "passed"
        )
    elif case == "attempt":
        carrier["attempt_id"] = "different-attempt"
    elif case == "return":
        carrier["targets"][0]["return_ref"] = (
            "git:" + "0" * 40
            if role == "work"
            else "verdict:sha256:" + "0" * 64
        )
    elif case == "return_uppercase":
        carrier["targets"][0]["return_ref"] = (
            "git:" + "A" * 40
            if role == "work"
            else "verdict:sha256:" + "A" * 64
        )
    elif case == "evidence":
        carrier["targets"][0]["evidence_refs"] = ["evidence:sha256:" + "0" * 64]
    elif case == "evidence_locator":
        carrier["targets"][0]["evidence_refs"] = ["evidence:/tmp/canary"]
    elif case == "evidence_multiple":
        carrier["targets"][0]["evidence_refs"].append(
            "evidence:sha256:" + "0" * 64
        )
    elif case == "scope":
        carrier["scope_status"] = "uncertain"
    elif case == "blocker":
        carrier["blocker_code"] = "authority_required"
    elif case == "items":
        if role == "validate":
            arguments["items"] = [{"item_id": "VAL-A", "passed": True}]
        else:
            carrier["targets"][0]["target_id"] = "VAL-Z"
            expected_fields = ["targets"]
    elif case == "passed":
        if role == "validate":
            arguments["passed"] = True
        else:
            carrier["targets"][0]["return_ref"] = "unbound"
            expected_fields = ["return_ref"]
    elif case == "done":
        if role == "work":
            arguments["done"] = False
            expected_fields = ["done", "evidence_refs", "status"]
        else:
            carrier["targets"][0]["return_ref"] = "unbound"
            expected_fields = ["return_ref"]

    result = await (
        create_validator_server() if role == "validate" else create_worker_server()
    ).call_tool("end_node", arguments)
    assert result.structured_content == {
        "recorded": False,
        "code": "completion_refused",
        "fields": sorted(expected_fields),
    }
    assert not handoff_path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["work", "validate"])
@pytest.mark.parametrize("repair", [True, False], ids=["valid-repair", "second-invalid"])
async def test_completion_refusal_survives_server_restart(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    repair: bool,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"],
        cwd=workspace,
        check=True,
    )
    store = ProjectStore(config)
    project_id = f"restart-{role}-{repair}"
    store.create_project("restart", workspace, project_id=project_id)
    node_id = f"{role}-node"
    store.save_task_list(
        project_id,
        "mission-001",
        TaskList(
            tasks=[
                Task(
                    id=node_id,
                    type=role,  # type: ignore[arg-type]
                    body="restart",
                    targets=["VAL-A"],
                    skill="test",
                )
            ]
        ),
    )
    attempt_id = "same-exact-attempt"
    handoff_path = store.attempt_path(project_id, "mission-001", attempt_id, node_id)
    for key, value in {
        "UNREST_HOME": str(config.harness_home),
        "UNREST_PROJECTS_DIR": str(config.projects_dir),
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": role,
        "UNREST_HANDOFF_PATH": str(handoff_path),
    }.items():
        monkeypatch.setenv(key, value)
    arguments: dict[str, object] = {
        "done": True,
        "report": "RESTART_PRIVACY_CANARY",
    }
    if role == "validate":
        arguments.update(
            items=[{"item_id": "VAL-A", "passed": False}],
            passed=False,
        )
    tasks_path = store.mission_runtime_dir(project_id, "mission-001") / "tasks.json"
    task_digest = hashlib.sha256(tasks_path.read_bytes()).hexdigest()

    first_server = create_validator_server() if role == "validate" else create_worker_server()
    first = await first_server.call_tool(
        "end_node", {**arguments, "completion": {}}
    )
    assert first.structured_content["recorded"] is False
    assert hashlib.sha256(tasks_path.read_bytes()).hexdigest() == task_digest
    assert not handoff_path.exists()
    marker = next(
        store.mission_runtime_dir(project_id, "mission-001").glob(
            "completion-refusals/*.json"
        )
    )
    assert "RESTART_PRIVACY_CANARY" not in marker.read_text(encoding="utf-8")

    # Constructing a fresh server models coordinator/run-control reconstruction;
    # the private marker, not process memory, carries the consumed quota.
    restarted = create_validator_server() if role == "validate" else create_worker_server()
    second_arguments = dict(arguments)
    if not repair:
        second_arguments["completion"] = {}
    second = await restarted.call_tool("end_node", second_arguments)
    assert second.structured_content["recorded"] is True
    assert not marker.exists()
    handoff = store.read_attempt(project_id, "mission-001", attempt_id, node_id)
    assert handoff.attempt_id == attempt_id
    assert handoff.done is repair
    assert handoff.request_attention is not repair


@pytest.mark.parametrize(
    "recovery_state",
    (
        "orphan-before-link",
        "linked-before-directory-fsync",
        "linked-after-directory-fsync",
        "corrupt-final",
    ),
)
def test_completion_refusal_marker_recovers_exact_crash_states(
    config: HarnessConfig,
    recovery_state: str,
) -> None:
    store = ProjectStore(config)
    project_id = "marker-recovery"
    mission_id = "mission-001"
    node_id = "worker-node"
    attempt_id = "exact-attempt"
    path = server_module._completion_refusal_path(
        store, project_id, mission_id, attempt_id, node_id
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    expected = (
        json.dumps(
            {
                "attempt_id": attempt_id,
                "carrier_schema": "unrest.v045.node-completion.v1",
                "consumed": True,
                "mission_id": mission_id,
                "node_id": node_id,
                "project_id": project_id,
                "schema": "unrest.v045.completion-refusal.v1",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    orphan = path.parent / f".{path.name}.crashed.tmp"
    if recovery_state == "orphan-before-link":
        orphan.write_bytes(b"private partial temporary")
    elif recovery_state in {
        "linked-before-directory-fsync",
        "linked-after-directory-fsync",
    }:
        path.write_bytes(expected)
        path.chmod(0o600)
        orphan.write_bytes(expected)
    else:
        path.write_bytes(b'{"schema":"wrong"}\n')
        path.chmod(0o644)

    consumed = server_module._consume_completion_refusal(
        path,
        project_id=project_id,
        mission_id=mission_id,
        node_id=node_id,
        attempt_id=attempt_id,
    )

    assert consumed is (recovery_state == "orphan-before-link")
    assert path.read_bytes() == expected
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(path.parent.glob(f".{path.name}.*.tmp"))
    assert (
        server_module._consume_completion_refusal(
            path,
            project_id=project_id,
            mission_id=mission_id,
            node_id=node_id,
            attempt_id=attempt_id,
        )
        is False
    )


def test_completion_refusal_clear_is_idempotent_when_unlink_faults(
    config: HarnessConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(config)
    path = server_module._completion_refusal_path(
        store, "project", "mission", "attempt", "node"
    )
    assert server_module._consume_completion_refusal(
        path,
        project_id="project",
        mission_id="mission",
        node_id="node",
        attempt_id="attempt",
    )
    original_unlink = Path.unlink

    def fail_marker_unlink(candidate: Path, *args: object, **kwargs: object) -> None:
        if candidate == path:
            raise OSError("injected clear fault")
        original_unlink(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_marker_unlink)
    server_module._clear_completion_refusal(path)
    assert path.is_file()
    monkeypatch.setattr(Path, "unlink", original_unlink)
    server_module._clear_completion_refusal(path)
    server_module._clear_completion_refusal(path)
    assert not path.exists()


def test_structurally_valid_defect_requires_independent_validator_and_gate(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    (workspace / "product.txt").write_text("DEFECT\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(["git", "add", "product.txt"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "defective candidate"],
        cwd=workspace,
        check=True,
    )
    dispatches: list[str] = []
    process_identities: list[tuple[str, int, int]] = []

    class ProcessDispatcher:
        supports_isolated_workspaces = True

        def __init__(self) -> None:
            self.store = ProjectStore(config)

        def dispatch(self, request: DispatchRequest) -> WorkHandoff | ValidateHandoff:
            dispatches.append(request.task.type)
            handoff_path = self.store.attempt_path(
                request.project_id,
                request.mission_id,
                request.spawn_ts,
                request.task.id,
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                    "UNREST_HOME": str(config.harness_home),
                    "UNREST_PROJECTS_DIR": str(config.projects_dir),
                    "UNREST_PROJECT_ID": request.project_id,
                    "UNREST_MISSION_ID": request.mission_id,
                    "UNREST_NODE_ID": request.task.id,
                    "UNREST_NODE_TYPE": request.task.type,
                    "UNREST_HANDOFF_PATH": str(handoff_path),
                    "UNREST_WORKSPACE": str(workspace),
                }
            )
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    """
import asyncio
import os
from pathlib import Path
from unrest_harness.server import create_validator_server, create_worker_server

role = os.environ["UNREST_NODE_TYPE"]
if role == "validate":
    assert (Path(os.environ["UNREST_WORKSPACE"]) / "product.txt").read_text() == "DEFECT\\n"
    arguments = {
        "done": True,
        "report": "independent validator found the defect",
        "items": [{"item_id": "VAL-DEFECT", "passed": False}],
        "passed": False,
    }
    server = create_validator_server()
else:
    arguments = {
        "done": True,
        "report": "claimed complete despite substantive defect",
    }
    server = create_worker_server()
result = asyncio.run(server.call_tool("end_node", arguments))
assert result.structured_content["recorded"] is True
""",
                ],
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            pgid = os.getpgid(child.pid)
            output, _ = child.communicate(timeout=20)
            assert child.returncode == 0, output.decode(errors="replace")
            process_identities.append((request.task.type, child.pid, pgid))
            return self.store.read_attempt(
                request.project_id,
                request.mission_id,
                request.spawn_ts,
                request.task.id,
            )

    class ReviewerTrap:
        def review(self, project_id: str, mission_id: str, spawn_ts: str) -> TerminalReviewHandoff:
            raise AssertionError("terminal reviewer must not run before a passing gate")

    controller = ProjectController(
        config,
        ProcessDispatcher(),
        ReviewerTrap(),
    )
    project_id = controller.start_project("defective candidate", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-DEFECT.md").write_text("# VAL-DEFECT\n", encoding="utf-8")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(id="work", type="work", body="implement", targets=["VAL-DEFECT"], skill="test"),
                Task(id="validate", type="validate", body="inspect", targets=["VAL-DEFECT"], skill="test", depends_on=["work"]),
                Task(id="gate", type="gate", body="", targets=["VAL-DEFECT"], skill=None, depends_on=["validate"]),
            ]
        ),
    )

    result = controller.advance_project(project_id)

    assert dispatches == ["work", "validate"]
    assert [role for role, _, _ in process_identities] == ["work", "validate"]
    assert len({pid for _, pid, _ in process_identities}) == 2
    assert all(pid == pgid for _, pid, pgid in process_identities)
    assert result.state.state == "attention_needed"
    assert controller.store.load_contract_state(
        project_id, "mission-001"
    ).items["VAL-DEFECT"].status == "failed"
    attention = controller.store.load_attention(project_id)
    assert len(attention) == 1
    assert attention[0].kind == "gate_failed"


@pytest.mark.asyncio
async def test_completion_preflight_is_invariant_to_prose_and_evidence_body(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"],
        cwd=workspace,
        check=True,
    )
    store = ProjectStore(config)
    task = Task(
        id="work-node",
        type="work",
        body="content differential",
        targets=["VAL-A"],
        skill="test",
    )
    attempt_id = "same-attempt"
    results: list[dict[str, object]] = []
    reports = ["optimistic prose", "pessimistic prose with DEFECT_CANARY"]
    carrier_bytes: list[bytes] = []
    for index, report in enumerate(reports):
        project_id = f"content-differential-{index}"
        store.create_project("content differential", workspace, project_id=project_id)
        store.save_task_list(
            project_id, "mission-001", TaskList(tasks=[task])
        )
        handoff_path = store.attempt_path(
            project_id, "mission-001", attempt_id, task.id
        )
        for key, value in {
            "UNREST_HOME": str(config.harness_home),
            "UNREST_PROJECTS_DIR": str(config.projects_dir),
            "UNREST_PROJECT_ID": project_id,
            "UNREST_MISSION_ID": "mission-001",
            "UNREST_NODE_ID": task.id,
            "UNREST_NODE_TYPE": task.type,
            "UNREST_HANDOFF_PATH": str(handoff_path),
        }.items():
            monkeypatch.setenv(key, value)
        carrier = _completion_oracle(
            workspace=workspace,
            attempt_id=attempt_id,
            task_type=task.type,
            targets=task.targets,
            items=[],
            done=True,
        )
        carrier_bytes.append(
            json.dumps(carrier, sort_keys=True, separators=(",", ":")).encode("ascii")
        )
        (workspace / "referenced-evidence-body.txt").write_text(
            f"body variant {index}: EVIDENCE_CONTENT_CANARY\n", encoding="utf-8"
        )
        outcome = await create_worker_server().call_tool(
            "end_node",
            {"done": True, "report": report, "completion": carrier},
        )
        results.append(outcome.structured_content)
        assert store.read_attempt(
            project_id, "mission-001", attempt_id, task.id
        ).report == report

    assert carrier_bytes[0] == carrier_bytes[1]
    assert results[0] == results[1]


# ---------------------------------------------------------------------------
# CLI startup boundary
# ---------------------------------------------------------------------------


_STARTUP_REJECTION = "unrest-server: startup configuration rejected\n"


def _install_startup_rejection_traps(
    monkeypatch: pytest.MonkeyPatch,
    markers: list[str],
) -> None:
    def fastmcp_trap(*args, **kwargs):
        markers.append("fastmcp")
        raise AssertionError("FastMCP construction reached after startup rejection")

    def dispatcher_trap(*args, **kwargs):
        markers.append("dispatch")
        raise AssertionError("dispatch construction reached after startup rejection")

    monkeypatch.setattr(server_module, "FastMCP", fastmcp_trap)
    monkeypatch.setattr(acp_runner, "ACPNodeDispatcher", dispatcher_trap)
    monkeypatch.setattr(acp_runner, "ACPTerminalReviewer", dispatcher_trap)


def _invalid_policy_fixture(tmp_path: Path, variant: str) -> Path:
    source = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    root = tmp_path / "bundled"
    shutil.copytree(source, root)
    path = root / "policies" / "role-capabilities.v1.json"
    if variant == "symlink-root":
        linked = tmp_path / "linked"
        linked.symlink_to(root, target_is_directory=True)
        return linked
    if variant == "dot-dot-root":
        return root / "policies" / ".."
    text = path.read_text(encoding="utf-8")
    if variant == "duplicate-member":
        text = text.replace(
            '"schema_version": 1',
            '"schema_version": 1,\n  "schema_version": 1',
            1,
        )
    else:
        document = json.loads(text)
        if variant == "unknown-field":
            document["unknown"] = True
        elif variant == "unsupported-version":
            document["schema_version"] = 2
        else:
            document["profiles"]["safe"]["worker"]["process"]["enabled"] = "true"
        text = json.dumps(document, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "mode", ("orchestrator", "worker", "validator", "terminal-reviewer")
)
@pytest.mark.parametrize(
    "variant",
    (
        "unknown-field",
        "unsupported-version",
        "duplicate-member",
        "malformed-type",
        "symlink-root",
        "dot-dot-root",
    ),
)
def test_every_mode_rejects_malformed_injected_policy_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    variant: str,
) -> None:
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    root = _invalid_policy_fixture(tmp_path, variant)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main(bundled_dir=root)

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert "Traceback" not in captured.err
    assert markers == []


@pytest.mark.parametrize(
    ("mode", "provider_selector"),
    (
        ("orchestrator", "UNREST_ORCHESTRATOR_PROVIDER"),
        ("worker", "UNREST_WORKER_PROVIDER"),
        ("validator", "UNREST_VALIDATOR_PROVIDER"),
        ("terminal-reviewer", "UNREST_TERMINAL_REVIEWER_PROVIDER"),
    ),
)
def test_every_mode_rejects_its_unknown_provider_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    provider_selector: str,
) -> None:
    secret = "known-provider-credential-value"
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    monkeypatch.setenv(provider_selector, secret)
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert secret not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert markers == []


@pytest.mark.parametrize(
    "mode", ("orchestrator", "worker", "validator", "terminal-reviewer")
)
@pytest.mark.parametrize(
    "invalid_environment",
    (
        {"UNREST_CAPABILITY_PROFILE": "known-profile-credential-value"},
        {"UNREST_CAPABILITY_POLICY_VERSION": "known-version-credential-value"},
        {"UNREST_CAPABILITY_POLICY_VERSION": "2"},
        {"UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED": "0"},
        {"UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED": "1"},
        {"UNREST_CAPABILITY_PROFILE": UNSAFE_DEVELOPMENT_PROFILE},
        {"UNREST_UNKNOWN_UNSAFE_OPT_IN": "1"},
    ),
)
def test_every_mode_rejects_invalid_capability_startup_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    invalid_environment: dict[str, str],
) -> None:
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    for name, value in invalid_environment.items():
        monkeypatch.setenv(name, value)
    supplied = next(iter(invalid_environment.values()))
    monkeypatch.setenv("OPENAI_API_KEY", supplied)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert supplied not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert markers == []


@pytest.mark.parametrize(
    "mode", ("orchestrator", "worker", "validator", "terminal-reviewer")
)
@pytest.mark.parametrize(
    "variable",
    (
        "UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS",
        "UNREST_WORKER_REASONING_EFFORT",
        "UNREST_VALIDATOR_REASONING_EFFORT",
        "UNREST_TERMINAL_REVIEWER_REASONING_EFFORT",
    ),
)
def test_every_mode_bounds_value_configuration_rejection_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    variable: str,
) -> None:
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    sentinel = f"invalid-{mode}-{variable.lower()}-sentinel"
    monkeypatch.setenv(variable, sentinel)
    monkeypatch.setenv("OPENAI_API_KEY", sentinel)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert sentinel not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert markers == []


class _RunRecordingServer:
    def __init__(self, markers: list[str], mode: str) -> None:
        self._markers = markers
        self._mode = mode

    def run(self, **kwargs) -> None:
        self._markers.append(f"run:{self._mode}:{kwargs['transport']}")


@pytest.mark.parametrize(
    "mode", ("orchestrator", "worker", "validator", "terminal-reviewer")
)
@pytest.mark.parametrize("profile", ("safe", UNSAFE_DEVELOPMENT_PROFILE))
def test_every_mode_reaches_server_run_for_supported_profiles(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    profile: str,
) -> None:
    markers: list[str] = []
    monkeypatch.setenv("UNREST_CAPABILITY_PROFILE", profile)
    if profile == UNSAFE_DEVELOPMENT_PROFILE:
        monkeypatch.setenv("UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    def server_factory(*args, **kwargs):
        markers.append(f"construct:{mode}")
        return _RunRecordingServer(markers, mode)

    monkeypatch.setattr(server_module, f"create_{mode.replace('-', '_')}_server", server_factory)
    if mode == "orchestrator":
        monkeypatch.setattr(
            acp_runner,
            "ACPNodeDispatcher",
            lambda config: markers.append("dispatch") or object(),
        )
        monkeypatch.setattr(
            acp_runner,
            "ACPTerminalReviewer",
            lambda config: markers.append("reviewer") or object(),
        )

    server_module.main()

    if mode == "orchestrator":
        assert markers == [
            "dispatch",
            "reviewer",
            "construct:orchestrator",
            "run:orchestrator:stdio",
        ]
    else:
        assert markers == [f"construct:{mode}", f"run:{mode}:stdio"]


# ---------------------------------------------------------------------------
# end_node writes to UNREST_HANDOFF_PATH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_node_writes_handoff_file(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.setenv("UNREST_NODE_ID", "w1")
    server = create_worker_server()
    await server.call_tool(
        "end_node",
        {"done": True, "report": "ok"},
    )
    assert handoff_path.exists()
    data = json.loads(handoff_path.read_text())
    assert data == {
        "node_id": "w1",
        "attempt_id": "handoff",
        "done": True,
        "report": "ok",
        "request_attention": False,
    }


@pytest.mark.asyncio
async def test_end_node_validate_writes_items(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "validate")
    monkeypatch.setenv("UNREST_NODE_ID", "v1")
    server = create_validator_server()
    await server.call_tool(
        "end_node",
        {
            "done": True,
            "report": "audited",
            "items": [{"item_id": "VAL-001", "passed": True}],
            "passed": True,
        },
    )
    data = json.loads(handoff_path.read_text())
    assert data["items"][0]["item_id"] == "VAL-001"
    assert data["passed"] is True


@pytest.mark.asyncio
async def test_end_node_requires_env_node_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(tmp_path / "h.json"))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.delenv("UNREST_NODE_ID", raising=False)
    server = create_worker_server()
    with pytest.raises(Exception):
        await server.call_tool(
            "end_node",
            {"done": True, "report": ""},
        )


@pytest.mark.asyncio
async def test_end_node_idempotent_overwrite(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.setenv("UNREST_NODE_ID", "w1")
    server = create_worker_server()
    await server.call_tool(
        "end_node", {"done": True, "report": "first"}
    )
    await server.call_tool(
        "end_node", {"done": True, "report": "second"}
    )
    assert json.loads(handoff_path.read_text())["report"] == "second"


@pytest.mark.asyncio
async def test_submit_terminal_review_writes_file(tmp_path: Path, monkeypatch) -> None:
    review_path = tmp_path / "terminal-review.json"
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(review_path))
    server = create_terminal_reviewer_server()
    await server.call_tool(
        "submit_terminal_review", {"done": True, "report": "all clean"}
    )
    data = json.loads(review_path.read_text())
    assert data == {"done": True, "report": "all clean"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "path_name"),
    (("worker", "handoff.json"), ("reviewer", "terminal-review.json")),
)
async def test_mcp_handoff_is_redacted_before_tool_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    path_name: str,
) -> None:
    secret = "plum"
    inventory = credential_source_values(
        {"DECLARED_AUTH": secret},
        declared_names=("DECLARED_AUTH",),
    )
    path = tmp_path / path_name
    if mode == "worker":
        monkeypatch.setenv("UNREST_HANDOFF_PATH", str(path))
        monkeypatch.setenv("UNREST_NODE_TYPE", "work")
        monkeypatch.setenv("UNREST_NODE_ID", "w-secret")
        server = create_worker_server(inventory)
        await server.call_tool(
            "end_node",
            {"done": True, "report": secret},
        )
    else:
        monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(path))
        server = create_terminal_reviewer_server(inventory)
        await server.call_tool(
            "submit_terminal_review",
            {"done": True, "report": secret},
        )

    persisted = path.read_text(encoding="utf-8")
    assert secret not in persisted
    assert "<redacted:DECLARED_AUTH>" in persisted


@pytest.mark.asyncio
async def test_redacted_mcp_handoffs_survive_restart_and_mirroring(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "validate-handoff-credential-a17f"
    inventory = credential_source_values(
        {"DECLARED_AUTH": secret},
        declared_names=("DECLARED_AUTH",),
    )
    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id="p-secret")
    spawn_ts = "2026-08-03T00-00-00Z"

    attempt_path = store.attempt_path("p-secret", "mission-001", spawn_ts, "v-secret")
    assert not attempt_path.exists()
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(attempt_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "validate")
    monkeypatch.setenv("UNREST_NODE_ID", "v-secret")
    await create_worker_server(inventory).call_tool(
        "end_node",
        {
            "done": True,
            "report": f"validate result: {secret}",
            "items": [{"item_id": "VAL-SINK-001", "passed": True}],
            "passed": True,
        },
    )

    attempt_bytes = attempt_path.read_bytes()
    assert secret.encode() not in attempt_bytes
    assert b"validate result: <redacted:DECLARED_AUTH>" in attempt_bytes

    restarted = ProjectStore(config)
    handoff = restarted.read_attempt(
        "p-secret", "mission-001", spawn_ts, "v-secret"
    )
    assert isinstance(handoff, ValidateHandoff)
    assert handoff.items == [ValidationItem(item_id="VAL-SINK-001", passed=True)]
    assert handoff.passed is True
    restarted.save_attempt(
        "p-secret", "mission-001", spawn_ts, "v-secret", handoff
    )

    review_path = restarted.terminal_review_path(
        "p-secret", "mission-001", spawn_ts
    )
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(review_path))
    await create_terminal_reviewer_server(inventory).call_tool(
        "submit_terminal_review",
        {"done": True, "report": secret},
    )
    restarted_again = ProjectStore(config)
    review = TerminalReviewHandoff.model_validate_json(
        review_path.read_text(encoding="utf-8")
    )
    restarted_again.save_terminal_review(
        "p-secret", "mission-001", spawn_ts, review
    )

    persisted_paths = (
        attempt_path,
        restarted.attempt_report_path(
            "p-secret", "mission-001", spawn_ts, "v-secret"
        ),
        review_path,
        restarted_again.terminal_review_report_path(
            "p-secret", "mission-001", spawn_ts
        ),
    )
    for path in persisted_paths:
        persisted = path.read_text(encoding="utf-8")
        assert secret not in persisted
        assert "<redacted:DECLARED_AUTH>" in persisted


# ---------------------------------------------------------------------------
# Integration: orchestrator tools in-process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_end_to_end_in_process(
    config: HarnessConfig, workspace: Path
) -> None:
    def responder(req):
        if req.task.type == "work":
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")
        return ValidateHandoff(
            node_id=req.task.id,
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-001", passed=True)],
            passed=True,
        )

    controller = ProjectController(
        config,
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)

    await server.call_tool(
        "start_project",
        {"brief": "Ship it.", "workspace_dir": str(workspace)},
    )
    pid = ProjectStore(config).list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n")
    task_list_dict = {
        "tasks": [
            {"id": "w1", "type": "work", "body": "do", "targets": ["VAL-001"], "skill": "s", "depends_on": []},
            {"id": "v1", "type": "validate", "body": "audit", "targets": ["VAL-001"], "skill": "aud", "depends_on": ["w1"]},
            {"id": "g1", "type": "gate", "body": "", "targets": ["VAL-001"], "skill": None, "depends_on": ["v1"]},
        ],
    }
    await server.call_tool("submit_plan", {"project_id": pid, "task_list": task_list_dict})
    await server.call_tool("advance_project", {"project_id": pid})
    items = controller.store.load_attention(pid)
    assert len(items) == 1
    await server.call_tool(
        "decide_attention",
        {
            "project_id": pid,
            "decisions": [{"item_id": items[0].id, "action": "continue"}],
        },
    )
    await server.call_tool("advance_project", {"project_id": pid})
    await server.call_tool("inspect_project", {"project_id": pid})
    report = (
        controller.store.mission_dir(pid, "mission-001")
        / "evidence"
        / "final"
        / "report.md"
    )
    report.parent.mkdir(parents=True)
    report.write_text("final report", encoding="utf-8")
    await server.call_tool(
        "end_mission",
        {"project_id": pid, "deliverable_roots": [str(report)]},
    )
    state = controller.store.load_state(pid)
    assert state is not None
    assert state.state == "done"
    review_config = controller.store.load_terminal_review_config(
        pid, "mission-001"
    )
    assert review_config.deliverable_roots == [str(report.resolve())]


# ---------------------------------------------------------------------------
# Regression: dispatcher that calls asyncio.run() must not crash the MCP
# event loop. Reproduces:
#   "asyncio.run() cannot be called from a running event loop"
# observed in the attempts/*.json report when a worker dispatch path
# inadvertently ran inside the FastMCP handler's loop.
# ---------------------------------------------------------------------------


class _AsyncioRunDispatcher:
    """Dispatcher whose dispatch() goes through asyncio.run(), mimicking
    ACPNodeDispatcher. If invoked from a running loop without thread
    isolation, raises the canonical RuntimeError.
    """

    def dispatch(self, request: DispatchRequest) -> WorkHandoff | ValidateHandoff:
        async def _do() -> WorkHandoff | ValidateHandoff:
            await asyncio.sleep(0)
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        return asyncio.run(_do())

    def dispatch_batch(
        self, requests: list[DispatchRequest]
    ) -> list[WorkHandoff | ValidateHandoff]:
        return [self.dispatch(r) for r in requests]


@pytest.mark.asyncio
async def test_advance_project_tolerates_asyncio_run_dispatcher(
    config: HarnessConfig, workspace: Path
) -> None:
    controller = ProjectController(
        config,
        _AsyncioRunDispatcher(),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)
    await server.call_tool(
        "start_project",
        {"brief": "Ship it.", "workspace_dir": str(workspace)},
    )
    pid = ProjectStore(config).list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n")
    task_list_dict = {
        "tasks": [
            {"id": "w1", "type": "work", "body": "do", "targets": ["VAL-001"], "skill": "s", "depends_on": []},
            {"id": "v1", "type": "validate", "body": "audit", "targets": ["VAL-001"], "skill": "aud", "depends_on": ["w1"]},
            {"id": "g1", "type": "gate", "body": "", "targets": ["VAL-001"], "skill": None, "depends_on": ["v1"]},
        ],
    }
    await server.call_tool("submit_plan", {"project_id": pid, "task_list": task_list_dict})
    # Before the fix this raised:
    #   RuntimeError: asyncio.run() cannot be called from a running event loop
    await server.call_tool("advance_project", {"project_id": pid})
    items = controller.store.load_attention(pid)
    assert len(items) == 1


def test_run_coro_blocking_works_inside_running_loop() -> None:
    """The dispatcher defense: if asyncio.run() is reached while a loop is
    already running, _run_coro_blocking falls back to a worker thread.
    """
    from unrest_harness.acp_runner import _run_coro_blocking

    async def _outer() -> int:
        async def _inner() -> int:
            await asyncio.sleep(0)
            return 42

        return _run_coro_blocking(_inner())

    assert asyncio.run(_outer()) == 42


def _free_loopback_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


async def _process_mcp_call(
    url: str, name: str, arguments: dict[str, object]
) -> dict[str, object]:
    from fastmcp import Client

    async with Client(url) as client:
        result = await asyncio.wait_for(client.call_tool(name, arguments), timeout=10)
    assert isinstance(result.structured_content, dict)
    return result.structured_content


def _call_process_mcp(
    url: str, name: str, arguments: dict[str, object]
) -> dict[str, object]:
    return asyncio.run(_process_mcp_call(url, name, arguments))


async def _process_mcp_liveness(url: str) -> set[str]:
    from fastmcp import Client

    async with Client(url) as client:
        return {tool.name for tool in await asyncio.wait_for(client.list_tools(), 5)}


@contextmanager
def _http_server_process(
    config: HarnessConfig,
    workspace: Path,
    *,
    mode: str,
    role_environment: dict[str, str] | None = None,
) -> Iterator[tuple[subprocess.Popen[bytes], str]]:
    port = _free_loopback_port()
    log = workspace / f".{mode}-{port}.log"
    stream = log.open("wb")
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            "UNREST_HOME": str(config.harness_home),
            "UNREST_PROJECTS_DIR": str(config.projects_dir),
            "UNREST_WORKER_PROVIDER": "claude",
            "UNREST_WORKER_ACP_COMMAND": "/bin/true",
            "UNREST_VALIDATOR_PROVIDER": "claude",
            "UNREST_VALIDATOR_ACP_COMMAND": "/bin/true",
            "UNREST_TERMINAL_REVIEWER_PROVIDER": "claude",
            "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": "/bin/true",
        }
    )
    environment.update(role_environment or {})
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from unrest_harness.server import main; main()",
            "--mode",
            mode,
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=workspace,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    pgid = os.getpgid(process.pid)
    assert pgid == process.pid
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(log.read_text(encoding="utf-8", errors="replace"))
            try:
                asyncio.run(_process_mcp_liveness(url))
                break
            except Exception:  # noqa: BLE001 - readiness is transport-level
                time.sleep(0.05)
        else:
            raise AssertionError(f"HTTP MCP server did not become ready: {mode}")
        yield process, url
    finally:
        if process.poll() is None:
            os.killpg(pgid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                process.wait(timeout=10)
        stream.close()
        assert process.poll() is not None


def _process_group_inventory(pgid: int) -> list[tuple[int, int, int]]:
    output = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    rows: list[tuple[int, int, int]] = []
    for line in output.splitlines():
        pid_text, ppid_text, pgid_text = line.split()
        if int(pgid_text) == pgid:
            rows.append((int(pid_text), int(ppid_text), int(pgid_text)))
    return sorted(rows)


def _write_composed_acp_adapter(workspace: Path) -> tuple[Path, Path]:
    """Create the real JSON-RPC adapter only inside this test's private root."""
    adapter = workspace / ".hermetic-acp-adapter.py"
    trace = workspace / ".hermetic-acp-trace.jsonl"
    adapter.write_text(
        r'''#!/usr/bin/env python3
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from fastmcp import Client

TRACE = Path(sys.argv[1])
CONTROL = TRACE.parent / ".hermetic-acp-control"
SESSION = f"hermetic-{os.getpid()}"
MCP_URL = None

def record(event, **values):
    row = {
        "event": event,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "pgid": os.getpgrp(),
        "sid": os.getsid(0),
        "session": SESSION,
        **values,
    }
    fd = os.open(TRACE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)

async def call(name, arguments):
    record("mcp_call", tool=name)
    async with Client(MCP_URL) as client:
        result = await client.call_tool(name, arguments)
    return result.structured_content

async def prompt():
    role = "terminal_reviewer" if os.environ.get("UNREST_TERMINAL_REVIEW_PATH") else (
        "validator" if os.environ.get("UNREST_NODE_TYPE") == "validate" else "worker"
    )
    identity_path = os.environ.get("UNREST_TERMINAL_REVIEW_PATH") or os.environ["UNREST_HANDOFF_PATH"]
    attempt = Path(identity_path).stem.split("__", 1)[0]
    node = None if role == "terminal_reviewer" else os.environ["UNREST_NODE_ID"]
    snapshot = {
        "attempt_id": attempt,
        "blocker_code": None,
        "checkpoint_requests": 0,
        "checkpoint_sequence": 1,
        "completed_target_ids": [],
        "elapsed_nanoseconds": 0,
        "last_effect_sequence": 0,
        "mission_id": os.environ["UNREST_MISSION_ID"],
        "node_id": node,
        "phase": "waiting_at_checkpoint",
        "project_id": os.environ["UNREST_PROJECT_ID"],
        "remaining_target_ids": ["VAL-COMPOSED"],
        "role": role,
        "scope_status": "in_scope",
        "supervision_status": "waiting",
        "terminal_review_id": attempt if role == "terminal_reviewer" else None,
    }
    checkpoint_started = time.monotonic()
    outcome = await call("report_supervision_checkpoint", {"snapshot": snapshot})
    record("checkpoint_result", role=role, action=outcome.get("action"), code=outcome.get("code"), wait_seconds=time.monotonic() - checkpoint_started)
    role_key = node or role
    pause_checkpoint = CONTROL / f"pause-checkpoint-{role_key}"
    if pause_checkpoint.exists():
        record("checkpoint_paused", role=role, node=node)
        release = CONTROL / f"release-checkpoint-{role_key}"
        while not release.exists():
            await asyncio.sleep(0.02)
    if (CONTROL / f"second-checkpoint-{node or role}").exists():
        snapshot.update(
            checkpoint_sequence=2,
            elapsed_nanoseconds=0,
            last_effect_sequence=1,
            phase="waiting_at_checkpoint",
            supervision_status="waiting",
        )
        outcome = await call("report_supervision_checkpoint", {"snapshot": snapshot})
        record("second_checkpoint_result", role=role, action=outcome.get("action"), code=outcome.get("code"))
    hold = CONTROL / f"hold-effect-{node or role}"
    if hold.exists():
        record("effect_open", role=role, node=node)
        release = CONTROL / f"release-effect-{node or role}"
        while not release.exists():
            await asyncio.sleep(0.02)
        record("effect_released", role=role, node=node)
    if role == "terminal_reviewer":
        review = await call(
            "submit_terminal_review",
            {"done": True, "report": "hermetic review"},
        )
        record("terminal_completion", role=role, recorded=review.get("recorded"))
        return
    arguments = {"done": True, "report": "hermetic node"}
    if role == "validator":
        passed = not (CONTROL / f"dissent-{node}").exists()
        arguments.update(
            items=[{"item_id": "VAL-COMPOSED", "passed": passed}],
            passed=passed,
        )
    refused = await call("end_node", {**arguments, "completion": {}})
    record("completion_refusal", role=role, recorded=refused.get("recorded"), fields=refused.get("fields"))
    pause = CONTROL / f"pause-refusal-{node}"
    if pause.exists():
        record("refusal_paused", role=role, node=node)
        release = CONTROL / f"release-refusal-{node}"
        while not release.exists():
            await asyncio.sleep(0.02)
    completed = await call(
        "end_node",
        ({**arguments, "completion": {}} if (CONTROL / f"second-invalid-{node}").exists() else arguments),
    )
    record("completion_repair", role=role, recorded=completed.get("recorded"))

def response(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    req_id = message.get("id")
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {"loadSession": False, "promptCapabilities": {"audio": False, "embeddedContent": False, "image": False}}, "authMethods": []}
    elif method == "session/new":
        MCP_URL = message["params"]["mcpServers"][0]["url"]
        record("session_new", role=os.environ.get("UNREST_NODE_TYPE", "terminal_reviewer"), mcp_url=MCP_URL)
        result = {"sessionId": SESSION}
    elif method == "session/set_mode":
        result = {}
    elif method == "session/prompt":
        prompt_bytes = json.dumps(message.get("params", {}), sort_keys=True, separators=(",", ":")).encode()
        record(
            "session_prompt",
            role=os.environ.get("UNREST_NODE_TYPE", "terminal_reviewer"),
            provider_role=("terminal_reviewer" if os.environ.get("UNREST_TERMINAL_REVIEW_PATH") else os.environ.get("UNREST_NODE_TYPE", "work")),
            prompt_byte_count=len(prompt_bytes),
            prompt_sha256=hashlib.sha256(prompt_bytes).hexdigest(),
        )
        asyncio.run(prompt())
        result = {"stopReason": "end_turn", "usage": {"model": "hermetic", "inputTokens": 0, "outputTokens": 0, "reportedCostUsd": 0}}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps(response(req_id, result)) + "\n")
    sys.stdout.flush()
''',
        encoding="utf-8",
    )
    adapter.chmod(0o700)
    return adapter, trace


def _write_undeliverable_adapter(workspace: Path) -> Path:
    """Model a role adapter without delivery support inside child processes."""
    shim = workspace / "sitecustomize.py"
    shim.write_text(
        """\
import unrest_harness.api as api

_apply_steering = api.apply_steering

def _blocked_delivery(store, request, **kwargs):
    kwargs["delivery_supported"] = False
    return _apply_steering(store, request, **kwargs)

api.apply_steering = _blocked_delivery
""",
        encoding="utf-8",
    )
    return shim


def _wait_for_attached_checkpoint(
    url: str,
    run_id: str,
    *,
    role: str | None = None,
    sequence: int = 1,
    timeout: float = 75,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        attached = _call_process_mcp(url, "inspect_run", {"run_id": run_id})
        attempts = attached.get("active_attempts", [])
        if (
            attempts
            and attempts[0].get("checkpoint_sequence") == sequence
            and (role is None or attempts[0].get("role") == role)
        ):
            return attempts[0]
        if attached.get("state") in {"attention", "cancelled", "failed", "succeeded"}:
            raise AssertionError(attached)
        time.sleep(0.05)
    raise AssertionError("attached run did not expose a semantic checkpoint")


def _wait_for_run(url: str, run_id: str, state: str, *, timeout: float = 30) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        attached = _call_process_mcp(url, "inspect_run", {"run_id": run_id})
        if attached.get("state") == state:
            blocking_attach = _call_process_mcp(
                url, "attach_run", {"run_id": run_id}
            )
            assert blocking_attach == attached
            return attached
        if attached.get("state") in {"attention", "cancelled", "failed"}:
            raise AssertionError(attached)
        time.sleep(0.05)
    raise AssertionError(f"run did not reach {state}")


def _wait_for_trace_event(
    trace: Path,
    event: str,
    *,
    node: str | None = None,
    timeout: float = 30,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if trace.exists():
            for line in trace.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row.get("event") == event and (node is None or row.get("node") == node):
                    return row
        time.sleep(0.02)
    raise AssertionError(f"adapter did not record {event} for {node}")


def _attached_steering_request(
    project_id: str,
    checkpoint: dict[str, object],
    action: str,
    *,
    body: str | None = None,
) -> dict[str, object]:
    request = {
        "project_id": project_id,
        "mission_id": checkpoint["mission_id"],
        "node_id": checkpoint["node_id"],
        "terminal_review_id": checkpoint["terminal_review_id"],
        "attempt_id": checkpoint["attempt_id"],
        "checkpoint_sequence": checkpoint["checkpoint_sequence"],
        "action": action,
        "actor": "orchestrator",
    }
    if body is not None:
        request["body"] = body
    return request


def test_composed_hermetic_acp_topology_uses_public_attached_control(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    """Run worker, validator, and reviewer through one real process topology."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    owned_pgids: set[int] = set()
    with _http_server_process(
        config,
        workspace,
        mode="orchestrator",
        role_environment=role_environment,
    ) as (orchestrator, url):
        created = _call_process_mcp(
            url,
            "start_project",
            {"brief": "composed hermetic topology", "workspace_dir": str(workspace)},
        )
        project_id = str(created["projectId"])
        store = ProjectStore(config)
        contract = store.ensure_contract_dir(project_id, "mission-001")
        (contract / "VAL-COMPOSED.md").write_text(
            "# VAL-COMPOSED\n", encoding="utf-8"
        )
        planned = _call_process_mcp(
            url,
            "submit_plan",
            {
                "project_id": project_id,
                "task_list": {
                    "tasks": [
                        {"id": "worker-1", "type": "work", "body": "work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []},
                        {"id": "validator-1", "type": "validate", "body": "validate", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]},
                        {"id": "gate-1", "type": "gate", "body": "", "targets": ["VAL-COMPOSED"], "skill": None, "depends_on": ["validator-1"]},
                    ]
                },
            },
        )
        assert planned["state"]["state"] == "mission_running"
        admitted = _call_process_mcp(
            url,
            "submit_run",
            {
                "operation": "advance_project",
                "arguments": {"project_id": project_id},
                "idempotency_key": "composed-advance",
            },
        )
        run_id = str(admitted["run_id"])

        worker = _wait_for_attached_checkpoint(url, run_id)
        assert worker["role"] == "worker"
        assert worker["elapsed_nanoseconds"] == 0
        assert worker["checkpoint_requests"] == 0
        cursor = next(
            (config.harness_home / ".unrest-runtime" / "runs").glob(
                "*.worker.json"
            )
        )
        cursor_value = json.loads(cursor.read_text(encoding="utf-8"))
        worker_pgid = int(cursor_value["pgid"])
        owned_pgids.add(worker_pgid)
        inventory = _process_group_inventory(worker_pgid)
        assert len(inventory) >= 3
        assert all(row[2] == worker_pgid for row in inventory)

        # This is deliberately real wall time. No injected clock and no steering.
        wait_started = time.monotonic()
        thirty_second_projection: dict[str, object] | None = None
        while True:
            rows = [json.loads(line) for line in trace.read_text().splitlines()]
            timeout_rows = [
                row for row in rows
                if row["event"] == "checkpoint_result"
                and row["role"] == "worker"
            ]
            if timeout_rows:
                break
            elapsed = time.monotonic() - wait_started
            if elapsed >= 30 and thirty_second_projection is None:
                thirty_second_projection = _call_process_mcp(
                    url, "inspect_run", {"run_id": run_id}
                )["active_attempts"][0]
            assert elapsed < 70
            time.sleep(0.05)
        waited = time.monotonic() - wait_started
        assert timeout_rows[0]["wait_seconds"] >= 60.0
        assert waited >= 59.0
        assert timeout_rows == [
            {**timeout_rows[0], "action": "continue", "code": "timeout_continue"}
        ]
        assert thirty_second_projection is not None
        assert thirty_second_projection["elapsed_nanoseconds"] >= 30_000_000_000
        assert thirty_second_projection["checkpoint_requests"] == 0
        assert thirty_second_projection["checkpoint_sequence"] == 1

        validator = _wait_for_attached_checkpoint(url, run_id, role="validator")
        assert validator["role"] == "validator"
        steer = _call_process_mcp(
            url,
            "steer_attempt",
            {
                "run_id": run_id,
                "request": {
                    "project_id": project_id,
                    "mission_id": validator["mission_id"],
                    "node_id": validator["node_id"],
                    "terminal_review_id": None,
                    "attempt_id": validator["attempt_id"],
                    "checkpoint_sequence": 1,
                    "action": "continue",
                    "actor": "orchestrator",
                },
            },
        )
        assert steer["code"] == "continued"
        advanced = _wait_for_run(url, run_id, "succeeded")
        assert advanced["result"]["state"]["state"] == "attention_needed"
        gate_item = advanced["result"]["state"]["items"][0]

        gate_run = _call_process_mcp(
            url,
            "submit_run",
            {
                "operation": "decide_attention",
                "arguments": {
                    "project_id": project_id,
                    "decisions": [
                        {
                            "item_id": gate_item["id"],
                            "action": "continue",
                            "justification": "accept hermetic validator evidence",
                        }
                    ],
                },
                "idempotency_key": "composed-gate",
            },
        )
        _wait_for_run(url, str(gate_run["run_id"]), "succeeded")

        closure = _call_process_mcp(
            url,
            "submit_run",
            {
                "operation": "end_mission",
                "arguments": {"project_id": project_id},
                "idempotency_key": "composed-close",
            },
        )
        close_id = str(closure["run_id"])
        reviewer = _wait_for_attached_checkpoint(url, close_id)
        assert reviewer["role"] == "terminal_reviewer"
        close_steer = _call_process_mcp(
            url,
            "steer_attempt",
            {
                "run_id": close_id,
                "request": {
                    "project_id": project_id,
                    "mission_id": reviewer["mission_id"],
                    "node_id": None,
                    "terminal_review_id": reviewer["terminal_review_id"],
                    "attempt_id": reviewer["attempt_id"],
                    "checkpoint_sequence": 1,
                    "action": "continue",
                    "actor": "orchestrator",
                },
            },
        )
        assert close_steer["code"] == "continued"
        closed = _wait_for_run(url, close_id, "succeeded")
        assert closed["result"]["state"]["state"] == "done"
        assert orchestrator.poll() is None

    rows = [json.loads(line) for line in trace.read_text().splitlines()]
    assert [row["role"] for row in rows if row["event"] == "completion_refusal"] == [
        "worker",
        "validator",
    ]
    assert all(
        row["recorded"] is False
        for row in rows
        if row["event"] == "completion_refusal"
    )
    assert [row["role"] for row in rows if row["event"] == "completion_repair"] == [
        "worker",
        "validator",
    ]
    assert len({row["pid"] for row in rows if row["event"] == "session_prompt"}) == 3
    assert len([row for row in rows if row["event"] == "session_prompt"]) == 3
    assert trace.stat().st_mode & 0o777 == 0o600
    assert all(
        str(row["mcp_url"]).startswith("http://127.0.0.1:")
        for row in rows
        if row["event"] == "session_new"
    )
    assert not any(_process_group_inventory(pgid) for pgid in owned_pgids)


def test_composed_restart_stop_replacement_and_cancel_are_distinct(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    """Keep one ACP attempt across restart, then prove stop and hard cancel."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    control = workspace / ".hermetic-acp-control"
    control.mkdir(mode=0o700)
    (control / "pause-refusal-worker-1").touch()
    (control / "second-checkpoint-worker-1").touch()
    (control / "hold-effect-validator-1").touch()
    (control / "second-invalid-validator-2").touch()
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    run_ids: list[str] = []
    owned_pgids: set[int] = set()

    def submit_advance(url: str, project_id: str, key: str) -> str:
        admitted = _call_process_mcp(
            url,
            "submit_run",
            {
                "operation": "advance_project",
                "arguments": {"project_id": project_id},
                "idempotency_key": key,
            },
        )
        run_id = str(admitted["run_id"])
        run_ids.append(run_id)
        return run_id

    try:
        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (first_orchestrator, first_url):
            created = _call_process_mcp(
                first_url,
                "start_project",
                {"brief": "restart stop topology", "workspace_dir": str(workspace)},
            )
            project_id = str(created["projectId"])
            store = ProjectStore(config)
            contract = store.ensure_contract_dir(project_id, "mission-001")
            (contract / "VAL-COMPOSED.md").write_text(
                "# VAL-COMPOSED\n", encoding="utf-8"
            )
            _call_process_mcp(
                first_url,
                "submit_plan",
                {
                    "project_id": project_id,
                    "task_list": {
                        "tasks": [
                            {"id": "worker-1", "type": "work", "body": "work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []},
                            {"id": "validator-1", "type": "validate", "body": "validate", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]},
                            {"id": "gate-1", "type": "gate", "body": "", "targets": ["VAL-COMPOSED"], "skill": None, "depends_on": ["validator-1"]},
                        ]
                    },
                },
            )
            run_id = submit_advance(first_url, project_id, "restart-stop-advance")
            worker = _wait_for_attached_checkpoint(first_url, run_id, role="worker")
            project_projection = _call_process_mcp(
                first_url, "inspect_project", {"project_id": project_id}
            )
            assert project_projection["active_attempts"] == [worker]
            cursor_path = next(
                path
                for path in (config.harness_home / ".unrest-runtime" / "runs").glob(
                    "*.worker.json"
                )
                if json.loads(path.read_text(encoding="utf-8"))["run_id"] == run_id
            )
            cursor_before = cursor_path.read_bytes()
            cursor_value = json.loads(cursor_before)
            worker_pgid = int(cursor_value["pgid"])
            owned_pgids.add(worker_pgid)
            inventory_before = _process_group_inventory(worker_pgid)
            runtime_mission = store.mission_runtime_dir(project_id, "mission-001")
            truth_before = {
                name: (runtime_mission / name).read_bytes()
                for name in ("tasks.json", "task-state.json", "contract-state.json")
            }

            wrong = _attached_steering_request(project_id, worker, "continue")
            wrong["attempt_id"] = "wrong-attempt"
            assert _call_process_mcp(
                first_url, "steer_attempt", {"run_id": run_id, "request": wrong}
            )["error"]["code"] == "steering_binding_mismatch"
            stale = _attached_steering_request(project_id, worker, "continue")
            stale["checkpoint_sequence"] = 0
            assert _call_process_mcp(
                first_url, "steer_attempt", {"run_id": run_id, "request": stale}
            )["error"]["code"] == "stale_checkpoint_binding"
            for forbidden_field in ("target_ids", "budget"):
                widened = _attached_steering_request(
                    project_id, worker, "continue"
                )
                widened[forbidden_field] = (
                    ["VAL-OUT-OF-SCOPE"] if forbidden_field == "target_ids" else 2
                )
                assert _call_process_mcp(
                    first_url,
                    "steer_attempt",
                    {"run_id": run_id, "request": widened},
                )["error"]["code"] == "invalid_argument"
            unsupported = _attached_steering_request(
                project_id, worker, "unsupported"
            )
            assert _call_process_mcp(
                first_url,
                "steer_attempt",
                {"run_id": run_id, "request": unsupported},
            )["error"]["code"] == "invalid_argument"
            too_large = _attached_steering_request(
                project_id, worker, "nudge", body="é" * 1025
            )
            assert _call_process_mcp(
                first_url,
                "steer_attempt",
                {"run_id": run_id, "request": too_large},
            )["error"]["code"] == "invalid_argument"
            nudge = _attached_steering_request(
                project_id, worker, "nudge", body="private composed nudge"
            )
            assert _call_process_mcp(
                first_url, "steer_attempt", {"run_id": run_id, "request": nudge}
            )["code"] == "nudge_pending"
            worker_two = _wait_for_attached_checkpoint(
                first_url, run_id, role="worker", sequence=2
            )
            assert _call_process_mcp(
                first_url,
                "steer_attempt",
                {
                    "run_id": run_id,
                    "request": _attached_steering_request(
                        project_id, worker_two, "nudge", body="second nudge"
                    ),
                },
            )["error"]["code"] == "nudge_limit_exceeded"
            assert _call_process_mcp(
                first_url,
                "steer_attempt",
                {
                    "run_id": run_id,
                    "request": _attached_steering_request(
                        project_id, worker_two, "continue"
                    ),
                },
            )["code"] == "continued"
            assert _call_process_mcp(
                first_url, "steer_attempt", {"run_id": run_id, "request": nudge}
            )["error"]["code"] in {
                "stale_checkpoint_binding",
                "steering_action_replayed",
            }
            _wait_for_trace_event(trace, "refusal_paused", node="worker-1")
            assert _process_group_inventory(worker_pgid) == inventory_before
            assert {
                name: (runtime_mission / name).read_bytes()
                for name in truth_before
            } == truth_before
            rows_before = [json.loads(line) for line in trace.read_text().splitlines()]
            worker_session = next(
                row for row in rows_before
                if row["event"] == "session_new" and row["role"] == "work"
            )
            refusal_marker = next(
                store.mission_runtime_dir(project_id, "mission-001").glob(
                    "completion-refusals/*.json"
                )
            )
            marker_bytes = refusal_marker.read_bytes()
            assert refusal_marker.stat().st_mode & 0o777 == 0o600
            assert b"private composed nudge" not in marker_bytes
            first_pid = first_orchestrator.pid

        assert first_orchestrator.poll() is not None
        assert [
            (pid, pgid)
            for pid, _, pgid in _process_group_inventory(worker_pgid)
        ] == [(pid, pgid) for pid, _, pgid in inventory_before]

        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (second_orchestrator, second_url):
            assert second_orchestrator.pid != first_pid
            restarted = _call_process_mcp(second_url, "inspect_run", {"run_id": run_id})
            restarted_worker = restarted["active_attempts"][0]
            for identity_field in (
                "project_id",
                "mission_id",
                "node_id",
                "attempt_id",
                "role",
            ):
                assert restarted_worker[identity_field] == worker[identity_field]
            assert restarted_worker["phase"] == "active"
            assert _call_process_mcp(
                second_url, "inspect_project", {"project_id": project_id}
            )["active_attempts"] == [restarted_worker]
            assert cursor_path.read_bytes() == cursor_before
            assert refusal_marker.read_bytes() == marker_bytes
            assert [
                (pid, pgid)
                for pid, _, pgid in _process_group_inventory(worker_pgid)
            ] == [(pid, pgid) for pid, _, pgid in inventory_before]
            (control / "release-refusal-worker-1").touch()

            validator = _wait_for_attached_checkpoint(
                second_url, run_id, role="validator"
            )
            stop = _attached_steering_request(
                project_id, validator, "stop_for_attention"
            )
            assert _call_process_mcp(
                second_url, "steer_attempt", {"run_id": run_id, "request": stop}
            )["code"] == "stop_requested"
            _wait_for_trace_event(trace, "effect_open", node="validator-1")
            still_running = _call_process_mcp(
                second_url, "inspect_run", {"run_id": run_id}
            )
            assert still_running["state"] == "running"
            assert _call_process_mcp(
                second_url, "inspect_project", {"project_id": project_id}
            )["state"]["state"] == "mission_running"
            (control / "release-effect-validator-1").touch()
            stopped = _wait_for_run(second_url, run_id, "succeeded")
            assert stopped["result"]["state"]["state"] == "attention_needed"
            attention = stopped["result"]["state"]["items"]
            assert len(attention) == 1

            replacement = _call_process_mcp(
                second_url,
                "submit_run",
                {
                    "operation": "decide_attention",
                    "arguments": {
                        "project_id": project_id,
                        "decisions": [
                            {
                                "item_id": attention[0]["id"],
                                "action": "patch",
                                "justification": "explicit composed replacement",
                                "patch": {
                                    "add": [
                                        {"id": "validator-2", "type": "validate", "body": "replacement", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]}
                                    ],
                                    "supersede": {"validator-1": "validator-2"},
                                },
                            }
                        ],
                    },
                    "idempotency_key": "restart-stop-replacement",
                },
            )
            replacement_run = str(replacement["run_id"])
            run_ids.append(replacement_run)
            _wait_for_run(second_url, replacement_run, "succeeded")
            replacement_advance = submit_advance(
                second_url, project_id, "restart-stop-replacement-advance"
            )
            validator_two = _wait_for_attached_checkpoint(
                second_url, replacement_advance, role="validator"
            )
            assert validator_two["node_id"] == "validator-2"
            assert _call_process_mcp(
                second_url,
                "steer_attempt",
                {
                    "run_id": replacement_advance,
                    "request": _attached_steering_request(
                        project_id, validator_two, "continue"
                    ),
                },
            )["code"] == "continued"
            failed_replacement = _wait_for_run(
                second_url, replacement_advance, "succeeded"
            )
            assert failed_replacement["result"]["state"]["state"] == (
                "attention_needed"
            )
            lineage = _call_process_mcp(
                second_url, "inspect_project", {"project_id": project_id}
            )["supersession_lineage"]
            assert lineage == [
                {
                    "current": {"mission_id": "mission-001", "node_id": "validator-2"},
                    "superseded": [
                        {"mission_id": "mission-001", "node_id": "validator-1"}
                    ],
                }
            ]

            cancelled_project = _call_process_mcp(
                second_url,
                "start_project",
                {"brief": "distinct hard cancel", "workspace_dir": str(workspace)},
            )
            cancelled_id = str(cancelled_project["projectId"])
            cancel_contract = store.ensure_contract_dir(cancelled_id, "mission-001")
            (cancel_contract / "VAL-COMPOSED.md").write_text(
                "# VAL-COMPOSED\n", encoding="utf-8"
            )
            _call_process_mcp(
                second_url,
                "submit_plan",
                {
                    "project_id": cancelled_id,
                    "task_list": {
                        "tasks": [
                            {"id": "cancel-worker", "type": "work", "body": "cancel", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []}
                        ]
                    },
                },
            )
            cancel_run_id = submit_advance(
                second_url, cancelled_id, "distinct-cancel-advance"
            )
            _wait_for_attached_checkpoint(second_url, cancel_run_id, role="worker")
            cancel_cursor = next(
                path
                for path in (config.harness_home / ".unrest-runtime" / "runs").glob(
                    "*.worker.json"
                )
                if json.loads(path.read_text(encoding="utf-8"))["run_id"]
                == cancel_run_id
            )
            cancel_pgid = int(json.loads(cancel_cursor.read_text())["pgid"])
            owned_pgids.add(cancel_pgid)
            cancelled = _call_process_mcp(
                second_url,
                "cancel_run",
                {
                    "run_id": cancel_run_id,
                    "reason": "explicit hard cancel",
                    "idempotency_key": "distinct-cancel",
                },
            )
            assert cancelled["state"] in {"cancel_requested", "draining", "cancelled"}
            _wait_for_run(second_url, cancel_run_id, "cancelled")
            assert _call_process_mcp(
                second_url, "inspect_project", {"project_id": cancelled_id}
            )["state"]["state"] == "mission_running"

            rows_after = [json.loads(line) for line in trace.read_text().splitlines()]
            same_worker = [
                row for row in rows_after
                if row.get("session") == worker_session["session"]
            ]
            assert len([row for row in same_worker if row["event"] == "session_new"]) == 1
            assert len([row for row in same_worker if row["event"] == "session_prompt"]) == 1
            assert not any("private composed nudge" in path.read_text(
                encoding="utf-8", errors="ignore"
            ) for path in store.bucket_root(project_id).rglob("*") if path.is_file())

        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (fresh_server, fresh_url):
            assert fresh_server.pid != second_orchestrator.pid
            fresh_cancel = _call_process_mcp(
                fresh_url, "inspect_run", {"run_id": cancel_run_id}
            )
            fresh_project = _call_process_mcp(
                fresh_url, "inspect_project", {"project_id": cancelled_id}
            )
            assert fresh_cancel["state"] == "cancelled"
            assert fresh_cancel["active_attempts"] == []
            assert fresh_project["active_attempts"] == []
            assert fresh_project["state"]["state"] == "mission_running"
    finally:
        if run_ids:
            with _http_server_process(
                config,
                workspace,
                mode="orchestrator",
                role_environment=role_environment,
            ) as (_, cleanup_url):
                for candidate_run_id in run_ids:
                    summary = _call_process_mcp(
                        cleanup_url, "inspect_run", {"run_id": candidate_run_id}
                    )
                    if summary.get("state") not in {
                        "attention", "cancelled", "failed", "succeeded"
                    }:
                        _call_process_mcp(
                            cleanup_url,
                            "cancel_run",
                            {
                                "run_id": candidate_run_id,
                                "reason": "test teardown",
                                "idempotency_key": f"teardown-{candidate_run_id}",
                            },
                        )
        for pgid in owned_pgids:
            deadline = time.monotonic() + 5
            while _process_group_inventory(pgid) and time.monotonic() < deadline:
                time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while _process_group_inventory(pgid) and time.monotonic() < deadline:
                    time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGKILL)
            assert not _process_group_inventory(pgid)


def _composed_run_cursor(config: HarnessConfig, run_id: str) -> Path:
    return next(
        path
        for path in (config.harness_home / ".unrest-runtime" / "runs").glob(
            "*.worker.json"
        )
        if json.loads(path.read_text(encoding="utf-8"))["run_id"] == run_id
    )


def _composed_digest_ledger(paths: list[Path]) -> dict[str, str]:
    return {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
        if path.exists()
    }


def _submit_composed_advance(url: str, project_id: str, key: str) -> str:
    admitted = _call_process_mcp(
        url,
        "submit_run",
        {
            "operation": "advance_project",
            "arguments": {"project_id": project_id},
            "idempotency_key": key,
        },
    )
    return str(admitted["run_id"])


def _continue_composed_checkpoint(
    url: str,
    run_id: str,
    project_id: str,
    *,
    role: str,
) -> dict[str, object]:
    checkpoint = _wait_for_attached_checkpoint(url, run_id, role=role)
    project = _call_process_mcp(url, "inspect_project", {"project_id": project_id})
    run = _call_process_mcp(url, "inspect_run", {"run_id": run_id})
    assert project["active_attempts"] == run["active_attempts"] == [checkpoint]
    receipt = _call_process_mcp(
        url,
        "steer_attempt",
        {
            "run_id": run_id,
            "request": _attached_steering_request(
                project_id, checkpoint, "continue"
            ),
        },
    )
    assert receipt["code"] == "continued"
    return checkpoint


@pytest.mark.parametrize(
    "stop_role",
    ("worker", "validator", "terminal_reviewer"),
)
def test_composed_all_role_parity_restart_and_cooperative_stop(
    config: HarnessConfig,
    workspace: Path,
    stop_role: str,
) -> None:
    """Prove every execution role survives server replacement and stops cleanly."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    control = workspace / ".hermetic-acp-control"
    control.mkdir(mode=0o700)
    role_node = {
        "worker": "worker-1",
        "validator": "validator-1",
        "terminal_reviewer": "terminal_reviewer",
    }[stop_role]
    (control / f"hold-effect-{role_node}").touch()
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    owned_pgids: set[int] = set()
    run_id = ""
    project_id = ""
    target_checkpoint: dict[str, object]
    cursor_path: Path
    cursor_bytes: bytes
    inventory: list[tuple[int, int, int]]
    target_session: dict[str, object]
    first_server_pid = -1
    try:
        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (first_server, first_url):
            created = _call_process_mcp(
                first_url,
                "start_project",
                {"brief": f"all-role stop {stop_role}", "workspace_dir": str(workspace)},
            )
            project_id = str(created["projectId"])
            store = ProjectStore(config)
            contract = store.ensure_contract_dir(project_id, "mission-001")
            (contract / "VAL-COMPOSED.md").write_text(
                "# VAL-COMPOSED\n", encoding="utf-8"
            )
            _call_process_mcp(
                first_url,
                "submit_plan",
                {
                    "project_id": project_id,
                    "task_list": {
                        "tasks": [
                            {"id": "worker-1", "type": "work", "body": "work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []},
                            {"id": "validator-1", "type": "validate", "body": "validate", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]},
                            {"id": "gate-1", "type": "gate", "body": "", "targets": ["VAL-COMPOSED"], "skill": None, "depends_on": ["validator-1"]},
                        ]
                    },
                },
            )
            run_id = _submit_composed_advance(
                first_url, project_id, f"all-role-stop-{stop_role}"
            )
            if stop_role != "worker":
                _continue_composed_checkpoint(
                    first_url, run_id, project_id, role="worker"
                )
            if stop_role == "terminal_reviewer":
                _continue_composed_checkpoint(
                    first_url, run_id, project_id, role="validator"
                )
                gate = _wait_for_run(first_url, run_id, "succeeded")
                gate_item = gate["result"]["state"]["items"][0]
                decision = _call_process_mcp(
                    first_url,
                    "submit_run",
                    {
                        "operation": "decide_attention",
                        "arguments": {
                            "project_id": project_id,
                            "decisions": [
                                {
                                    "item_id": gate_item["id"],
                                    "action": "continue",
                                    "justification": "enter terminal review",
                                }
                            ],
                        },
                        "idempotency_key": "all-role-terminal-gate",
                    },
                )
                _wait_for_run(first_url, str(decision["run_id"]), "succeeded")
                closure = _call_process_mcp(
                    first_url,
                    "submit_run",
                    {
                        "operation": "end_mission",
                        "arguments": {"project_id": project_id},
                        "idempotency_key": "all-role-terminal-close",
                    },
                )
                run_id = str(closure["run_id"])

            target_checkpoint = _wait_for_attached_checkpoint(
                first_url, run_id, role=stop_role
            )
            project_projection = _call_process_mcp(
                first_url, "inspect_project", {"project_id": project_id}
            )
            run_projection = _call_process_mcp(
                first_url, "inspect_run", {"run_id": run_id}
            )
            assert project_projection["active_attempts"] == (
                run_projection["active_attempts"]
            ) == [target_checkpoint]
            cursor_path = _composed_run_cursor(config, run_id)
            cursor_bytes = cursor_path.read_bytes()
            cursor = json.loads(cursor_bytes)
            worker_pgid = int(cursor["pgid"])
            owned_pgids.add(worker_pgid)
            inventory = _process_group_inventory(worker_pgid)
            assert len(inventory) >= 3
            target_session = _wait_for_trace_event(
                trace,
                "session_new",
                node=None,
            )
            role_rows = [
                row
                for row in (json.loads(line) for line in trace.read_text().splitlines())
                if row.get("event") == "session_new"
                and (
                    (stop_role == "terminal_reviewer" and row.get("role") == "terminal_reviewer")
                    or (stop_role == "worker" and row.get("role") == "work")
                    or (stop_role == "validator" and row.get("role") == "validate")
                )
            ]
            assert len(role_rows) == 1
            target_session = role_rows[0]
            first_server_pid = first_server.pid

        assert first_server.poll() is not None
        restarted_inventory = _process_group_inventory(worker_pgid)
        assert [(pid, pgid) for pid, _, pgid in restarted_inventory] == [
            (pid, pgid) for pid, _, pgid in inventory
        ]
        # The separately sessioned run worker is intentionally orphaned when
        # only its former orchestrator parent exits; its live descendants keep
        # their exact parentage inside the unchanged process group.
        original_ppids = {pid: ppid for pid, ppid, _ in inventory}
        restarted_ppids = {pid: ppid for pid, ppid, _ in restarted_inventory}
        assert restarted_ppids[worker_pgid] == 1
        assert {
            pid: ppid for pid, ppid in restarted_ppids.items() if pid != worker_pgid
        } == {
            pid: ppid for pid, ppid in original_ppids.items() if pid != worker_pgid
        }

        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (second_server, second_url):
            assert second_server.pid != first_server_pid
            restarted_run = _call_process_mcp(
                second_url, "inspect_run", {"run_id": run_id}
            )
            restarted_project = _call_process_mcp(
                second_url, "inspect_project", {"project_id": project_id}
            )
            assert restarted_project["active_attempts"] == (
                restarted_run["active_attempts"]
            ) == [target_checkpoint]
            assert cursor_path.read_bytes() == cursor_bytes
            assert _process_group_inventory(worker_pgid) == restarted_inventory
            rows = [json.loads(line) for line in trace.read_text().splitlines()]
            same_session = [
                row for row in rows if row.get("session") == target_session["session"]
            ]
            assert len([row for row in same_session if row["event"] == "session_new"]) == 1
            assert len([row for row in same_session if row["event"] == "session_prompt"]) == 1
            for field in ("pid", "ppid", "pgid", "sid", "session"):
                assert same_session[0][field] == target_session[field]

            stop = _call_process_mcp(
                second_url,
                "steer_attempt",
                {
                    "run_id": run_id,
                    "request": _attached_steering_request(
                        project_id, target_checkpoint, "stop_for_attention"
                    ),
                },
            )
            assert stop["code"] == "stop_requested"
            _wait_for_trace_event(
                trace,
                "effect_open",
                node=(None if stop_role == "terminal_reviewer" else role_node),
            )
            assert _call_process_mcp(
                second_url, "inspect_run", {"run_id": run_id}
            )["state"] == "running"
            (control / f"release-effect-{role_node}").touch()
            stopped = _wait_for_run(second_url, run_id, "succeeded")
            assert stopped["result"]["state"]["state"] == "attention_needed"
            assert _call_process_mcp(
                second_url, "inspect_project", {"project_id": project_id}
            )["active_attempts"] == []

        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (fresh_server, fresh_url):
            assert fresh_server.pid not in {first_server_pid, second_server.pid}
            fresh_run = _call_process_mcp(
                fresh_url, "inspect_run", {"run_id": run_id}
            )
            fresh_project = _call_process_mcp(
                fresh_url, "inspect_project", {"project_id": project_id}
            )
            assert fresh_run["state"] == "succeeded"
            assert fresh_run["active_attempts"] == []
            assert fresh_project["active_attempts"] == []
            assert fresh_project["state"]["state"] == "attention_needed"
    finally:
        for pgid in owned_pgids:
            deadline = time.monotonic() + 5
            while _process_group_inventory(pgid) and time.monotonic() < deadline:
                time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while _process_group_inventory(pgid) and time.monotonic() < deadline:
                    time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGKILL)
            assert not _process_group_inventory(pgid)


@pytest.mark.parametrize("completion_role", ("worker", "validator"))
@pytest.mark.parametrize(
    ("repair", "restart"),
    ((True, True), (False, True), (False, False)),
    ids=("repair-restart", "second-invalid-restart", "second-invalid-live"),
)
def test_composed_completion_refusal_matrix_uses_original_generation(
    config: HarnessConfig,
    workspace: Path,
    completion_role: str,
    repair: bool,
    restart: bool,
) -> None:
    """Exercise worker/validator refusal outcomes on the complete process chain."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    control = workspace / ".hermetic-acp-control"
    control.mkdir(mode=0o700)
    target_node = "worker-1" if completion_role == "worker" else "validator-1"
    (control / f"pause-refusal-{target_node}").touch()
    if not repair:
        (control / f"second-invalid-{target_node}").touch()
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    owned_pgids: set[int] = set()
    project_id = ""
    run_id = ""
    target_checkpoint: dict[str, object]
    cursor_path: Path
    cursor_bytes: bytes
    inventory: list[tuple[int, int, int]]
    marker: Path
    marker_bytes: bytes
    truth_ledger: dict[str, str]
    downstream_at_refusal: dict[str, int]
    first_server_pid = -1

    def finish(url: str) -> dict[str, object]:
        (control / f"release-refusal-{target_node}").touch()
        if repair and completion_role == "worker":
            _continue_composed_checkpoint(
                url, run_id, project_id, role="validator"
            )
        return _wait_for_run(url, run_id, "succeeded")

    try:
        with _http_server_process(
            config,
            workspace,
            mode="orchestrator",
            role_environment=role_environment,
        ) as (first_server, first_url):
            created = _call_process_mcp(
                first_url,
                "start_project",
                {
                    "brief": f"completion {completion_role} {repair} {restart}",
                    "workspace_dir": str(workspace),
                },
            )
            project_id = str(created["projectId"])
            store = ProjectStore(config)
            contract = store.ensure_contract_dir(project_id, "mission-001")
            (contract / "VAL-COMPOSED.md").write_text(
                "# VAL-COMPOSED\n", encoding="utf-8"
            )
            _call_process_mcp(
                first_url,
                "submit_plan",
                {
                    "project_id": project_id,
                    "task_list": {
                        "tasks": [
                            {"id": "worker-1", "type": "work", "body": "work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []},
                            {"id": "validator-1", "type": "validate", "body": "validate", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]},
                            {"id": "gate-1", "type": "gate", "body": "", "targets": ["VAL-COMPOSED"], "skill": None, "depends_on": ["validator-1"]},
                        ]
                    },
                },
            )
            run_id = _submit_composed_advance(
                first_url,
                project_id,
                f"completion-{completion_role}-{repair}-{restart}",
            )
            if completion_role == "validator":
                _continue_composed_checkpoint(
                    first_url, run_id, project_id, role="worker"
                )
            target_checkpoint = _wait_for_attached_checkpoint(
                first_url, run_id, role=completion_role
            )
            assert _call_process_mcp(
                first_url, "inspect_project", {"project_id": project_id}
            )["active_attempts"] == [target_checkpoint]
            cursor_path = _composed_run_cursor(config, run_id)
            cursor_bytes = cursor_path.read_bytes()
            cursor = json.loads(cursor_bytes)
            worker_pgid = int(cursor["pgid"])
            owned_pgids.add(worker_pgid)
            inventory = _process_group_inventory(worker_pgid)
            mission = store.mission_runtime_dir(project_id, "mission-001")
            run_root = workspace / ".unrest" / "runs" / run_id.removeprefix("run:")
            truth_paths = [
                mission / "tasks.json",
                mission / "task-state.json",
                mission / "contract-state.json",
                *sorted((run_root / "events").glob("*.json")),
            ]
            truth_ledger = _composed_digest_ledger(truth_paths)
            assert not store.attempt_path(
                project_id,
                "mission-001",
                str(target_checkpoint["attempt_id"]),
                target_node,
            ).exists()
            receipt = _call_process_mcp(
                first_url,
                "steer_attempt",
                {
                    "run_id": run_id,
                    "request": _attached_steering_request(
                        project_id, target_checkpoint, "continue"
                    ),
                },
            )
            assert receipt["code"] == "continued"
            refusal = _wait_for_trace_event(
                trace, "refusal_paused", node=target_node
            )
            assert refusal["session"]
            marker = next(
                store.mission_runtime_dir(project_id, "mission-001").glob(
                    "completion-refusals/*.json"
                )
            )
            marker_bytes = marker.read_bytes()
            assert marker.stat().st_mode & 0o777 == 0o600
            assert b"hermetic node" not in marker_bytes
            assert _composed_digest_ledger(truth_paths) == truth_ledger
            assert not store.attempt_path(
                project_id,
                "mission-001",
                str(target_checkpoint["attempt_id"]),
                target_node,
            ).exists()
            rows = [json.loads(line) for line in trace.read_text().splitlines()]
            downstream_at_refusal = {
                role: len(
                    [
                        row
                        for row in rows
                        if row.get("event") == "session_prompt"
                        and row.get("provider_role") == role
                    ]
                )
                for role in ("work", "validate", "terminal_reviewer")
            }
            assert downstream_at_refusal == (
                {"work": 1, "validate": 0, "terminal_reviewer": 0}
                if completion_role == "worker"
                else {"work": 1, "validate": 1, "terminal_reviewer": 0}
            )
            first_server_pid = first_server.pid
            if not restart:
                finished = finish(first_url)
                assert finished["result"]["state"]["state"] == "attention_needed"

        if restart:
            restarted_inventory = _process_group_inventory(worker_pgid)
            assert [(pid, pgid) for pid, _, pgid in restarted_inventory] == [
                (pid, pgid) for pid, _, pgid in inventory
            ]
            with _http_server_process(
                config,
                workspace,
                mode="orchestrator",
                role_environment=role_environment,
            ) as (second_server, second_url):
                assert second_server.pid != first_server_pid
                restarted_run = _call_process_mcp(
                    second_url, "inspect_run", {"run_id": run_id}
                )
                restarted_project = _call_process_mcp(
                    second_url, "inspect_project", {"project_id": project_id}
                )
                assert restarted_project["active_attempts"] == restarted_run[
                    "active_attempts"
                ]
                assert len(restarted_run["active_attempts"]) == 1
                restarted_attempt = restarted_run["active_attempts"][0]
                for field in (
                    "project_id",
                    "mission_id",
                    "node_id",
                    "terminal_review_id",
                    "attempt_id",
                    "role",
                    "checkpoint_sequence",
                ):
                    assert restarted_attempt[field] == target_checkpoint[field]
                assert restarted_attempt["phase"] == "active"
                assert restarted_attempt["supervision_status"] == "running"
                assert cursor_path.read_bytes() == cursor_bytes
                assert marker.read_bytes() == marker_bytes
                assert _composed_digest_ledger(truth_paths) == truth_ledger
                finished = finish(second_url)
                assert finished["result"]["state"]["state"] == "attention_needed"

        handoff = ProjectStore(config).read_attempt(
            project_id,
            "mission-001",
            str(target_checkpoint["attempt_id"]),
            target_node,
        )
        assert handoff.attempt_id == target_checkpoint["attempt_id"]
        assert handoff.done is repair
        assert handoff.request_attention is (not repair)
        assert not marker.exists()
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        target_sessions = [
            row
            for row in rows
            if row.get("event") == "session_prompt"
            and row.get("provider_role") == (
                "work" if completion_role == "worker" else "validate"
            )
        ]
        assert len(target_sessions) == 1
        if not repair:
            assert {
                role: len(
                    [
                        row
                        for row in rows
                        if row.get("event") == "session_prompt"
                        and row.get("provider_role") == role
                    ]
                )
                for role in ("work", "validate", "terminal_reviewer")
            } == downstream_at_refusal
    finally:
        for pgid in owned_pgids:
            deadline = time.monotonic() + 5
            while _process_group_inventory(pgid) and time.monotonic() < deadline:
                time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while _process_group_inventory(pgid) and time.monotonic() < deadline:
                    time.sleep(0.02)
            if _process_group_inventory(pgid):
                os.killpg(pgid, signal.SIGKILL)
            assert not _process_group_inventory(pgid)


def test_composed_defective_work_reaches_independent_validator_dissent(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    """Structural work acceptance must not suppress a real validator failure."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    control = workspace / ".hermetic-acp-control"
    control.mkdir(mode=0o700)
    (control / "dissent-validator-1").touch()
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    owned_pgids: set[int] = set()
    with _http_server_process(
        config,
        workspace,
        mode="orchestrator",
        role_environment=role_environment,
    ) as (_, url):
        created = _call_process_mcp(
            url,
            "start_project",
            {"brief": "defective composed work", "workspace_dir": str(workspace)},
        )
        project_id = str(created["projectId"])
        store = ProjectStore(config)
        contract = store.ensure_contract_dir(project_id, "mission-001")
        (contract / "VAL-COMPOSED.md").write_text(
            "# VAL-COMPOSED\n", encoding="utf-8"
        )
        _call_process_mcp(
            url,
            "submit_plan",
            {
                "project_id": project_id,
                "task_list": {
                    "tasks": [
                        {"id": "worker-1", "type": "work", "body": "defective work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []},
                        {"id": "validator-1", "type": "validate", "body": "independent validation", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": ["worker-1"]},
                        {"id": "gate-1", "type": "gate", "body": "", "targets": ["VAL-COMPOSED"], "skill": None, "depends_on": ["validator-1"]},
                    ]
                },
            },
        )
        run_id = _submit_composed_advance(url, project_id, "defective-dissent")
        worker_checkpoint = _continue_composed_checkpoint(
            url, run_id, project_id, role="worker"
        )
        cursor = _composed_run_cursor(config, run_id)
        worker_pgid = int(json.loads(cursor.read_text())["pgid"])
        owned_pgids.add(worker_pgid)
        validator_checkpoint = _continue_composed_checkpoint(
            url, run_id, project_id, role="validator"
        )
        completed = _wait_for_run(url, run_id, "succeeded")
        assert completed["result"]["state"]["state"] == "attention_needed"
        assert len(completed["result"]["state"]["items"]) == 1

        worker = store.read_attempt(
            project_id,
            "mission-001",
            str(worker_checkpoint["attempt_id"]),
            "worker-1",
        )
        validator = store.read_attempt(
            project_id,
            "mission-001",
            str(validator_checkpoint["attempt_id"]),
            "validator-1",
        )
        assert worker.done is True
        assert validator.done is True
        assert validator.passed is False
        assert validator.items == [
            ValidationItem(item_id="VAL-COMPOSED", passed=False)
        ]
        assert _call_process_mcp(
            url, "inspect_project", {"project_id": project_id}
        )["state"]["state"] == "attention_needed"

    rows = [json.loads(line) for line in trace.read_text().splitlines()]
    assert [
        row["provider_role"]
        for row in rows
        if row.get("event") == "session_prompt"
    ] == ["work", "validate"]
    assert [
        (row["role"], row["recorded"])
        for row in rows
        if row.get("event") == "completion_repair"
    ] == [("worker", True), ("validator", True)]
    for pgid in owned_pgids:
        deadline = time.monotonic() + 5
        while _process_group_inventory(pgid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _process_group_inventory(pgid)


def test_composed_undeliverable_nudge_continues_without_body_persistence(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    """Drive the delivery-blocked outcome through public attached steering."""
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    adapter, trace = _write_composed_acp_adapter(workspace)
    _write_undeliverable_adapter(workspace)
    command = f"{sys.executable} {adapter} {trace}"
    role_environment = {
        "PYTHONPATH": str(workspace),
        "UNREST_WORKER_ACP_COMMAND": command,
        "UNREST_VALIDATOR_ACP_COMMAND": command,
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": command,
    }
    body = "PRIVATE-UNDELIVERABLE-NUDGE"
    owned_pgids: set[int] = set()
    with _http_server_process(
        config,
        workspace,
        mode="orchestrator",
        role_environment=role_environment,
    ) as (_, url):
        created = _call_process_mcp(
            url,
            "start_project",
            {"brief": "undeliverable composed nudge", "workspace_dir": str(workspace)},
        )
        project_id = str(created["projectId"])
        store = ProjectStore(config)
        contract = store.ensure_contract_dir(project_id, "mission-001")
        (contract / "VAL-COMPOSED.md").write_text(
            "# VAL-COMPOSED\n", encoding="utf-8"
        )
        _call_process_mcp(
            url,
            "submit_plan",
            {
                "project_id": project_id,
                "task_list": {
                    "tasks": [
                        {"id": "worker-1", "type": "work", "body": "work", "targets": ["VAL-COMPOSED"], "skill": "test", "depends_on": []}
                    ]
                },
            },
        )
        run_id = _submit_composed_advance(url, project_id, "undeliverable-nudge")
        checkpoint = _wait_for_attached_checkpoint(url, run_id, role="worker")
        cursor = _composed_run_cursor(config, run_id)
        worker_pgid = int(json.loads(cursor.read_text())["pgid"])
        owned_pgids.add(worker_pgid)
        blocked = _call_process_mcp(
            url,
            "steer_attempt",
            {
                "run_id": run_id,
                "request": _attached_steering_request(
                    project_id, checkpoint, "nudge", body=body
                ),
            },
        )
        assert blocked["code"] == "delivery_blocked"
        assert blocked["delivery_status"] == "delivery_blocked"
        completed = _wait_for_run(url, run_id, "succeeded")
        assert completed["result"]["state"]["state"] == "mission_running"
        durable = b"".join(
            path.read_bytes()
            for path in store.bucket_root(project_id).rglob("*")
            if path.is_file()
        )
        assert body.encode() not in durable

    rows = [json.loads(line) for line in trace.read_text().splitlines()]
    outcome = next(row for row in rows if row["event"] == "checkpoint_result")
    assert (outcome["action"], outcome["code"]) == (
        "continue",
        "delivery_blocked",
    )
    assert len([row for row in rows if row["event"] == "session_prompt"]) == 1
    for pgid in owned_pgids:
        deadline = time.monotonic() + 5
        while _process_group_inventory(pgid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _process_group_inventory(pgid)


@pytest.mark.parametrize("role", ("work", "validate"))
@pytest.mark.parametrize("repair", (True, False), ids=("repair", "second-invalid"))
def test_real_orchestrator_restart_preserves_completion_refusal_attempt(
    config: HarnessConfig,
    workspace: Path,
    role: str,
    repair: bool,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
        cwd=workspace,
        check=True,
    )
    store = ProjectStore(config)
    project_id = f"real-restart-{role}-{repair}"
    store.create_project("real restart", workspace, project_id=project_id)
    node_id = f"{role}-node"
    target_id = "VAL-BOUND-CANARY"
    store.save_task_list(
        project_id,
        "mission-001",
        TaskList(
            tasks=[
                Task(
                    id=node_id,
                    type=role,  # type: ignore[arg-type]
                    body="restart",
                    targets=[target_id],
                    skill="test",
                )
            ]
        ),
    )
    attempt_id = "same-process-attempt"
    handoff_path = store.attempt_path(
        project_id, "mission-001", attempt_id, node_id
    )
    counter = workspace / ".forbidden-child-counter"
    trap = workspace / ".forbidden-child-trap"
    trap.write_text(
        f"#!/bin/sh\nprintf x >> '{counter}'\nexit 91\n", encoding="utf-8"
    )
    trap.chmod(0o700)
    role_environment = {
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        "UNREST_NODE_ID": node_id,
        "UNREST_NODE_TYPE": role,
        "UNREST_HANDOFF_PATH": str(handoff_path),
        "UNREST_WORKER_ACP_COMMAND": str(trap),
        "UNREST_VALIDATOR_ACP_COMMAND": str(trap),
        "UNREST_TERMINAL_REVIEWER_ACP_COMMAND": str(trap),
    }
    items = [ValidationItem(item_id=target_id, passed=False)] if role == "validate" else []
    arguments: dict[str, object] = {
        "done": True,
        "report": "REPORT_PRIVACY_CANARY",
    }
    if role == "validate":
        arguments.update(
            items=[item.model_dump(mode="json") for item in items],
            passed=False,
        )
    carrier = _completion_oracle(
        workspace=workspace,
        attempt_id=attempt_id,
        task_type=role,
        targets=[target_id],
        done=True,
        items=items,
    )

    with _http_server_process(
        config,
        workspace,
        mode="validator" if role == "validate" else "worker",
        role_environment=role_environment,
    ) as (role_process, role_url):
        role_pgid = os.getpgid(role_process.pid)
        before = _process_group_inventory(role_pgid)
        with _http_server_process(config, workspace, mode="orchestrator") as (
            first_orchestrator,
            first_url,
        ):
            assert "inspect_project" in asyncio.run(_process_mcp_liveness(first_url))
            refused = _call_process_mcp(
                role_url, "end_node", {**arguments, "completion": {}}
            )
            assert refused["recorded"] is False
            first_orchestrator_pid = first_orchestrator.pid
        assert first_orchestrator.poll() is not None
        assert role_process.poll() is None
        assert os.getpgid(role_process.pid) == role_pgid
        after_refusal = _process_group_inventory(role_pgid)
        assert after_refusal == before
        assert not counter.exists()
        marker = next(
            store.mission_runtime_dir(project_id, "mission-001").glob(
                "completion-refusals/*.json"
            )
        )
        marker_bytes = marker.read_bytes()
        marker_mode = marker.stat().st_mode & 0o777
        assert b"REPORT_PRIVACY_CANARY" not in marker_bytes
        assert marker_mode == 0o600

        with _http_server_process(config, workspace, mode="orchestrator") as (
            second_orchestrator,
            second_url,
        ):
            assert second_orchestrator.pid != first_orchestrator_pid
            assert "inspect_project" in asyncio.run(_process_mcp_liveness(second_url))
            assert role_process.poll() is None
            assert os.getpgid(role_process.pid) == role_pgid
            second_arguments = dict(arguments)
            second_arguments["completion"] = carrier if repair else {}
            completed = _call_process_mcp(role_url, "end_node", second_arguments)
            assert completed["recorded"] is True
        assert _process_group_inventory(role_pgid) == before
        assert not counter.exists()
        assert not marker.exists()

    handoff = store.read_attempt(
        project_id, "mission-001", attempt_id, node_id
    )
    assert handoff.attempt_id == attempt_id
    assert handoff.done is repair
    assert handoff.request_attention is not repair


@pytest.mark.parametrize(
    ("role", "mode"),
    (
        ("worker", "worker"),
        ("validator", "validator"),
        ("terminal_reviewer", "terminal-reviewer"),
    ),
)
@pytest.mark.parametrize(
    ("action", "delivery_supported"),
    (("continue", True), ("nudge", True), ("nudge", False), ("stop_for_attention", True)),
    ids=("continue", "nudge", "blocked-delivery", "stop"),
)
def test_real_http_all_role_supervision_is_coordinator_causal(
    config: HarnessConfig,
    workspace: Path,
    role: str,
    mode: str,
    action: str,
    delivery_supported: bool,
) -> None:
    """One coordinator owns clock/requests while a distinct role process waits."""
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    project_id = controller.start_project("causal supervision", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-CAUSAL.md").write_text("# VAL-CAUSAL\n", encoding="utf-8")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="worker-1",
                    type="work",
                    body="work",
                    targets=["VAL-CAUSAL"],
                    skill="worker",
                ),
                Task(
                    id="validator-1",
                    type="validate",
                    body="validate",
                    targets=["VAL-CAUSAL"],
                    skill="validator",
                    depends_on=["worker-1"],
                ),
            ]
        ),
    )
    attempt_id = f"attempt-{role}"
    node_id = None if role == "terminal_reviewer" else f"{role}-1"
    coordinator = MissionCoordinator(
        controller.store,
        project_id,
        controller.dispatcher,
        controller.terminal_reviewer,
    )
    coordinator_thread = threading.get_ident()
    coordinator._begin_supervision_attempt(
        "mission-001",
        attempt_id=attempt_id,
        role=role,
        assigned_target_ids=["VAL-CAUSAL"],
        node_id=node_id,
        started_nanoseconds=0,
    )
    task_list = controller.store.load_task_list(project_id, "mission-001")
    for second, expected_requests in ((30, 0), (899, 0), (900, 1)):
        assert threading.get_ident() == coordinator_thread
        coordinator.poll_supervision(
            "mission-001", task_list, now_nanoseconds=second * 1_000_000_000
        )
        policy = load_policy_state(
            controller.store, project_id, "mission-001", attempt_id
        )
        assert policy is not None
        assert policy.checkpoint_requests == expected_requests
    started = load_snapshot(controller.store, project_id, "mission-001", attempt_id)
    assert started is not None
    assert started.elapsed_nanoseconds == 900_000_000_000
    assert started.checkpoint_requests == 1
    assert started.supervision_status == "checkpoint_due"
    coordinator.poll_supervision(
        "mission-001", task_list, now_nanoseconds=1_500 * 1_000_000_000
    )
    outstanding = load_policy_state(
        controller.store, project_id, "mission-001", attempt_id
    )
    assert outstanding is not None
    assert outstanding.checkpoint_requests == 1
    started = load_snapshot(controller.store, project_id, "mission-001", attempt_id)
    assert started is not None

    identity_path = (
        controller.store.terminal_review_path(project_id, "mission-001", attempt_id)
        if role == "terminal_reviewer"
        else controller.store.attempt_path(project_id, "mission-001", attempt_id, node_id)
    )
    role_environment = {
        "UNREST_PROJECT_ID": project_id,
        "UNREST_MISSION_ID": "mission-001",
        (
            "UNREST_TERMINAL_REVIEW_PATH"
            if role == "terminal_reviewer"
            else "UNREST_HANDOFF_PATH"
        ): str(identity_path),
    }
    if node_id is not None:
        role_environment["UNREST_NODE_ID"] = node_id
    child_snapshot = started.model_copy(
        update={
            "checkpoint_requests": 0,
            "checkpoint_sequence": 1,
            "elapsed_nanoseconds": 0,
            "phase": "waiting_at_checkpoint",
            "supervision_status": "waiting",
        },
        deep=True,
    ).model_dump(mode="json")
    effect_thread: list[int] = []
    with _http_server_process(
        config, workspace, mode=mode, role_environment=role_environment
    ) as (role_process, role_url), _http_server_process(
        config, workspace, mode="orchestrator"
    ) as (orchestrator_process, orchestrator_url), ThreadPoolExecutor(
        max_workers=1
    ) as pool:
        future = pool.submit(
            lambda: (
                effect_thread.append(threading.get_ident()),
                _call_process_mcp(
                    role_url,
                    "report_supervision_checkpoint",
                    {"snapshot": child_snapshot},
                ),
            )[1]
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            waiting = load_snapshot(
                controller.store, project_id, "mission-001", attempt_id
            )
            if waiting is not None and waiting.checkpoint_sequence == 1:
                break
            time.sleep(0.02)
        else:
            raise AssertionError("role effect did not reach its semantic checkpoint")
        assert effect_thread and effect_thread[0] != coordinator_thread
        assert role_process.pid != orchestrator_process.pid
        direct = controller.inspect_project_live(project_id).model_dump(mode="json")
        remote = _call_process_mcp(
            orchestrator_url, "inspect_project", {"project_id": project_id}
        )
        assert remote["active_attempts"] == direct["active_attempts"]

        seeded = dict(child_snapshot)
        seeded["elapsed_nanoseconds"] = 1
        seeded_error = _call_process_mcp(
            role_url, "report_supervision_checkpoint", {"snapshot": seeded}
        )
        assert seeded_error == {
            "error": {
                "code": "child_policy_state_forbidden",
                "message": "child policy state forbidden",
            }
        }
        assert "report_supervision_checkpoint" in asyncio.run(
            _process_mcp_liveness(role_url)
        )
        body = "PRIVATE-NUDGE-CANARY" if action == "nudge" else None
        receipt = controller.steer_attempt(
            SteeringRequest(
                project_id=project_id,
                mission_id="mission-001",
                node_id=node_id,
                terminal_review_id=(attempt_id if role == "terminal_reviewer" else None),
                attempt_id=attempt_id,
                checkpoint_sequence=1,
                action=action,
                actor="orchestrator",
                body=body,
            ),
            delivery_supported=delivery_supported,
        )
        outcome = future.result(timeout=10)
        expected_action = action if delivery_supported else "continue"
        assert outcome["action"] == expected_action
        assert outcome["code"] == (
            "nudge_consumed"
            if action == "nudge" and delivery_supported
            else receipt.code
        )
        durable = json.dumps(
            controller.inspect_project_live(project_id).model_dump(mode="json"),
            sort_keys=True,
        ) + "".join(
            path.read_text(encoding="utf-8")
            for path in controller.store.bucket_root(project_id).rglob("*.json")
        )
        assert "PRIVATE-NUDGE-CANARY" not in durable

    current = load_snapshot(controller.store, project_id, "mission-001", attempt_id)
    assert current is not None
    save_snapshot(
        controller.store,
        terminal_snapshot(current),
        assigned_target_ids=["VAL-CAUSAL"],
    )
    restarted = ProjectStore(config)
    assert load_snapshot(restarted, project_id, "mission-001", attempt_id) is not None
    assert restarted.load_state(project_id) is not None
    with _http_server_process(config, workspace, mode="orchestrator") as (
        third_process,
        third_url,
    ):
        post_stop = _call_process_mcp(
            third_url, "inspect_project", {"project_id": project_id}
        )
        assert post_stop["active_attempts"] == []
        assert third_process.poll() is None
