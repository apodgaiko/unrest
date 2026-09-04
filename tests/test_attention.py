"""v0.4.5 attention identity, privacy, ordering, and restart proofs."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from unrest_harness import attention as attention_factory
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.envelope import public_attention_items
from unrest_harness.models import (
    AttentionItem,
    AttentionItemInternal,
    AttentionNeeded,
    Decision,
    Draft,
    Done,
    Failed,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore


PRIVATE_CANARIES = (
    "prompt-canary-DO-NOT-PUBLISH",
    "provider-output-canary",
    "secret-token-canary",
    "/private/source/path",
    "decision body canary",
)

EXPECTED_SUMMARIES = {
    "node_failed": "node failed; inspect authorized private attempt evidence before deciding",
    "node_attention": "node requested attention; inspect authorized private attempt evidence before deciding",
    "gate_failed": "gate failed; inspect authorized private gate evidence before deciding",
    "gate_checkpoint": "gate checkpoint; inspect authorized private gate evidence before deciding",
    "terminal_review": "terminal review; inspect authorized private review evidence before deciding",
}
INT_REQUIREMENTS = (
    Path(__file__).parent
    / "fixtures"
    / "legibility_v045"
    / "int-v045-compatibility-requirements.v1.json"
)


def _config(home: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=Path(__file__).parents[1] / "src" / "unrest_harness" / "bundled",
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=1,
    )


def _controller(tmp_path: Path) -> tuple[ProjectController, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(tmp_path / "home")
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                attempt_id=request.spawn_ts,
                done=True,
                report="complete",
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="complete")),
    )
    record = controller.store.create_project("brief", str(workspace), project_id="project")
    record.current_mission_id = "mission-001"
    controller.store.save_project(record)
    return controller, record.id


def _internal_items() -> list[AttentionItemInternal]:
    canaries = " | ".join(PRIVATE_CANARIES)
    return [
        AttentionItemInternal(
            id="a-node-failed",
            report=canaries,
            kind="node_failed",
            mission_id="mission-001",
            node_id="work-a",
            attempt_id="attempt-a",
            terminal_review_id=None,
        ),
        AttentionItemInternal(
            id="a-node-attention",
            report=canaries,
            kind="node_attention",
            mission_id="mission-001",
            node_id="validate-a",
            attempt_id="attempt-b",
            terminal_review_id=None,
        ),
        AttentionItemInternal(
            id="a-gate-failed",
            report=canaries,
            kind="gate_failed",
            mission_id="mission-001",
            node_id="gate-a",
            attempt_id=None,
            terminal_review_id=None,
        ),
        AttentionItemInternal(
            id="a-gate-checkpoint",
            report=canaries,
            kind="gate_checkpoint",
            mission_id="mission-001",
            node_id="gate-b",
            attempt_id=None,
            terminal_review_id=None,
        ),
        AttentionItemInternal(
            id="a-terminal",
            report=canaries,
            kind="terminal_review",
            mission_id="mission-001",
            node_id=None,
            attempt_id=None,
            terminal_review_id="review-a",
        ),
    ]


def _inventory(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _inspect_in_process(home: str, project_id: str, output: Any) -> None:
    config = _config(Path(home))
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                attempt_id=request.spawn_ts,
                done=True,
                report="complete",
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    output.put((multiprocessing.current_process().pid, controller.inspect_project(project_id).model_dump_json()))


def test_factories_author_exact_kind_specific_identity() -> None:
    work = Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")
    gate = Task(id="gate", type="gate", body="", targets=["FUT-A"])
    work_handoff = WorkHandoff(
        node_id="work", attempt_id="attempt-1", done=False, report="private"
    )
    validate_handoff = ValidateHandoff(
        node_id="work",
        attempt_id="attempt-2",
        done=True,
        report="private",
        request_attention=True,
    )

    rows = [
        attention_factory.node_failed("mission-001", work, work_handoff),
        attention_factory.node_attention("mission-001", work, validate_handoff),
        attention_factory.gate_failed("mission-001", gate, "private"),
        attention_factory.gate_checkpoint("mission-001", gate),
        attention_factory.terminal_review(
            "mission-001",
            TerminalReviewHandoff(done=False, report="private"),
            "review-1",
        ),
    ]

    assert [row.kind for row in rows] == list(EXPECTED_SUMMARIES)
    assert [row.attempt_id for row in rows] == ["attempt-1", "attempt-2", None, None, None]
    assert [row.terminal_review_id for row in rows] == [None, None, None, None, "review-1"]
    assert [row.node_id for row in rows] == ["work", "work", "gate", "gate", None]


@pytest.mark.parametrize("factory_name", ("node_failed", "node_attention"))
@pytest.mark.parametrize("attempt_id", (None, "", " ", "../attempt"))
def test_new_node_authoring_without_usable_attempt_identity_fails(
    factory_name: str,
    attempt_id: str | None,
) -> None:
    task = Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")
    handoff = WorkHandoff(
        node_id="work", attempt_id=attempt_id, done=False, report="private"
    )
    factory = getattr(attention_factory, factory_name)

    with pytest.raises(ValueError, match="immutable attempt identity"):
        factory("mission-001", task, handoff)


def test_public_projection_is_closed_ordered_exact_and_body_free() -> None:
    projected = public_attention_items(_internal_items())
    dumped = [item.model_dump(mode="json") for item in projected]

    assert [item["id"] for item in dumped] == [row.id for row in _internal_items()]
    assert [item["report"] for item in dumped] == list(EXPECTED_SUMMARIES.values())
    assert all(len(item.report.encode("utf-8")) <= 160 for item in projected)
    assert all(
        set(item) == {
            "id", "report", "kind", "mission_id", "node_id", "attempt_id",
            "terminal_review_id",
        }
        for item in dumped
    )
    public_bytes = json.dumps(dumped, sort_keys=True).encode()
    assert all(canary.encode() not in public_bytes for canary in PRIVATE_CANARIES)


def test_public_model_rejects_missing_and_extra_members() -> None:
    valid = public_attention_items(_internal_items()[:1])[0].model_dump(mode="json")
    for missing in ("kind", "mission_id", "attempt_id", "terminal_review_id"):
        mutated = dict(valid)
        mutated.pop(missing)
        with pytest.raises(ValidationError):
            AttentionItem.model_validate(mutated)
    with pytest.raises(ValidationError):
        AttentionItem.model_validate({**valid, "private_report": "forbidden"})


@pytest.mark.parametrize(
    "payload",
    (
        {
            "id": "bad-gate",
            "report": "private",
            "kind": "gate_failed",
            "mission_id": "mission-001",
            "node_id": "gate",
            "attempt_id": "attempt-x",
            "terminal_review_id": None,
        },
        {
            "id": "bad-review",
            "report": "private",
            "kind": "terminal_review",
            "mission_id": "mission-001",
            "node_id": "node-x",
            "attempt_id": "attempt-x",
            "terminal_review_id": "review-x",
        },
        {
            "id": "bad-node",
            "report": "private",
            "kind": "node_failed",
            "mission_id": "mission-001",
            "node_id": "node-x",
            "attempt_id": "attempt-x",
            "terminal_review_id": "review-x",
        },
    ),
)
def test_cross_kind_attention_identity_refuses_at_model_read_and_projection(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        AttentionItem.model_validate(payload)
    with pytest.raises(ValidationError):
        AttentionItemInternal.model_validate(payload)

    controller, project_id = _controller(tmp_path)
    attention_path = controller.store.unrest_runtime_dir(project_id) / "attention.json"
    attention_path.write_text(json.dumps({"items": [payload]}) + "\n", encoding="utf-8")
    original = attention_path.read_bytes()
    controller.store.save_state(project_id, AttentionNeeded(items=[]))
    before = _inventory(controller.store.bucket_root(project_id))

    with pytest.raises(ValidationError):
        controller.store.load_attention(project_id)
    with pytest.raises(ValidationError):
        controller.inspect_project(project_id)
    assert attention_path.read_bytes() == original
    assert _inventory(controller.store.bucket_root(project_id)) == before

    bypassed = AttentionItemInternal.model_construct(**payload)
    with pytest.raises(ValidationError):
        public_attention_items([_internal_items()[0], bypassed])


@pytest.mark.parametrize("count", (0, 1, 5))
def test_controller_rebuilds_zero_one_many_attention_and_restart_bytes(
    tmp_path: Path, count: int
) -> None:
    controller, project_id = _controller(tmp_path)
    items = _internal_items()[:count]
    controller.store.save_attention(project_id, items)
    controller.store.save_state(
        project_id,
        AttentionNeeded(items=public_attention_items(items)),
    )
    # Poison only the redundant state report. Projection must use attention.json.
    state_path = controller.store.unrest_runtime_dir(project_id) / "state.json"
    state_payload = json.loads(state_path.read_bytes())
    for item in state_payload["items"]:
        item["report"] = "stale-state-" + "-".join(PRIVATE_CANARIES)
    state_path.write_text(json.dumps(state_payload, separators=(",", ":")) + "\n")
    before = _inventory(controller.store.bucket_root(project_id))

    first = controller.inspect_project(project_id)
    first_bytes = first.model_dump_json().encode()
    restarted = ProjectController(
        controller.config, controller.dispatcher, controller.terminal_reviewer
    )
    second = restarted.inspect_project(project_id)
    advanced = restarted.advance_project(project_id, max_steps=1)

    assert first.next_action == "decide_attention"
    assert [item.id for item in first.state.items] == [item.id for item in items]
    assert first_bytes == second.model_dump_json().encode()
    assert first_bytes == advanced.model_dump_json().encode()
    assert _inventory(controller.store.bucket_root(project_id)) == before
    assert all(canary.encode() not in first_bytes for canary in PRIVATE_CANARIES)


@pytest.mark.parametrize(
    ("state_name", "expected"),
    (
        ("draft", "abort_project"),
        ("planning", "submit_plan"),
        ("running", "advance_project"),
        ("quiescent", "end_mission"),
        ("attention", "decide_attention"),
        ("done", "none"),
        ("failed", "none"),
        ("aborted", "none"),
    ),
)
def test_controller_next_action_matrix_is_read_only(
    tmp_path: Path, state_name: str, expected: str
) -> None:
    controller, project_id = _controller(tmp_path)
    mission_id = "mission-001"
    if state_name in {"running", "quiescent"}:
        controller.store.save_task_list(
            project_id,
            mission_id,
            TaskList(
                tasks=[
                    Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")
                ]
            ),
        )
        task_state = TaskStateFile()
        task_state.set_status("work", "pending" if state_name == "running" else "cleared")
        controller.store.save_task_state(project_id, mission_id, task_state)
        state: object = MissionRunning(mission_id=mission_id)
    elif state_name == "draft":
        state = Draft()
    elif state_name == "planning":
        state = MissionPlanning(mission_id=mission_id)
    elif state_name == "attention":
        item = _internal_items()[0]
        controller.store.save_attention(project_id, [item])
        state = AttentionNeeded(items=public_attention_items([item]))
    elif state_name == "done":
        state = Done()
    elif state_name == "failed":
        state = Failed(reason="failed")
    else:
        from unrest_harness.models import Aborted

        state = Aborted(reason="aborted")
    controller.store.save_state(project_id, state)  # type: ignore[arg-type]
    before = _inventory(controller.store.bucket_root(project_id))

    envelope = controller.inspect_project(project_id)

    assert envelope.next_action == expected
    assert _inventory(controller.store.bucket_root(project_id)) == before


def test_whole_envelope_bytes_match_in_independent_process_after_restart(
    tmp_path: Path,
) -> None:
    controller, project_id = _controller(tmp_path)
    items = _internal_items()
    controller.store.save_attention(project_id, items)
    controller.store.save_state(
        project_id, AttentionNeeded(items=public_attention_items(items))
    )
    expected = controller.inspect_project(project_id).model_dump_json()
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_inspect_in_process,
        args=(str(controller.config.harness_home), project_id, output),
    )

    process.start()
    child_pid, observed = output.get(timeout=2)
    process.join(10)
    assert process.exitcode == 0
    assert child_pid != multiprocessing.current_process().pid
    assert observed == expected


def test_legacy_missing_additive_ids_projects_explicit_null_without_rewrite(
    tmp_path: Path,
) -> None:
    controller, project_id = _controller(tmp_path)
    attention_path = controller.store.unrest_runtime_dir(project_id) / "attention.json"
    attention_path.write_text(
        '{"items":[{"id":"legacy","report":"private","kind":"node_failed",'
        '"mission_id":"mission-001","node_id":"work"}]}\n',
        encoding="utf-8",
    )
    original = attention_path.read_bytes()
    controller.store.save_state(
        project_id,
        AttentionNeeded(items=public_attention_items(controller.store.load_attention(project_id))),
    )

    envelope = controller.inspect_project(project_id)
    item = envelope.state.items[0]

    assert item.attempt_id is None
    assert item.terminal_review_id is None
    assert '"attempt_id":null' in envelope.model_dump_json()
    assert '"terminal_review_id":null' in envelope.model_dump_json()
    assert attention_path.read_bytes() == original


@pytest.mark.parametrize("missing", ("kind", "mission_id"))
def test_corrupt_required_internal_metadata_fails_closed_without_rewrite(
    tmp_path: Path, missing: str
) -> None:
    controller, project_id = _controller(tmp_path)
    payload = _internal_items()[0].model_dump(mode="json")
    payload.pop(missing)
    attention_path = controller.store.unrest_runtime_dir(project_id) / "attention.json"
    attention_path.write_text(json.dumps({"items": [payload]}) + "\n")
    original = attention_path.read_bytes()
    controller.store.save_state(project_id, AttentionNeeded(items=[]))

    with pytest.raises(ValidationError):
        controller.inspect_project(project_id)

    assert attention_path.read_bytes() == original


def test_safe_identity_resolves_existing_private_attempt_gate_and_review_readers(
    tmp_path: Path,
) -> None:
    controller, project_id = _controller(tmp_path)
    store: ProjectStore = controller.store
    mission_id = "mission-001"
    task = Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")
    attempt_id = "2026-08-30T00-00-00Z"
    private_attempt = WorkHandoff(
        node_id="work", attempt_id=attempt_id, done=False, report="private-attempt"
    )
    store.save_attempt(project_id, mission_id, attempt_id, task.id, private_attempt)
    review_id = "2026-08-30T00-01-00Z"
    private_review = TerminalReviewHandoff(done=False, report="private-review")
    store.save_terminal_review(project_id, mission_id, review_id, private_review)
    items = [
        attention_factory.node_failed(mission_id, task, private_attempt),
        attention_factory.gate_failed(
            mission_id,
            Task(id="gate", type="gate", body="", targets=["FUT-A"]),
            "private-gate",
        ),
        attention_factory.terminal_review(mission_id, private_review, review_id),
    ]
    store.save_attention(project_id, items)
    public = public_attention_items(items)

    attempt = store.read_attempt(
        project_id, public[0].mission_id, public[0].attempt_id or "", public[0].node_id or ""
    )
    gate = next(item for item in store.load_attention(project_id) if item.id == public[1].id)
    review = store.read_terminal_review(
        project_id, public[2].mission_id, public[2].terminal_review_id or ""
    )

    assert attempt.report == "private-attempt"
    assert gate.report.startswith("Gate report from gate")
    assert review.report == "private-review"


def test_int_requirements_are_path_specific_and_digest_backed() -> None:
    fixture_bytes = INT_REQUIREMENTS.read_bytes()
    payload = json.loads(fixture_bytes)
    rows = payload["requirements"]

    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "d00088228e5f81d394d25934338f07d316614524be1dbc077bda474eaf386de7"
    )
    assert payload["schema"] == "unrest.v045.w-leg-int-requirements.v1"
    assert len({row["path"] for row in rows}) == len(rows)
    assert all(row["operation"] in {"modify", "none"} for row in rows)
    assert all(row["contract_ids"] and row["requirement"] for row in rows)
    assert {
        "docs/v03/v0.3.1/public-surface.v1.json",
        "src/unrest_harness/bundled/foundation/public-surface.v1.json",
        "src/unrest_harness/public_schema.py",
        "src/unrest_harness/server.py",
        "src/unrest_harness/coordinator.py",
        "tests/test_server.py",
        "tests/test_distribution_check.py",
        "tools/check_distribution.py",
    } == {row["path"] for row in rows}


def test_real_controller_actions_follow_every_non_none_precondition(
    tmp_path: Path,
) -> None:
    controller, project_id = _controller(tmp_path)
    mission_id = "mission-001"

    controller.store.save_state(project_id, Draft())
    draft = controller.inspect_project(project_id)
    assert draft.next_action == "abort_project"
    aborted = controller.abort_project(project_id, "replace separately")
    assert aborted.next_action == "none"
    assert aborted.dag is None

    replacement_workspace = tmp_path / "replacement-workspace"
    replacement_workspace.mkdir()
    replacement = controller.start_project("replacement brief", str(replacement_workspace))
    assert replacement.projectId != project_id
    assert replacement.next_action == "submit_plan"
    assert controller.inspect_project(project_id).state.state == "aborted"

    replacement_id = replacement.projectId
    replacement_mission = replacement.state.mission_id
    contract_dir = controller.store.ensure_contract_dir(replacement_id, replacement_mission)
    (contract_dir / "FUT-A.md").write_text(
        "# FUT-A: controller flow\n\n"
        "Surface: library.\nNeeds: none.\nBehavior: flow.\nEvidence: test.\n",
        encoding="utf-8",
    )
    task_list = TaskList(
        tasks=[Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")]
    )
    submitted = controller.submit_plan(replacement_id, task_list)
    assert submitted.next_action == "advance_project"
    assert submitted.dag == submitted.frontier

    advanced = controller.advance_project(replacement_id, max_steps=1)
    assert advanced.next_action == "end_mission"
    inspected = controller.inspect_project(replacement_id)
    assert inspected.dag is not None and "work" in inspected.dag
    ended = controller.end_mission(replacement_id)
    assert ended.next_action == "none"
    assert ended.dag is None

    # A separate coherent attention fixture exercises the remaining public action.
    controller.store.save_state(project_id, MissionPlanning(mission_id=mission_id))
    controller.store.save_task_list(
        project_id,
        mission_id,
        TaskList(tasks=[Task(id="work", type="work", body="body", targets=["FUT-A"], skill="s")]),
    )
    task_state = TaskStateFile()
    task_state.set_status("work", "cleared")
    controller.store.save_task_state(project_id, mission_id, task_state)
    attention = AttentionItemInternal(
        id="attention",
        report="private",
        kind="node_attention",
        mission_id=mission_id,
        node_id="work",
        attempt_id="attempt",
        terminal_review_id=None,
    )
    controller.store.save_attention(project_id, [attention])
    controller.store.save_state(
        project_id, AttentionNeeded(items=public_attention_items([attention]))
    )
    projected = controller.inspect_project(project_id)
    assert projected.next_action == "decide_attention"
    decided = controller.decide_attention(
        project_id, [Decision(item_id="attention", action="continue")]
    )
    assert decided.state.state == "mission_running"
    assert decided.dag is None
