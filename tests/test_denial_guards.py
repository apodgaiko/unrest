"""Controlled originating-denial guards: no genuine provider is invoked."""
from __future__ import annotations

import json

import pytest

from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.models import (
    Decision, MissionRunning, Task, TaskListPatch, ValidateHandoff, WorkHandoff,
)
from unrest_harness.storage import AttemptValidationError
from tests.test_provider_review import controller_fixture, publish


def fixture(tmp_path, *, pending=True):
    controller, store, calls = controller_fixture(tmp_path)
    publish(store)
    store.save_attempt("project", "mission-001", "attempt-1", "w1", WorkHandoff(
        node_id="w1", done=False, request_attention=True, report="controlled denial",
    ))
    envelope = controller.advance_project("project", max_steps=1)
    item = store.load_attention("project")[0]
    tl = store.load_task_list("project", "mission-001")
    tl.tasks.extend([
        Task(id="independent", type="work", body="controlled", targets=[], skill="s"),
        Task(id="descendant", type="work", body="controlled", targets=[], skill="s", depends_on=["w1"]),
    ])
    store.save_task_list("project", "mission-001", tl)
    ts = store.load_task_state("project", "mission-001")
    ts.set_status("w1", "pending" if pending else "failed")
    ts.set_status("independent", "pending")
    ts.set_status("descendant", "pending")
    store.save_task_state("project", "mission-001", ts)
    if pending:
        store.save_state("project", MissionRunning(mission_id="mission-001"))
    assert envelope.state.state == "attention_needed"
    return controller, store, calls, item


def protected(store):
    durable, cursor = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    return {p: p.read_bytes() for p in (
        durable, cursor,
        store.attempt_path("project", "mission-001", "attempt-1", "w1"),
        store.attempt_report_path("project", "mission-001", "attempt-1", "w1"),
        store.mission_runtime_dir("project", "mission-001") / "tasks.json",
    )}


def assert_protected(before):
    assert all(path.read_bytes() == data for path, data in before.items())


def test_public_advance_reconciles_before_selection_restart_and_preserves_origin(tmp_path, monkeypatch):
    controller, store, calls, _ = fixture(tmp_path)
    before = protected(store)
    sync_statuses = []
    synchronize = store.sync_workspace_skill_surfaces

    def observe_sync(project_id):
        state = store.load_task_state(project_id, "mission-001")
        sync_statuses.append(state.status_of("w1"))
        assert state.status_of("w1") == "failed"
        assert state.tasks["w1"].last_attempt == "attempt-1"
        assert_protected(before)
        synchronize(project_id)

    monkeypatch.setattr(controller.store, "sync_workspace_skill_surfaces", observe_sync)
    controller.advance_project("project", max_steps=1)
    assert sync_statuses == ["failed", "failed"]
    assert calls == ["independent"]
    ts = store.load_task_state("project", "mission-001")
    assert ts.status_of("w1") == "failed" and ts.tasks["w1"].last_attempt == "attempt-1"
    assert ts.status_of("independent") == "cleared" and ts.status_of("descendant") == "pending"
    c = MissionCoordinator(store, "project", controller.dispatcher, controller.terminal_reviewer)
    assert c._all_runnable_tasks(store.load_task_list("project", "mission-001"), ts) == []
    assert_protected(before)
    after = (store.mission_runtime_dir("project", "mission-001") / "task-state.json").read_bytes()
    restarted = ProjectController(store.config, controller.dispatcher, controller.terminal_reviewer)
    for _ in range(2):
        restarted.advance_project("project", max_steps=1)
    assert calls == ["independent"]
    assert (store.mission_runtime_dir("project", "mission-001") / "task-state.json").read_bytes() == after
    assert len(store.list_attempts("project", "mission-001", "w1")) == 1
    assert_protected(before)


@pytest.mark.parametrize("path", ["transactional", "legacy"])
def test_additive_patch_keeps_failed_origin(tmp_path, path):
    controller, store, calls, item = fixture(tmp_path, pending=False)
    before = protected(store)
    # tasks.json legitimately changes for this patch.
    before.pop(store.mission_runtime_dir("project", "mission-001") / "tasks.json")
    decision = Decision(item_id=item.id, action="patch", patch=TaskListPatch(add=[
        Task(id="repair", type="work", body="controlled", targets=[], skill="s"),
    ]))
    if path == "transactional":
        controller.decide_attention("project", [decision])
    else:
        with controller._project_access("project"):
            controller._apply_one("project", item, decision)
    ts = store.load_task_state("project", "mission-001")
    assert ts.status_of("w1") == "failed" and ts.tasks["w1"].last_attempt == "attempt-1"
    assert calls == []
    assert_protected(before)


@pytest.mark.parametrize("path", ["transactional", "legacy"])
@pytest.mark.parametrize("action", ["retry", "continue", "cancel", "supersede"])
def test_denial_decisions_cannot_override(tmp_path, path, action):
    controller, store, calls, item = fixture(tmp_path, pending=False)
    before = protected(store)
    state = (store.mission_runtime_dir("project", "mission-001") / "task-state.json").read_bytes()
    if action in ("cancel", "supersede"):
        patch = TaskListPatch(cancel=["w1"] if action == "cancel" else [],
                              supersede={"w1": "independent"} if action == "supersede" else {})
        decision = Decision(item_id=item.id, action="patch", patch=patch)
    else:
        decision = Decision(item_id=item.id, action=action)
    with pytest.raises(ToolError, match="prose consent"):
        if path == "transactional":
            controller.decide_attention("project", [decision])
        else:
            with controller._project_access("project"):
                controller._apply_one("project", item, decision)
    assert calls == []
    assert_protected(before)
    assert (store.mission_runtime_dir("project", "mission-001") / "task-state.json").read_bytes() == state


@pytest.mark.parametrize("damage", [
    "json", "session", "attempt", "node", "project", "missing_block", "missing_cursor",
    "new_generation", "missing_attempt", "handoff_node", "handoff_attempt", "receipt", "oversized",
])
def test_invalid_input_refuses_before_reconciliation_or_dispatch(tmp_path, monkeypatch, damage):
    controller, store, calls, _ = fixture(tmp_path)
    durable, cursor = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    if damage == "json":
        durable.write_text("{")
    elif damage == "oversized":
        durable.write_text("x" * 4097)
    elif damage in ("session", "attempt", "node", "project"):
        value = json.loads(durable.read_text())
        value[damage + "_id"] = "wrong"
        durable.write_text(json.dumps(value))
    elif damage in ("missing_block", "missing_cursor"):
        (durable if damage == "missing_block" else cursor).unlink()
    elif damage == "new_generation":
        ts = store.load_task_state("project", "mission-001")
        ts.set_last_attempt("w1", "newer")
        store.save_task_state("project", "mission-001", ts)
    elif damage == "receipt":
        durable.with_suffix(".appeal.json").write_text('{"disposition":"completed"}')
    else:
        path = store.attempt_path("project", "mission-001", "attempt-1", "w1")
        if damage == "missing_attempt":
            path.unlink()
        else:
            value = json.loads(path.read_text())
            value["node_id" if damage == "handoff_node" else "attempt_id"] = "wrong"
            path.write_text(json.dumps(value))
    directory = store.bucket_root("project")
    before = {p: p.read_bytes() for p in directory.rglob("*.json")}
    sync_calls = []
    monkeypatch.setattr(controller.store, "sync_workspace_skill_surfaces", sync_calls.append)
    with pytest.raises(AttemptValidationError):
        controller.advance_project("project", max_steps=1)
    assert calls == [] and sync_calls == []
    assert_protected(before)


@pytest.mark.parametrize("boundary", ["single", "batch", "isolated"])
def test_final_dispatch_boundary_excludes_denied_and_descendant(tmp_path, boundary):
    controller, store, calls, _ = fixture(tmp_path)
    before = protected(store)
    c = MissionCoordinator(store, "project", controller.dispatcher, controller.terminal_reviewer)
    tl = store.load_task_list("project", "mission-001")
    ts = store.load_task_state("project", "mission-001")
    if boundary == "single":
        c._dispatch_one("mission-001", tl.tasks[0])
        assert calls == []
    elif boundary == "isolated":
        c._dispatch_isolated_work_batch("mission-001", ts, tl.tasks)
        assert calls == ["independent"]
    else:
        for task in tl.tasks:
            task.type = "validate"
        store.save_task_list("project", "mission-001", tl)
        store.save_attempt("project", "mission-001", "attempt-1", "w1", ValidateHandoff(
            node_id="w1", done=False, report="controlled denial", items=[], passed=False,
        ))
        before = protected(store)
        before.pop(store.mission_runtime_dir("project", "mission-001") / "tasks.json")
        controller.dispatcher = type(controller.dispatcher)(lambda r: (
            calls.append(r.task.id) or ValidateHandoff(node_id=r.task.id, done=True, report="ok", items=[], passed=True)
        ))
        c.dispatcher = controller.dispatcher
        c._dispatch_batch("mission-001", tl, ts, tl.tasks)
        assert calls == ["independent"]
    assert store.load_task_state("project", "mission-001").tasks["w1"].last_attempt == "attempt-1"
    assert_protected(before)


@pytest.mark.parametrize("disposition", ["completed", "invalid"])
def test_completed_receipt_never_authorizes_fresh_replay(tmp_path, disposition):
    controller, store, calls, _ = fixture(tmp_path)
    durable, _ = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    durable.with_suffix(".appeal.json").write_text(json.dumps({
        "schema": "unrest.provider-review-appeal.v1", "run_id": "run:" + "a" * 64,
        "project_id": "project", "mission_id": "mission-001", "attempt_id": "attempt-1", "node_id": "w1",
        "disposition": disposition, "origin": {"threadId": "thread-1", "turnId": "turn-1", "reviewId": "review-1"},
    }))
    if disposition == "invalid":
        before = protected(store)
        with pytest.raises(AttemptValidationError):
            controller.advance_project("project", max_steps=1)
        assert calls == []
        assert_protected(before)
        return
    assert store.read_provider_review("project", "mission-001", "attempt-1", "w1") is None
    controller.advance_project("project", max_steps=1)
    assert calls == ["independent"]
    assert store.load_task_state("project", "mission-001").status_of("w1") == "failed"


def test_unrelated_retry_compatibility(tmp_path):
    controller, store, calls = controller_fixture(tmp_path)
    store.save_attempt("project", "mission-001", "attempt-1", "w1", WorkHandoff(node_id="w1", done=False, report="ordinary failure"))
    envelope = controller.advance_project("project", max_steps=1)
    controller.decide_attention("project", [Decision(item_id=envelope.state.items[0].id, action="retry")])
    controller.advance_project("project", max_steps=1)
    assert calls == ["w1"]


def test_validate_entire_inventory_before_any_status_write(tmp_path, monkeypatch):
    controller, store, calls, _ = fixture(tmp_path)
    from unrest_harness.provider_review import ProviderReviewBlock, ReviewIdentity

    ts = store.load_task_state("project", "mission-001")
    ts.set_last_attempt("independent", "attempt-2")
    store.save_task_state("project", "mission-001", ts)
    store.begin_provider_review("project", "mission-001", "attempt-2", "independent", "thread-2")
    store.save_provider_review("project", "mission-001", "attempt-2", "independent", "thread-2",
                              ProviderReviewBlock("denied", ReviewIdentity("thread-2", "turn-2", "review-2")))
    store.save_attempt("project", "mission-001", "attempt-2", "independent", WorkHandoff(node_id="independent", done=False, report="denied"))
    _, cursor = store.provider_review_paths("project", "mission-001", "attempt-2", "independent")
    cursor.write_text("{")
    before = {p: p.read_bytes() for p in store.bucket_root("project").rglob("*.json")}
    sync_calls = []
    monkeypatch.setattr(controller.store, "sync_workspace_skill_surfaces", sync_calls.append)
    with pytest.raises(AttemptValidationError):
        controller.advance_project("project", max_steps=1)
    assert calls == [] and sync_calls == []
    assert store.load_task_state("project", "mission-001").status_of("w1") == "pending"
    assert_protected(before)


@pytest.mark.parametrize("status", ["cleared", "superseded"])
def test_contradictory_disposition_refuses(tmp_path, status):
    controller, store, calls, _ = fixture(tmp_path)
    ts = store.load_task_state("project", "mission-001")
    ts.set_status("w1", status)
    store.save_task_state("project", "mission-001", ts)
    with pytest.raises(AttemptValidationError, match="disposition"):
        controller.advance_project("project", max_steps=1)
    assert calls == []
