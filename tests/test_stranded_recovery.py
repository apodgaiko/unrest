"""File-backed recovery through public calls; no provider campaign."""
from __future__ import annotations

import json
from pathlib import Path

from fastmcp import Client
import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    Decision, MissionRunning, Task, TaskList, TaskListPatch,
    TerminalReviewHandoff, ValidateHandoff, WorkHandoff,
)
from unrest_harness.provider_review import ProviderReviewBlock, ReviewIdentity
from unrest_harness.server import create_orchestrator_server
from unrest_harness.storage import AttemptValidationError

MID = "mission-001"
CANARY = "private-retained-report-CANARY"


def task(name, kind="work", deps=()):
    return Task(id=name, type=kind, body="" if kind == "gate" else "controlled",
                targets=["VAL-001"] if name in ("failure", "gate") else [],
                skill=None if kind == "gate" else "s", depends_on=list(deps))


def setup(tmp_path, kind="work", extra=(), *, fail=True):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = HarnessConfig(
        bundled_dir=Path(__import__("unrest_harness").__file__).parent / "bundled",
        harness_home=tmp_path / "home", projects_dir=tmp_path / "home/projects",
        orchestrator_provider_name="claude", worker_provider_name="claude",
        worker_acp_command=None, validator_provider_name=None, validator_acp_command=None,
        terminal_reviewer_provider_name=None, terminal_reviewer_acp_command=None,
        max_parallel_nodes=1,
    )

    def respond(req):
        done = req.task.id != "failure" or not fail
        if req.task.type == "validate":
            return ValidateHandoff(node_id=req.task.id, done=done, report=CANARY)
        return WorkHandoff(node_id=req.task.id, done=done, report=CANARY)

    controller = ProjectController(config, MockDispatcher(respond),
                                   MockTerminalReviewer(TerminalReviewHandoff(done=True)))
    pid = controller.start_project("controlled recovery", str(workspace)).projectId
    contract = controller.store.ensure_contract_dir(pid, MID)
    (contract / "VAL-001.md").write_text("# VAL-001\n\nControlled.\n")
    failure = task("failure", kind)
    tasks = [failure, *extra]
    if kind == "validate":
        owner = task("owner").model_copy(update={"targets": ["VAL-001"]})
        failure.depends_on = ["owner"]
        tasks.insert(0, owner)
    controller.submit_plan(pid, TaskList(tasks=tasks))
    if kind == "validate":
        controller.advance_project(pid, max_steps=1)
        controller.dispatcher.calls.clear()
    return controller, pid


def restart(controller):
    return ProjectController(controller.config, controller.dispatcher, controller.terminal_reviewer)


def strand(controller, pid, monkeypatch):
    # Interrupt the actual original publication, after failure status/attempt
    # persistence. No fixture rewrites a verdict to manufacture stranding.
    with monkeypatch.context() as patch:
        def cut(*args):
            raise OSError("publication interrupted")
        patch.setattr(controller.store, "save_attention", cut)
        with pytest.raises(OSError, match="publication interrupted"):
            controller.advance_project(pid, max_steps=1)
    assert isinstance(controller.store.load_state(pid), MissionRunning)
    assert controller.store.load_task_state(pid, MID).status_of("failure") == "failed"


def preserved(controller, pid):
    store = controller.store
    attempts = store.list_attempts(pid, MID)
    return {
        "tasks": store.load_task_state(pid, MID).model_dump(),
        "contracts": store.load_contract_state(pid, MID).model_dump(),
        "attempts": {str(rec.path): (rec.path.read_bytes(),
                     store.attempt_report_path(pid, MID, rec.spawn_ts, rec.node_id).read_bytes())
                     for rec in attempts},
    }


@pytest.mark.parametrize("kind", ["work", "validate"])
@pytest.mark.parametrize("chain", ["serial", "transitive", "gate"])
def test_recover_exact_failure_without_reapplying_or_dispatch(tmp_path, monkeypatch, kind, chain):
    extra = [task("successor", deps=["failure"])]
    if chain == "transitive":
        extra.append(task("last", deps=["successor"]))
    if chain == "gate":
        extra = [task("gate", "gate", ["failure"]), task("last", deps=["gate"])]
    controller, pid = setup(tmp_path, kind, extra)
    strand(controller, pid, monkeypatch)
    before = preserved(controller, pid)
    calls = len(controller.dispatcher.calls)
    controller = restart(controller)
    envelope = controller.advance_project(pid)
    assert envelope.state.state == "attention_needed"
    item = controller.store.load_attention(pid)[0]
    assert item.kind == ("node_failed" if kind == "work" else "node_attention")
    assert (item.mission_id, item.node_id, item.attempt_id) == (
        MID, "failure", before["tasks"]["tasks"]["failure"]["last_attempt"])
    assert CANARY in item.report and "No new attempt was executed" in item.report
    assert CANARY not in envelope.model_dump_json()
    for _ in range(2):
        assert restart(controller).advance_project(pid).state == envelope.state
    assert len(controller.dispatcher.calls) == calls
    assert preserved(controller, pid) == before


@pytest.mark.parametrize("boundary", ["before_attention", "after_attention", "after_state"])
def test_actual_publication_boundaries_restart_deduplicates(tmp_path, monkeypatch, boundary):
    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    before = preserved(controller, pid)
    with monkeypatch.context() as patch:
        method = "save_attention" if boundary != "after_state" else "save_state"
        original = getattr(controller.store, method)
        def cut(*args):
            if boundary != "before_attention":
                original(*args)
            raise OSError("recovery cut")
        patch.setattr(controller.store, method, cut)
        with pytest.raises(OSError, match="recovery cut"):
            controller.advance_project(pid)
    open_before = controller.store.load_attention(pid)
    restart(controller).advance_project(pid)
    items = controller.store.load_attention(pid)
    assert len(items) == 1
    if open_before:
        assert items == open_before
    assert preserved(controller, pid) == before
    assert len(controller.dispatcher.calls) == 1


def test_resolved_validator_failure_is_resurfaced_with_new_event(tmp_path):
    controller, pid = setup(tmp_path, "validate", [task("successor", deps=["failure"])])
    first = controller.advance_project(pid).state.items[0]
    controller.decide_attention(pid, [Decision(item_id=first.id, action="continue")])
    before = preserved(controller, pid)
    second = restart(controller).advance_project(pid).state.items[0]
    assert second.id != first.id and second.attempt_id == first.attempt_id
    assert preserved(controller, pid) == before
    assert len(controller.dispatcher.calls) == 1


@pytest.mark.parametrize("fault", ["missing", "malformed", "node", "generation", "null", "type", "done", "stale", "absent_generation"])
def test_unverifiable_failure_refuses_without_mutation(tmp_path, monkeypatch, fault):
    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    store = controller.store
    entry = store.load_task_state(pid, MID).tasks["failure"]
    path = store.attempt_path(pid, MID, entry.last_attempt, "failure")
    raw = json.loads(path.read_text())
    if fault == "missing":
        path.unlink()
    elif fault == "malformed":
        path.write_text("{")
    elif fault == "stale":
        store.save_attempt(pid, MID, "zz-newer", "failure", WorkHandoff(node_id="failure", done=False, report="newer"))
    elif fault == "absent_generation":
        state = store.load_task_state(pid, MID)
        state.tasks["failure"].last_attempt = None
        store.save_task_state(pid, MID, state)
    else:
        if fault == "node":
            raw["node_id"] = "wrong"
        elif fault == "generation":
            raw["attempt_id"] = "wrong"
        elif fault == "null":
            raw["attempt_id"] = None
        elif fault == "type":
            raw.update(items=[], passed=False)
        else:
            raw["done"] = True
        path.write_text(json.dumps(raw))
    state_before = store.load_task_state(pid, MID)
    bytes_before = path.read_bytes() if path.exists() else None
    with pytest.raises(AttemptValidationError):
        restart(controller).advance_project(pid)
    assert store.load_task_state(pid, MID) == state_before
    assert store.load_attention(pid) == []
    assert (path.read_bytes() if path.exists() else None) == bytes_before
    assert len(controller.dispatcher.calls) == 1


@pytest.mark.parametrize("kind", ["work", "validate"])
def test_supported_retirement_preserves_history_and_invalid_patch_rolls_back(tmp_path, monkeypatch, kind):
    controller, pid = setup(tmp_path, kind, [task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    item = restart(controller).advance_project(pid).state.items[0]
    before = preserved(controller, pid)
    with pytest.raises(ToolError, match="patch validation failed"):
        controller.decide_attention(pid, [Decision(item_id=item.id, action="patch",
            patch=TaskListPatch(cancel=["absent"]))])
    assert preserved(controller, pid) == before
    assert controller.inspect_project(pid).state.items[0].id == item.id
    controller.decide_attention(pid, [Decision(item_id=item.id, action="patch",
        justification="explicit bounded retirement", patch=TaskListPatch(cancel=["failure"],
            add=[task("replacement").model_copy(update={"targets": ["VAL-001"]})] if kind == "work" else []))])
    after = preserved(controller, pid)
    assert after["attempts"] == before["attempts"] and after["contracts"] == before["contracts"]
    assert after["tasks"]["tasks"]["failure"]["status"] == "superseded"
    controller.advance_project(pid, max_steps=1)
    assert [req.task.id for req in controller.dispatcher.calls] == ["failure", "successor"]


@pytest.mark.parametrize("action", ["continue", "retry", "cancel", "supersede"])
def test_provider_guard_refuses_after_recovery(tmp_path, monkeypatch, action):
    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    entry = controller.store.load_task_state(pid, MID).tasks["failure"]
    controller.store.save_provider_review(pid, MID, entry.last_attempt, "failure", "thread",
        ProviderReviewBlock("denied", ReviewIdentity("thread", "turn", "review")))
    item = restart(controller).advance_project(pid).state.items[0]
    before = preserved(controller, pid)
    patch = None
    if action == "cancel":
        patch = TaskListPatch(cancel=["failure"])
    if action == "supersede":
        patch = TaskListPatch(add=[task("replacement")], supersede={"failure": "replacement"})
    with pytest.raises(ToolError) as caught:
        controller.decide_attention(pid, [Decision(item_id=item.id,
            action="patch" if patch else action, patch=patch)])
    assert caught.value.code == "invalid_decisions"
    assert preserved(controller, pid) == before
    assert len(controller.dispatcher.calls) == 1


@pytest.mark.parametrize("control", ["ready_work", "complete", "unrelated_failure", "reconciliation"])
def test_normal_scheduling_controls(tmp_path, monkeypatch, control):
    if control == "complete":
        controller, pid = setup(tmp_path, fail=False)
        controller.advance_project(pid)
        assert restart(controller).advance_project(pid).state.state == "mission_running"
        assert len(controller.dispatcher.calls) == 1
        return
    extra = [task("independent")] if control == "ready_work" else []
    controller, pid = setup(tmp_path, extra=extra)
    if control == "reconciliation":
        original = controller.store.save_task_state
        def cut(pid_, mid, state):
            if state.status_of("failure") == "failed":
                raise OSError("handoff cut")
            original(pid_, mid, state)
        with monkeypatch.context() as patch:
            patch.setattr(controller.store, "save_task_state", cut)
            with pytest.raises(OSError):
                controller.advance_project(pid)
        assert controller.store.load_task_state(pid, MID).status_of("failure") == "running"
        assert restart(controller).advance_project(pid).state.state == "attention_needed"
    else:
        strand(controller, pid, monkeypatch)
        assert restart(controller).advance_project(pid, max_steps=1).state.state == "mission_running"
        assert len(controller.dispatcher.calls) == (2 if control == "ready_work" else 1)


async def test_mcp_real_tools_recovery_inspection_and_retirement(tmp_path, monkeypatch):
    controller, pid = setup(tmp_path, "validate", [task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    async with Client(create_orchestrator_server(controller.config, controller=restart(controller))) as client:
        before = (await client.call_tool("inspect_project", {"project_id": pid})).data
        assert before["state"]["state"] == "mission_running"
        reply = (await client.call_tool("advance_project", {"project_id": pid})).data
        assert reply["state"]["state"] == "attention_needed" and CANARY not in json.dumps(reply)
        item = reply["state"]["items"][0]
        decision = (await client.call_tool("decide_attention", {"project_id": pid,
            "decisions": [{"item_id": item["id"], "action": "patch", "patch": {"cancel": ["failure"]}}]})).data
        assert decision["state"]["state"] == "mission_running"
    assert len(controller.dispatcher.calls) == 1


def test_live_snapshot_prevents_stranded_publication(tmp_path, monkeypatch):
    from unrest_harness.models import ActiveAttemptSnapshot
    from unrest_harness.supervision import save_snapshot

    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    snapshot = ActiveAttemptSnapshot(
        project_id=pid, mission_id=MID, node_id=None, role="terminal_reviewer",
        attempt_id="live-review", terminal_review_id="live-review", phase="active",
        supervision_status="running", completed_target_ids=[], remaining_target_ids=["VAL-001"],
        scope_status="in_scope", elapsed_nanoseconds=0, checkpoint_requests=0,
        checkpoint_sequence=0, last_effect_sequence=0, blocker_code=None,
    )
    save_snapshot(controller.store, snapshot, assigned_target_ids=["VAL-001"])
    assert restart(controller).advance_project(pid).state.state == "mission_running"
    assert controller.store.load_attention(pid) == []
    assert len(controller.dispatcher.calls) == 1


def test_actual_project_lock_contention_refuses_recovery(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from unrest_harness.project_lock import project_access_guard

    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    with project_access_guard(controller.store, pid):
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(ToolError) as caught:
                pool.submit(restart(controller).advance_project, pid).result()
    assert caught.value.code == "project_busy"
    assert controller.store.load_attention(pid) == []
    assert restart(controller).advance_project(pid).state.state == "attention_needed"


def test_ready_gate_precedes_stranded_failure(tmp_path, monkeypatch):
    controller, pid = setup(tmp_path, extra=[task("independent"),
        task("auditor", "validate", ["independent"]).model_copy(update={"targets": ["VAL-001"]}),
        task("gate", "gate", ["auditor"])])
    strand(controller, pid, monkeypatch)
    controller.advance_project(pid, max_steps=1)
    controller.advance_project(pid, max_steps=1)
    reply = controller.advance_project(pid)
    assert reply.state.state == "attention_needed"
    assert reply.state.items[0].kind == "gate_failed"
    assert reply.state.items[0].node_id == "gate"
    assert len(controller.dispatcher.calls) == 3


def test_multiple_failure_selection_uses_authored_order(tmp_path, monkeypatch):
    controller, pid = setup(tmp_path, "validate", [
        task("second", "validate", ["owner"]).model_copy(update={"targets": ["VAL-001"]}),
        task("last", deps=["second", "failure"]),
    ])
    controller.dispatcher._responder = lambda req: ValidateHandoff(node_id=req.task.id, done=False, report=req.task.id)
    # Both validators dispatch in one capacity slice and persist actual failure.
    from dataclasses import replace
    controller.config = replace(controller.config, max_parallel_nodes=2)
    controller.store.config = controller.config
    strand(controller, pid, monkeypatch)
    assert controller.store.load_task_state(pid, MID).status_of("second") == "failed"
    before = preserved(controller, pid)
    item = restart(controller).advance_project(pid).state.items[0]
    assert item.node_id == "failure"
    controller.decide_attention(pid, [Decision(item_id=item.id, action="patch", patch=TaskListPatch(cancel=["failure"]))])
    second = restart(controller).advance_project(pid).state.items[0]
    assert second.node_id == "second" and second.attempt_id != item.attempt_id
    assert preserved(controller, pid)["attempts"] == before["attempts"]
    assert len(controller.dispatcher.calls) == 2


@pytest.mark.parametrize("boundary", ["before_commit_create", "after_target_install:task_state"])
def test_retirement_transaction_interruption_recovers_whole_generation(tmp_path, monkeypatch, boundary):
    import unrest_harness.controller as module
    from unrest_harness.patch_transaction import PatchTransaction

    controller, pid = setup(tmp_path, "validate", [task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    item = restart(controller).advance_project(pid).state.items[0]
    before = preserved(controller, pid)
    class Cut(BaseException):
        pass
    def factory(*args, **kwargs):
        def fault(event):
            if event == boundary:
                raise Cut(event)
        return PatchTransaction(*args, **kwargs, fault_injector=fault)
    with monkeypatch.context() as patch:
        patch.setattr(module, "PatchTransaction", factory)
        with pytest.raises(Cut):
            controller.decide_attention(pid, [Decision(item_id=item.id, action="patch",
                patch=TaskListPatch(cancel=["failure"]))])
    state = restart(controller).inspect_project(pid).state
    after = preserved(controller, pid)
    assert after["attempts"] == before["attempts"] and after["contracts"] == before["contracts"]
    if boundary == "before_commit_create":
        assert state.state == "attention_needed" and after == before
    else:
        assert state.state == "mission_running"
        assert after["tasks"]["tasks"]["failure"]["status"] == "superseded"


@pytest.mark.parametrize("fault", ["type", "passed"])
def test_contradictory_validator_refuses(tmp_path, monkeypatch, fault):
    controller, pid = setup(tmp_path, "validate", [task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    entry = controller.store.load_task_state(pid, MID).tasks["failure"]
    path = controller.store.attempt_path(pid, MID, entry.last_attempt, "failure")
    raw = json.loads(path.read_text())
    if fault == "type":
        raw.pop("items")
        raw.pop("passed")
    else:
        raw["passed"] = True
    path.write_text(json.dumps(raw))
    before = preserved(controller, pid)
    with pytest.raises(AttemptValidationError):
        restart(controller).advance_project(pid)
    assert preserved(controller, pid) == before
    assert controller.store.load_attention(pid) == []


def test_real_cli_inspection_after_recovery(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys

    controller, pid = setup(tmp_path, extra=[task("successor", deps=["failure"])])
    strand(controller, pid, monkeypatch)
    restart(controller).advance_project(pid)
    env = dict(os.environ, UNREST_HOME=str(controller.config.harness_home),
               UNREST_PROJECTS_DIR=str(controller.config.projects_dir))
    result = subprocess.run([sys.executable, "-c", "from unrest_harness.cli import cli; cli()",
        "inspect-tasks", "--project", pid], env=env, cwd=tmp_path,
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "failure" in result.stdout and "failed" in result.stdout
    assert CANARY not in result.stdout + result.stderr
