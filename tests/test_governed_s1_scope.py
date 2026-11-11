"""Governed S1 execution scopes, outcome and abandon (VAL-30..36)."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.governed_s1_support import (
    abandon_request,
    governed_dir,
    governed_project,
    request,
    tree_snapshot,
    work_plan,
)
from unrest_harness import coordinator as coordinator_module
from unrest_harness import governed_admission as ga
from unrest_harness import governed_records as gr
from unrest_harness.controller import ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import DispatchRequest
from unrest_harness.models import MissionRunning, Task, TaskList, WorkHandoff
from unrest_harness.storage import AttemptValidationError


def _coordinator(controller, project_id) -> MissionCoordinator:
    return MissionCoordinator(controller.store, project_id, controller.dispatcher,
                              controller.terminal_reviewer, governed_delivery_route=True)


def _executions(controller, project_id, mid) -> Path:
    return governed_dir(controller.store, project_id, mid) / "executions"


def _scope_records(controller, project_id, mid) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    executions = _executions(controller, project_id, mid)
    if not executions.exists():
        return result
    for scope in sorted(executions.iterdir()):
        result[scope.name] = {
            name: json.loads((scope / f"{name}.json").read_bytes())
            for name in ("opened", "outcome", "closed") if (scope / f"{name}.json").exists()
        }
    return result


VALIDATION = TaskList(tasks=[
    Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s"),
    Task(id="w1", type="work", body="do", targets=["VAL-B"], skill="s"),
    Task(id="v0", type="validate", body="c", targets=["VAL-A"], skill="s",
         depends_on=["w0", "w1"]),
    Task(id="v1", type="validate", body="c", targets=["VAL-B"], skill="s",
         depends_on=["w0", "w1"])])
TWO = {"VAL-A": "a\n", "VAL-B": "b\n"}


def _validation_project(tmp_path, **kwargs):
    controller, project_id, mid = governed_project(tmp_path, criteria=TWO, plan=VALIDATION,
                                                   max_parallel_nodes=2, **kwargs)
    task_state = controller.store.load_task_state(project_id, mid)
    for task_id in ("w0", "w1"):
        task_state.set_status(task_id, "cleared")
    controller.store.save_task_state(project_id, mid, task_state)
    return controller, project_id, mid


# VAL-30 ----------------------------------------------------------------------


@pytest.mark.parametrize("failure", ["assert_unblocked", "save_task_state"])
def test_val30_single_failure_after_open_closes_not_launched(tmp_path, monkeypatch, failure):
    controller, project_id, mid = governed_project(tmp_path)
    if failure == "assert_unblocked":
        def boom(self, *args, **kwargs):
            raise AttemptValidationError("blocked")

        monkeypatch.setattr(MissionCoordinator, "_assert_dispatch_unblocked", boom)
        expected: type[BaseException] = AttemptValidationError
    else:
        def boom_store(*args, **kwargs):
            raise OSError("disk")

        monkeypatch.setattr(controller.store, "save_task_state", boom_store)
        expected = OSError
    with pytest.raises(expected):
        _coordinator(controller, project_id).step()
    monkeypatch.undo()
    (records,) = _scope_records(controller, project_id, mid).values()
    assert records["closed"]["closure"] == "not_launched"
    assert "outcome" not in records
    assert controller.dispatcher.calls == []
    receipt = controller.abandon_governance(project_id, mid, abandon_request())
    assert receipt["governed_abandon"]["status"] == "ABANDONED"


# VAL-31 ----------------------------------------------------------------------


def test_val31_batch_order_and_second_open_failure(tmp_path, monkeypatch):
    controller, project_id, mid = _validation_project(tmp_path)
    events: list[str] = []
    real_unique = MissionCoordinator._unique_attempt_id
    real_open = coordinator_module.open_scope
    real_save = controller.store.save_task_state

    def unique(self, *args):
        events.append("spawn")
        return real_unique(self, *args)

    def open_spy(store, scope):
        events.append("open")
        if events.count("open") == 2:
            raise OSError("second scope")
        return real_open(store, scope)

    def save_spy(*args, **kwargs):
        events.append("save")
        return real_save(*args, **kwargs)

    monkeypatch.setattr(MissionCoordinator, "_unique_attempt_id", unique)
    monkeypatch.setattr(coordinator_module, "open_scope", open_spy)
    monkeypatch.setattr(controller.store, "save_task_state", save_spy)
    task_state = controller.store.mission_runtime_dir(project_id, mid) / "task-state.json"
    before = task_state.read_bytes()
    result = _coordinator(controller, project_id).step()
    assert result.detail == "governed_witness_unavailable"
    assert events == ["spawn", "spawn", "open", "open"]
    assert task_state.read_bytes() == before
    (records,) = _scope_records(controller, project_id, mid).values()
    assert records["closed"]["closure"] == "not_launched"
    assert controller.dispatcher.calls == []


def test_val31_successful_batch_order(tmp_path, monkeypatch):
    controller, project_id, mid = _validation_project(tmp_path)
    events: list[str] = []
    real_unique = MissionCoordinator._unique_attempt_id
    real_open = coordinator_module.open_scope
    real_save = controller.store.save_task_state
    monkeypatch.setattr(MissionCoordinator, "_unique_attempt_id",
                        lambda self, *a: events.append("spawn") or real_unique(self, *a))
    monkeypatch.setattr(coordinator_module, "open_scope",
                        lambda store, scope: events.append("open") or real_open(store, scope))
    monkeypatch.setattr(controller.store, "save_task_state",
                        lambda *a, **k: events.append("save") or real_save(*a, **k))
    _coordinator(controller, project_id).step()
    assert events[:5] == ["spawn", "spawn", "open", "open", "save"]


# VAL-32 ----------------------------------------------------------------------


class _FakeManager:
    instances: list["_FakeManager"] = []

    def __init__(self, repository, **kwargs):
        self.cancelled: list[str] = []
        self.cleaned: list[str] = []
        self.leased: list[str] = []
        _FakeManager.instances.append(self)

    def lease_workspace(self, **kwargs):
        lease_id = kwargs["lease_id"]
        self.leased.append(lease_id)
        return SimpleNamespace(lease_id=lease_id, worktree_path=Path("/nonexistent"))

    def cancel_workspace(self, lease_id):
        self.cancelled.append(lease_id)

    def cleanup_workspace(self, lease_id):
        self.cleaned.append(lease_id)


def test_val32_isolated_open_failure_cancels_leases_without_fallback(tmp_path, monkeypatch):
    plan = TaskList(tasks=[
        Task(id="w0", type="work", body="do\nWrites: a.txt", targets=["VAL-A"], skill="s",
             auto_merge=True),
        Task(id="w1", type="work", body="do\nWrites: b.txt", targets=["VAL-B"], skill="s",
             auto_merge=True)])
    controller, project_id, mid = governed_project(tmp_path, criteria=TWO, plan=plan,
                                                   max_parallel_nodes=2)
    controller.dispatcher.supports_isolated_workspaces = True
    workspace = controller.store.workspace_dir(project_id).resolve()

    def fake_run(args, **kwargs):
        stdout = str(workspace) if "--show-toplevel" in args else "0" * 40
        return subprocess.CompletedProcess(args, 0, stdout=stdout + "\n", stderr="")

    _FakeManager.instances.clear()
    monkeypatch.setattr(coordinator_module.subprocess, "run", fake_run)
    monkeypatch.setattr(coordinator_module, "WorkspaceManager", _FakeManager)
    monkeypatch.setattr(coordinator_module, "open_scope",
                        lambda store, scope: (_ for _ in ()).throw(OSError("open")))
    fallback: list[str] = []
    real_one = MissionCoordinator._dispatch_one
    monkeypatch.setattr(MissionCoordinator, "_dispatch_one",
                        lambda self, *a, **k: fallback.append("one") or real_one(self, *a, **k))
    result = _coordinator(controller, project_id).step()
    assert result.detail == "governed_witness_unavailable"
    (manager,) = _FakeManager.instances
    assert len(manager.leased) == 2
    assert manager.cancelled == manager.leased and manager.cleaned == manager.leased
    assert fallback == []
    assert controller.dispatcher.calls == []


# VAL-33 ----------------------------------------------------------------------


def _outcome(controller, project_id, mid) -> list[str | None]:
    return [records.get("outcome", {}).get("outcome")  # type: ignore[union-attr,attr-defined]
            for records in _scope_records(controller, project_id, mid).values()]


@pytest.mark.parametrize("branch", ["other_node", "null_attempt", "stale_attempt"])
def test_val33_synthesis_branches_are_synthetic(tmp_path, branch):
    def responder(req: DispatchRequest):
        handoff = WorkHandoff(node_id="zz" if branch == "other_node" else req.task.id,
                              done=True, report="ok")
        if branch == "null_attempt":
            return handoff.model_copy(update={"attempt_id": None})
        if branch == "stale_attempt":
            return handoff.model_copy(update={"attempt_id": "20000101T000000Z"})
        return handoff

    controller, project_id, mid = governed_project(tmp_path, responder=responder)
    _coordinator(controller, project_id).step()
    assert _outcome(controller, project_id, mid) == ["synthetic"]


@pytest.mark.parametrize(("done", "expected"), [(True, "completed"), (False, "failed")])
def test_val33_plain_handoff(tmp_path, done, expected):
    controller, project_id, mid = governed_project(
        tmp_path, responder=lambda req: WorkHandoff(node_id=req.task.id, done=done, report="r"))
    _coordinator(controller, project_id).step()
    assert _outcome(controller, project_id, mid) == [expected]
    (records,) = _scope_records(controller, project_id, mid).values()
    assert records["closed"]["closure"] == "owner_joined"


def test_val33_single_dispatcher_exception_is_synthetic(tmp_path):
    def boom(req):
        raise RuntimeError("crash")

    controller, project_id, mid = governed_project(tmp_path, responder=boom)
    _coordinator(controller, project_id).step()
    assert _outcome(controller, project_id, mid) == ["synthetic"]


def test_val33_batch_crash_all_synthetic(tmp_path, monkeypatch):
    controller, project_id, mid = _validation_project(tmp_path)
    monkeypatch.setattr(controller.dispatcher, "dispatch_batch",
                        lambda requests: (_ for _ in ()).throw(RuntimeError("batch")),
                        raising=False)
    _coordinator(controller, project_id).step()
    assert _outcome(controller, project_id, mid) == ["synthetic", "synthetic"]


def test_val33_pool_per_request_exception(tmp_path, monkeypatch):
    def responder(req):
        if req.task.id == "v1":
            raise RuntimeError("one")
        return gr_validate_ok(req)

    controller, project_id, mid = _validation_project(tmp_path, responder=responder)
    monkeypatch.setattr(controller.dispatcher, "dispatch_batch", None, raising=False)
    _coordinator(controller, project_id).step()
    by_node = {records["opened"]["node_id"]: records.get("outcome", {}).get("outcome")
               for records in _scope_records(controller, project_id, mid).values()}
    assert by_node == {"v0": "completed", "v1": "synthetic"}


def gr_validate_ok(req):
    from unrest_harness.models import ValidateHandoff

    return ValidateHandoff(node_id=req.task.id, done=True, report="ok", items=[], passed=True)


def test_val33_base_exception_is_cancelled(tmp_path):
    class Stop(BaseException):
        pass

    def stop(req):
        raise Stop()

    controller, project_id, mid = governed_project(tmp_path, responder=stop)
    with pytest.raises(Stop):
        _coordinator(controller, project_id).step()
    assert _outcome(controller, project_id, mid) == ["cancelled"]


def test_val33_no_observation_no_outcome(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path)

    def broken(self, task, handoff, spawn_ts):
        raise ValueError("binding failed")

    monkeypatch.setattr(MissionCoordinator, "_bind_dispatched_handoff_observed", broken)
    with pytest.raises(ValueError):
        _coordinator(controller, project_id).step()
    (records,) = _scope_records(controller, project_id, mid).values()
    assert "outcome" not in records and records["closed"]["closure"] == "owner_joined"


def test_val33_closed_absent_while_dispatcher_blocked(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def blocking(req):
        entered.set()
        assert release.wait(30)
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    controller, project_id, mid = governed_project(tmp_path, responder=blocking)
    worker = threading.Thread(target=_coordinator(controller, project_id).step)
    worker.start()
    try:
        assert entered.wait(30)
        (records,) = _scope_records(controller, project_id, mid).values()
        assert "closed" not in records and "opened" in records
    finally:
        release.set()
        worker.join(30)
    (records,) = _scope_records(controller, project_id, mid).values()
    assert records["closed"]["closure"] == "owner_joined"


# VAL-34 ----------------------------------------------------------------------


def _fill_closed_scopes(controller, project_id, mid, count: int) -> None:
    executions = _executions(controller, project_id, mid)
    executions.mkdir(exist_ok=True)
    c = gr.classify(controller.store, project_id, mid)
    for index in range(count):
        attempt = f"2000-01-01T00-00-00Z-{index:04d}"
        scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                                  project_id=project_id, mission_id=mid,
                                  admission_id=c.admission_id or "", attempt_id=attempt,
                                  node_id="w0", inventory={})
        gr.open_scope(controller.store, scope)
        gr.close_scope(scope, effect_started=False, outcome=None)


def test_val34_capacity_refuses_before_mkdir_and_abandon_fits(tmp_path):
    controller, project_id, mid = governed_project(tmp_path)
    _fill_closed_scopes(controller, project_id, mid, gr.EXECUTIONS_MAX)
    executions = _executions(controller, project_id, mid)
    before = tree_snapshot(executions)
    assert _coordinator(controller, project_id).step().detail == "governed_witness_unavailable"
    assert tree_snapshot(executions) == before
    assert gr.classify(controller.store, project_id, mid).executions_status == "ok"
    receipt = controller.abandon_governance(project_id, mid, abandon_request())
    assert receipt["governed_abandon"]["status"] == "ABANDONED"
    size = (governed_dir(controller.store, project_id, mid) / "abandoned.json").stat().st_size
    assert size <= 169_184


def test_val34_batch_of_two_at_4095(tmp_path, monkeypatch):
    controller, project_id, mid = _validation_project(tmp_path)
    monkeypatch.setattr(coordinator_module, "count_executions",
                        lambda *a: gr.EXECUTIONS_MAX - 1)
    opened: list[str] = []
    monkeypatch.setattr(coordinator_module, "open_scope",
                        lambda store, scope: opened.append(scope.attempt_id))
    assert _coordinator(controller, project_id).step().detail == "governed_witness_unavailable"
    assert opened == []
    assert not _executions(controller, project_id, mid).exists()


# VAL-35 ----------------------------------------------------------------------


def test_val35_abandon_scope_lifecycle(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def blocking(req):
        entered.set()
        assert release.wait(30)
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    controller, project_id, mid = governed_project(tmp_path, responder=blocking)
    worker = threading.Thread(target=_coordinator(controller, project_id).step)
    worker.start()
    try:
        assert entered.wait(30)
        assert pytest.raises(ToolError, controller.abandon_governance, project_id, mid,
                             abandon_request()).value.code == "governed_scope_open"
    finally:
        release.set()
        worker.join(30)
    receipt = controller.abandon_governance(project_id, mid, abandon_request())
    record = json.loads((governed_dir(controller.store, project_id, mid)
                         / "abandoned.json").read_bytes())
    c = gr.classify(controller.store, project_id, mid)
    assert record["inspected_admission_ids"] == list(c.admission_ids)
    assert record["closed_execution_attempt_ids"] == sorted(c.executions)
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    again = controller.abandon_governance(project_id, mid, abandon_request())
    assert again["governed_abandon"]["replayed"] is True
    assert again["governed_abandon"]["abandon_id"] == receipt["governed_abandon"]["abandon_id"]
    assert tree_snapshot(bucket) == before
    assert pytest.raises(ToolError, controller.abandon_governance, project_id, mid,
                         abandon_request("other")).value.code == "governed_already_abandoned"
    late = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                             project_id=project_id, mission_id=mid,
                             admission_id=c.admission_id or "",
                             attempt_id="2000-01-01T00-00-00Z-9999", node_id="w0", inventory={})
    gr.open_scope(controller.store, late)
    gr.close_scope(late, effect_started=False, outcome=None)
    late_c = gr.classify(controller.store, project_id, mid)
    assert (late_c.admission_status, late_c.status_reason) == ("UNAVAILABLE", "abandon_conflict")
    controller.abort_project(project_id, "stop")


def test_val35_orphan_abandon_then_legacy_stays_abandoned(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path, admit=False)
    real_publish = ga.publish
    monkeypatch.setattr(ga, "publish", lambda fd, name, *a, **k: (
        (_ for _ in ()).throw(OSError("cut")) if name == "intent.json"
        else real_publish(fd, name, *a, **k)))
    with pytest.raises(ToolError):
        controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request())
    monkeypatch.undo()
    receipt = controller.abandon_governance(project_id, mid, abandon_request())
    assert receipt["governed_abandon"]["admission_phase"] == "precommit_orphan"
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert isinstance(controller.store.load_state(project_id), MissionRunning)
    assert gr.classify(controller.store, project_id, mid).admission_status == "ABANDONED"
    controller.abort_project(project_id, "stop")


def test_val35_abort_with_open_scope_is_baseline(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def blocking(req):
        entered.set()
        assert release.wait(30)
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    controller, project_id, mid = governed_project(tmp_path, responder=blocking)
    worker = threading.Thread(target=_coordinator(controller, project_id).step)
    worker.start()
    try:
        assert entered.wait(30)
        envelope = controller.abort_project(project_id, "stop")
        assert envelope.state.state == "aborted"
    finally:
        release.set()
        worker.join(30)


# VAL-36 ----------------------------------------------------------------------


def test_val36_scope_guard_inventory_and_conflict(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path)
    seen: list[tuple[object, ...]] = []
    real_guard = gr.guard

    def guard_spy(data, inventories):
        seen.append(tuple(inventories))
        return real_guard(data, inventories)

    monkeypatch.setattr(gr, "guard", guard_spy)
    monkeypatch.setenv("OPENAI_API_KEY", "zz-secret-value-0123456789")
    controller.store.refresh_inventory(os.environ)
    expected = dict(controller.store.inventory)
    assert expected
    _coordinator(controller, project_id).step()
    assert seen and all(len(item) == 1 and item[0] == expected for item in seen)
    monkeypatch.undo()
    c = gr.classify(controller.store, project_id, mid)
    scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                              project_id=project_id, mission_id=mid,
                              admission_id=c.admission_id or "",
                              attempt_id="2000-01-01T00-00-00Z-0001", node_id="w0",
                              inventory={"TOKEN": c.admission_id or ""})
    controller.store.inventory = {"TOKEN": c.admission_id or ""}
    with pytest.raises(gr.GovernedRedactionConflict):
        gr.open_scope(controller.store, scope)


# S-1 (declared limit) ----------------------------------------------------------


@pytest.mark.parametrize("cut", ["publish_eio", "guard_conflict"])
def test_s1_partial_open_cut_is_permanent_fail_closed(tmp_path, monkeypatch, cut):
    """A cut inside the real ``open_scope`` after ``mkdir X`` and before ``opened.json``
    leaves the mission's governed path permanently refused; abort stays available.
    Declared fail-closed limit: no recovery, retry or repair is claimed."""
    controller, project_id, mid = governed_project(tmp_path)
    if cut == "publish_eio":
        real_publish = gr.publish

        def publish(dir_fd, name, data, limit, **kwargs):
            if name == "opened.json":
                raise OSError(5, "injected EIO")
            return real_publish(dir_fd, name, data, limit, **kwargs)

        monkeypatch.setattr(gr, "publish", publish)
    else:
        real_guard = gr.guard

        def guard(data, inventories):
            if b"unrest.governed-execution-opened.v1" in data:
                raise gr.GovernedRedactionConflict()
            return real_guard(data, inventories)

        monkeypatch.setattr(gr, "guard", guard)
    first = _coordinator(controller, project_id).step()
    monkeypatch.undo()
    assert first.detail == "governed_witness_unavailable"
    assert controller.dispatcher.calls == []
    (scope,) = _executions(controller, project_id, mid).iterdir()
    assert sorted(p.name for p in scope.iterdir()) == []
    second = _coordinator(controller, project_id).step()
    assert second.detail == "governed_content_unavailable"
    assert controller.dispatcher.calls == []
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    assert pytest.raises(ToolError, controller.abandon_governance, project_id, mid,
                         abandon_request()).value.code == "governed_content_unavailable"
    assert tree_snapshot(bucket) == before
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert summary["executions_status"] == "unavailable"
    assert controller.abort_project(project_id, "operator abort").state.state == "aborted"
