"""Advisory ticks preserve published semantic checkpoints on real storage."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.models import Task, TaskList, TaskStateFile
from unrest_harness.run_control import RunControl
from unrest_harness import supervision as s
from tests.test_run_control import project, _wait_for_state  # noqa: F401
from tests.test_supervision import _store, _controller, _request

NS = 1_000_000_000
Role = Literal["worker", "validator", "terminal_reviewer"]


def prepare(tmp_path: Path, role: Role):
    store = _store(tmp_path)
    tasks = TaskList(tasks=[
        Task(id="work-1", type="work", body="work", targets=["VAL-ONE"], skill="worker"),
        Task(id="validate-1", type="validate", body="validate", targets=["VAL-ONE"], skill="validator"),
    ])
    store.save_task_list("project-1", "mission-001", tasks)
    store.save_task_state("project-1", "mission-001", TaskStateFile())
    controller = _controller(store)
    coordinator = MissionCoordinator(store, "project-1", controller.dispatcher, controller.terminal_reviewer)
    coordinator._begin_supervision_attempt("mission-001", attempt_id="attempt-1", role=role,
        assigned_target_ids=["VAL-ONE"], node_id=(None if role == "terminal_reviewer" else
        "validate-1" if role == "validator" else "work-1"), started_nanoseconds=0)
    active = s.load_snapshot(store, "project-1", "mission-001", "attempt-1")
    assert active is not None
    return store, controller, coordinator, tasks, active


@pytest.mark.parametrize("role", ["worker", "validator", "terminal_reviewer"])
def test_waiting_row_stable_across_ticks_and_attached_projection(tmp_path, project, role):  # noqa: F811
    store, controller, coordinator, tasks, active = prepare(tmp_path, role)
    waiting = active.model_copy(update={"checkpoint_sequence": 1,
        "phase": "waiting_at_checkpoint", "supervision_status": "waiting"})
    controller.report_supervision_checkpoint(waiting)
    path = s.snapshot_path(store, "project-1", "mission-001", "attempt-1")
    before = path.read_bytes()
    saved = controller.inspect_project_live("project-1").model_dump(mode="json")["active_attempts"]
    assert saved == [waiting.model_dump(mode="json")]
    control = RunControl(project, executor_ref="executor_fixture:execute",
        project_inspector=lambda pid: controller.inspect_project_live(pid).model_dump(mode="json"))
    run = control.submit_run("advance_project", {"project_id": "project-1", "max_steps": 99}, "waiting")
    try:
        _wait_for_state(control, run.run_id, {"running"})
        for second in (29, 30, 59, 60, 900, 1500):
            coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=second * NS)
            assert control.inspect_run(run.run_id).as_dict()["active_attempts"] == saved
            assert controller.inspect_project_live("project-1").model_dump(mode="json")["active_attempts"] == saved
            assert path.read_bytes() == before
            assert s.load_policy_state(store, "project-1", "mission-001", "attempt-1").checkpoint_requests == 0
    finally:
        control.cancel_run(run.run_id, "test complete", "cancel-waiting")
        assert control.attach_run(run.run_id, timeout_seconds=5).state == "cancelled"


@pytest.mark.parametrize("role", ["worker", "validator", "terminal_reviewer"])
@pytest.mark.parametrize("action", ["continue", "stop_for_attention"])
def test_transition_restores_progress_and_terminal_is_fenced(tmp_path, role, action):
    store, controller, coordinator, tasks, active = prepare(tmp_path, role)
    for second in (30, 60):
        coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=second * NS)
        assert s.load_snapshot(store, "project-1", "mission-001", "attempt-1").elapsed_nanoseconds == second * NS
    current = s.load_snapshot(store, "project-1", "mission-001", "attempt-1")
    waiting = current.model_copy(update={"checkpoint_sequence": 1,
        "phase": "waiting_at_checkpoint", "supervision_status": "waiting"})
    binding = controller.report_supervision_checkpoint(waiting)
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=90 * NS)
    controller.steer_attempt(_request(binding, action))
    if action == "continue":
        assert s.wait_for_steering_action(store, binding, timeout_seconds=0).action == "continue"
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=120 * NS)
    current = s.load_snapshot(store, "project-1", "mission-001", "attempt-1")
    assert current.phase == ("active" if action == "continue" else "stopping")
    assert current.elapsed_nanoseconds == 120 * NS
    s.finalize_supervision_attempt(store, "project-1", "mission-001", "attempt-1", assigned_target_ids=["VAL-ONE"])
    path = s.snapshot_path(store, "project-1", "mission-001", "attempt-1")
    terminal = path.read_bytes()
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=150 * NS)
    assert path.read_bytes() == terminal


@pytest.mark.parametrize("role", ["worker", "validator", "terminal_reviewer"])
@pytest.mark.parametrize("transition", ["checkpoint", "resume", "stop", "terminal"])
def test_poll_cannot_overwrite_concurrent_semantic_publication(tmp_path, role, transition):
    import sys
    import threading

    store, controller, coordinator, tasks, active = prepare(tmp_path, role)
    admitted = threading.Event()
    release = threading.Event()
    errors = []

    def trace(frame, event, arg):
        if event == "call" and frame.f_code is s.save_advisory_snapshot.__code__:
            admitted.set()
            assert release.wait(5)
        return trace

    def poll():
        sys.settrace(trace)
        try:
            coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=900 * NS)
        except BaseException as exc:
            errors.append(exc)
        finally:
            sys.settrace(None)

    thread = threading.Thread(target=poll)
    thread.start()
    try:
        assert admitted.wait(5)
        waiting = active.model_copy(update={"checkpoint_sequence": 1,
            "phase": "waiting_at_checkpoint", "supervision_status": "waiting"})
        binding = controller.report_supervision_checkpoint(waiting)
        if transition in {"resume", "stop"}:
            action = "continue" if transition == "resume" else "stop_for_attention"
            controller.steer_attempt(_request(binding, action))
            if transition == "resume":
                s.wait_for_steering_action(store, binding, timeout_seconds=0)
        elif transition == "terminal":
            s.finalize_supervision_attempt(store, "project-1", "mission-001", "attempt-1",
                assigned_target_ids=["VAL-ONE"])
        path = s.snapshot_path(store, "project-1", "mission-001", "attempt-1")
        published = path.read_bytes()
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert path.read_bytes() == published
    policy = s.load_policy_state(store, "project-1", "mission-001", "attempt-1")
    assert policy.checkpoint_requests == 0
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=930 * NS)
    current = s.load_snapshot(store, "project-1", "mission-001", "attempt-1")
    if transition in {"checkpoint", "terminal"}:
        assert path.read_bytes() == published
    else:
        assert current.elapsed_nanoseconds == 930 * NS
        assert current.checkpoint_sequence == 1
        assert current.phase == ("active" if transition == "resume" else "stopping")


def test_waiting_policy_observes_effect_without_publishing_clock(tmp_path):
    store, controller, coordinator, tasks, active = prepare(tmp_path, "worker")
    waiting = active.model_copy(update={"checkpoint_sequence": 1, "last_effect_sequence": 1,
        "phase": "waiting_at_checkpoint", "supervision_status": "waiting"})
    controller.report_supervision_checkpoint(waiting)
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=60 * NS)
    policy = s.load_policy_state(store, "project-1", "mission-001", "attempt-1")
    assert policy.last_effect_sequence == 1 and policy.backoff_index == 1
    assert policy.checkpoint_requests == 0
    assert s.load_snapshot(store, "project-1", "mission-001", "attempt-1") == waiting


def test_active_clock_does_not_regress_within_tick(tmp_path):
    store, _, coordinator, tasks, active = prepare(tmp_path, "worker")
    # A semantic elapsed observation may be more precise than the quantized tick.
    s.save_snapshot(store, active.model_copy(update={"elapsed_nanoseconds": 61 * NS}),
        assigned_target_ids=["VAL-ONE"])
    coordinator.poll_supervision("mission-001", tasks, now_nanoseconds=62 * NS)
    assert s.load_snapshot(store, "project-1", "mission-001", "attempt-1").elapsed_nanoseconds == 61 * NS


def test_advisory_compare_does_not_swallow_corrupt_storage(tmp_path):
    store, _, coordinator, tasks, active = prepare(tmp_path, "worker")
    path = s.snapshot_path(store, "project-1", "mission-001", "attempt-1")
    path.write_bytes(b"{}")
    with pytest.raises(s.SupervisionSnapshotError):
        s.save_advisory_snapshot(store, active,
            active.model_copy(update={"elapsed_nanoseconds": 30 * NS}), assigned_target_ids=["VAL-ONE"])


@pytest.mark.parametrize("fault", ["missing", "target_partition"])
def test_advisory_compare_refuses_lost_or_corrupt_generation(tmp_path, fault):
    store, _, _, _, active = prepare(tmp_path, "worker")
    path = s.snapshot_path(store, "project-1", "mission-001", "attempt-1")
    if fault == "missing":
        path.unlink()
    else:
        path.write_text(active.model_copy(update={"remaining_target_ids": ["VAL-OTHER"]}).model_dump_json())
    with pytest.raises(s.SupervisionSnapshotError):
        s.save_advisory_snapshot(store, active,
            active.model_copy(update={"elapsed_nanoseconds": 30 * NS}), assigned_target_ids=["VAL-ONE"])
