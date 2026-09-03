"""Envelope rendering tests (task-list shape)."""
from __future__ import annotations


import hashlib

import pytest

from unrest_harness.envelope import make_envelope, project_next_action, render_task_list
from unrest_harness.models import (
    Aborted,
    AttentionItem,
    AttentionNeeded,
    Done,
    Draft,
    Failed,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
)


def _build_pipeline(n_work: int) -> tuple[TaskList, TaskStateFile]:
    tasks: list[Task] = []
    target_ids = [f"X-{i:03d}" for i in range(n_work)]
    work_ids: list[str] = []
    for i in range(n_work):
        tid = f"w{i:03d}"
        work_ids.append(tid)
        tasks.append(
            Task(id=tid, type="work", body="b", targets=[f"X-{i:03d}"], skill="s")
        )
    tasks.append(
        Task(id="v1", type="validate", body="audit",
             targets=target_ids, skill="aud", depends_on=work_ids)
    )
    tasks.append(
        Task(id="g1", type="gate", body="", targets=target_ids, depends_on=["v1"])
    )
    return TaskList(tasks=tasks), TaskStateFile()


class TestRenderTaskList:
    def test_none(self) -> None:
        assert render_task_list(None, None) is None

    def test_header_counts(self) -> None:
        tl, ts = _build_pipeline(3)
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert rendered.startswith("Tasks — 5 total [pending:5]")

    def test_superseded_excluded_but_counted(self) -> None:
        tl, ts = _build_pipeline(3)
        ts.set_status("w001", "superseded")
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert "superseded:1" in rendered
        assert "w001" not in rendered

    def test_frontier_render_limits_to_ready_tasks(self) -> None:
        tl, ts = _build_pipeline(2)
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert "frontier: failed:0, running:0, ready:2, blocked:2" in rendered
        assert "gates: g1:pending" in rendered
        assert "w000" in rendered
        assert "w001" in rendered

    def test_summary_includes_focus_subgraph_around_last_cleared(self) -> None:
        tl, ts = _build_pipeline(2)
        ts.set_status("w000", "cleared")
        ts.set_status("w001", "cleared")
        ts.set_status("v1", "cleared")
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert "focus-subgraph around last-cleared:v1" in rendered
        assert "w000" in rendered
        assert "w001" in rendered
        assert "g1" in rendered

    def test_frontier_mode_keeps_action_rows_without_focus_subgraph(self) -> None:
        tl, ts = _build_pipeline(2)
        rendered = render_task_list(tl, ts, mode="frontier")
        assert rendered is not None
        assert "frontier: failed:0, running:0, ready:2, blocked:2" in rendered
        assert "    w000  [work:s]  pending  → X-000  ← (root)" in rendered
        assert "    w001  [work:s]  pending  → X-001  ← (root)" in rendered
        assert "focus-subgraph" not in rendered

    def test_full_mode_lists_predecessors(self) -> None:
        tl, ts = _build_pipeline(2)
        rendered = render_task_list(tl, ts, mode="full")
        assert rendered is not None
        assert "← w000,w001" in rendered or "← w001,w000" in rendered
        assert "← (root)" in rendered

    def test_envelope_dump_fields(self) -> None:
        env = make_envelope(
            "proj-1", Draft(), "/tmp/.unrest", "/home/u/.unrest/projects/proj-1"
        )
        dumped = env.model_dump()
        assert set(dumped.keys()) == {
            "projectId",
            "state",
            "projectRoot",
            "harnessRoot",
            "dag",
            "frontier",
            "next_action",
            "supersession_lineage",
            "active_attempts",
        }
        assert dumped["projectId"] == "proj-1"
        assert dumped["harnessRoot"] == "/home/u/.unrest/projects/proj-1"
        assert dumped["active_attempts"] == []

    def test_envelope_can_omit_dag(self) -> None:
        tl, ts = _build_pipeline(2)
        env = make_envelope(
            "proj-1",
            Draft(),
            "/tmp/.unrest",
            "/home/u/.unrest/projects/proj-1",
            tl,
            ts,
            dag_mode="none",
        )
        assert env.dag is None
        assert env.frontier is not None

    def test_ceiling_100_nodes_under_64kib(self) -> None:
        tl, ts = _build_pipeline(100)
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert "more frontier tasks omitted" in rendered
        assert len(rendered.encode("utf-8")) < 64 * 1024


@pytest.mark.parametrize(
    ("state", "expected"),
    (
        (Draft(), "abort_project"),
        (MissionPlanning(mission_id="mission-001"), "submit_plan"),
        (
            AttentionNeeded(
                items=[
                    AttentionItem(
                        id="a",
                        report="gate failed; inspect authorized private gate evidence before deciding",
                        kind="gate_failed",
                        mission_id="mission-001",
                        node_id="gate",
                        attempt_id=None,
                        terminal_review_id=None,
                    )
                ]
            ),
            "decide_attention",
        ),
        (Done(), "none"),
        (Failed(reason="failed"), "none"),
        (Aborted(reason="aborted"), "none"),
    ),
)
def test_next_action_closed_state_rows(state: object, expected: str) -> None:
    assert project_next_action(state, None, None) == expected  # type: ignore[arg-type]


def test_next_action_mission_running_preconditions() -> None:
    tl, ts = _build_pipeline(1)
    assert project_next_action(MissionRunning(mission_id="mission-001"), tl, ts) == (
        "advance_project"
    )
    for task in tl.tasks:
        ts.set_status(task.id, "cleared")
    assert project_next_action(MissionRunning(mission_id="mission-001"), tl, ts) == (
        "end_mission"
    )
    assert project_next_action(
        MissionRunning(mission_id="mission-001"), tl, None
    ) == "advance_project"


def test_full_dag_and_bounded_frontier_coexist() -> None:
    tl, ts = _build_pipeline(20)
    envelope = make_envelope(
        "project",
        MissionRunning(mission_id="mission-001"),
        "/project",
        "/harness",
        tl,
        ts,
        dag_mode="full",
    )

    assert envelope.dag is not None
    assert all(task.id in envelope.dag for task in tl.tasks)
    assert envelope.frontier is not None
    assert "more frontier tasks omitted" in envelope.frontier
    assert len(envelope.frontier) < len(envelope.dag)


def test_envelope_bytes_ignore_unordered_state_map_construction() -> None:
    tl, first = _build_pipeline(3)
    second = TaskStateFile()
    for task_id in reversed([task.id for task in tl.tasks]):
        second.set_status(task_id, first.status_of(task_id))

    one = make_envelope(
        "project",
        MissionRunning(mission_id="mission-001"),
        "/project",
        "/harness",
        tl,
        first,
        dag_mode="full",
    ).model_dump_json()
    two = make_envelope(
        "project",
        MissionRunning(mission_id="mission-001"),
        "/project",
        "/harness",
        tl,
        second,
        dag_mode="full",
    ).model_dump_json()

    assert hashlib.sha256(one.encode()).digest() == hashlib.sha256(two.encode()).digest()


def test_authored_task_order_remains_visible() -> None:
    first = Task(id="z-first", type="work", body="b", targets=["X-1"], skill="s")
    second = Task(id="a-second", type="work", body="b", targets=["X-2"], skill="s")
    tl = TaskList(tasks=[first, second])
    rendered = render_task_list(tl, TaskStateFile(), mode="full")

    assert rendered is not None
    assert rendered.index("z-first") < rendered.index("a-second")
