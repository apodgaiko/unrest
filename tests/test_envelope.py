"""Envelope rendering tests (task-list shape)."""
from __future__ import annotations


from unrest_harness.envelope import make_envelope, render_task_list
from unrest_harness.models import (
    Draft,
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
        }
        assert dumped["projectId"] == "proj-1"
        assert dumped["harnessRoot"] == "/home/u/.unrest/projects/proj-1"

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

    def test_ceiling_100_nodes_under_64kib(self) -> None:
        tl, ts = _build_pipeline(100)
        rendered = render_task_list(tl, ts)
        assert rendered is not None
        assert "more frontier tasks omitted" in rendered
        assert len(rendered.encode("utf-8")) < 64 * 1024
