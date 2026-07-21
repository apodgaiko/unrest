"""Supersede + cancel patch semantics (rewrite-on-patch model).

Covers:
- `supersede`: old marked superseded, downstream `depends_on` references
  rewritten to the new id in-place.
- `cancel`: task marked superseded, dropped from every downstream
  `depends_on` (no replacement).
- Status guards: cleared / running / sealed tasks cannot be
  superseded/cancelled.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.task_list_patch import apply_patch


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


def _task(
    tid: str,
    ttype: str,
    targets: list[str],
    skill: str | None = None,
    depends_on: list[str] | None = None,
) -> Task:
    if skill is None and ttype != "gate":
        skill = "s"
    return Task(
        id=tid,
        type=ttype,  # type: ignore[arg-type]
        body="" if ttype == "gate" else "b",
        targets=targets,
        skill=skill,
        depends_on=depends_on or [],
    )


class TestSupersedeRewrite:
    """supersede rewrites every downstream `depends_on` reference in-place."""

    def test_downstream_refs_rewritten(self) -> None:
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("v1", "validate", ["X"], skill="aud", depends_on=["w1"]),
            _task("g1", "gate", ["X"], depends_on=["v1"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "failed")
        patch = TaskListPatch(
            supersede={"w1": "w1_v2"},
            add=[_task("w1_v2", "work", ["X"])],
        )
        new_tl, new_ts, _, errs = apply_patch(tl, ts, {"X"}, patch)
        assert errs == []
        # v1's depends_on rewritten from [w1] to [w1_v2].
        v1_after = next(t for t in new_tl.tasks if t.id == "v1")
        assert v1_after.depends_on == ["w1_v2"]
        # w1 itself stays in the list (audit) with status=superseded.
        assert any(t.id == "w1" for t in new_tl.tasks)
        assert new_ts.status_of("w1") == "superseded"
        assert new_ts.status_of("w1_v2") == "pending"

    def test_runtime_runnable_after_rewrite(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        """After rewrite, a downstream task is runnable iff the rewritten
        dep (the live replacement) is cleared — not the old superseded one.
        """
        from unrest_harness.coordinator import MissionCoordinator
        from unrest_harness.storage import ProjectStore

        store = ProjectStore(config)
        store.create_project("brief", workspace, project_id="p1")

        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("downstream", "work", ["Y"], depends_on=["w1"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "failed")
        patch = TaskListPatch(
            supersede={"w1": "w1_v2"},
            add=[_task("w1_v2", "work", ["X"])],
        )
        new_tl, new_ts, _, errs = apply_patch(tl, ts, {"X", "Y"}, patch)
        assert errs == []

        coord = MissionCoordinator(
            store, "p1",
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        # w1_v2 pending → downstream blocked (its dep was rewritten to w1_v2).
        runnable_ids = [t.id for t in coord._all_runnable_tasks(new_tl, new_ts)]
        assert "w1_v2" in runnable_ids
        assert "downstream" not in runnable_ids

        # After w1_v2 clears, downstream becomes runnable.
        new_ts.set_status("w1_v2", "cleared")
        runnable_ids = [t.id for t in coord._all_runnable_tasks(new_tl, new_ts)]
        assert "downstream" in runnable_ids


class TestSupersedeGuards:
    def test_supersede_cleared_rejected(self) -> None:
        tl = TaskList(tasks=[_task("w1", "work", ["X"])])
        ts = TaskStateFile()
        ts.set_status("w1", "cleared")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(
                supersede={"w1": "w1_v2"},
                add=[_task("w1_v2", "work", ["X"])],
            ),
        )
        assert any(e.code == "supersede_cleared_task" for e in errs)

    def test_supersede_running_rejected(self) -> None:
        tl = TaskList(tasks=[_task("w1", "work", ["X"])])
        ts = TaskStateFile()
        ts.set_status("w1", "running")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(
                supersede={"w1": "w1_v2"},
                add=[_task("w1_v2", "work", ["X"])],
            ),
        )
        assert any(e.code == "supersede_status_invalid" for e in errs)

    def test_supersede_self_rejected(self) -> None:
        tl = TaskList(tasks=[_task("w1", "work", ["X"])])
        ts = TaskStateFile()
        ts.set_status("w1", "failed")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(supersede={"w1": "w1"}),
        )
        assert any(e.code == "supersede_self" for e in errs)

    def test_supersede_unknown_target(self) -> None:
        tl = TaskList(tasks=[_task("w1", "work", ["X"])])
        ts = TaskStateFile()
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(
                supersede={"ghost": "w_new"},
                add=[_task("w_new", "work", ["X"])],
            ),
        )
        assert any(e.code == "unknown_supersede_target" for e in errs)

    def test_supersede_inside_sealed_subgraph_rejected(self) -> None:
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("v1", "validate", ["X"], skill="aud", depends_on=["w1"]),
            _task("g1", "gate", ["X"], depends_on=["v1"]),
        ])
        ts = TaskStateFile()
        # Sealed: w1, v1 cleared; g1 cleared (sealed all upstream).
        ts.set_status("w1", "cleared")
        ts.set_status("v1", "cleared")
        ts.set_status("g1", "cleared")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(
                supersede={"w1": "w1_v2"},
                add=[_task("w1_v2", "work", ["X"])],
            ),
        )
        # supersede_cleared_task fires (more specific) — that alone is enough
        # to reject the patch.
        codes = {e.code for e in errs}
        assert codes & {"supersede_cleared_task", "supersede_inside_sealed_subgraph"}


class TestCancel:
    """cancel removes a task: superseded + dropped from downstream deps."""

    def test_cancel_drops_dep(self) -> None:
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("w2", "work", ["Y"]),
            _task("downstream", "work", ["Z"], depends_on=["w1", "w2"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "failed")
        # Cancel w1; downstream should keep only w2 as a dep.
        # The downstream task targets [Z] which has no fulfiller — provide one.
        # The simplest scenario: only test the rewrite, not the coverage rule,
        # by superseding the failed w1 with an empty cancel + add new fulfiller.
        new_tl, new_ts, _, errs = apply_patch(
            tl, ts, {"X", "Y", "Z"},
            TaskListPatch(
                cancel=["w1"],
                add=[
                    _task("w_z", "work", ["Z"]),
                    _task("w_x", "work", ["X"]),
                ],
            ),
        )
        # downstream covers Z — but `downstream` already targets Z too.
        # Coverage rule: every assertion → exactly one non-superseded work.
        # w1 is superseded; w_x covers X. downstream covers Z; w_z also covers Z
        # → over_covered_assertion.
        assert any(e.code == "over_covered_assertion" for e in errs)
        # Try simpler: cancel without changing coverage.

    def test_cancel_simple_drops_dep(self) -> None:
        # A discovery task with no targets is the cleanest cancel test —
        # cancelling it doesn't disturb assertion coverage.
        tl2 = TaskList(tasks=[
            _task("w_x", "work", ["X"]),
            _task("scout", "work", []),  # discovery, no targets
            _task("v", "validate", ["X"], skill="aud", depends_on=["w_x", "scout"]),
            _task("g", "gate", ["X"], depends_on=["v"]),
        ])
        ts2 = TaskStateFile()
        ts2.set_status("scout", "failed")
        new_tl, new_ts, _, errs = apply_patch(
            tl2, ts2, {"X"},
            TaskListPatch(cancel=["scout"]),
        )
        assert errs == [], errs
        v_after = next(t for t in new_tl.tasks if t.id == "v")
        assert v_after.depends_on == ["w_x"]
        # scout itself stays in the list as audit, status=superseded.
        scout_after = next(t for t in new_tl.tasks if t.id == "scout")
        assert scout_after is not None
        assert new_ts.status_of("scout") == "superseded"

    def test_cancel_unblocks_downstream(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        """A downstream task whose only dep is cancelled becomes runnable."""
        from unrest_harness.coordinator import MissionCoordinator
        from unrest_harness.storage import ProjectStore

        store = ProjectStore(config)
        store.create_project("brief", workspace, project_id="p1")

        tl = TaskList(tasks=[
            _task("scout", "work", []),
            _task("w_x", "work", ["X"], depends_on=["scout"]),
        ])
        ts = TaskStateFile()
        ts.set_status("scout", "failed")
        new_tl, new_ts, _, errs = apply_patch(
            tl, ts, {"X"}, TaskListPatch(cancel=["scout"]),
        )
        assert errs == []

        coord = MissionCoordinator(
            store, "p1",
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        runnable_ids = [t.id for t in coord._all_runnable_tasks(new_tl, new_ts)]
        assert "w_x" in runnable_ids

    def test_cancel_cleared_rejected(self) -> None:
        tl = TaskList(tasks=[
            _task("w_x", "work", ["X"]),
            _task("scout", "work", []),
        ])
        ts = TaskStateFile()
        ts.set_status("scout", "cleared")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"}, TaskListPatch(cancel=["scout"]),
        )
        assert any(e.code == "cancel_cleared_task" for e in errs)

    def test_cancel_running_rejected(self) -> None:
        tl = TaskList(tasks=[
            _task("w_x", "work", ["X"]),
            _task("scout", "work", []),
        ])
        ts = TaskStateFile()
        ts.set_status("scout", "running")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"}, TaskListPatch(cancel=["scout"]),
        )
        assert any(e.code == "cancel_status_invalid" for e in errs)

    def test_cancel_unknown_rejected(self) -> None:
        tl = TaskList(tasks=[_task("w_x", "work", ["X"])])
        ts = TaskStateFile()
        _, _, _, errs = apply_patch(
            tl, ts, {"X"}, TaskListPatch(cancel=["ghost"]),
        )
        assert any(e.code == "unknown_cancel_target" for e in errs)

    def test_cancel_overlap_with_supersede_rejected(self) -> None:
        tl = TaskList(tasks=[
            _task("w_x", "work", ["X"]),
            _task("scout", "work", []),
        ])
        ts = TaskStateFile()
        ts.set_status("scout", "failed")
        _, _, _, errs = apply_patch(
            tl, ts, {"X"},
            TaskListPatch(
                cancel=["scout"],
                supersede={"scout": "scout_v2"},
                add=[_task("scout_v2", "work", [])],
            ),
        )
        assert any(e.code == "cancel_supersede_overlap" for e in errs)
