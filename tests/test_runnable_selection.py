"""Runnable-task selection.

See `specs/task_list/PRODUCT.md` §Dispatch and Goal G4 (list order = topo
tie-breaker hint).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
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
        body="" if ttype == "gate" else "body",
        targets=targets,
        skill=skill,
        depends_on=depends_on or [],
    )


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


def _coordinator(config: HarnessConfig) -> MissionCoordinator:
    from unrest_harness.storage import ProjectStore
    dispatcher = MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report=""))
    reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
    return MissionCoordinator(ProjectStore(config), "p", dispatcher, reviewer)


class TestRunnableSelection:
    def test_list_order_tie_break(self, config: HarnessConfig) -> None:
        """Two work tasks share `depends_on: []`. List order = tie-break."""
        tl = TaskList(tasks=[
            _task("a", "work", ["X"]),
            _task("b", "work", ["Y"]),
        ])
        ts = TaskStateFile()
        ts.set_status("a", "pending")
        ts.set_status("b", "pending")
        c = _coordinator(config)
        runnable = c._all_runnable_tasks(tl, ts)
        assert [t.id for t in runnable] == ["a", "b"]

    def test_list_order_reversed_respected(self, config: HarnessConfig) -> None:
        tl = TaskList(tasks=[
            _task("b", "work", ["Y"]),
            _task("a", "work", ["X"]),
        ])
        ts = TaskStateFile()
        ts.set_status("a", "pending")
        ts.set_status("b", "pending")
        c = _coordinator(config)
        runnable = c._all_runnable_tasks(tl, ts)
        assert [t.id for t in runnable] == ["b", "a"]

    def test_gate_excluded_from_runnable(self, config: HarnessConfig) -> None:
        tl = TaskList(tasks=[
            _task("g1", "gate", ["X"]),
        ])
        ts = TaskStateFile()
        ts.set_status("g1", "pending")
        c = _coordinator(config)
        assert c._all_runnable_tasks(tl, ts) == []

    def test_blocked_by_pending_dep(self, config: HarnessConfig) -> None:
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("w2", "work", ["Y"], depends_on=["w1"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "pending")
        ts.set_status("w2", "pending")
        c = _coordinator(config)
        runnable = c._all_runnable_tasks(tl, ts)
        assert [t.id for t in runnable] == ["w1"]

    def test_unblocked_when_dep_cleared(self, config: HarnessConfig) -> None:
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("w2", "work", ["Y"], depends_on=["w1"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "cleared")
        ts.set_status("w2", "pending")
        c = _coordinator(config)
        runnable = c._all_runnable_tasks(tl, ts)
        assert [t.id for t in runnable] == ["w2"]

    def test_dep_on_superseded_does_not_become_runnable(
        self, config: HarnessConfig
    ) -> None:
        """With rewrite-on-patch, a task that still points at a superseded
        id is a contract violation (apply_patch would have rewritten the
        reference). The runtime is allowed to leave it un-runnable — only
        a `cleared` dep counts as satisfied.
        """
        tl = TaskList(tasks=[
            _task("w1", "work", ["X"]),
            _task("w2", "work", ["Y"], depends_on=["w1"]),
        ])
        ts = TaskStateFile()
        ts.set_status("w1", "superseded")
        ts.set_status("w2", "pending")
        c = _coordinator(config)
        runnable = c._all_runnable_tasks(tl, ts)
        assert runnable == []

    @pytest.mark.parametrize(
        ("task_types", "selected_id"),
        [
            (["work", "work"], "first"),
            (["work", "validate"], "first"),
            (["validate", "work"], "first"),
        ],
    )
    def test_capacity_slice_containing_work_selects_one_authored_task(
        self,
        config: HarnessConfig,
        task_types: list[str],
        selected_id: str,
    ) -> None:
        object.__setattr__(config, "max_parallel_nodes", 2)
        tl = TaskList(
            tasks=[
                _task("first", task_types[0], ["X"]),
                _task("second", task_types[1], ["Y"]),
            ]
        )
        ts = TaskStateFile()
        for task in tl.tasks:
            ts.set_status(task.id, "pending")

        coordinator = _coordinator(config)
        runnable = coordinator._all_runnable_tasks(tl, ts)

        assert [
            task.id
            for task in coordinator._select_dispatch_tasks(tl, ts, runnable)
        ] == [selected_id]

    def test_validator_only_capacity_slice_remains_batchable(
        self, config: HarnessConfig
    ) -> None:
        object.__setattr__(config, "max_parallel_nodes", 2)
        tl = TaskList(
            tasks=[
                _task("v1", "validate", ["X"]),
                _task("v2", "validate", ["Y"]),
                _task("v3", "validate", ["Z"]),
            ]
        )
        ts = TaskStateFile()
        for task in tl.tasks:
            ts.set_status(task.id, "pending")

        coordinator = _coordinator(config)
        runnable = coordinator._all_runnable_tasks(tl, ts)

        assert [
            task.id
            for task in coordinator._select_dispatch_tasks(tl, ts, runnable)
        ] == ["v1", "v2"]

    @pytest.mark.parametrize(
        ("capacity", "first_expected", "refill_expected"),
        [
            (1, ["validator-b"], ["validator-a"]),
            (2, ["validator-b", "validator-a"], ["validator-c"]),
        ],
    )
    def test_ready_gate_validator_lane_is_capacity_bounded_and_refills_in_order(
        self,
        config: HarnessConfig,
        capacity: int,
        first_expected: list[str],
        refill_expected: list[str],
    ) -> None:
        object.__setattr__(config, "max_parallel_nodes", capacity)
        validator_ids = ["validator-b", "validator-a", "validator-c"]
        tl = TaskList(
            tasks=[
                _task("work-owner", "work", ["X"]),
                _task("later-work", "work", [], depends_on=["work-owner"]),
                *[
                    _task(
                        validator_id,
                        "validate",
                        ["X"],
                        depends_on=["work-owner"],
                    )
                    for validator_id in validator_ids
                ],
                _task(
                    "gate",
                    "gate",
                    ["X"],
                    depends_on=[
                        "validator-c",
                        "validator-a",
                        "validator-b",
                    ],
                ),
            ]
        )
        ts = TaskStateFile()
        for task in tl.tasks:
            ts.set_status(task.id, "pending")
        ts.set_status("work-owner", "cleared")

        coordinator = _coordinator(config)
        runnable = coordinator._all_runnable_tasks(tl, ts)
        selected = coordinator._select_dispatch_tasks(tl, ts, runnable)

        assert [task.id for task in selected] == first_expected
        for task in selected:
            ts.set_status(task.id, "cleared")

        refill_runnable = coordinator._all_runnable_tasks(tl, ts)
        refill = coordinator._select_dispatch_tasks(tl, ts, refill_runnable)

        assert [task.id for task in refill] == refill_expected


class TestSerialDispatchPicksFirstByListOrder:
    def test_serial_prioritizes_ready_gate_validation_before_later_work(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        spawn_order: list[str] = []

        def responder(req: DispatchRequest) -> NodeHandoff:
            spawn_order.append(req.task.id)
            if req.task.type == "validate":
                return ValidateHandoff(
                    node_id=req.task.id,
                    done=True,
                    report="",
                    items=[ValidationItem(item_id=t, passed=True) for t in req.task.targets],
                    passed=True,
                )
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        controller.start_project("Brief.", str(workspace))
        pid = controller.store.list_projects()[0].id
        contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
        (contract_dir / "VAL-A.md").write_text("# VAL-A\n")
        (contract_dir / "VAL-B.md").write_text("# VAL-B\n")

        # `b` is runnable after `a` clears, but `va` can now seal the first
        # gate, so validation runs before dispatching later independent work.
        controller.submit_plan(pid, TaskList(tasks=[
            _task("a", "work", ["VAL-A"]),
            _task("b", "work", ["VAL-B"]),
            _task("va", "validate", ["VAL-A"], skill="aud", depends_on=["a"]),
            _task("vb", "validate", ["VAL-B"], skill="aud", depends_on=["b"]),
            _task("ga", "gate", ["VAL-A"], depends_on=["va"]),
            _task("gb", "gate", ["VAL-B"], depends_on=["vb"]),
        ]))
        controller.advance_project(pid)
        assert spawn_order == ["a", "va"]
