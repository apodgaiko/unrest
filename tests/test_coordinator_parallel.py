"""Parallel coordinator behaviour (task-list shape)."""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    MissionRunning,
    Task,
    TaskList,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore


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
    )


def _task(tid: str, target: str) -> Task:
    return Task(id=tid, type="work", body="b", targets=[target], skill="s")


def _write_contract(store: ProjectStore, pid: str, mission_id: str, assertion: str) -> None:
    d = store.ensure_contract_dir(pid, mission_id)
    (d / f"{assertion}.md").write_text(f"# {assertion}\n\nStatement body.\n")


def _parallel_config(config: HarnessConfig, n: int = 2) -> HarnessConfig:
    object.__setattr__(config, "max_parallel_nodes", n)
    return config


class _BatchTrackingDispatcher(MockDispatcher):
    def __init__(self, responder: Callable[[DispatchRequest], NodeHandoff]):
        super().__init__(responder)
        self.batch_calls: list[list[str]] = []

    def dispatch_batch(self, requests: list[DispatchRequest]) -> list[NodeHandoff]:
        self.batch_calls.append([request.task.id for request in requests])
        return super().dispatch_batch(requests)


class _FallbackDispatcher:
    """Dispatcher without dispatch_batch, exercising coordinator fallback."""

    def __init__(self, responder: Callable[[DispatchRequest], NodeHandoff]):
        self._responder = responder
        self.calls: list[DispatchRequest] = []

    def dispatch(self, request: DispatchRequest) -> NodeHandoff:
        self.calls.append(request)
        handoff = self._responder(request)
        if "attempt_id" not in handoff.model_fields_set:
            return handoff.model_copy(update={"attempt_id": request.spawn_ts})
        return handoff


def _dispatcher(
    kind: str,
    responder: Callable[[DispatchRequest], NodeHandoff],
) -> _BatchTrackingDispatcher | _FallbackDispatcher:
    if kind == "batch":
        return _BatchTrackingDispatcher(responder)
    return _FallbackDispatcher(responder)


def test_batch_dispatch_crash_matches_serial_bounded_redaction(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "batch-overlap-known-value-86e2"
    monkeypatch.setenv("OPENAI_API_KEY", sentinel)

    def crash(_request: DispatchRequest) -> NodeHandoff:
        raise RuntimeError(f"{sentinel}|{sentinel}-suffix|" + "y" * 5000)

    class BatchCrashDispatcher:
        def dispatch(self, request: DispatchRequest) -> NodeHandoff:
            return crash(request)

        def dispatch_batch(self, _requests: list[DispatchRequest]) -> list[NodeHandoff]:
            raise RuntimeError(f"{sentinel}|{sentinel}-suffix|" + "y" * 5000)

    controller = ProjectController(
        _parallel_config(config, n=2),
        BatchCrashDispatcher(),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("batch diagnostic", str(workspace))
    pid = controller.store.list_projects()[0].id
    for target in ("VAL-A", "VAL-B"):
        _write_contract(controller.store, pid, "mission-001", target)
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                Task(id="work-a", type="work", body="b", targets=["VAL-A"], skill="s"),
                Task(id="work-b", type="work", body="b", targets=["VAL-B"], skill="s"),
                Task(
                    id="validator-a",
                    type="validate",
                    body="b",
                    targets=["VAL-A"],
                    skill="s",
                    depends_on=["work-a"],
                ),
                Task(
                    id="validator-b",
                    type="validate",
                    body="b",
                    targets=["VAL-B"],
                    skill="s",
                    depends_on=["work-b"],
                ),
            ]
        ),
    )
    task_state = controller.store.load_task_state(pid, "mission-001")
    task_state.set_status("work-a", "cleared")
    task_state.set_status("work-b", "cleared")
    controller.store.save_task_state(pid, "mission-001", task_state)
    controller.advance_project(pid, max_steps=1)

    runtime_attempts = sorted(
        controller.store.attempts_runtime_dir(pid, "mission-001").glob("*.json")
    )
    assert len(runtime_attempts) == 2
    for path in runtime_attempts:
        report = json.loads(path.read_text())["report"]
        assert len(report) <= 2000
        assert sentinel not in report
    for root in (
        controller.store.unrest_dir(pid),
        controller.store.unrest_runtime_dir(pid),
    ):
        for path in root.rglob("*"):
            if path.is_file():
                assert sentinel not in path.read_text(errors="replace")


def test_max_parallel_one_uses_current_workspace(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    seen_cwds: dict[str, str | None] = {}

    def responder(req: DispatchRequest) -> WorkHandoff:
        seen_cwds[req.task.id] = req.cwd
        (workspace / f"{req.task.id}.txt").write_text(f"{req.task.id}\n")
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    serial_config = _parallel_config(config, n=1)
    controller = ProjectController(
        serial_config,
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    _write_contract(controller.store, pid, "mission-001", "VAL-B")
    controller.submit_plan(pid, TaskList(tasks=[_task("a", "VAL-A"), _task("b", "VAL-B")]))

    controller.advance_project(pid, max_steps=1)
    controller.advance_project(pid, max_steps=1)

    assert seen_cwds == {"a": None, "b": None}
    assert (workspace / "a.txt").read_text() == "a\n"
    assert (workspace / "b.txt").read_text() == "b\n"


def test_auto_merge_false_still_uses_current_workspace(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    seen_cwd: Path | None = None

    def responder(req: DispatchRequest) -> WorkHandoff:
        nonlocal seen_cwd
        seen_cwd = Path(req.cwd) if req.cwd is not None else workspace
        (workspace / "candidate.txt").write_text("candidate\n")
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    serial_config = _parallel_config(config, n=1)
    controller = ProjectController(
        serial_config,
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "EXP-A")
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                Task(
                    id="exp-a",
                    type="work",
                    body="b",
                    targets=["EXP-A"],
                    skill="s",
                    auto_merge=False,
                )
            ]
        ),
    )

    env = controller.advance_project(pid, max_steps=1)

    assert env.state.state == "mission_running"
    assert seen_cwd == workspace
    assert (workspace / "candidate.txt").read_text() == "candidate\n"
    assert controller.store.load_attention(pid) == []


@pytest.mark.parametrize("dispatcher_kind", ["batch", "fallback"])
@pytest.mark.parametrize("capacity", [1, 2])
def test_ready_gate_validator_lane_respects_capacity_and_refills_before_more_work(
    config: HarnessConfig,
    workspace: Path,
    dispatcher_kind: str,
    capacity: int,
) -> None:
    starts: dict[str, float] = {}
    finishes: dict[str, float] = {}
    running_snapshots: list[tuple[str, ...]] = []
    work_calls: list[str] = []
    lock = threading.Lock()
    pid = ""

    def responder(req: DispatchRequest) -> WorkHandoff | ValidateHandoff:
        if req.task.type == "work":
            work_calls.append(req.task.id)
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")

        with lock:
            starts[req.task.id] = time.monotonic()
            task_state = controller.store.load_task_state(pid, "mission-001")
            running_snapshots.append(
                tuple(
                    task.id
                    for task in controller.store.load_task_list(
                        pid, "mission-001"
                    ).tasks
                    if task_state.status_of(task.id) == "running"
                )
            )
        time.sleep(0.05)
        with lock:
            finishes[req.task.id] = time.monotonic()
        return ValidateHandoff(
            node_id=req.task.id,
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-A", passed=True)],
            passed=True,
        )

    dispatcher = _dispatcher(dispatcher_kind, responder)
    controller = ProjectController(
        _parallel_config(config, n=capacity),
        dispatcher,  # type: ignore[arg-type]
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    validator_ids = ["validator-b", "validator-a", "validator-c"]
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                _task("w1", "VAL-A"),
                Task(
                    id="w2",
                    type="work",
                    body="later work",
                    targets=[],
                    skill="s",
                    depends_on=["w1"],
                ),
                *[
                    Task(
                        id=validator_id,
                        type="validate",
                        body=f"audit {validator_id}",
                        targets=["VAL-A"],
                        skill="aud",
                        depends_on=["w1"],
                    )
                    for validator_id in validator_ids
                ],
                Task(
                    id="g1",
                    type="gate",
                    body="",
                    targets=["VAL-A"],
                    skill=None,
                    depends_on=[
                        "validator-c",
                        "validator-a",
                        "validator-b",
                    ],
                ),
            ]
        ),
    )
    controller.advance_project(pid, max_steps=1)
    assert work_calls == ["w1"]

    first_expected = validator_ids[:capacity]
    controller.advance_project(pid, max_steps=1)
    first_state = controller.store.load_task_state(pid, "mission-001")

    assert set(starts) == set(first_expected)
    assert running_snapshots == [tuple(first_expected)] * capacity
    assert max(len(snapshot) for snapshot in running_snapshots) == capacity
    assert [first_state.status_of(task_id) for task_id in first_expected] == [
        "cleared"
    ] * capacity
    assert [
        first_state.status_of(task_id) for task_id in validator_ids[capacity:]
    ] == ["pending"] * (len(validator_ids) - capacity)
    assert first_state.status_of("w2") == "pending"
    assert work_calls == ["w1"]
    if capacity == 2:
        assert max(starts.values()) < min(finishes.values())

    starts.clear()
    finishes.clear()
    running_snapshots.clear()

    second_expected = validator_ids[capacity : capacity * 2]
    controller.advance_project(pid, max_steps=1)
    second_state = controller.store.load_task_state(pid, "mission-001")

    assert set(starts) == set(second_expected)
    assert running_snapshots == [tuple(second_expected)] * len(second_expected)
    assert all(len(snapshot) <= capacity for snapshot in running_snapshots)
    assert [
        second_state.status_of(task_id) for task_id in validator_ids[: capacity * 2]
    ] == ["cleared"] * min(len(validator_ids), capacity * 2)
    assert second_state.status_of("w2") == "pending"
    assert work_calls == ["w1"]
    if isinstance(dispatcher, _BatchTrackingDispatcher):
        expected_batch_calls = [first_expected] if capacity == 2 else []
        assert dispatcher.batch_calls == expected_batch_calls


def test_serial_mode_prioritizes_remaining_gate_validator_before_more_work(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    spawn_order: list[str] = []

    def responder(req: DispatchRequest) -> WorkHandoff | ValidateHandoff:
        spawn_order.append(req.task.id)
        if req.task.type == "work":
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")
        return ValidateHandoff(
            node_id=req.task.id,
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-A", passed=True)],
            passed=True,
        )

    serial_config = _parallel_config(config, n=1)
    controller = ProjectController(
        serial_config,
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                _task("w1", "VAL-A"),
                Task(
                    id="w2",
                    type="work",
                    body="later work",
                    targets=[],
                    skill="s",
                    depends_on=["w1"],
                ),
                Task(
                    id="v-cleared",
                    type="validate",
                    body="already audited",
                    targets=["VAL-A"],
                    skill="aud",
                    depends_on=["w1"],
                ),
                Task(
                    id="v-ready",
                    type="validate",
                    body="remaining audit",
                    targets=["VAL-A"],
                    skill="aud",
                    depends_on=["w1"],
                ),
                Task(
                    id="g1",
                    type="gate",
                    body="",
                    targets=["VAL-A"],
                    skill=None,
                    depends_on=["v-cleared", "v-ready"],
                ),
            ]
        ),
    )
    controller.advance_project(pid, max_steps=1)
    task_state = controller.store.load_task_state(pid, "mission-001")
    task_state.set_status("v-cleared", "cleared")
    controller.store.save_task_state(pid, "mission-001", task_state)

    controller.advance_project(pid, max_steps=1)

    assert spawn_order == ["w1", "v-ready"]


@pytest.mark.parametrize("dispatcher_kind", ["batch", "fallback"])
def test_parallel_config_serializes_work_in_authored_order(
    config: HarnessConfig,
    workspace: Path,
    dispatcher_kind: str,
) -> None:
    intervals: dict[str, tuple[float, float]] = {}
    events: list[tuple[str, str]] = []
    running_snapshots: list[tuple[str, ...]] = []
    lock = threading.Lock()
    pid = ""

    def responder(req: DispatchRequest) -> WorkHandoff:
        started = time.monotonic()
        with lock:
            events.append(("start", req.task.id))
            task_state = controller.store.load_task_state(pid, "mission-001")
            running_snapshots.append(
                tuple(
                    task.id
                    for task in controller.store.load_task_list(
                        pid, "mission-001"
                    ).tasks
                    if task_state.status_of(task.id) == "running"
                )
            )
        time.sleep(0.05)
        finished = time.monotonic()
        with lock:
            events.append(("end", req.task.id))
            intervals[req.task.id] = (started, finished)
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    dispatcher = _dispatcher(dispatcher_kind, responder)
    controller = ProjectController(
        _parallel_config(config),
        dispatcher,  # type: ignore[arg-type]
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    _write_contract(controller.store, pid, "mission-001", "VAL-B")
    controller.submit_plan(
        pid,
        TaskList(tasks=[_task("work-b", "VAL-B"), _task("work-a", "VAL-A")]),
    )

    controller.advance_project(pid, max_steps=1)
    first_state = controller.store.load_task_state(pid, "mission-001")
    controller.advance_project(pid, max_steps=1)
    final_state = controller.store.load_task_state(pid, "mission-001")

    assert events == [
        ("start", "work-b"),
        ("end", "work-b"),
        ("start", "work-a"),
        ("end", "work-a"),
    ]
    assert intervals["work-b"][1] <= intervals["work-a"][0]
    assert running_snapshots == [("work-b",), ("work-a",)]
    assert first_state.status_of("work-b") == "cleared"
    assert first_state.status_of("work-a") == "pending"
    assert final_state.status_of("work-a") == "cleared"
    if isinstance(dispatcher, _BatchTrackingDispatcher):
        assert dispatcher.batch_calls == []


@pytest.mark.parametrize("dispatcher_kind", ["batch", "fallback"])
@pytest.mark.parametrize(
    "authored_types",
    [("work", "validate"), ("validate", "work")],
)
def test_parallel_config_never_overlaps_work_and_validator(
    config: HarnessConfig,
    workspace: Path,
    dispatcher_kind: str,
    authored_types: tuple[str, str],
) -> None:
    intervals: dict[str, tuple[float, float]] = {}
    events: list[tuple[str, str]] = []
    running_snapshots: list[tuple[str, ...]] = []
    pid = ""

    def responder(req: DispatchRequest) -> NodeHandoff:
        started = time.monotonic()
        events.append(("start", req.task.id))
        task_state = controller.store.load_task_state(pid, "mission-001")
        running_snapshots.append(
            tuple(
                task.id
                for task in controller.store.load_task_list(pid, "mission-001").tasks
                if task_state.status_of(task.id) == "running"
            )
        )
        time.sleep(0.05)
        finished = time.monotonic()
        events.append(("end", req.task.id))
        intervals[req.task.id] = (started, finished)
        if req.task.type == "validate":
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-A", passed=True)],
                passed=True,
            )
        return WorkHandoff(node_id=req.task.id, done=True, report="ok")

    authored_tasks = [
        Task(
            id=f"{task_type}-{index}",
            type=task_type,  # type: ignore[arg-type]
            body="body",
            targets=["VAL-A"],
            skill="s",
        )
        for index, task_type in enumerate(authored_types)
    ]
    dispatcher = _dispatcher(dispatcher_kind, responder)
    controller = ProjectController(
        _parallel_config(config),
        dispatcher,  # type: ignore[arg-type]
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    controller.submit_plan(pid, TaskList(tasks=authored_tasks))

    controller.advance_project(pid, max_steps=1)
    controller.advance_project(pid, max_steps=1)

    authored_ids = [task.id for task in authored_tasks]
    assert events == [
        ("start", authored_ids[0]),
        ("end", authored_ids[0]),
        ("start", authored_ids[1]),
        ("end", authored_ids[1]),
    ]
    assert intervals[authored_ids[0]][1] <= intervals[authored_ids[1]][0]
    assert running_snapshots == [(authored_ids[0],), (authored_ids[1],)]
    task_state = controller.store.load_task_state(pid, "mission-001")
    assert [task_state.status_of(task_id) for task_id in authored_ids] == [
        "cleared",
        "cleared",
    ]
    if isinstance(dispatcher, _BatchTrackingDispatcher):
        assert dispatcher.batch_calls == []


@pytest.mark.parametrize("dispatcher_kind", ["batch", "fallback"])
def test_unrelated_validator_only_set_batches_without_work(
    config: HarnessConfig,
    workspace: Path,
    dispatcher_kind: str,
) -> None:
    barrier = threading.Barrier(2)
    starts: dict[str, float] = {}
    finishes: dict[str, float] = {}
    running_snapshots: list[tuple[str, ...]] = []
    lock = threading.Lock()
    pid = ""

    def responder(req: DispatchRequest) -> NodeHandoff:
        if req.task.type == "work":
            return WorkHandoff(node_id=req.task.id, done=True, report="unused")
        with lock:
            starts[req.task.id] = time.monotonic()
            task_state = controller.store.load_task_state(pid, "mission-001")
            running_snapshots.append(
                tuple(
                    task.id
                    for task in controller.store.load_task_list(
                        pid, "mission-001"
                    ).tasks
                    if task_state.status_of(task.id) == "running"
                )
            )
        barrier.wait(timeout=2)
        with lock:
            finishes[req.task.id] = time.monotonic()
        return ValidateHandoff(
            node_id=req.task.id,
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-A", passed=True)],
            passed=True,
        )

    dispatcher = _dispatcher(dispatcher_kind, responder)
    controller = ProjectController(
        _parallel_config(config),
        dispatcher,  # type: ignore[arg-type]
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                _task("work-owner", "VAL-A"),
                Task(
                    id="validator-a",
                    type="validate",
                    body="audit a",
                    targets=["VAL-A"],
                    skill="aud",
                ),
                Task(
                    id="validator-b",
                    type="validate",
                    body="audit b",
                    targets=["VAL-A"],
                    skill="aud",
                ),
            ]
        ),
    )
    task_state = controller.store.load_task_state(pid, "mission-001")
    task_state.set_status("work-owner", "cleared")
    controller.store.save_task_state(pid, "mission-001", task_state)

    controller.advance_project(pid, max_steps=1)

    assert set(starts) == {"validator-a", "validator-b"}
    assert max(starts.values()) <= min(finishes.values())
    assert running_snapshots == [
        ("validator-a", "validator-b"),
        ("validator-a", "validator-b"),
    ]
    final_state = controller.store.load_task_state(pid, "mission-001")
    assert final_state.status_of("work-owner") == "cleared"
    assert final_state.status_of("validator-a") == "cleared"
    assert final_state.status_of("validator-b") == "cleared"
    if isinstance(dispatcher, _BatchTrackingDispatcher):
        assert dispatcher.batch_calls == [["validator-a", "validator-b"]]


def test_parallel_non_git_workspace_runs_in_workspace(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    parallel_config = _parallel_config(config)
    controller = ProjectController(
        parallel_config,
        MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    controller.submit_plan(pid, TaskList(tasks=[_task("a", "VAL-A")]))

    env = controller.advance_project(pid)

    assert env.state.state == "mission_running"


def test_reconcile_historical_running_attempts_before_fresh_serial_dispatch(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    events: list[tuple[str, str]] = []
    running_snapshots: list[tuple[str, ...]] = []
    pid = ""

    def responder(req: DispatchRequest) -> WorkHandoff:
        events.append(("start", req.task.id))
        task_state = controller.store.load_task_state(pid, "mission-001")
        running_snapshots.append(
            tuple(
                task.id
                for task in controller.store.load_task_list(pid, "mission-001").tasks
                if task_state.status_of(task.id) == "running"
            )
        )
        events.append(("end", req.task.id))
        return WorkHandoff(node_id=req.task.id, done=True, report="fresh")

    controller = ProjectController(
        _parallel_config(config),
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    _write_contract(controller.store, pid, "mission-001", "VAL-B")
    tl = TaskList(
        tasks=[
            _task("historical-a", "VAL-A"),
            _task("historical-b", "VAL-B"),
            Task(
                id="fresh-a",
                type="work",
                body="fresh a",
                targets=[],
                skill="s",
                depends_on=["historical-a", "historical-b"],
            ),
            Task(
                id="fresh-b",
                type="work",
                body="fresh b",
                targets=[],
                skill="s",
                depends_on=["historical-a", "historical-b"],
            ),
        ]
    )
    controller.submit_plan(pid, tl)

    task_state = controller.store.load_task_state(pid, "mission-001")
    historical_attempts = {
        "historical-a": "2026-01-01T00-00-00Z-a",
        "historical-b": "2026-01-01T00-00-00Z-b",
    }
    for tid, spawn_ts in historical_attempts.items():
        task_state.set_status(tid, "running")
        task_state.set_last_attempt(tid, spawn_ts)
        controller.store.save_attempt(
            pid,
            "mission-001",
            spawn_ts,
            tid,
            WorkHandoff(node_id=tid, done=True, report="ok"),
        )
    controller.store.save_task_state(pid, "mission-001", task_state)
    controller.store.save_state(pid, MissionRunning(mission_id="mission-001"))

    reconciled = controller.advance_project(pid, max_steps=1)
    reconciled_state = controller.store.load_task_state(pid, "mission-001")
    contract_state = controller.store.load_contract_state(pid, "mission-001")

    assert reconciled.state.state == "mission_running"
    assert events == []
    assert reconciled_state.status_of("historical-a") == "cleared"
    assert reconciled_state.status_of("historical-b") == "cleared"
    assert reconciled_state.status_of("fresh-a") == "pending"
    assert reconciled_state.status_of("fresh-b") == "pending"
    assert {
        item_id: entry.status for item_id, entry in contract_state.items.items()
    } == {"VAL-A": "pending", "VAL-B": "pending"}
    assert controller.store.load_attention(pid) == []

    controller.advance_project(pid, max_steps=1)
    controller.advance_project(pid, max_steps=1)

    assert events == [
        ("start", "fresh-a"),
        ("end", "fresh-a"),
        ("start", "fresh-b"),
        ("end", "fresh-b"),
    ]
    assert running_snapshots == [("fresh-a",), ("fresh-b",)]


def test_reconcile_historical_missing_attempt_without_fresh_dispatch(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    dispatcher = MockDispatcher(
        lambda request: WorkHandoff(
            node_id=request.task.id,
            done=True,
            report="must not dispatch",
        )
    )
    controller = ProjectController(
        _parallel_config(config),
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Brief.", str(workspace))
    pid = controller.store.list_projects()[0].id
    _write_contract(controller.store, pid, "mission-001", "VAL-A")
    _write_contract(controller.store, pid, "mission-001", "VAL-B")
    controller.submit_plan(
        pid,
        TaskList(
            tasks=[
                _task("historical-present", "VAL-A"),
                _task("historical-missing", "VAL-B"),
                Task(
                    id="fresh",
                    type="work",
                    body="fresh",
                    targets=[],
                    skill="s",
                    depends_on=["historical-present", "historical-missing"],
                ),
            ]
        ),
    )

    present_ts = "2026-01-01T00-00-00Z-present"
    missing_ts = "2026-01-01T00-00-00Z-missing"
    task_state = controller.store.load_task_state(pid, "mission-001")
    task_state.set_status("historical-present", "running")
    task_state.set_last_attempt("historical-present", present_ts)
    task_state.set_status("historical-missing", "running")
    task_state.set_last_attempt("historical-missing", missing_ts)
    controller.store.save_task_state(pid, "mission-001", task_state)
    controller.store.save_attempt(
        pid,
        "mission-001",
        present_ts,
        "historical-present",
        WorkHandoff(
            node_id="historical-present",
            done=True,
            report="landed",
        ),
    )
    controller.store.save_state(pid, MissionRunning(mission_id="mission-001"))

    recovered = controller.advance_project(pid, max_steps=1)
    final_task_state = controller.store.load_task_state(pid, "mission-001")
    contract_state = controller.store.load_contract_state(pid, "mission-001")
    attention = controller.store.load_attention(pid)
    synthetic = controller.store.read_attempt(
        pid,
        "mission-001",
        missing_ts,
        "historical-missing",
    )

    assert recovered.state.state == "attention_needed"
    assert dispatcher.calls == []
    assert final_task_state.status_of("historical-present") == "cleared"
    assert final_task_state.status_of("historical-missing") == "failed"
    assert final_task_state.status_of("fresh") == "pending"
    assert {
        item_id: entry.status for item_id, entry in contract_state.items.items()
    } == {"VAL-A": "pending", "VAL-B": "pending"}
    assert len(attention) == 1
    assert attention[0].kind == "node_failed"
    assert attention[0].node_id == "historical-missing"
    assert isinstance(synthetic, WorkHandoff)
    assert synthetic.done is False
    assert "no attempt file was present" in synthetic.report
