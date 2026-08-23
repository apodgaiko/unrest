"""Focused public-surface coverage for per-project mutation locking."""
from __future__ import annotations

import asyncio
import errno
import gc
import io
import json
import logging
import multiprocessing
import os
import threading
import weakref
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from time import monotonic
from typing import Any

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    MissionPlanning,
    Task,
    TaskList,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.project_lock import (
    ProjectMutationLock,
    _prepare_windows_lockfile,
    _try_lock_windows,
)
from unrest_harness.server import create_orchestrator_server
from unrest_harness.storage import ProjectStore


SENTINEL = "LOCK-SECRET-c738e740"
MUTATIONS = (
    "submit_plan",
    "advance_project",
    "end_mission",
    "decide_attention",
    "abort_project",
)


def _config(harness_home: Path) -> HarnessConfig:
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


def _seed_project(config: HarnessConfig, workspace: Path, project_id: str) -> None:
    store = ProjectStore(config)
    record = store.create_project("lock test", workspace, project_id=project_id)
    record.current_mission_id = "mission-001"
    store.save_project(record)
    store.save_state(project_id, MissionPlanning(mission_id="mission-001"))


def _arguments(method: str, project_id: str, *, sensitive: bool = False) -> dict[str, Any]:
    marker = SENTINEL if sensitive else "ordinary"
    common: dict[str, Any] = {"project_id": project_id}
    if method == "submit_plan":
        common["task_list"] = {
            "tasks": [
                {
                    "id": "w1",
                    "type": "work",
                    "body": marker,
                    "targets": ["VAL-X"],
                    "skill": "worker",
                    "depends_on": [],
                }
            ]
        }
    elif method == "advance_project":
        common["max_steps"] = 1
    elif method == "end_mission":
        common["deliverable_roots"] = [f"/tmp/{marker}"]
    elif method == "decide_attention":
        common["decisions"] = [
            {"item_id": "attention-1", "action": "continue", "justification": marker}
        ]
    elif method == "abort_project":
        common["reason"] = marker
    else:  # pragma: no cover - test helper guard
        raise AssertionError(method)
    return common


def _payload(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        nested = structured.get("result")
        return nested if isinstance(nested, dict) else structured
    content = getattr(result, "content", None)
    if content:
        parsed = json.loads(content[0].text)
        if isinstance(parsed, dict):
            return parsed
    raise AssertionError(f"tool result had no object payload: {result!r}")


class _CountingDispatcher:
    def __init__(self) -> None:
        self.calls = 0

    def dispatch(self, request: Any) -> WorkHandoff:
        self.calls += 1
        return WorkHandoff(
            node_id=request.task.id,
            attempt_id=request.spawn_ts,
            done=True,
            report="",
        )

    def dispatch_batch(self, requests: list[Any]) -> list[WorkHandoff]:
        return [self.dispatch(request) for request in requests]


class _BlockingDispatcher(_CountingDispatcher):
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self.entered = entered
        self.release = release

    def dispatch(self, request: Any) -> WorkHandoff:
        self.calls += 1
        self.entered.set()
        if not self.release.wait(2):
            raise RuntimeError("test dispatcher release timed out")
        return WorkHandoff(
            node_id=request.task.id,
            attempt_id=request.spawn_ts,
            done=True,
            report="completed",
        )


class _CountingProjectController(ProjectController):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.advance_entries = 0

    def advance_project(self, project_id: str, max_steps: int | None = None) -> Any:
        self.advance_entries += 1
        return super().advance_project(project_id, max_steps)


class _RecordingController:
    def __init__(
        self,
        config: HarnessConfig,
        *,
        entered_event: Any | None = None,
        release_event: Any | None = None,
        block_first: bool = False,
        exception_first: bool = False,
        exception_message: str = "expected controller exception",
    ) -> None:
        self.store = ProjectStore(config)
        self.dispatcher = _CountingDispatcher()
        self.entered: list[tuple[str, str]] = []
        self.entered_event = entered_event
        self.release_event = release_event
        self.block_first = block_first
        self.exception_first = exception_first
        self.exception_message = exception_message

    def _entry(self, method: str, project_id: str) -> None:
        self.entered.append((method, project_id))
        first = len(self.entered) == 1
        if self.entered_event is not None:
            self.entered_event.set()
        if self.block_first and first:
            assert self.release_event is not None
            self.release_event.wait()
        if self.exception_first and first:
            raise RuntimeError(self.exception_message)
        raise ToolError("controller_entered", method)

    def submit_plan(self, project_id: str, task_list: Any) -> None:
        self._entry("submit_plan", project_id)

    def advance_project(self, project_id: str, max_steps: int | None = None) -> None:
        self._entry("advance_project", project_id)

    def end_mission(
        self, project_id: str, deliverable_roots: list[str] | None = None
    ) -> None:
        self._entry("end_mission", project_id)

    def decide_attention(self, project_id: str, decisions: list[Any]) -> None:
        self._entry("decide_attention", project_id)

    def abort_project(self, project_id: str, reason: str) -> None:
        self._entry("abort_project", project_id)


def _holder_process(
    harness_home: str,
    project_id: str,
    method: str,
    entered_event: Any,
    release_event: Any,
) -> None:
    config = _config(Path(harness_home))
    controller = _RecordingController(
        config,
        entered_event=entered_event,
        release_event=release_event,
        block_first=True,
    )
    server = create_orchestrator_server(config, controller)  # type: ignore[arg-type]
    asyncio.run(server.call_tool(method, _arguments(method, project_id)))


def _competitor_process(
    harness_home: str,
    project_id: str,
    other_project_id: str,
    output: Any,
) -> None:
    captured = io.StringIO()
    with redirect_stdout(captured), redirect_stderr(captured):
        config = _config(Path(harness_home))
        controller = _RecordingController(config)
        server = create_orchestrator_server(config, controller)  # type: ignore[arg-type]

        async def exercise() -> dict[str, Any]:
            results: dict[str, Any] = {}
            for method in MUTATIONS:
                started = monotonic()
                result = await server.call_tool(
                    method, _arguments(method, project_id, sensitive=True)
                )
                results[method] = {
                    "elapsed": monotonic() - started,
                    "payload": _payload(result),
                }
            different = await server.call_tool(
                "abort_project", _arguments("abort_project", other_project_id)
            )
            results["different_project"] = _payload(different)
            return results

        results = asyncio.run(exercise())
    output.put(
        {
            "results": results,
            "controller_entries": controller.entered,
            "dispatch_count": controller.dispatcher.calls,
            "logs": captured.getvalue(),
        }
    )


def _single_call_process(
    harness_home: str,
    project_id: str,
    method: str,
    output: Any,
) -> None:
    config = _config(Path(harness_home))
    controller = _RecordingController(config)
    server = create_orchestrator_server(config, controller)  # type: ignore[arg-type]
    result = asyncio.run(server.call_tool(method, _arguments(method, project_id)))
    output.put(
        {
            "payload": _payload(result),
            "controller_entries": controller.entered,
            "dispatch_count": controller.dispatcher.calls,
        }
    )


def _active_mutation_task() -> asyncio.Task[Any]:
    tasks = [
        task
        for task in asyncio.all_tasks()
        if task.get_name() == "unrest-project-mutation"
    ]
    assert len(tasks) == 1
    return tasks[0]


async def _wait_until(predicate: Any, *, timeout: float = 2.0) -> None:
    deadline = monotonic() + timeout
    while not predicate():
        if monotonic() >= deadline:
            raise AssertionError("condition did not become true before timeout")
        await asyncio.sleep(0.01)


async def _wait_for_reference_clear(reference: Any) -> None:
    def cleared() -> bool:
        gc.collect()
        return reference() is None

    await _wait_until(cleared)


@pytest.mark.skipif(os.name == "nt", reason="native contention lane runs on POSIX")
def test_spawned_public_mutations_are_exclusive_and_project_scoped(
    tmp_path: Path,
) -> None:
    ctx = multiprocessing.get_context("spawn")
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "project-a")
    _seed_project(config, workspace, "project-b")
    store = ProjectStore(config)
    state_path = store.unrest_runtime_dir("project-a") / "state.json"
    before_state = state_path.read_bytes()
    before_attempts = sorted(store.bucket_root("project-a").glob("**/attempts/*"))

    entered = ctx.Event()
    release = ctx.Event()
    holder = ctx.Process(
        target=_holder_process,
        args=(str(harness_home), "project-a", "advance_project", entered, release),
    )
    holder.start()
    assert entered.wait(2), "holder did not acquire the project lock"

    output = ctx.Queue()
    competitor = ctx.Process(
        target=_competitor_process,
        args=(str(harness_home), "project-a", "project-b", output),
    )
    competitor.start()
    competitor.join(5)
    assert competitor.exitcode == 0
    observation = output.get(timeout=1)

    for method in MUTATIONS:
        assert observation["results"][method]["payload"]["error"] == "project_busy"
        assert observation["results"][method]["elapsed"] < 1.0
    assert observation["results"]["different_project"]["error"] == "controller_entered"
    assert observation["controller_entries"] == [("abort_project", "project-b")]
    assert observation["dispatch_count"] == 0
    assert SENTINEL not in json.dumps(observation, sort_keys=True)
    assert state_path.read_bytes() == before_state
    assert sorted(store.bucket_root("project-a").glob("**/attempts/*")) == before_attempts

    release.set()
    holder.join(3)
    assert holder.exitcode == 0


@pytest.mark.skipif(os.name == "nt", reason="native abrupt-death lane runs on POSIX")
def test_os_releases_lock_after_abrupt_holder_death(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _seed_project(_config(harness_home), workspace, "project-a")

    entered = ctx.Event()
    never_release = ctx.Event()
    holder = ctx.Process(
        target=_holder_process,
        args=(str(harness_home), "project-a", "advance_project", entered, never_release),
    )
    holder.start()
    assert entered.wait(2)
    holder.terminate()
    holder.join(3)
    assert holder.exitcode is not None and holder.exitcode != 0

    output = ctx.Queue()
    successor = ctx.Process(
        target=_single_call_process,
        args=(str(harness_home), "project-a", "advance_project", output),
    )
    successor.start()
    successor.join(3)
    assert successor.exitcode == 0
    observation = output.get(timeout=1)
    assert observation["payload"]["error"] == "controller_entered"
    assert observation["controller_entries"] == [("advance_project", "project-a")]
    assert observation["dispatch_count"] == 0


@pytest.mark.asyncio
async def test_same_server_calls_queue_and_release_after_exception(tmp_path: Path) -> None:
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "project-a")
    entered = threading.Event()
    release = threading.Event()
    controller = _RecordingController(
        config,
        entered_event=entered,
        release_event=release,
        block_first=True,
        exception_first=True,
    )
    server = create_orchestrator_server(config, controller)  # type: ignore[arg-type]

    first = asyncio.create_task(
        server.call_tool("advance_project", _arguments("advance_project", "project-a"))
    )
    assert await asyncio.to_thread(entered.wait, 1)
    second = asyncio.create_task(
        server.call_tool("abort_project", _arguments("abort_project", "project-a"))
    )
    await asyncio.sleep(0.05)
    assert not second.done()
    release.set()
    with pytest.raises(Exception, match="expected controller exception"):
        await first
    assert _payload(await second)["error"] == "controller_entered"
    assert controller.entered == [
        ("advance_project", "project-a"),
        ("abort_project", "project-a"),
    ]


@pytest.mark.asyncio
async def test_cancelled_waiter_retains_mutation_and_lock_until_normal_completion(
    tmp_path: Path,
) -> None:
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "project-a")
    entered = threading.Event()
    release = threading.Event()
    first_controller = _RecordingController(
        config,
        entered_event=entered,
        release_event=release,
        block_first=True,
    )
    second_controller = _RecordingController(config)
    first_server = create_orchestrator_server(
        config, first_controller  # type: ignore[arg-type]
    )
    second_server = create_orchestrator_server(
        config, second_controller  # type: ignore[arg-type]
    )

    waiter = asyncio.create_task(
        first_server.call_tool(
            "advance_project", _arguments("advance_project", "project-a")
        )
    )
    assert await asyncio.to_thread(entered.wait, 1)
    mutation_task = _active_mutation_task()
    mutation_reference = weakref.ref(mutation_task)
    del mutation_task

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    gc.collect()
    assert mutation_reference() is not None
    assert not release.is_set()

    blocked = _payload(
        await second_server.call_tool(
            "advance_project", _arguments("advance_project", "project-a")
        )
    )
    assert blocked["error"] == "project_busy"
    assert second_controller.entered == []

    release.set()
    await _wait_for_reference_clear(mutation_reference)
    recovered = _payload(
        await second_server.call_tool(
            "advance_project", _arguments("advance_project", "project-a")
        )
    )
    assert recovered["error"] == "controller_entered"
    assert second_controller.entered == [("advance_project", "project-a")]


@pytest.mark.asyncio
async def test_cancelled_detached_exception_is_consumed_safely_and_releases_lock(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "project-a")
    entered = threading.Event()
    release = threading.Event()
    first_controller = _RecordingController(
        config,
        entered_event=entered,
        release_event=release,
        block_first=True,
        exception_first=True,
        exception_message=SENTINEL,
    )
    second_controller = _RecordingController(config)
    first_server = create_orchestrator_server(
        config, first_controller  # type: ignore[arg-type]
    )
    second_server = create_orchestrator_server(
        config, second_controller  # type: ignore[arg-type]
    )
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    caplog.set_level(logging.ERROR, logger="unrest_harness.server")

    try:
        waiter = asyncio.create_task(
            first_server.call_tool(
                "advance_project", _arguments("advance_project", "project-a")
            )
        )
        assert await asyncio.to_thread(entered.wait, 1)
        mutation_task = _active_mutation_task()
        mutation_reference = weakref.ref(mutation_task)
        del mutation_task
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

        blocked = _payload(
            await second_server.call_tool(
                "advance_project", _arguments("advance_project", "project-a")
            )
        )
        assert blocked["error"] == "project_busy"
        release.set()
        await _wait_for_reference_clear(mutation_reference)
    finally:
        release.set()
        loop.set_exception_handler(previous_handler)

    detached_logs = [
        record.getMessage()
        for record in caplog.records
        if record.name == "unrest_harness.server"
        and record.getMessage().startswith("Detached project mutation")
    ]
    assert detached_logs == ["Detached project mutation failed"]
    assert SENTINEL not in caplog.text
    assert unhandled == []
    recovered = _payload(
        await second_server.call_tool(
            "advance_project", _arguments("advance_project", "project-a")
        )
    )
    assert recovered["error"] == "controller_entered"


@pytest.mark.asyncio
async def test_cancelled_public_advance_keeps_real_dispatch_exclusive_and_recovers(
    tmp_path: Path,
) -> None:
    started = monotonic()
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "project-a")
    entered = threading.Event()
    release = threading.Event()
    first_dispatcher = _BlockingDispatcher(entered, release)
    second_dispatcher = _CountingDispatcher()
    reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
    first_controller = _CountingProjectController(
        config, first_dispatcher, reviewer
    )
    contract_dir = first_controller.store.ensure_contract_dir(
        "project-a", "mission-001"
    )
    (contract_dir / "VAL-TIMEOUT.md").write_text(
        "# VAL-TIMEOUT\n\nTimeout overlap remains exclusive.\n",
        encoding="utf-8",
    )
    first_controller.submit_plan(
        "project-a",
        TaskList(
            tasks=[
                Task(
                    id="work-one",
                    type="work",
                    body="Run one controlled dispatch.",
                    targets=["VAL-TIMEOUT"],
                    skill="test-worker",
                )
            ]
        ),
    )
    second_controller = _CountingProjectController(
        config, second_dispatcher, reviewer
    )
    first_server = create_orchestrator_server(config, first_controller)
    second_server = create_orchestrator_server(config, second_controller)
    store = ProjectStore(config)
    state_path = store.unrest_runtime_dir("project-a") / "state.json"
    task_state_path = (
        store.unrest_runtime_dir("project-a")
        / "missions"
        / "mission-001"
        / "task-state.json"
    )
    before_state = state_path.read_bytes()
    before_task_state = task_state_path.read_bytes()
    before_attempts = (
        sorted(store.attempts_runtime_dir("project-a", "mission-001").glob("*")),
        sorted(store.attempts_dir("project-a", "mission-001").glob("*")),
    )

    waiter = asyncio.create_task(
        first_server.call_tool(
            "advance_project", _arguments("advance_project", "project-a")
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        during_state = state_path.read_bytes()
        during_task_state = task_state_path.read_bytes()
        during_attempts = (
            sorted(store.attempts_runtime_dir("project-a", "mission-001").glob("*")),
            sorted(store.attempts_dir("project-a", "mission-001").glob("*")),
        )
        assert during_state == before_state
        assert during_task_state != before_task_state
        assert during_attempts == before_attempts
        assert store.load_task_state("project-a", "mission-001").status_of(
            "work-one"
        ) == "running"

        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        competitor_started = monotonic()
        competitor = _payload(
            await second_server.call_tool(
                "advance_project", _arguments("advance_project", "project-a")
            )
        )
        assert monotonic() - competitor_started < 1.0
        assert competitor["error"] == "project_busy"
        assert first_controller.advance_entries == 1
        assert second_controller.advance_entries == 0
        assert first_dispatcher.calls == 1
        assert second_dispatcher.calls == 0
        assert state_path.read_bytes() == during_state
        assert task_state_path.read_bytes() == during_task_state
        assert (
            sorted(store.attempts_runtime_dir("project-a", "mission-001").glob("*")),
            sorted(store.attempts_dir("project-a", "mission-001").glob("*")),
        ) == during_attempts

        release.set()
        await _wait_until(
            lambda: store.load_task_state("project-a", "mission-001").status_of(
                "work-one"
            )
            == "cleared"
        )
        runtime_attempts = sorted(
            store.attempts_runtime_dir("project-a", "mission-001").glob("*.json")
        )
        report_attempts = sorted(
            store.attempts_dir("project-a", "mission-001").glob("*.md")
        )
        assert len(runtime_attempts) == len(report_attempts) == 1
        persisted = json.loads(runtime_attempts[0].read_text(encoding="utf-8"))
        assert persisted["node_id"] == "work-one"
        assert persisted["done"] is True
        assert persisted["report"] == "completed"
        assert "missing" not in report_attempts[0].read_text(encoding="utf-8").lower()
        assert state_path.read_bytes() == before_state

        recovered = _payload(
            await second_server.call_tool(
                "abort_project", _arguments("abort_project", "project-a")
            )
        )
        assert recovered["state"]["state"] == "aborted"
        assert second_controller.advance_entries == 0
        assert first_dispatcher.calls == 1
        assert second_dispatcher.calls == 0
    finally:
        release.set()
    assert monotonic() - started < 10.0


@pytest.mark.asyncio
async def test_uncontended_success_lock_error_and_missing_project_compatibility(
    tmp_path: Path,
) -> None:
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(harness_home)
    _seed_project(config, workspace, "success")
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(node_id=request.task.id, done=True, report="")
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)
    first = _payload(
        await server.call_tool("abort_project", _arguments("abort_project", "success"))
    )
    second = _payload(
        await server.call_tool("abort_project", _arguments("abort_project", "success"))
    )
    assert first["state"]["state"] == "aborted"
    assert second["state"]["state"] == "aborted"
    invalid = _payload(
        await server.call_tool(
            "abort_project", {"project_id": "success", "reason": " "}
        )
    )
    assert invalid["error"] == "invalid_abort_reason"

    for method in ("submit_plan", "end_mission", "decide_attention"):
        missing = _payload(
            await server.call_tool(method, _arguments(method, "does-not-exist"))
        )
        assert missing["error"] == "not_found"
    for method in ("advance_project", "abort_project"):
        with pytest.raises(Exception, match="project not found: does-not-exist"):
            await server.call_tool(method, _arguments(method, "does-not-exist"))
    assert not ProjectStore(config).bucket_root("does-not-exist").exists()

    _seed_project(config, workspace, "broken-lock")
    lock_path = ProjectStore(config).mutation_lock_path("broken-lock")
    lock_path.mkdir()
    recording = _RecordingController(config)
    recording_server = create_orchestrator_server(config, recording)  # type: ignore[arg-type]
    failed = _payload(
        await recording_server.call_tool(
            "abort_project", _arguments("abort_project", "broken-lock")
        )
    )
    assert failed == {
        "error": "project_lock_error",
        "message": "project mutation lock unavailable",
        "details": [],
    }
    assert recording.entered == []

    missing_via_recording_controller = _payload(
        await recording_server.call_tool(
            "abort_project", _arguments("abort_project", "does-not-exist")
        )
    )
    assert missing_via_recording_controller["error"] == "controller_entered"
    assert not ProjectStore(config).bucket_root("does-not-exist").exists()


def test_windows_adapter_uses_nonblocking_standard_library_lock(tmp_path: Path) -> None:
    lock_path = tmp_path / "windows.lock"
    with lock_path.open("w+b", buffering=0) as lock_file:
        _prepare_windows_lockfile(lock_file)
        assert lock_path.read_bytes() == b"\0"

        class Available:
            LK_NBLCK = 2

            @staticmethod
            def locking(fd: int, mode: int, length: int) -> None:
                assert (fd, mode, length) == (lock_file.fileno(), 2, 1)

        assert _try_lock_windows(lock_file, Available)

        class Busy:
            LK_NBLCK = 2

            @staticmethod
            def locking(fd: int, mode: int, length: int) -> None:
                raise OSError(errno.EACCES, "busy")

        assert not _try_lock_windows(lock_file, Busy)


def test_lock_handle_release_does_not_require_file_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "mutation.lock"
    first = ProjectMutationLock(path)
    second = ProjectMutationLock(path)
    assert first.try_acquire()
    assert not second.try_acquire()
    first.release()
    assert path.exists()
    assert second.try_acquire()
    second.release()
