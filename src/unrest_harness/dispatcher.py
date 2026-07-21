"""NodeDispatcher protocol + in-process mock.

The production `ACPNodeDispatcher` lives in `acp_runner` (Phase 5). The
coordinator only depends on the abstract protocol so tests can inject
mocks without spinning up subprocesses.
"""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
from typing import Callable, Protocol

from .models import Task, TerminalReviewHandoff, ValidateHandoff, WorkHandoff


NodeHandoff = WorkHandoff | ValidateHandoff


@dataclass
class DispatchRequest:
    project_id: str
    mission_id: str
    task: Task
    spawn_ts: str
    cwd: str | None = None


class NodeDispatcher(Protocol):
    """The thing the coordinator calls to run one task."""

    def dispatch(self, request: DispatchRequest) -> NodeHandoff: ...

    def dispatch_batch(self, requests: list[DispatchRequest]) -> list[NodeHandoff]: ...


class TerminalReviewer(Protocol):
    def review(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> TerminalReviewHandoff: ...


# ---------------------------------------------------------------------------
# In-process mock (for tests)
# ---------------------------------------------------------------------------


class MockDispatcher:
    """Tests build this with a callable that maps `DispatchRequest -> NodeHandoff`."""

    def __init__(
        self,
        responder: Callable[[DispatchRequest], NodeHandoff],
    ):
        self._responder = responder
        self.calls: list[DispatchRequest] = []

    def dispatch(self, request: DispatchRequest) -> NodeHandoff:
        self.calls.append(request)
        return self._responder(request)

    def dispatch_batch(self, requests: list[DispatchRequest]) -> list[NodeHandoff]:
        def _run(request: DispatchRequest) -> NodeHandoff:
            try:
                return self.dispatch(request)
            except Exception as exc:  # noqa: BLE001
                if request.task.type == "validate":
                    return ValidateHandoff(
                        node_id=request.task.id,
                        done=False,
                        report=f"Dispatcher crashed: {exc}",
                        items=[],
                        passed=False,
                    )
                return WorkHandoff(
                    node_id=request.task.id,
                    done=False,
                    report=f"Dispatcher crashed: {exc}",
                    request_attention=False,
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests) or 1) as pool:
            return list(pool.map(_run, requests))


class MockTerminalReviewer:
    def __init__(self, review: TerminalReviewHandoff):
        self.review_result = review
        self.calls: list[tuple[str, str, str]] = []

    def review(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> TerminalReviewHandoff:
        self.calls.append((project_id, mission_id, spawn_ts))
        return self.review_result


__all__ = [
    "DispatchRequest",
    "NodeDispatcher",
    "TerminalReviewer",
    "NodeHandoff",
    "MockDispatcher",
    "MockTerminalReviewer",
]
