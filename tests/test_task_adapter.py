from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import socket
import subprocess

import pytest

from unrest_harness.provider_sessions import ProviderSessionRunner
from unrest_harness.task_adapter import (
    TaskBounds,
    TaskRequest,
    run_task,
)


class FakeInquiryLifecycle:
    def __init__(
        self,
        *,
        advance_state: str = "answered",
        advance_error: Exception | None = None,
    ) -> None:
        self.advance_state = advance_state
        self.advance_error = advance_error
        self.state = "open"
        self.calls: list[str] = []
        self.provider_effects = 0
        self.external_effects = 0

    def _inquiry(self) -> dict[str, object]:
        outcome = {
            "open": "pending",
            "paused": "paused",
            "answered": "answered",
            "failed": "failed",
            "budget_exhausted": "budget_exhausted",
        }.get(self.state, "running")
        return {
            "state": self.state,
            "receipt_id": "receipt:inquiry-evidence:answer" if self.state == "answered" else None,
            "inquiry_id": "inquiry:stable",
            "branch_outcomes": {"evidence": outcome, "direct": outcome},
        }

    def open_inquiry(
        self,
        question: str,
        budget: Mapping[str, int],
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Mapping[str, object]:
        assert question
        assert budget == {"max_branches": 2, "max_steps": 2, "timeout_seconds": 10}
        assert idempotency_key.startswith("task-adapter:")
        assert project_id == "project:test"
        self.calls.append("open_inquiry")
        return self._inquiry()

    async def advance_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        assert inquiry_id == "inquiry:stable"
        assert idempotency_key.startswith("task-adapter:")
        self.calls.append("advance_inquiry")
        if self.advance_error is not None:
            raise self.advance_error
        self.state = self.advance_state
        return self._inquiry()

    def pause_inquiry(
        self,
        inquiry_id: str,
        reason: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        assert inquiry_id == "inquiry:stable"
        assert reason
        assert idempotency_key.startswith("task-adapter:")
        self.calls.append("pause_inquiry")
        self.state = "paused"
        return self._inquiry()

    def resume_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        assert inquiry_id == "inquiry:stable"
        assert idempotency_key.startswith("task-adapter:")
        self.calls.append("resume_inquiry")
        self.state = "open"
        return self._inquiry()

    def handoff_inquiry(
        self,
        inquiry_id: str,
        consumer_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        assert inquiry_id == "inquiry:stable"
        assert idempotency_key.startswith("task-adapter:")
        self.calls.append("handoff_inquiry")
        return {
            "receipt_id": "receipt:inquiry-evidence:handoff",
            "inquiry_id": inquiry_id,
            "handoff_id": "handoff:stable",
            "consumer_id": consumer_id,
        }

    def inspect_inquiry(self, inquiry_id: str) -> Mapping[str, object]:
        assert inquiry_id == "inquiry:stable"
        self.calls.append("inspect_inquiry")
        return self._inquiry()


def _request(**overrides: object) -> TaskRequest:
    values: dict[str, object] = {
        "brief": "PRIVATE-BRIEF: compare alpha and beta",
        "bounds": TaskBounds(max_steps=2, timeout_seconds=10, max_branches=2),
        "consumer_id": "consumer:task",
        "idempotency_key": "PRIVATE-IDEMPOTENCY",
        "project_id": "project:test",
    }
    values.update(overrides)
    return TaskRequest(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_nominal_bounded_completion_and_handoff() -> None:
    lifecycle = FakeInquiryLifecycle()

    result = await run_task(lifecycle, _request())

    assert result.terminal == "completed"
    assert result.inquiry.state == "answered"
    assert result.inquiry.receipt_id == "receipt:inquiry-evidence:answer"
    assert result.handoff is not None
    assert result.handoff.receipt_id == "receipt:inquiry-evidence:handoff"
    assert lifecycle.calls == [
        "open_inquiry",
        "advance_inquiry",
        "handoff_inquiry",
        "inspect_inquiry",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["budget_exhausted", "failed"])
async def test_bound_exhaustion_and_failure_stop_without_handoff(state: str) -> None:
    lifecycle = FakeInquiryLifecycle(advance_state=state)

    result = await run_task(lifecycle, _request())

    assert result.terminal == state
    assert lifecycle.calls == ["open_inquiry", "advance_inquiry", "inspect_inquiry"]
    assert result.handoff is None


@pytest.mark.asyncio
async def test_pause_returns_without_advancing() -> None:
    lifecycle = FakeInquiryLifecycle()

    result = await run_task(
        lifecycle,
        _request(pause_reason="PRIVATE-PAUSE: operator checkpoint"),
    )

    assert result.terminal == "paused"
    assert lifecycle.calls == ["open_inquiry", "pause_inquiry", "inspect_inquiry"]


@pytest.mark.asyncio
async def test_pause_resume_then_completes() -> None:
    lifecycle = FakeInquiryLifecycle()

    result = await run_task(
        lifecycle,
        _request(
            pause_reason="PRIVATE-PAUSE: operator checkpoint",
            resume_after_pause=True,
        ),
    )

    assert result.terminal == "completed"
    assert lifecycle.calls == [
        "open_inquiry",
        "pause_inquiry",
        "resume_inquiry",
        "advance_inquiry",
        "handoff_inquiry",
        "inspect_inquiry",
    ]
    states = [operation.inquiry.state for operation in result.operations if operation.inquiry]
    assert states == ["open", "paused", "open", "answered", "answered"]


@pytest.mark.asyncio
async def test_underlying_operation_failure_is_preserved_and_stops() -> None:
    failure = RuntimeError("underlying failure")
    lifecycle = FakeInquiryLifecycle(advance_error=failure)

    with pytest.raises(RuntimeError) as caught:
        await run_task(lifecycle, _request())

    assert caught.value is failure
    assert lifecycle.calls == ["open_inquiry", "advance_inquiry"]


@pytest.mark.asyncio
async def test_serialization_is_deterministic_private_and_preserves_provenance() -> None:
    first_lifecycle = FakeInquiryLifecycle()
    second_lifecycle = FakeInquiryLifecycle()
    request = _request(
        pause_reason="PRIVATE-PAUSE: operator checkpoint",
        resume_after_pause=True,
    )

    first = await run_task(first_lifecycle, request)
    second = await run_task(second_lifecycle, request)
    first_bytes = first.canonical_bytes()

    assert first_bytes == second.canonical_bytes()
    assert first_bytes == json.dumps(
        first.public_record(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert b"PRIVATE-BRIEF" not in first_bytes
    assert b"PRIVATE-IDEMPOTENCY" not in first_bytes
    assert b"PRIVATE-PAUSE" not in first_bytes
    assert b"inquiry:stable" in first_bytes
    assert b"receipt:inquiry-evidence:answer" in first_bytes
    assert b"receipt:inquiry-evidence:handoff" in first_bytes
    assert first_lifecycle.provider_effects == second_lifecycle.provider_effects == 0
    assert first_lifecycle.external_effects == second_lifecycle.external_effects == 0


@pytest.mark.asyncio
async def test_adapter_has_no_provider_or_external_effect_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = FakeInquiryLifecycle()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("adapter attempted a forbidden effect")

    monkeypatch.setattr(ProviderSessionRunner, "run", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    result = await run_task(lifecycle, _request())

    assert result.terminal == "completed"
    assert lifecycle.provider_effects == 0
    assert lifecycle.external_effects == 0
