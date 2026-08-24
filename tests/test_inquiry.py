from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.canonical_identity import canonical_json_bytes
from unrest_harness.inquiry import (
    BRANCH_ROLES,
    InquiryBudget,
    InquiryError,
    InquiryManager,
)
from unrest_harness.provider_sessions import ProviderSessionRequest, ProviderSessionResult


ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"


def _config(tmp_path: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name="claude",
        validator_acp_command=None,
        terminal_reviewer_provider_name="claude",
        terminal_reviewer_acp_command=None,
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "mission-record.json").write_text('{"mission":"unchanged"}\n')
    (root / "accepted-point.json").write_text('{"accepted":"unchanged"}\n')
    return root


class FakeRunner:
    def __init__(
        self,
        *,
        branch_modes: dict[str, str] | None = None,
        invalid_synthesis: bool = False,
        delay: float = 0.03,
    ) -> None:
        self.branch_modes = branch_modes or {}
        self.invalid_synthesis = invalid_synthesis
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.calls: list[tuple[str, str]] = []

    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if request.role == "inquiry_branch":
                role = next(
                    line.removeprefix("Branch role: ")
                    for line in request.prompt.splitlines()
                    if line.startswith("Branch role: ")
                )
                self.calls.append((request.role, role))
                mode = self.branch_modes.get(role, "answered")
                if mode == "blocking":
                    assert cancel_event is not None
                    await cancel_event.wait()
                    return self._persist(request, None, status="cancelled", error="cancelled")
                await asyncio.sleep(self.delay)
                if cancel_event is not None and cancel_event.is_set():
                    return self._persist(request, None, status="cancelled", error="cancelled")
                if mode == "failed":
                    return self._persist(request, None, status="failed", error="protocol_error")
                if mode == "timed_out":
                    return self._persist(request, None, status="timed_out", error="timed_out")
                steps = 99 if mode == "budget" else 1
                parsed = {
                    "answer": f"private answer from {role}",
                    "evidence": [f"private evidence from {role}"],
                    "limitations": [],
                    "steps_used": steps,
                }
                return self._persist(request, parsed)

            self.calls.append((request.role, "synthesis"))
            marker = request.prompt.index('{"branches":')
            denominator = json.loads(request.prompt[marker:])
            citations = [
                {
                    "branch_identity": branch["branch_identity"],
                    "outcome": branch["outcome"],
                }
                for branch in denominator["branches"]
            ]
            if self.invalid_synthesis:
                citations = citations[:-1]
            parsed = {
                "answer": "private combined answer",
                "citations": citations,
                "limitations": ["private limitation"],
                "minority_dissent": ["private critic dissent"],
            }
            return self._persist(request, parsed)
        finally:
            self.active -= 1

    @staticmethod
    def _persist(
        request: ProviderSessionRequest,
        parsed: dict[str, object] | None,
        *,
        status: str = "completed",
        error: str | None = None,
    ) -> ProviderSessionResult:
        artifact = {
            "error_code": error,
            "input": {"prompt": request.prompt},
            "output": {
                "parsed": parsed,
                "response_bytes": 100,
                "response_text": json.dumps(parsed),
                "response_truncated": False,
                "stderr": "",
            },
            "privacy": "private-provider-session",
            "provider": "claude",
            "role": request.role,
            "schema_version": 1,
            "status": status,
        }
        request.private_artifact_path.parent.mkdir(parents=True, exist_ok=True)
        request.private_artifact_path.write_text(
            json.dumps(artifact, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(request.private_artifact_path, 0o600)
        return ProviderSessionResult(
            role=request.role,
            provider="claude",
            status=status,  # type: ignore[arg-type]
            stop_reason="end_turn" if status == "completed" else None,
            response_bytes=100,
            response_truncated=False,
            structured_output=parsed is not None,
            adapter_exit_code=0,
            error_code=error,  # type: ignore[arg-type]
        )


def _open(manager: InquiryManager, *, key: str = "open-one", steps: int = 4):
    return manager.open_inquiry(
        question="PRIVATE-CANARY: Which architecture is most robust?",
        budget=InquiryBudget(max_steps=steps, timeout_seconds=5),
        idempotency_key=key,
        project_id="project:test",
    )


def _public_bytes(project: Path) -> bytes:
    chunks = []
    root = project / ".unrest" / "inquiries"
    for path in sorted(root.rglob("*")):
        if path.is_file() and "private" not in path.parts:
            chunks.append(path.read_bytes())
    return b"".join(chunks)


def test_open_is_idempotent_durable_private_and_mission_adjacent(project: Path, tmp_path: Path) -> None:
    manager = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())
    mission_before = (project / "mission-record.json").read_bytes()
    accepted_before = (project / "accepted-point.json").read_bytes()

    opened = _open(manager)
    replay = _open(manager)
    restarted = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())

    assert replay == opened == restarted.inspect_inquiry(opened.inquiry_id)
    assert opened.state == "open"
    assert opened.branch_outcomes == {role: "pending" for role in BRANCH_ROLES}
    assert b"PRIVATE-CANARY" not in _public_bytes(project)
    private_question = next((project / ".unrest" / "inquiries").rglob("private/question.json"))
    assert "PRIVATE-CANARY" in private_question.read_text()
    assert stat.S_IMODE(private_question.stat().st_mode) == 0o600
    assert (project / "mission-record.json").read_bytes() == mission_before
    assert (project / "accepted-point.json").read_bytes() == accepted_before
    identity_kinds = {
        path.parent.name
        for path in (project / ".unrest" / "foundation" / "identities").glob("*/*.json")
    }
    assert {"inquiry", "inquiry_branch"}.issubset(identity_kinds)

    open_index = next((project / ".unrest" / "inquiries" / "open-index").glob("*.json"))
    open_index.unlink()
    assert _open(restarted) == opened

    with pytest.raises(InquiryError) as caught:
        manager.open_inquiry(
            question="different",
            budget=InquiryBudget(max_steps=4, timeout_seconds=5),
            idempotency_key="open-one",
        )
    assert caught.value.code == "conflict"
    assert "different" not in str(caught.value)


@pytest.mark.asyncio
async def test_concurrent_four_way_fanout_synthesis_and_exact_handoff(
    project: Path, tmp_path: Path
) -> None:
    runner = FakeRunner()
    manager = InquiryManager(project, _config(tmp_path), provider_runner=runner)
    mission_before = (project / "mission-record.json").read_bytes()
    opened = _open(manager)

    answered = await manager.advance_inquiry(opened.inquiry_id, idempotency_key="advance-one")

    assert answered.state == "answered"
    assert set(answered.branch_outcomes.values()) == {"answered"}
    assert answered.receipt_id is not None
    assert runner.max_active == 4
    assert runner.calls[:4] != []
    assert runner.calls[-1] == ("inquiry_synthesis", "synthesis")
    assert b"private answer" not in _public_bytes(project)
    assert b"private combined" not in _public_bytes(project)
    assert (project / "mission-record.json").read_bytes() == mission_before
    synthesis_receipt = next(
        (project / ".unrest" / "inquiries").rglob("evidence-receipts/*.json")
    )
    assert json.loads(synthesis_receipt.read_text())["authoritative"] is False

    handoff = manager.handoff_inquiry(
        opened.inquiry_id,
        consumer_id="consumer:planning-thread",
        idempotency_key="handoff-one",
    )
    replay = manager.handoff_inquiry(
        opened.inquiry_id,
        consumer_id="consumer:planning-thread",
        idempotency_key="handoff-one",
    )
    assert replay == handoff
    assert handoff.receipt_id.startswith("receipt:inquiry-evidence:")
    handoff_path = next((project / ".unrest" / "inquiries").rglob("private/handoffs/*.json"))
    artifact = json.loads(handoff_path.read_text())
    assert artifact["privacy"] == "private-evidence-only-handoff"
    assert artifact["consumer_id"] == "consumer:planning-thread"
    assert len(artifact["branch_denominator"]) == 4
    assert "PRIVATE-CANARY" in artifact["question"]
    assert len(list((project / ".unrest" / "inquiries").rglob("evidence-receipts/*.json"))) == 2

    with pytest.raises(InquiryError) as caught:
        manager.handoff_inquiry(
            opened.inquiry_id,
            consumer_id="consumer:other",
            idempotency_key="handoff-one",
        )
    assert caught.value.code == "conflict"


@pytest.mark.asyncio
async def test_failure_timeout_and_budget_outcomes_are_retained_in_synthesis(
    project: Path, tmp_path: Path
) -> None:
    runner = FakeRunner(
        branch_modes={"evidence": "failed", "critic": "timed_out", "analogy": "budget"}
    )
    manager = InquiryManager(project, _config(tmp_path), provider_runner=runner)
    opened = _open(manager, steps=2)

    result = await manager.advance_inquiry(opened.inquiry_id, idempotency_key="mixed")

    assert result.state == "answered"
    assert result.branch_outcomes == {
        "analogy": "budget_exhausted",
        "critic": "failed",
        "direct": "answered",
        "evidence": "failed",
    }
    synthesis_path = next((project / ".unrest" / "inquiries").rglob("private/synthesis/*.json"))
    synthesis_prompt = json.loads(synthesis_path.read_text())["input"]["prompt"]
    assert '"outcome": "failed"' in synthesis_prompt
    assert '"outcome": "budget_exhausted"' in synthesis_prompt
    assert "private answer from direct" in synthesis_prompt


@pytest.mark.asyncio
async def test_pause_restart_resume_and_cancel_stop_inflight_branches(
    project: Path, tmp_path: Path
) -> None:
    blocking = FakeRunner(branch_modes={role: "blocking" for role in BRANCH_ROLES})
    manager = InquiryManager(project, _config(tmp_path), provider_runner=blocking)
    opened = _open(manager)
    advancing = asyncio.create_task(
        manager.advance_inquiry(opened.inquiry_id, idempotency_key="advance-paused")
    )
    for _ in range(100):
        if blocking.active == 4:
            break
        await asyncio.sleep(0.01)
    with pytest.raises(InquiryError) as caught:
        await manager.advance_inquiry(opened.inquiry_id, idempotency_key="duplicate-live")
    assert caught.value.code == "busy"

    paused = manager.pause_inquiry(
        opened.inquiry_id,
        reason="operator requested pause PRIVATE-REASON",
        idempotency_key="pause-one",
    )
    advance_result = await asyncio.wait_for(advancing, timeout=2)
    assert paused.state == advance_result.state == "paused"
    assert set(advance_result.branch_outcomes.values()) == {"paused"}
    assert b"PRIVATE-REASON" not in _public_bytes(project)
    assert len(list((project / ".unrest" / "inquiries").rglob("private/branches/*/*.json"))) == 4

    completing = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())
    resumed = completing.resume_inquiry(opened.inquiry_id, idempotency_key="resume-one")
    assert resumed.state == "open"
    assert set(resumed.branch_outcomes.values()) == {"pending"}
    answered = await completing.advance_inquiry(
        opened.inquiry_id, idempotency_key="advance-resumed"
    )
    assert answered.state == "answered"

    other = _open(completing, key="open-cancel")
    cancelled = completing.cancel_inquiry(
        other.inquiry_id,
        reason="no longer needed",
        idempotency_key="cancel-one",
    )
    assert cancelled.state == "cancelled"
    assert set(cancelled.branch_outcomes.values()) == {"cancelled"}
    with pytest.raises(InquiryError) as caught:
        completing.resume_inquiry(other.inquiry_id, idempotency_key="resume-cancelled")
    assert caught.value.code == "invalid_transition"


@pytest.mark.asyncio
async def test_restart_reclaims_interrupted_advance_with_same_key(
    project: Path, tmp_path: Path
) -> None:
    blocking = FakeRunner(branch_modes={role: "blocking" for role in BRANCH_ROLES})
    first = InquiryManager(project, _config(tmp_path), provider_runner=blocking)
    opened = _open(first)
    task = asyncio.create_task(
        first.advance_inquiry(opened.inquiry_id, idempotency_key="crash-key")
    )
    for _ in range(100):
        if blocking.active == 4:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert first.inspect_inquiry(opened.inquiry_id).state == "exploring"

    restarted = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())
    recovered = await restarted.advance_inquiry(
        opened.inquiry_id, idempotency_key="crash-key"
    )
    assert recovered.state == "answered"
    assert set(recovered.branch_outcomes.values()) == {"answered"}


@pytest.mark.asyncio
async def test_incomplete_synthesis_citations_fail_closed(project: Path, tmp_path: Path) -> None:
    manager = InquiryManager(
        project,
        _config(tmp_path),
        provider_runner=FakeRunner(invalid_synthesis=True),
    )
    opened = _open(manager)
    result = await manager.advance_inquiry(opened.inquiry_id, idempotency_key="bad-synthesis")
    assert result.state == "failed"
    assert result.receipt_id is None
    with pytest.raises(InquiryError) as caught:
        manager.handoff_inquiry(
            opened.inquiry_id,
            consumer_id="consumer:test",
            idempotency_key="no-handoff",
        )
    assert caught.value.code == "invalid_transition"


@pytest.mark.asyncio
async def test_branch_event_and_synthesis_artifact_mutations_fail_closed(
    project: Path, tmp_path: Path
) -> None:
    manager = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())
    first = _open(manager)
    await manager.advance_inquiry(first.inquiry_id, idempotency_key="advance-tamper-state")
    inquiry_root = next((project / ".unrest" / "inquiries").glob("[0-9a-f]*"))
    latest = sorted((inquiry_root / "events").glob("*.json"))[-1]
    state = json.loads(latest.read_text())
    state["branches"]["direct"]["identity_digest"] = "sha256:" + "0" * 64
    latest.write_bytes(canonical_json_bytes(state))
    with pytest.raises(InquiryError) as caught:
        manager.inspect_inquiry(first.inquiry_id)
    assert caught.value.code == "integrity_error"

    second = _open(manager, key="open-tamper-artifact")
    await manager.advance_inquiry(second.inquiry_id, idempotency_key="advance-tamper-artifact")
    roots = sorted((project / ".unrest" / "inquiries").glob("[0-9a-f]*"))
    second_root = next(path for path in roots if path != inquiry_root)
    synthesis = next(second_root.glob("private/synthesis/*.json"))
    artifact = json.loads(synthesis.read_text())
    artifact["output"]["parsed"]["answer"] = "mutated private answer"
    synthesis.write_text(json.dumps(artifact, sort_keys=True) + "\n")
    with pytest.raises(InquiryError) as caught:
        manager.handoff_inquiry(
            second.inquiry_id,
            consumer_id="consumer:test",
            idempotency_key="tampered-handoff",
        )
    assert caught.value.code == "integrity_error"


def test_invalid_budget_and_state_transitions_are_value_free(project: Path, tmp_path: Path) -> None:
    with pytest.raises(InquiryError) as caught:
        InquiryBudget(max_steps=0, timeout_seconds=1)
    assert caught.value.code == "invalid_argument"
    manager = InquiryManager(project, _config(tmp_path), provider_runner=FakeRunner())
    opened = _open(manager)
    with pytest.raises(InquiryError) as caught:
        manager.resume_inquiry(opened.inquiry_id, idempotency_key="SECRET-IDEMPOTENCY")
    assert caught.value.code == "invalid_transition"
    assert "SECRET-IDEMPOTENCY" not in str(caught.value)
