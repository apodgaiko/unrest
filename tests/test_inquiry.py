from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.canonical_identity import canonical_json_bytes
from unrest_harness.foundation_tools import FoundationTools
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
        synthesis_mode: str = "answered",
        synthesis_answer: str = "private combined answer",
        delay: float = 0.03,
    ) -> None:
        self.branch_modes = branch_modes or {}
        self.invalid_synthesis = invalid_synthesis
        self.synthesis_mode = synthesis_mode
        self.synthesis_answer = synthesis_answer
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.calls: list[tuple[str, str]] = []
        self.requests: list[ProviderSessionRequest] = []

    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult:
        self.requests.append(request)
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
                    "dissent": [],
                    "evidence": [f"private evidence from {role}"],
                    "limitations": [],
                    "steps_used": steps,
                }
                if mode == "missing":
                    parsed.pop("dissent")
                elif mode == "unknown":
                    parsed["unexpected"] = []
                elif mode == "type-invalid":
                    parsed["steps_used"] = True
                elif mode == "partial":
                    parsed = {"answer": f"partial {role}"}
                elif mode == "malformed":
                    return self._persist(
                        request,
                        None,
                        status="failed",
                        error="invalid_structured_output",
                    )
                elif mode == "truncated":
                    return self._persist(
                        request,
                        None,
                        status="failed",
                        error="output_limit_exceeded",
                    )
                elif mode == "persist-then-block":
                    result = self._persist(request, parsed)
                    await asyncio.Event().wait()
                    return result
                return self._persist(request, parsed)

            self.calls.append((request.role, "synthesis"))
            if self.synthesis_mode == "failed":
                return self._persist(request, None, status="failed", error="protocol_error")
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
            failed_branches = [
                branch["branch_identity"]
                for branch in denominator["branches"]
                if branch["outcome"] != "answered"
            ]
            parsed = {
                "answer": self.synthesis_answer,
                "citations": citations,
                "failed_branches": failed_branches,
                "limitations": ["private limitation"],
                "minority_dissent": ["private critic dissent"],
                "steps_used": 1,
            }
            if self.synthesis_mode == "missing":
                parsed.pop("failed_branches")
            elif self.synthesis_mode == "unknown":
                parsed["unexpected"] = []
            elif self.synthesis_mode == "type-invalid":
                parsed["steps_used"] = False
            elif self.synthesis_mode == "budget":
                parsed["steps_used"] = 99
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


def _open_with_branches(
    manager: InquiryManager,
    *,
    key: str,
    max_branches: int,
    steps: int = 4,
):
    return manager.open_inquiry(
        question="PRIVATE-CANARY: Which architecture is most robust?",
        budget=InquiryBudget(
            max_steps=steps,
            timeout_seconds=5,
            max_branches=max_branches,
        ),
        idempotency_key=key,
        project_id="project:test",
    )


def _rewrite_events_as_v040(project: Path, inquiry_id: str) -> dict[Path, bytes]:
    root = (
        project
        / ".unrest"
        / "inquiries"
        / inquiry_id.removeprefix("inquiry:")
    )
    predecessor: str | None = None
    latest = b""
    for path in sorted((root / "events").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        document.pop("event_digest")
        document.pop("predecessor_event_digest")
        for role, branch in document["branches"].items():
            branch.pop("artifact_digest", None)
            branch.pop("error_code", None)
            branch.pop("output_contract_version", None)
            attempts = branch.get("attempts", 0)
            if attempts:
                branch["artifact_relative_path"] = (
                    f"branches/{role}/attempt-{attempts:04d}.json"
                )
        synthesis = document["synthesis"]
        if synthesis["state"] == "present":
            value = synthesis["value"]
            value.pop("error_code", None)
            value.pop("output_contract_version", None)
            value.pop("steps_used", None)
            if value.get("attempt"):
                value["artifact_relative_path"] = (
                    f"synthesis/attempt-{value['attempt']:04d}.json"
                )
        document["predecessor_event_digest"] = (
            {"state": "absent"}
            if predecessor is None
            else {"state": "present", "value": predecessor}
        )
        material = canonical_json_bytes(document)
        predecessor = "sha256:" + hashlib.sha256(material).hexdigest()
        document["event_digest"] = predecessor
        latest = canonical_json_bytes(document)
        path.write_bytes(latest)
    (root / "state.json").write_bytes(latest)
    return {
        path: path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


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


@pytest.mark.asyncio
async def test_bundled_contracts_are_closed_and_runtime_assignments_match(
    project: Path, tmp_path: Path
) -> None:
    runner = FakeRunner()
    manager = InquiryManager(project, _config(tmp_path), provider_runner=runner)
    opened = _open_with_branches(manager, key="contract-match", max_branches=1)

    result = await manager.advance_inquiry(
        opened.inquiry_id, idempotency_key="contract-match-advance"
    )

    assert result.state == "answered"
    assert len(runner.requests) == 2
    for request in runner.requests:
        prompt_path = BUNDLED / "prompts" / request.role / "system_prompt.md"
        marker = next(
            line
            for line in prompt_path.read_text(encoding="utf-8").splitlines()
            if line.startswith("<!-- INQUIRY_OUTPUT_SCHEMA ")
        )
        encoded = marker.removeprefix("<!-- INQUIRY_OUTPUT_SCHEMA ").removesuffix(
            " -->"
        )
        schema = json.loads(encoded)
        assert encoded == json.dumps(schema, sort_keys=True, separators=(",", ":"))
        assert set(schema["properties"]) == set(schema["required"])
        assert schema["additionalProperties"] is False
        assert encoded in request.prompt
        assert request.max_response_bytes == 65_536


@pytest.mark.parametrize(
    ("mode", "error_code"),
    [
        ("missing", "invalid_structured_output"),
        ("unknown", "invalid_structured_output"),
        ("type-invalid", "invalid_structured_output"),
        ("partial", "invalid_structured_output"),
        ("malformed", "invalid_structured_output"),
        ("truncated", "output_limit_exceeded"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_branch_output_is_explicit_unknown_and_private(
    project: Path,
    tmp_path: Path,
    mode: str,
    error_code: str,
) -> None:
    runner = FakeRunner(branch_modes={"direct": mode})
    manager = InquiryManager(project, _config(tmp_path), provider_runner=runner)
    opened = _open_with_branches(
        manager, key=f"invalid-{mode}", max_branches=1
    )

    result = await manager.advance_inquiry(
        opened.inquiry_id, idempotency_key=f"advance-{mode}"
    )
    public = result.public_record()

    assert result.state == "failed"
    assert result.answer is None
    assert result.receipt_id is None
    assert result.diagnostics == {
        "aggregate_known_steps": 0,
        "branch_attempts": 1,
        "branch_steps_used": {"direct": None},
        "error_codes": {"direct": error_code, "synthesis": None},
        "synthesis_attempts": 0,
        "synthesis_steps_used": None,
        "unknown_step_attempts": 1,
    }
    encoded = json.dumps(public, sort_keys=True)
    assert "PRIVATE-CANARY" not in encoded
    assert "private answer" not in encoded
    assert "stderr" not in encoded
    assert ".unrest" not in encoded
    assert runner.calls == [("inquiry_branch", "direct")]


@pytest.mark.asyncio
async def test_all_branch_failure_skips_synthesis_and_returns_safe_diagnostics(
    project: Path, tmp_path: Path
) -> None:
    runner = FakeRunner(branch_modes={"direct": "failed", "evidence": "timed_out"})
    manager = InquiryManager(project, _config(tmp_path), provider_runner=runner)
    opened = _open_with_branches(manager, key="all-failed", max_branches=2)

    result = await manager.advance_inquiry(
        opened.inquiry_id, idempotency_key="all-failed-advance"
    )

    assert result.state == "failed"
    assert result.answer is None
    assert result.receipt_id is None
    assert result.diagnostics["branch_attempts"] == 2
    assert result.diagnostics["synthesis_attempts"] == 0
    assert result.diagnostics["unknown_step_attempts"] == 2
    assert result.diagnostics["error_codes"] == {
        "direct": "protocol_error",
        "evidence": "timed_out",
        "synthesis": None,
    }
    assert all(role != "inquiry_synthesis" for role, _ in runner.calls)
    assert not list((project / ".unrest" / "inquiries").rglob("synthesis/*.json"))


@pytest.mark.asyncio
async def test_synthesis_failure_and_budget_are_truthful(
    project: Path, tmp_path: Path
) -> None:
    failed_runner = FakeRunner(synthesis_mode="failed")
    failed_manager = InquiryManager(
        project, _config(tmp_path), provider_runner=failed_runner
    )
    failed_open = _open_with_branches(
        failed_manager, key="synthesis-failed", max_branches=2
    )
    failed = await failed_manager.advance_inquiry(
        failed_open.inquiry_id, idempotency_key="synthesis-failed-advance"
    )
    assert failed.state == "failed"
    assert failed.answer is None
    assert failed.diagnostics == {
        "aggregate_known_steps": 2,
        "branch_attempts": 2,
        "branch_steps_used": {"direct": 1, "evidence": 1},
        "error_codes": {
            "direct": None,
            "evidence": None,
            "synthesis": "protocol_error",
        },
        "synthesis_attempts": 1,
        "synthesis_steps_used": None,
        "unknown_step_attempts": 1,
    }

    budget_runner = FakeRunner(synthesis_mode="budget")
    budget_manager = InquiryManager(
        project, _config(tmp_path), provider_runner=budget_runner
    )
    budget_open = _open_with_branches(
        budget_manager, key="synthesis-budget", max_branches=1, steps=2
    )
    exhausted = await budget_manager.advance_inquiry(
        budget_open.inquiry_id, idempotency_key="synthesis-budget-advance"
    )
    assert exhausted.state == "budget_exhausted"
    assert exhausted.answer is None
    assert exhausted.diagnostics["aggregate_known_steps"] == 100
    assert exhausted.diagnostics["synthesis_steps_used"] == 99
    assert exhausted.diagnostics["error_codes"] == {
        "direct": None,
        "synthesis": "budget_exhausted",
    }


@pytest.mark.asyncio
async def test_product_workspace_and_private_provider_bucket_are_separate(
    project: Path, tmp_path: Path
) -> None:
    bucket = tmp_path / "provider-bucket"
    bucket.mkdir()
    product_before = {
        path.relative_to(project): path.read_bytes()
        for path in sorted(project.rglob("*"))
        if path.is_file()
    }
    runner = FakeRunner()
    manager = InquiryManager(
        bucket,
        _config(tmp_path),
        workspace_root=project,
        provider_runner=runner,
    )
    opened = _open_with_branches(manager, key="separate-roots", max_branches=2)

    answered = await manager.advance_inquiry(
        opened.inquiry_id, idempotency_key="separate-roots-advance"
    )

    assert answered.state == "answered"
    assert all(request.workspace_path == project for request in runner.requests)
    assert all(
        request.project_record_path.is_relative_to(bucket)
        and request.private_artifact_path.is_relative_to(bucket)
        and request.private_artifact_root.is_relative_to(bucket)
        and request.deliverable_roots == ()
        for request in runner.requests
    )
    product_after = {
        path.relative_to(project): path.read_bytes()
        for path in sorted(project.rglob("*"))
        if path.is_file()
    }
    assert product_after == product_before
    assert b"PRIVATE-CANARY" not in _public_bytes(bucket)
    assert b"private combined answer" not in _public_bytes(bucket)
    assert list((bucket / ".unrest" / "inquiries").rglob("private/question.json"))


@pytest.mark.asyncio
async def test_answer_utf8_boundary_and_credential_redaction(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exact_runner = FakeRunner(synthesis_answer="é" * 32_768)
    exact_manager = InquiryManager(
        project, _config(tmp_path), provider_runner=exact_runner
    )
    exact_open = _open_with_branches(
        exact_manager, key="answer-exact", max_branches=1
    )
    exact = await exact_manager.advance_inquiry(
        exact_open.inquiry_id, idempotency_key="answer-exact-advance"
    )
    assert exact.answer is not None
    assert len(exact.answer.encode("utf-8")) == 65_536

    oversized_runner = FakeRunner(synthesis_answer="é" * 32_769)
    oversized_manager = InquiryManager(
        project, _config(tmp_path), provider_runner=oversized_runner
    )
    oversized_open = _open_with_branches(
        oversized_manager, key="answer-oversized", max_branches=1
    )
    oversized = await oversized_manager.advance_inquiry(
        oversized_open.inquiry_id, idempotency_key="answer-oversized-advance"
    )
    assert oversized.answer is not None
    assert len(oversized.answer.encode("utf-8")) == 65_536

    monkeypatch.setenv("ANTHROPIC_API_KEY", "CREDENTIAL-CANARY-123")
    secret_runner = FakeRunner(
        synthesis_answer="prefix CREDENTIAL-CANARY-123 suffix"
    )
    secret_manager = InquiryManager(
        project, _config(tmp_path), provider_runner=secret_runner
    )
    secret_open = _open_with_branches(
        secret_manager, key="answer-redacted", max_branches=1
    )
    redacted = await secret_manager.advance_inquiry(
        secret_open.inquiry_id, idempotency_key="answer-redacted-advance"
    )
    assert redacted.answer is not None
    assert "CREDENTIAL-CANARY-123" not in redacted.answer
    assert "prefix" in redacted.answer and "suffix" in redacted.answer


@pytest.mark.parametrize(
    "budget",
    [
        {},
        {"max_steps": 1},
        {"timeout_seconds": 1},
        {"max_steps": 0, "timeout_seconds": 1},
        {"max_steps": -1, "timeout_seconds": 1},
        {"max_steps": True, "timeout_seconds": 1},
        {"max_steps": "1", "timeout_seconds": 1},
        {"max_steps": 1, "timeout_seconds": 0},
        {"max_steps": 1, "timeout_seconds": -1},
        {"max_steps": 1, "timeout_seconds": False},
        {"max_steps": 1, "timeout_seconds": "1"},
        {"max_steps": 1, "timeout_seconds": 1, "max_branches": 0},
        {"max_steps": 1, "timeout_seconds": 1, "max_branches": -1},
        {"max_steps": 1, "timeout_seconds": 1, "max_branches": True},
        {"max_steps": 1, "timeout_seconds": 1, "max_branches": "1"},
        {"max_steps": 1, "timeout_seconds": 1, "max_branches": 5},
        {"max_steps": 1, "timeout_seconds": 1, "unknown": 2},
    ],
)
def test_invalid_direct_budget_fails_before_store_work(
    tmp_path: Path, budget: dict[str, object]
) -> None:
    tools = object.__new__(FoundationTools)
    tools.config = _config(tmp_path)
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    with pytest.raises(InquiryError) as caught:
        FoundationTools.open_inquiry(
            tools,
            "question",
            budget,
            "invalid-budget",
        )

    assert caught.value.code == "invalid_argument"
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }
    assert after == before
    assert not (tmp_path / "home" / "foundation" / ".unrest").exists()


def test_direct_budget_uses_compatible_default() -> None:
    budget = InquiryBudget.from_mapping({"max_steps": 1, "timeout_seconds": 2})
    assert budget.public_record() == {
        "max_branches": 4,
        "max_steps": 1,
        "timeout_seconds": 2,
    }


@pytest.mark.asyncio
async def test_restart_reuses_persisted_attempts_without_provider_repetition(
    project: Path, tmp_path: Path
) -> None:
    first_runner = FakeRunner(
        branch_modes={"direct": "persist-then-block", "evidence": "persist-then-block"}
    )
    first = InquiryManager(project, _config(tmp_path), provider_runner=first_runner)
    opened = _open_with_branches(first, key="persisted-restart", max_branches=2)
    task = asyncio.create_task(
        first.advance_inquiry(
            opened.inquiry_id, idempotency_key="persisted-restart-advance"
        )
    )
    for _ in range(200):
        artifacts = list(
            (project / ".unrest" / "inquiries").rglob("private/branches/*/*.json")
        )
        if len(artifacts) == 2:
            break
        await asyncio.sleep(0.01)
    assert len(artifacts) == 2
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    recovery_runner = FakeRunner()
    restarted = InquiryManager(
        project, _config(tmp_path), provider_runner=recovery_runner
    )
    recovered = await restarted.advance_inquiry(
        opened.inquiry_id, idempotency_key="persisted-restart-advance"
    )

    assert recovered.state == "answered"
    assert recovery_runner.calls == [("inquiry_synthesis", "synthesis")]
    assert recovered.diagnostics["branch_attempts"] == 2
    assert recovered.diagnostics["synthesis_attempts"] == 1


@pytest.mark.asyncio
async def test_v040_record_projects_additive_fields_without_rewrite_or_repeat(
    project: Path, tmp_path: Path
) -> None:
    original_runner = FakeRunner()
    manager = InquiryManager(
        project, _config(tmp_path), provider_runner=original_runner
    )
    opened = _open_with_branches(manager, key="legacy-record", max_branches=2)
    answered = await manager.advance_inquiry(
        opened.inquiry_id, idempotency_key="legacy-record-advance"
    )
    assert answered.state == "answered"
    old_bytes = _rewrite_events_as_v040(project, opened.inquiry_id)

    restarted_runner = FakeRunner()
    restarted = InquiryManager(
        project, _config(tmp_path), provider_runner=restarted_runner
    )
    inspected = restarted.inspect_inquiry(opened.inquiry_id)
    replayed = await restarted.advance_inquiry(
        opened.inquiry_id, idempotency_key="legacy-record-advance"
    )

    assert replayed == inspected
    assert inspected.answer == "private combined answer"
    assert inspected.diagnostics["synthesis_steps_used"] is None
    assert inspected.diagnostics["unknown_step_attempts"] == 1
    assert restarted_runner.calls == []
    observed = {
        path: path.read_bytes()
        for path in sorted(
            (
                project
                / ".unrest"
                / "inquiries"
                / opened.inquiry_id.removeprefix("inquiry:")
            ).rglob("*")
        )
        if path.is_file()
    }
    assert observed == old_bytes
