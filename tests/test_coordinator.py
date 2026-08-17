"""Coordinator state-machine tests with the in-process mock dispatcher.

See `specs/task_list/PRODUCT.md` §Dispatch.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import MAX_ABORT_REASON_BYTES, ProjectController, ToolError
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    Decision,
    MissionRunning,
    Task,
    TaskList,
    TaskListPatch,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
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


def _task(
    tid: str,
    ttype: str,
    targets: list[str],
    skill: str | None = None,
    depends_on: list[str] | None = None,
    body: str = "body",
) -> Task:
    if skill is None and ttype != "gate":
        skill = "s"
    return Task(
        id=tid,
        type=ttype,  # type: ignore[arg-type]
        body="" if ttype == "gate" else body,
        targets=targets,
        skill=skill,
        depends_on=depends_on or [],
    )


def _simple_tl() -> TaskList:
    return TaskList(
        tasks=[
            _task("w1", "work", ["VAL-001"]),
            _task("v1", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["v1"]),
        ]
    )


def _validate_no_gate_tl() -> TaskList:
    return TaskList(
        tasks=[
            _task("w1", "work", ["VAL-001"]),
            _task("v1", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
        ]
    )


def _seed_project(
    controller: ProjectController,
    workspace: Path,
    *,
    brief: str = "Brief.",
    mission_id: str = "mission-001",
    assertion: str = "VAL-001",
) -> str:
    controller.start_project(brief, str(workspace))
    pid = controller.store.list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, mission_id)
    (contract_dir / f"{assertion}.md").write_text(
        f"# {assertion}\n\nStatement body.\n"
    )
    return pid


def test_serial_dispatch_crash_is_bounded_and_redacted_in_reachable_sinks(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = {
        "ANTHROPIC_API_KEY": "short-key",
        "ANTHROPIC_AUTH_TOKEN": "overlap-known-value",
        "CODEX_API_KEY": "known-value",
        "GLM_API_KEY": "known-value-suffix",
        "OPENAI_API_KEY": "colliding-known-value",
        "ZAI_API_KEY": "punctuation@known",
    }
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)

    def crash(_request: DispatchRequest) -> NodeHandoff:
        raise RuntimeError("|".join(credentials.values()) + "-" + "x" * 5000)

    controller = ProjectController(
        config,
        MockDispatcher(crash),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    pid = _seed_project(controller, workspace)
    controller.submit_plan(pid, _simple_tl())
    controller.advance_project(pid, max_steps=1)

    attempt_path = next(controller.store.attempts_runtime_dir(pid, "mission-001").glob("*.json"))
    attempt = json.loads(attempt_path.read_text())
    assert len(attempt["report"]) <= 2000
    reachable = [
        attempt_path,
        next(controller.store.attempts_dir(pid, "mission-001").glob("*.md")),
        controller.store.unrest_runtime_dir(pid) / "attention.json",
        controller.store.unrest_runtime_dir(pid) / "state.json",
    ]
    for path in reachable:
        content = path.read_text()
        for value in credentials.values():
            assert value not in content


class TestHappyPath:
    def test_full_pipeline_to_done(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        dispatcher = MockDispatcher(responder)
        reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        controller = ProjectController(config, dispatcher, reviewer)

        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())

        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items and items[0].kind == "gate_checkpoint"

        env = controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        assert env.state.state in ("mission_running", "done")

        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "done"

    def test_advance_syncs_bucket_skill_to_real_host_dir_before_dispatch(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        codex_skills = workspace / ".codex" / "skills"
        codex_skills.mkdir(parents=True)
        (codex_skills / "user-skill" / "SKILL.md").parent.mkdir()
        (codex_skills / "user-skill" / "SKILL.md").write_text("# User skill\n")

        saw_synced_skill = False

        def responder(req: DispatchRequest) -> NodeHandoff:
            nonlocal saw_synced_skill
            saw_synced_skill = (
                codex_skills / "new-worker" / "SKILL.md"
            ).exists()
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        bucket_skill = (
            controller.store.unrest_dir(pid)
            / "skills"
            / "new-worker"
            / "SKILL.md"
        )
        bucket_skill.parent.mkdir(parents=True)
        bucket_skill.write_text("# New worker\n")

        controller.submit_plan(
            pid,
            TaskList(tasks=[_task("w1", "work", ["VAL-001"], skill="new-worker")]),
        )
        controller.advance_project(pid, max_steps=1)

        assert saw_synced_skill
        assert codex_skills.is_dir()
        assert not codex_skills.is_symlink()


class TestNodeFailedFlow:
    def test_work_failure_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_failed"
        assert "blocked" in items[0].report


class TestRequestAttentionRaisesNodeAttention:
    def test_request_attention_true_raises(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(
                node_id=req.task.id,
                done=True,
                report="finished",
                request_attention=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_attention"
        assert "finished" in items[0].report


class TestGateFailed:
    def test_validator_failing_raises_gate_failed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="found bug",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"

    @pytest.mark.parametrize(
        "invalid_kind", ("corrupt", "wrong-task", "stale-generation")
    )
    def test_invalid_gate_evidence_routes_to_attention_then_new_generation(
        self,
        config: HarnessConfig,
        workspace: Path,
        invalid_kind: str,
    ) -> None:
        def responder(request: DispatchRequest) -> NodeHandoff:
            return ValidateHandoff(
                node_id=request.task.id,
                attempt_id=request.spawn_ts,
                done=True,
                report="fresh validation",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "cleared")
        task_state.set_status("v1", "cleared")
        task_state.set_last_attempt("v1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        rejected = store.attempt_path(
            pid, "mission-001", generation, "v1"
        )
        rejected.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, object] = {
            "node_id": "v1",
            "attempt_id": generation,
            "done": True,
            "report": "forensic-sentinel-must-not-escape",
            "items": [{"item_id": "VAL-001", "passed": True}],
            "passed": True,
            "request_attention": False,
        }
        if invalid_kind == "corrupt":
            rejected.write_text("{forensic-sentinel-must-not-escape")
        else:
            if invalid_kind == "wrong-task":
                payload["node_id"] = "other-validator"
            else:
                payload["attempt_id"] = "2026-08-09T12-00-00Z"
            rejected.write_text(json.dumps(payload), encoding="utf-8")
        rejected_before = rejected.read_bytes()
        rejected_hash = hashlib.sha256(rejected_before).hexdigest()

        failed = controller.advance_project(pid, max_steps=1)

        assert failed.state.state == "attention_needed"
        attention = store.load_attention(pid)
        assert len(attention) == 1
        assert attention[0].kind == "gate_failed"
        assert "validator evidence rejected for v1" in attention[0].report
        assert len(attention[0].report.encode()) < 4096
        assert "forensic-sentinel" not in attention[0].report
        for sink in (
            store.unrest_runtime_dir(pid) / "attention.json",
            store.unrest_runtime_dir(pid) / "state.json",
        ):
            assert "forensic-sentinel" not in sink.read_text(encoding="utf-8")
        assert rejected.read_bytes() == rejected_before
        assert hashlib.sha256(rejected.read_bytes()).hexdigest() == rejected_hash

        replacement = TaskListPatch(
            supersede={"g1": "g1-v2"},
            add=[
                _task(
                    "v1-v2",
                    "validate",
                    ["VAL-001"],
                    skill="aud",
                    depends_on=["w1"],
                ),
                _task(
                    "g1-v2",
                    "gate",
                    ["VAL-001"],
                    depends_on=["v1-v2"],
                ),
            ],
        )
        controller.decide_attention(
            pid,
            [
                Decision(
                    item_id=attention[0].id,
                    action="patch",
                    patch=replacement,
                    justification="collect fresh validator evidence",
                )
            ],
        )
        recovered = controller.advance_project(pid)

        assert recovered.state.state == "attention_needed"
        final_attention = store.load_attention(pid)
        assert len(final_attention) == 1
        assert final_attention[0].kind == "gate_checkpoint"
        final_state = store.load_task_state(pid, "mission-001")
        assert final_state.status_of("g1-v2") == "cleared"
        new_generation = final_state.tasks["v1-v2"].last_attempt
        assert new_generation is not None and new_generation != generation
        assert rejected.read_bytes() == rejected_before
        assert hashlib.sha256(rejected.read_bytes()).hexdigest() == rejected_hash


class TestGateOptional:
    def test_validator_failure_without_downstream_gate_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="found bug",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _validate_no_gate_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_attention"
        assert "VAL-001: failed" in items[0].report


class TestValidatorDissentFailsGate:
    @staticmethod
    def _two_validator_tl() -> TaskList:
        return TaskList(
            tasks=[
                _task("w1", "work", ["VAL-001"]),
                _task("v-scrutiny", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
                _task("v-user-surface", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
                _task("g1", "gate", ["VAL-001"], depends_on=["v-scrutiny", "v-user-surface"]),
            ]
        )

    def test_dissent_raises_gate_failed_not_checkpoint(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            passed = req.task.id == "v-scrutiny"
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="scrutiny ok" if passed else "user-surface broken",
                items=[ValidationItem(item_id="VAL-001", passed=passed)],
                passed=passed,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"
        report = items[0].report
        assert "v-user-surface" in report
        assert "dissenting: VAL-001" in report
        assert "v-scrutiny: 1/1 passed" in report

    def test_all_validators_pass_clears_with_explicit_summary(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_checkpoint"
        report = items[0].report
        assert "v-scrutiny: 1/1 passed" in report
        assert "v-user-surface: 1/1 passed" in report

    def test_validator_omitting_items_fails_gate(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            if req.task.id == "v-scrutiny":
                return ValidateHandoff(
                    node_id=req.task.id,
                    done=True,
                    report="scrutiny ok",
                    items=[ValidationItem(item_id="VAL-001", passed=True)],
                    passed=True,
                )
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="ran but rendered no verdict",
                items=[],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"
        report = items[0].report
        assert "v-user-surface" in report
        assert "missing: VAL-001" in report


class TestSubmitPlanValidation:
    def test_contract_less_plan_rejected(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda req: WorkHandoff(node_id=req.task.id, done=True, report="ok")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        # Seed the project but author no contract assertion files.
        controller.start_project("Brief.", str(workspace))
        pid = controller.store.list_projects()[0].id

        with pytest.raises(ToolError) as exc:
            controller.submit_plan(pid, TaskList(tasks=[_task("w1", "work", [])]))
        assert exc.value.code == "invalid_task_list"
        assert any("empty_contract" in str(d) for d in (exc.value.details or []))

        state = controller.store.load_state(pid)
        assert state is not None and state.state == "mission_planning"


class TestDecideAttentionValidation:
    def test_atomic_rejection(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        with pytest.raises(ToolError) as exc:
            controller.decide_attention(
                pid,
                [Decision(item_id=items[0].id, action="next_mission")],
            )
        assert exc.value.code == "invalid_decisions"

    def test_missing_decision_rejected(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        with pytest.raises(ToolError) as exc:
            controller.decide_attention(pid, [])
        assert any(
            "unresolved_attention_item" in str(d) for d in (exc.value.details or [])
        )


class TestTerminalReview:
    def test_clean_review_to_done(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        responses: list[NodeHandoff] = [
            WorkHandoff(node_id="w1", done=True, report=""),
            ValidateHandoff(
                node_id="v1",
                done=True,
                report="",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            ),
        ]
        gen = iter(responses)

        def responder(req: DispatchRequest) -> NodeHandoff:
            return next(gen)

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "done"

    def test_terminal_review_report_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        reviewer = MockTerminalReviewer(
            TerminalReviewHandoff(
                done=False,
                report=(
                    "Terminal review found a blocking gap.\n"
                    "- brief_reference: brief quote\n"
                    "- description: missing endpoint"
                ),
            )
        )
        controller = ProjectController(config, MockDispatcher(responder), reviewer)
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "terminal_review"
        assert "missing endpoint" in items[0].report


class TestDecideAttentionPatchAddItems:
    """Regression: decide_attention(patch) with add_items must source
    old_ids from contract-state, not from disk listing."""

    def test_add_items_through_decide_attention_succeeds(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_checkpoint"

        contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
        (contract_dir / "NEW-001.md").write_text("# NEW-001\n\nNew assertion.\n")

        # Patch declaring NEW-001 + supporting tasks. The new gate depends on
        # g1 transitively via the new work task (which depends on g1).
        patch = TaskListPatch(
            add_items=["NEW-001"],
            add=[
                _task("w2", "work", ["NEW-001"], depends_on=["g1"]),
                _task("v2", "validate", ["NEW-001"], skill="aud", depends_on=["w2"]),
                _task("g2", "gate", ["NEW-001"], depends_on=["v2"]),
            ],
        )
        env2 = controller.decide_attention(
            pid,
            [Decision(item_id=items[0].id, action="patch", patch=patch)],
        )
        assert env2.state.state == "mission_running"


class TestEnvelopeProjectId:
    def test_envelope_carries_project_id(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config, MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        env = controller.inspect_project(pid)
        assert env.projectId == pid
        env2 = controller.inspect_project(env.projectId)
        assert env2.projectId == env.projectId

    def test_tool_specific_dag_modes(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        start = controller.start_project("Brief.", str(workspace))
        assert start.dag is None
        pid = start.projectId
        contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
        (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nStatement body.\n")

        submitted = controller.submit_plan(pid, _simple_tl())
        assert submitted.dag is not None
        assert "    w1  [work:s]  pending  → VAL-001  ← (root)" in submitted.dag
        assert "focus-subgraph" not in submitted.dag

        inspected = controller.inspect_project(pid)
        assert inspected.dag is not None
        assert "    w1" in inspected.dag
        assert "    v1" in inspected.dag
        assert "    g1" in inspected.dag
        assert "focus-subgraph" not in inspected.dag

        advanced = controller.advance_project(pid, max_steps=1)
        assert advanced.dag is not None
        assert "focus-subgraph" not in advanced.dag

        attention = controller.advance_project(pid)
        assert attention.state.state == "attention_needed"
        assert attention.dag is not None
        assert "focus-subgraph" not in attention.dag
        items = controller.store.load_attention(pid)

        decided = controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        assert decided.dag is None

        controller.advance_project(pid)
        ended = controller.end_mission(pid)
        assert ended.dag is None


class TestAbortProject:
    def test_aborts(self, config: HarnessConfig, workspace: Path) -> None:
        controller = ProjectController(
            config, MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.abort_project(pid, "user requested")
        assert env.state.state == "aborted"
        assert env.dag is None

    @pytest.mark.parametrize(
        "reason",
        (
            "a" * (MAX_ABORT_REASON_BYTES - 1),
            "a" * MAX_ABORT_REASON_BYTES,
            "🚀" * (MAX_ABORT_REASON_BYTES // 4),
        ),
        ids=("boundary-minus-one", "boundary", "unicode-byte-boundary"),
    )
    def test_abort_reason_utf8_boundary_persists_and_reloads_exactly(
        self, config: HarnessConfig, workspace: Path, reason: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True)),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)

        env = controller.abort_project(pid, reason)
        reloaded = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        ).inspect_project(pid)
        closeout = controller.store.mission_dir(pid, "mission-001") / "closeout.md"

        assert env.state.reason == reason  # type: ignore[union-attr]
        assert reloaded.state == env.state
        assert closeout.read_text().endswith(reason + "\n")
        assert len(env.state.reason.encode()) <= MAX_ABORT_REASON_BYTES  # type: ignore[union-attr]

    @pytest.mark.parametrize("active", (False, True), ids=("planning", "active"))
    @pytest.mark.parametrize(
        "reason",
        ("a" * (MAX_ABORT_REASON_BYTES + 1), "x" * 200_000),
        ids=("boundary-plus-one", "two-hundred-thousand"),
    )
    def test_oversized_abort_is_rejected_before_any_terminal_write(
        self, config: HarnessConfig, workspace: Path, active: bool, reason: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True)),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        if active:
            controller.submit_plan(pid, _simple_tl())
        state_path = controller.store.unrest_runtime_dir(pid) / "state.json"
        before = state_path.read_bytes()
        closeout = controller.store.mission_dir(pid, "mission-001") / "closeout.md"

        with pytest.raises(ToolError, match="4096 UTF-8 bytes") as exc_info:
            controller.abort_project(pid, reason)

        assert len(str(exc_info.value).encode()) < 256
        assert state_path.read_bytes() == before
        assert not closeout.exists()

    def test_abort_rejects_unencodable_unicode_before_writes(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True)),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        state_path = controller.store.unrest_runtime_dir(pid) / "state.json"
        before = state_path.read_bytes()

        with pytest.raises(ToolError, match="not valid Unicode"):
            controller.abort_project(pid, "\ud800")

        assert state_path.read_bytes() == before


class TestResume:
    def test_resume_picks_up_attempt_landed_while_down(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        store = controller.store
        controller.submit_plan(pid, _simple_tl())

        ts = store.load_task_state(pid, "mission-001")
        ts.set_status("w1", "running")
        ts.set_last_attempt("w1", "2026-01-01T00-00-00Z")
        store.save_task_state(pid, "mission-001", ts)
        store.save_attempt(
            pid,
            "mission-001",
            "2026-01-01T00-00-00Z",
            "w1",
            WorkHandoff(node_id="w1", done=True, report="landed"),
        )
        store.save_state(pid, MissionRunning(mission_id="mission-001"))
        controller.advance_project(pid)
        ts = store.load_task_state(pid, "mission-001")
        assert ts.status_of("w1") == "cleared"

    @pytest.mark.parametrize(
        "case",
        (
            "malformed_json",
            "wrong_task",
            "stale_generation",
            "replayed_success",
            "null_attempt_id",
            "missing_done",
        ),
    )
    def test_invalid_attempt_provenance_fails_closed_and_is_idempotent(
        self, config: HarnessConfig, workspace: Path, case: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True)),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "running")
        task_state.set_last_attempt("w1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        expected = store.attempt_path(pid, "mission-001", generation, "w1")
        expected.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "node_id": "w1",
            "attempt_id": generation,
            "done": True,
            "report": "must not be replayed",
            "request_attention": False,
        }
        if case == "malformed_json":
            expected.write_text("{")
        elif case == "wrong_task":
            payload["node_id"] = "other-task"
            expected.write_text(json.dumps(payload))
        elif case == "stale_generation":
            payload["attempt_id"] = "2026-08-09T12-00-00Z"
            expected.write_text(json.dumps(payload))
        elif case == "replayed_success":
            old = store.attempt_path(
                pid, "mission-001", "2026-08-09T12-00-00Z", "w1"
            )
            payload["attempt_id"] = "2026-08-09T12-00-00Z"
            old.write_text(json.dumps(payload))
        elif case == "null_attempt_id":
            payload["attempt_id"] = None
            expected.write_text(json.dumps(payload))
        else:
            payload.pop("done")
            expected.write_text(json.dumps(payload))

        restarted = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        )
        result = restarted.advance_project(pid, max_steps=1)

        assert result.state.state == "attention_needed"
        assert store.load_task_state(pid, "mission-001").status_of("w1") == "failed"
        attention = store.load_attention(pid)
        assert len(attention) == 1
        assert len(attention[0].report.encode()) < 4096
        observed = {
            "state": (store.unrest_runtime_dir(pid) / "state.json").read_bytes(),
            "tasks": (
                store.mission_runtime_dir(pid, "mission-001") / "task-state.json"
            ).read_bytes(),
            "attention": (
                store.unrest_runtime_dir(pid) / "attention.json"
            ).read_bytes(),
            "attempts": tuple(
                (path.name, path.read_bytes())
                for path in sorted(
                    store.attempts_runtime_dir(pid, "mission-001").glob("*.json")
                )
            ),
        }

        repeated = restarted.advance_project(pid, max_steps=1)
        assert repeated.state.state == "attention_needed"
        assert observed["state"] == (
            store.unrest_runtime_dir(pid) / "state.json"
        ).read_bytes()
        assert observed["tasks"] == (
            store.mission_runtime_dir(pid, "mission-001") / "task-state.json"
        ).read_bytes()
        assert observed["attention"] == (
            store.unrest_runtime_dir(pid) / "attention.json"
        ).read_bytes()
        assert observed["attempts"] == tuple(
            (path.name, path.read_bytes())
            for path in sorted(
                store.attempts_runtime_dir(pid, "mission-001").glob("*.json")
            )
        )

    def test_valid_current_generation_attempt_resumes_once(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True)),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "running")
        task_state.set_last_attempt("w1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        store.save_attempt(
            pid,
            "mission-001",
            generation,
            "w1",
            WorkHandoff(node_id="w1", done=True, report="current"),
        )

        restarted = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        )
        restarted.advance_project(pid, max_steps=1)
        attempts_before = tuple(store.list_attempts(pid, "mission-001", node_id="w1"))

        assert store.load_task_state(pid, "mission-001").status_of("w1") == "cleared"
        assert store.load_attention(pid) == []
        assert tuple(store.list_attempts(pid, "mission-001", node_id="w1")) == attempts_before

    def test_dispatched_explicit_null_attempt_id_fails_closed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id,
                    attempt_id=None,
                    done=True,
                    report="explicit null must not bind",
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())

        result = controller.advance_project(pid, max_steps=1)

        assert result.state.state == "attention_needed"
        attempt = controller.store.list_attempts(
            pid, "mission-001", node_id="w1"
        )[0]
        persisted = json.loads(attempt.path.read_text(encoding="utf-8"))
        assert persisted["done"] is False
        assert persisted["attempt_id"] == attempt.spawn_ts
        assert "null attempt identity" in persisted["report"]
