from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

from click.testing import CliRunner
import pytest

from unrest_harness import api
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.evolution import CampaignFreeze, EvolutionManager
from unrest_harness.improve_adapter import (
    ImprovementAdapterError,
    ImprovementRequest,
    run_improvement as run_improvement_direct,
)
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff
from unrest_harness.project_adapter import (
    ProjectAdapterError,
    ProjectDag,
    ProjectNode,
    run_project as run_project_direct,
)
from unrest_harness.task_adapter import (
    TaskAdapterError,
    TaskBounds,
    TaskRequest,
    run_task as run_task_direct,
)
from unrest_harness.workspaces import ResourceBudget, WorkspaceManager


BASE = "545ff97ef5cdab01859a0b56d9352c4715bdcabf"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(root: Path, label: str) -> Path:
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "ACT-190 Activation")
    _git(root, "config", "user.email", "act190@example.test")
    (root / "README.md").write_text(label + "\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", "base")
    return root


def _config(home: Path, *, parallelism: int = 2) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled",
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=parallelism,
    )


class _TaskLifecycle:
    def __init__(self) -> None:
        self.effects = 0
        self.state = "open"

    def _record(self) -> dict[str, object]:
        return {
            "branch_outcomes": {
                "analysis": "answered" if self.state == "answered" else "pending"
            },
            "inquiry_id": "inquiry:activation",
            "receipt_id": "receipt:activation" if self.state == "answered" else None,
            "state": self.state,
        }

    def open_inquiry(
        self,
        question: str,
        budget: Mapping[str, int],
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Mapping[str, object]:
        self.effects += 1
        assert question and budget and idempotency_key and project_id is None
        return self._record()

    async def advance_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        self.effects += 1
        assert inquiry_id == "inquiry:activation" and idempotency_key
        self.state = "answered"
        return self._record()

    def pause_inquiry(
        self,
        inquiry_id: str,
        reason: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        raise AssertionError("unused")

    def resume_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        raise AssertionError("unused")

    def handoff_inquiry(
        self,
        inquiry_id: str,
        consumer_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        self.effects += 1
        return {
            "consumer_id": consumer_id,
            "handoff_id": "handoff:activation",
            "inquiry_id": inquiry_id,
            "receipt_id": "receipt:activation",
        }

    def inspect_inquiry(self, inquiry_id: str) -> Mapping[str, object]:
        self.effects += 1
        assert inquiry_id == "inquiry:activation"
        return self._record()


@pytest.mark.asyncio
async def test_task_direct_and_api_carriers_match_and_are_private() -> None:
    brief = "private activation brief"
    key = "private-idempotency-key"
    request = TaskRequest(brief, TaskBounds(2, 30), key)
    direct_lifecycle = _TaskLifecycle()
    api_lifecycle = _TaskLifecycle()

    direct = await run_task_direct(direct_lifecycle, request)
    carried = await api.run_task(request, lifecycle=api_lifecycle)

    assert direct.canonical_bytes() == carried.canonical_bytes()
    assert direct_lifecycle.effects == api_lifecycle.effects == 4
    assert direct.terminal == "completed"
    assert brief.encode() not in direct.canonical_bytes()
    assert key.encode() not in direct.canonical_bytes()
    assert _canonical(json.loads(direct.canonical_bytes())) == direct.canonical_bytes()


def test_task_validation_precedes_effect() -> None:
    lifecycle = _TaskLifecycle()
    with pytest.raises(TaskAdapterError) as caught:
        TaskRequest("private", TaskBounds(1, 1), "")
    assert caught.value.code == "invalid_argument"
    assert lifecycle.effects == 0


def _project() -> ProjectDag:
    return ProjectDag(
        (
            ProjectNode(
                "join",
                "Join private leaf results.",
                needs=("leaf-b", "leaf-a"),
                writes=("result/join.txt",),
                result_path="result/join.txt",
                targets=("VAL-ACT190",),
            ),
            ProjectNode(
                "leaf-b",
                "Produce B privately.",
                writes=("result/b.txt",),
                result_path="result/b.txt",
            ),
            ProjectNode(
                "leaf-a",
                "Produce A privately.",
                writes=("result/a.txt",),
                result_path="result/a.txt",
            ),
        )
    )


def _project_runtime(
    tmp_path: Path,
    label: str,
    *,
    clear: bool = False,
) -> tuple[MissionCoordinator, str, str, ProjectDag, Path, int]:
    repository = _repository(tmp_path / f"repo-{label}", label)
    project = _project()
    effects = {"count": 0}

    def respond(request: Any) -> WorkHandoff:
        effects["count"] += 1
        root = Path(request.cwd or repository)
        if request.task.id == "leaf-a":
            target, content = root / "result/a.txt", "A\n"
        elif request.task.id == "leaf-b":
            target, content = root / "result/b.txt", "B\n"
        else:
            target = root / "result/join.txt"
            content = "A+B\n"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return WorkHandoff(node_id=request.task.id, done=True, report="private report")

    dispatcher = MockDispatcher(respond)
    dispatcher.supports_isolated_workspaces = True
    controller = ProjectController(
        _config(tmp_path / f"home-{label}"),
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    envelope = controller.start_project("private project brief", str(repository))
    project_id = envelope.projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-ACT190.md").write_text("# VAL-ACT190\n\nActivation.\n")
    controller.submit_plan(project_id, project.task_list())
    if clear:
        state = controller.store.load_task_state(project_id, "mission-001")
        for node in project.ordered_nodes():
            state.set_status(node.id, "cleared")
            if node.result_path is not None:
                target = repository / node.result_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(node.id + "\n", encoding="utf-8")
        controller.store.save_task_state(project_id, "mission-001", state)
    coordinator = MissionCoordinator(
        controller.store,
        project_id,
        dispatcher,
        controller.terminal_reviewer,
    )
    return coordinator, project_id, "mission-001", project, repository, effects["count"]


def test_project_direct_and_api_carriers_preserve_topology_and_state(tmp_path: Path) -> None:
    direct_runtime = _project_runtime(tmp_path, "direct")
    api_runtime = _project_runtime(tmp_path, "api")
    direct = run_project_direct(direct_runtime[0], direct_runtime[2], direct_runtime[3], max_steps=3)
    carried = api.run_project(api_runtime[0], api_runtime[2], api_runtime[3], max_steps=3)

    assert direct.status == carried.status == "completed"
    assert direct.ready_order == carried.ready_order
    assert direct.ready_order[0] == ("leaf-a", "leaf-b")
    assert direct.ready_order[-1] == ("join",)
    assert direct.dispatch_batches == carried.dispatch_batches
    assert [node.id for node in carried.nodes] == ["leaf-a", "leaf-b", "join"]
    assert _canonical(json.loads(carried.canonical_bytes())) + b"\n" == carried.canonical_bytes()
    assert b"private" not in carried.canonical_bytes()


def test_project_invalid_bound_precedes_store_effect() -> None:
    class Store:
        effects = 0

        def load_task_list(self, *_args: object) -> None:
            self.effects += 1

    class Coordinator:
        store = Store()
        project_id = "project:invalid"

    coordinator = Coordinator()
    with pytest.raises(ProjectAdapterError, match="invalid_step_bound"):
        api.run_project(coordinator, "mission-001", _project(), max_steps=0)
    assert coordinator.store.effects == 0


def _sha(character: str) -> str:
    return "sha256:" + character * 64


def _freeze(repository: Path) -> CampaignFreeze:
    return CampaignFreeze(
        accepted_revision=_git(repository, "rev-parse", "HEAD"),
        accepted_working_point_digest=_sha("a"),
        workload_digest=_sha("b"),
        oracle_digest=_sha("c"),
        author_policy_digest=_sha("d"),
        evaluator_policy_digest=_sha("e"),
        reviewer_policy_digest=_sha("f"),
        capability_policy_digest=_sha("1"),
        provider_configuration_digest=_sha("2"),
        route_profile_digest=_sha("3"),
        context_digest=_sha("4"),
        environment_digest=_sha("5"),
        secret_set_version_id="secret-set:activation:v1",
        author_id="worker:activation-author",
        evaluator_id="validator:activation-evaluator",
        reviewer_id="reviewer:activation-reviewer",
        budget_steps=20,
        seed=190,
        stopping_rule_digest=_sha("6"),
        promotion_rule_digest=_sha("7"),
        protected_paths=(".git", ".unrest", ".unrest-runtime"),
    )


def _improvement_runtime(
    tmp_path: Path,
    label: str,
    *,
    provider: object | None = None,
) -> tuple[Path, EvolutionManager, ImprovementRequest]:
    repository = _repository(tmp_path / f"improve-{label}", label)
    workspace = WorkspaceManager(repository)
    manager = EvolutionManager(
        repository,
        provider_runner=provider,
        workspace_manager=workspace,
    )
    freeze = _freeze(repository)
    lease = workspace.lease_workspace(
        base_revision=freeze.accepted_revision,
        owner_id=freeze.author_id,
        declared_write_paths=("candidate.txt",),
        capability_policy_digest=freeze.capability_policy_digest,
        duration_seconds=600,
        lease_id=f"lease:activation-{label}",
        resource_budget=ResourceBudget(max_patch_bytes=100_000),
    )
    Path(lease.worktree_path, "candidate.txt").write_text(
        "private candidate source token\n",
        encoding="utf-8",
    )
    workspace.return_workspace(lease.lease_id)
    request = ImprovementRequest(
        campaign_id=f"campaign:activation-{label}",
        freeze=freeze,
        lease_id=lease.lease_id,
        candidate_id=f"candidate:activation-{label}",
        action="original",
        author_id=freeze.author_id,
        evaluation_id=f"evaluation:activation-{label}",
        review_id=f"review:activation-{label}",
    )
    return repository, manager, request


@pytest.mark.asyncio
async def test_improvement_direct_and_api_carriers_stop_private_and_provider_free(
    tmp_path: Path,
) -> None:
    repository, manager, request = _improvement_runtime(tmp_path, "parity")
    direct = await run_improvement_direct(manager, request)
    sequence = manager.inspect_campaign(request.campaign_id).sequence
    carried = await api.run_improvement(EvolutionManager(repository), request)

    assert direct.to_json_bytes() == carried.to_json_bytes()
    assert carried.stage == "reviewed"
    assert carried.campaign_state == "decision_needed"
    assert carried.provider_effect_count == carried.later_decision_action_count == 0
    assert manager.inspect_campaign(request.campaign_id).sequence == sequence
    assert b"private candidate source token" not in carried.to_json_bytes()
    assert _canonical(json.loads(carried.to_json_bytes())) + b"\n" == carried.to_json_bytes()


@pytest.mark.asyncio
async def test_improvement_invalid_and_provider_reject_before_campaign_effect(tmp_path: Path) -> None:
    repository, manager, request = _improvement_runtime(tmp_path, "invalid")
    invalid = replace(request, candidate_cost_steps=-1)
    with pytest.raises(ImprovementAdapterError, match="invalid_argument"):
        await api.run_improvement(manager, invalid)
    assert not any((repository / ".unrest" / "evolution" / "campaigns").iterdir())

    class Provider:
        requests: list[object] = []

    provider_repository, provider_manager, provider_request = _improvement_runtime(
        tmp_path,
        "provider",
        provider=Provider(),
    )
    with pytest.raises(ImprovementAdapterError, match="provider_runner_configured"):
        await api.run_improvement(provider_manager, provider_request)
    assert not any(
        (provider_repository / ".unrest" / "evolution" / "campaigns").iterdir()
    )
    assert provider_manager.provider_runner.requests == []


def _project_cli_document(project_id: str, mission_id: str, project: ProjectDag) -> dict[str, object]:
    return {
        "max_steps": 2,
        "mission_id": mission_id,
        "nodes": [
            {
                "auto_merge": node.auto_merge,
                "body": node.body,
                "id": node.id,
                "needs": list(node.needs),
                "result_path": node.result_path,
                "skill": node.skill,
                "targets": list(node.targets),
                "writes": list(node.writes),
            }
            for node in project.nodes
        ],
        "project_id": project_id,
    }


def _improvement_cli_document(repository: Path, request: ImprovementRequest) -> dict[str, object]:
    return {
        "repository": str(repository),
        "request": {
            **asdict(request),
            "candidate_dissent_digests": list(request.candidate_dissent_digests),
            "freeze": asdict(request.freeze),
        },
    }


def _subprocess_cli(
    request_path: Path,
    command: str,
    *,
    home: Path,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["UNREST_HOME"] = str(home)
    environment["UNREST_PROJECTS_DIR"] = str(home / "projects")
    return subprocess.run(
        ["uv", "run", "unrest", command, "--request", str(request_path)],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        check=False,
    )


def test_click_commands_reject_invalid_input_before_runtime_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    effects = {"task": 0, "project": 0, "improvement": 0}

    async def unexpected_task(*_args: object, **_kwargs: object) -> None:
        effects["task"] += 1

    def unexpected_project(*_args: object, **_kwargs: object) -> None:
        effects["project"] += 1

    class UnexpectedManager:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            effects["improvement"] += 1

    import unrest_harness.evolution as evolution

    monkeypatch.setattr(api, "run_task", unexpected_task)
    monkeypatch.setattr("unrest_harness.cli._project_adapter_coordinator", unexpected_project)
    monkeypatch.setattr(evolution, "EvolutionManager", UnexpectedManager)

    invalid_task = tmp_path / "invalid-task.json"
    invalid_project = tmp_path / "invalid-project.json"
    invalid_improvement = tmp_path / "invalid-improvement.json"
    _write_json(invalid_task, {"brief": "private"})
    _write_json(
        invalid_project,
        {
            "max_steps": 1,
            "mission_id": "mission-001",
            "nodes": [{"body": "private", "id": "a", "needs": ["missing"]}],
            "project_id": "project:private",
        },
    )
    _write_json(
        invalid_improvement,
        {"repository": str(tmp_path), "request": {"private": "secret"}},
    )

    for command, path in (
        ("run-task", invalid_task),
        ("run-project", invalid_project),
        ("run-improvement", invalid_improvement),
    ):
        result = runner.invoke(cli, [command, "--request", str(path)])
        assert result.exit_code != 0
        assert "private" not in result.output
        assert "secret" not in result.output
    assert effects == {"task": 0, "project": 0, "improvement": 0}


def test_subprocess_commands_reject_private_invalid_requests_without_effect(
    tmp_path: Path,
) -> None:
    private = "private-subprocess-invalid-token"
    improvement_repository = tmp_path / "invalid-improvement-repository"
    improvement_repository.mkdir()
    requests = {
        "run-task": {"brief": private},
        "run-project": {
            "max_steps": 1,
            "mission_id": "mission-001",
            "nodes": [{"body": private, "id": "node", "needs": ["missing"]}],
            "project_id": "project:invalid",
        },
        "run-improvement": {
            "repository": str(improvement_repository),
            "request": {"private": private},
        },
    }
    for command, document in requests.items():
        request_path = tmp_path / f"{command}-invalid.json"
        home = tmp_path / f"{command}-invalid-home"
        _write_json(request_path, document)
        process = _subprocess_cli(request_path, command, home=home)
        assert process.returncode != 0
        assert private.encode() not in process.stdout + process.stderr
        assert not home.exists()
    assert not (improvement_repository / ".unrest").exists()


def test_task_click_and_subprocess_are_canonical_and_private(tmp_path: Path) -> None:
    request = tmp_path / "task.json"
    brief = "private cli task brief"
    key = "private-cli-idempotency"
    pause = "private-pause-secret"
    _write_json(
        request,
        {
            "bounds": {"max_branches": 1, "max_steps": 1, "timeout_seconds": 30},
            "brief": brief,
            "idempotency_key": key,
            "pause_reason": pause,
        },
    )
    home = tmp_path / "task-home"
    result = CliRunner().invoke(
        cli,
        ["run-task", "--request", str(request)],
        env={"UNREST_HOME": str(home), "UNREST_PROJECTS_DIR": str(home / "projects")},
    )
    assert result.exit_code == 0, result.output
    content = result.stdout_bytes.removesuffix(b"\n")
    assert _canonical(json.loads(content)) == content
    assert json.loads(content)["terminal"] == "paused"
    assert all(secret.encode() not in content for secret in (brief, key, pause))

    subprocess_request = tmp_path / "task-subprocess.json"
    subprocess_request.write_bytes(request.read_bytes())
    process = _subprocess_cli(
        subprocess_request,
        "run-task",
        home=tmp_path / "task-subprocess-home",
    )
    assert process.returncode == 0, process.stderr.decode()
    subprocess_content = process.stdout.removesuffix(b"\n")
    assert _canonical(json.loads(subprocess_content)) == subprocess_content
    assert all(secret.encode() not in process.stdout for secret in (brief, key, pause))


def test_project_click_and_subprocess_preserve_exact_topology(tmp_path: Path) -> None:
    runtime = _project_runtime(tmp_path, "click", clear=True)
    request = tmp_path / "project.json"
    _write_json(request, _project_cli_document(runtime[1], runtime[2], runtime[3]))
    home = tmp_path / "home-click"
    result = CliRunner().invoke(
        cli,
        ["run-project", "--request", str(request)],
        env={"UNREST_HOME": str(home), "UNREST_PROJECTS_DIR": str(home / "projects")},
    )
    assert result.exit_code == 0, result.output
    content = result.stdout_bytes.removesuffix(b"\n")
    payload = json.loads(content)
    assert _canonical(payload) == content
    assert payload["status"] == "completed"
    assert [node["id"] for node in payload["nodes"]] == ["leaf-a", "leaf-b", "join"]
    assert b"private" not in content

    subprocess_runtime = _project_runtime(tmp_path, "subprocess", clear=True)
    subprocess_request = tmp_path / "project-subprocess.json"
    _write_json(
        subprocess_request,
        _project_cli_document(
            subprocess_runtime[1],
            subprocess_runtime[2],
            subprocess_runtime[3],
        ),
    )
    process = _subprocess_cli(
        subprocess_request,
        "run-project",
        home=tmp_path / "home-subprocess",
    )
    assert process.returncode == 0, process.stderr.decode()
    subprocess_payload = json.loads(process.stdout)
    assert subprocess_payload["status"] == "completed"
    assert [node["id"] for node in subprocess_payload["nodes"]] == [
        "leaf-a",
        "leaf-b",
        "join",
    ]


def test_improvement_click_and_subprocess_stop_at_review_without_disclosure(
    tmp_path: Path,
) -> None:
    repository, _manager, request = _improvement_runtime(tmp_path, "click-cli")
    request_path = tmp_path / "improvement.json"
    _write_json(request_path, _improvement_cli_document(repository, request))
    result = CliRunner().invoke(cli, ["run-improvement", "--request", str(request_path)])
    assert result.exit_code == 0, result.output
    content = result.stdout_bytes.removesuffix(b"\n")
    payload = json.loads(content)
    assert _canonical(payload) == content
    assert (payload["stage"], payload["campaign_state"]) == ("reviewed", "decision_needed")
    assert payload["effects"] == {
        "external": 0,
        "later_decision_action": 0,
        "network": 0,
        "provider": 0,
    }
    assert b"private candidate source token" not in content

    subprocess_repository, _subprocess_manager, subprocess_request = _improvement_runtime(
        tmp_path,
        "subprocess-cli",
    )
    subprocess_path = tmp_path / "improvement-subprocess.json"
    _write_json(
        subprocess_path,
        _improvement_cli_document(subprocess_repository, subprocess_request),
    )
    process = _subprocess_cli(
        subprocess_path,
        "run-improvement",
        home=tmp_path / "unused-improvement-home",
    )
    assert process.returncode == 0, process.stderr.decode()
    subprocess_payload = json.loads(process.stdout)
    assert (subprocess_payload["stage"], subprocess_payload["campaign_state"]) == (
        "reviewed",
        "decision_needed",
    )
    assert b"private candidate source token" not in process.stdout


def test_v031_catalog_oracle_and_unowned_carriers_are_unchanged() -> None:
    root = Path(__file__).resolve().parents[1]
    catalog = root / "src" / "unrest_harness" / "bundled" / "foundation" / "public-surface.v1.json"
    accepted_catalog = subprocess.run(
        ["git", "show", f"{BASE}:src/unrest_harness/bundled/foundation/public-surface.v1.json"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    assert catalog.read_bytes() == accepted_catalog
    subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            BASE,
            "--",
            "src/unrest_harness/server.py",
            "src/unrest_harness/foundation_tools.py",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    assert callable(api.run_task)
    assert callable(api.run_project)
    assert callable(api.run_improvement)
    assert not {"run_task", "run_project", "run_improvement"} & set(api.__all__)
