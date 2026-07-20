from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from zenith_harness.cli import cli
from zenith_harness.config import HarnessConfig
from zenith_harness.live import ProjectSelectionError, build_live_snapshot
from zenith_harness.models import (
    AttentionItemInternal,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    Done,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    WorkHandoff,
)
from zenith_harness.storage import ProjectStore


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "zenith_harness" / "bundled"
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


@pytest.fixture
def store(config: HarnessConfig) -> ProjectStore:
    return ProjectStore(config)


def _seed_project(
    store: ProjectStore,
    workspace: Path,
    *,
    project_id: str,
    state: object,
    task_status: str = "running",
    attention: bool = False,
) -> None:
    record = store.create_project("brief", workspace, project_id=project_id)
    record.current_mission_id = "mission-001"
    store.save_project(record)
    store.save_state(project_id, state)  # type: ignore[arg-type]

    task_list = TaskList(
        tasks=[
            Task(
                id="w1",
                type="work",
                body="implement",
                targets=["VAL-001"],
                skill="engineering-mission-playbook",
            ),
            Task(
                id="v1",
                type="validate",
                body="validate",
                targets=["VAL-001"],
                skill="user-testing-validator",
                depends_on=["w1"],
            ),
        ]
    )
    store.save_task_list(project_id, "mission-001", task_list)
    task_state_file = TaskStateFile()
    task_state_file.set_status("w1", task_status)  # type: ignore[arg-type]
    store.save_task_state(project_id, "mission-001", task_state_file)

    contract_dir = store.ensure_contract_dir(project_id, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nBody.\n", encoding="utf-8")
    store.save_contract_state(
        project_id,
        "mission-001",
        ContractStateFile(items={"VAL-001": ContractStateEntry(status="pending")}),
    )
    store.save_attempt(
        project_id,
        "mission-001",
        "2026-01-01T00-00-00Z",
        "w1",
        WorkHandoff(node_id="w1", done=True, report="ok"),
    )
    evidence_dir = store.mission_dir(project_id, "mission-001") / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "probe.txt").write_text("evidence\n", encoding="utf-8")
    store.append_decision_record(
        project_id,
        [Decision(item_id="att-1", action="continue")],
        [
            AttentionItemInternal(
                id="att-1",
                kind="gate_checkpoint",
                mission_id="mission-001",
                node_id="g1",
                report="gate",
            )
        ],
        summary="continue",
    )
    if attention:
        store.save_attention(
            project_id,
            [
                AttentionItemInternal(
                    id="att-2",
                    kind="node_attention",
                    mission_id="mission-001",
                    node_id="w1",
                    report=(
                        "Needs a product decision about whether the terminal review "
                        "gap should retry W1 or patch the task list."
                    ),
                )
            ],
        )


def _touch_project(store: ProjectStore, project_id: str, mtime: float) -> None:
    for path in store.bucket_root(project_id).rglob("*"):
        if path.is_file():
            os.utime(path, (mtime, mtime))


def _file_mtimes(root: Path) -> dict[Path, int]:
    return {path: path.stat().st_mtime_ns for path in root.rglob("*") if path.is_file()}


def test_snapshot_discovers_multiple_projects_and_selects_newest_active(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    tmp_path: Path,
) -> None:
    ws2 = tmp_path / "workspace-2"
    ws2.mkdir()
    ws3 = tmp_path / "workspace-3"
    ws3.mkdir()
    _seed_project(
        store,
        workspace,
        project_id="active-old",
        state=MissionRunning(mission_id="mission-001"),
    )
    _seed_project(
        store,
        ws2,
        project_id="active-new",
        state=MissionRunning(mission_id="mission-001"),
        attention=True,
    )
    _seed_project(
        store,
        ws3,
        project_id="terminal-newer",
        state=Done(),
        task_status="cleared",
    )
    _touch_project(store, "active-old", 100)
    _touch_project(store, "active-new", 200)
    _touch_project(store, "terminal-newer", 300)

    snapshot = build_live_snapshot(config=config)

    assert {project.id for project in snapshot.projects} == {
        "active-old",
        "active-new",
        "terminal-newer",
    }
    assert snapshot.selected_project_id == "active-new"
    selected = next(project for project in snapshot.projects if project.id == "active-new")
    assert selected.workspace == str(ws2)
    assert selected.state == "mission_running"
    assert selected.current_mission_id == "mission-001"
    assert selected.attention_count == 1
    assert selected.attention_items[0].id == "att-2"
    assert selected.attention_items[0].kind == "node_attention"
    assert selected.attention_items[0].mission_id == "mission-001"
    assert selected.attention_items[0].node_id == "w1"
    assert "terminal review gap" in selected.attention_items[0].report

    pinned = build_live_snapshot(config=config, project="terminal-newer")
    assert pinned.selected_project_id == "terminal-newer"


def test_snapshot_contains_counts_recent_activity_and_partial_projects(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    tmp_path: Path,
) -> None:
    _seed_project(
        store,
        workspace,
        project_id="complete",
        state=MissionRunning(mission_id="mission-001"),
    )
    partial_ws = tmp_path / "partial-workspace"
    partial_ws.mkdir()
    store.create_project("partial", partial_ws, project_id="partial")

    snapshot = build_live_snapshot(config=config)
    complete = next(project for project in snapshot.projects if project.id == "complete")
    partial = next(project for project in snapshot.projects if project.id == "partial")

    assert partial.mission is None
    assert complete.mission is not None
    assert complete.mission.task_count == 2
    assert complete.mission.task_type_counts["work"] == 1
    assert complete.mission.task_state_counts["running"] == 1
    assert complete.mission.task_state_counts["pending"] == 1
    assert complete.mission.contract_count == 1
    assert complete.mission.contract_state_counts["pending"] == 1
    assert complete.mission.recent_attempts[0].node_id == "w1"
    assert complete.mission.recent_evidence[0].name == "probe.txt"
    assert complete.recent_decisions[0].name.endswith(".md")


def test_cli_json_is_parseable_and_supports_project_path_pin(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    tmp_path: Path,
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _seed_project(
        store,
        workspace,
        project_id="pinned",
        state=MissionRunning(mission_id="mission-001"),
    )
    _seed_project(
        store,
        other,
        project_id="newer",
        state=MissionRunning(mission_id="mission-001"),
    )
    _touch_project(store, "pinned", 100)
    _touch_project(store, "newer", 200)

    result = CliRunner().invoke(
        cli,
        [
            "live",
            "--once",
            "--json",
            "--projects-dir",
            str(config.projects_dir),
            "--project",
            str(store.bucket_root("pinned") / ".zenith-runtime" / "project.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["projects_dir"] == str(config.projects_dir)
    assert parsed["selected_project_id"] == "pinned"
    assert parsed["project_count"] == 2
    assert {project["id"] for project in parsed["projects"]} == {"pinned", "newer"}
    assert parsed["projects"][0]["mission"]["task_state_counts"]["running"] >= 1


def test_cli_shows_attention_details_in_json_and_human_output(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
) -> None:
    _seed_project(
        store,
        workspace,
        project_id="attention-project",
        state=MissionRunning(mission_id="mission-001"),
        attention=True,
    )

    json_result = CliRunner().invoke(
        cli,
        [
            "live",
            "--once",
            "--json",
            "--projects-dir",
            str(config.projects_dir),
            "--project",
            "attention-project",
        ],
    )
    human_result = CliRunner().invoke(
        cli,
        [
            "live",
            "--once",
            "--projects-dir",
            str(config.projects_dir),
            "--project",
            "attention-project",
        ],
    )

    assert json_result.exit_code == 0, json_result.output
    assert human_result.exit_code == 0, human_result.output
    parsed = json.loads(json_result.output)
    project = parsed["projects"][0]
    attention = project["attention_items"][0]
    assert project["attention_count"] == 1
    assert attention == {
        "id": "att-2",
        "report": (
            "Needs a product decision about whether the terminal review gap "
            "should retry W1 or patch the task list."
        ),
        "kind": "node_attention",
        "mission_id": "mission-001",
        "node_id": "w1",
    }
    assert "att-2 (node_attention, mission=mission-001, node=w1)" in human_result.output
    assert "terminal review gap should retry W1" in human_result.output


def test_cli_human_empty_projects_dir_has_zero_exit(tmp_path: Path) -> None:
    projects_dir = tmp_path / "does-not-exist"

    result = CliRunner().invoke(cli, ["live", "--once", "--projects-dir", str(projects_dir)])

    assert result.exit_code == 0, result.output
    assert "No Zenith projects found" in result.output


def test_live_cli_does_not_mutate_project_files(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
) -> None:
    _seed_project(
        store,
        workspace,
        project_id="readonly",
        state=MissionRunning(mission_id="mission-001"),
    )
    before = _file_mtimes(config.projects_dir)

    human = CliRunner().invoke(
        cli, ["live", "--once", "--projects-dir", str(config.projects_dir)]
    )
    json_result = CliRunner().invoke(
        cli, ["live", "--once", "--json", "--projects-dir", str(config.projects_dir)]
    )

    assert human.exit_code == 0, human.output
    assert json_result.exit_code == 0, json_result.output
    assert _file_mtimes(config.projects_dir) == before


def test_workspace_path_pin_is_ambiguous_for_same_workspace_projects(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
) -> None:
    _seed_project(
        store,
        workspace,
        project_id="same-a",
        state=MissionRunning(mission_id="mission-001"),
    )
    _seed_project(
        store,
        workspace,
        project_id="same-b",
        state=MissionRunning(mission_id="mission-001"),
    )

    with pytest.raises(ProjectSelectionError):
        build_live_snapshot(config=config, project=str(workspace))
