"""Frozen fixed-reference schema-v1/legacy restart compatibility matrix."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "persistence_schema_v1"
CORPUS_PATH = FIXTURE_DIR / "corpus.json"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
TRANSCRIPT_PATH = FIXTURE_DIR / "generation-transcript.json"


def _config(home: Path) -> HarnessConfig:
    bundled = Path(__file__).parents[1] / "src" / "unrest_harness" / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=1,
    )


def _materialize(
    root: Path, workspace: Path, files: dict[str, object]
) -> ProjectController:
    bucket = root / "projects" / "fixture"
    for relative, payload in sorted(files.items()):
        target = bucket / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, str):
            target.write_text(payload, encoding="utf-8")
        else:
            materialized = json.loads(
                json.dumps(payload).replace("__WORKSPACE__", str(workspace))
            )
            target.write_text(
                json.dumps(materialized, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    dispatcher = MockDispatcher(
        lambda request: WorkHandoff(
            node_id=request.task.id, done=True, report="unexpected dispatch"
        )
    )
    return ProjectController(
        _config(root),
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )


def _inventory(root: Path) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def test_frozen_fixture_hash_and_candidate_binding() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["reference_oracle"]["path"] == (
        ".unrest/missions/mission-001/oracles/persistence-schema-v1/corpus.json"
    )
    assert manifest["reference_oracle"]["sha256"] == (
        "01e3d203a2fe78fe90390febc7fbf6d6834f648f83a6411c59c48bc60a6b5d6e"
    )
    assert manifest["scenarios"] == [
        "planning",
        "running",
        "running_validation",
        "attention",
        "quiescent",
        "done",
        "failed",
        "aborted",
    ]
    assert manifest["files"] == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(FIXTURE_DIR.iterdir())
        if path.name != "manifest.json"
    }
    assert manifest["handoff_provenance"] == {
        "source_reference": "93c59e4378407f3d7cfb918cf86c8bdc81daa141",
        "source_tree": "35152a4a8c56198664f519691ec952ec9ca519f4",
        "work_schema": "src/unrest_harness/models.py:WorkHandoff",
        "validation_schema": "src/unrest_harness/models.py:ValidateHandoff",
        "producer": "src/unrest_harness/server.py:create_worker_server/end_node",
        "identity_member_at_source": "absent",
        "generator": "tools/generate_legacy_handoff_fixtures.py",
        "generator_sha256": hashlib.sha256(
            (Path(__file__).parents[1] / "tools/generate_legacy_handoff_fixtures.py").read_bytes()
        ).hexdigest(),
        "generation_transcript": "generation-transcript.json",
        "models_source_sha256": (
            "812a62fd41170f1b4d7307cfd731b329f194165325d67f6d1a101061e73596e5"
        ),
        "server_source_sha256": (
            "e21bcbebad4d551facdb59b3b968fa2cac7c3c5ae5bd4a990832a38acc6af9b8"
        ),
    }
    transcript = json.loads(TRANSCRIPT_PATH.read_text(encoding="utf-8"))
    assert transcript["reference"] == {
        "commit": manifest["handoff_provenance"]["source_reference"],
        "tree": manifest["handoff_provenance"]["source_tree"],
        "tracked_status": "clean",
        "models_path": "src/unrest_harness/models.py",
        "producer_path": manifest["handoff_provenance"]["producer"],
    }
    assert transcript["outputs"] == {
        filename: {
            "bytes": (path := FIXTURE_DIR / filename).stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for filename in ("legacy-work-handoff.json", "legacy-validation-handoff.json")
    }


@pytest.mark.parametrize(
    ("scenario", "expected_state", "expected_task_status"),
    (
        ("planning", "mission_planning", None),
        ("running", "mission_running", "cleared"),
        ("running_validation", "mission_running", "cleared"),
        ("attention", "attention_needed", None),
        ("quiescent", "mission_running", "cleared"),
        ("done", "done", None),
        ("failed", "failed", None),
        ("aborted", "aborted", None),
    ),
)
def test_fixed_reference_load_restart_resume_matrix_is_repeatable(
    tmp_path: Path,
    scenario: str,
    expected_state: str,
    expected_task_status: str | None,
) -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert corpus["schema_version"] == 1
    outcomes: list[tuple[str, str | None, int, tuple[tuple[str, bytes], ...]]] = []
    for run in range(2):
        root = tmp_path / f"run-{run}"
        workspace = tmp_path / f"workspace-{run}"
        workspace.mkdir()
        controller = _materialize(root, workspace, corpus["scenarios"][scenario])

        before = controller.store.load_state("fixture")
        assert before is not None
        result = controller.advance_project("fixture", max_steps=1)
        task_status = None
        if expected_task_status is not None:
            task_id = "v1" if scenario == "running_validation" else "w1"
            task_status = controller.store.load_task_state(
                "fixture", "mission-001"
            ).status_of(task_id)
        outcomes.append(
            (
                result.state.state,
                task_status,
                len(controller.dispatcher.calls),  # type: ignore[attr-defined]
                _inventory(root),
            )
        )

    assert [(state, status, calls) for state, status, calls, _ in outcomes] == [
        (expected_state, expected_task_status, 0),
        (expected_state, expected_task_status, 0),
    ]
    normalized = [
        tuple(
            (path, data.replace(str(tmp_path / f"workspace-{run}").encode(), b"__WORKSPACE__"))
            for path, data in inventory
        )
        for run, (*_, inventory) in enumerate(outcomes)
    ]
    assert normalized[0] == normalized[1]


@pytest.mark.parametrize(
    ("scenario", "task_id", "fixture_name"),
    (
        ("running", "w1", "legacy-work-handoff.json"),
        ("running_validation", "v1", "legacy-validation-handoff.json"),
    ),
    ids=("legacy-work", "legacy-validation"),
)
def test_absent_member_handoffs_bind_once_across_two_restarts_without_rewrite(
    tmp_path: Path, scenario: str, task_id: str, fixture_name: str
) -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    root = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = _materialize(root, workspace, corpus["scenarios"][scenario])
    generation = "2026-08-10T12-00-00Z"
    attempt_path = first.store.attempt_path(
        "fixture", "mission-001", generation, task_id
    )
    fixture_bytes = (FIXTURE_DIR / fixture_name).read_bytes()
    attempt_path.write_bytes(fixture_bytes)
    before_bytes = attempt_path.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()
    assert "attempt_id" not in json.loads(before_bytes)

    first_result = first.advance_project("fixture", max_steps=1)
    after_first = _inventory(root)
    second = ProjectController(
        _config(root), first.dispatcher, first.terminal_reviewer
    )
    second_result = second.advance_project("fixture", max_steps=1)

    assert first_result.state.state == "mission_running"
    assert second_result.state.state == "mission_running"
    assert second.store.load_task_state(
        "fixture", "mission-001"
    ).status_of(task_id) == "cleared"
    assert len(second.dispatcher.calls) == 0  # type: ignore[attr-defined]
    assert attempt_path.read_bytes() == before_bytes
    assert attempt_path.read_bytes() == fixture_bytes
    assert hashlib.sha256(attempt_path.read_bytes()).hexdigest() == before_hash
    assert _inventory(root) == after_first


@pytest.mark.parametrize(
    "mutation",
    (
        b"{",
        b'{"state":"unsupported_future"}\n',
        b'{"state":"done","schema_version":2}\n',
    ),
    ids=("malformed", "unsupported-state", "future-version"),
)
def test_state_mutations_fail_closed_without_rewrite(
    tmp_path: Path, mutation: bytes
) -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = _materialize(
        tmp_path / "home", workspace, corpus["scenarios"]["done"]
    )
    state_path = controller.store.unrest_runtime_dir("fixture") / "state.json"
    state_path.write_bytes(mutation)

    with pytest.raises((ValidationError, ValueError)) as exc_info:
        controller.inspect_project("fixture")

    assert len(str(exc_info.value).encode()) < 4096
    assert state_path.read_bytes() == mutation
