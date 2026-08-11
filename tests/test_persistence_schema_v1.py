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
    assert manifest["mission_oracle"] == (
        ".unrest/missions/mission-001/oracles/persistence-schema-v1/corpus.json"
    )
    assert manifest["oracle_sha256"] == (
        "01e3d203a2fe78fe90390febc7fbf6d6834f648f83a6411c59c48bc60a6b5d6e"
    )
    assert manifest["scenarios"] == [
        "planning",
        "running",
        "attention",
        "quiescent",
        "done",
        "failed",
        "aborted",
    ]
    assert manifest["files"] == {
        "corpus.json": hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    }
    assert manifest["oracle_sha256"] == manifest["files"]["corpus.json"]


@pytest.mark.parametrize(
    ("scenario", "expected_state", "expected_task_status"),
    (
        ("planning", "mission_planning", None),
        ("running", "mission_running", "cleared"),
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
            task_status = controller.store.load_task_state(
                "fixture", "mission-001"
            ).status_of("w1")
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
