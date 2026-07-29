"""Batch 0 characterization baseline.

The checked-in artifacts deliberately describe the approved legacy commit.
Known defects are evidence for later repairs, never repaired-behavior oracles.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from unrest_harness.baseline import (
    BASE_SHA,
    CLASSIFICATIONS,
    GENERATED_FILENAMES,
    KICKOFF_RECORD,
    check_baseline,
    generate_baseline,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASELINE_ROOT = REPOSITORY_ROOT / "evals" / "baseline"


def _json_fixture(name: str) -> dict[str, Any]:
    return json.loads(
        (BASELINE_ROOT / "fixtures" / name).read_text(encoding="utf-8")
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_files(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    )


def test_forward_reverse_generation_is_byte_identical_without_locking_defects(
    tmp_path: Path,
) -> None:
    forward = tmp_path / "forward"
    reverse = tmp_path / "reverse"

    generate_baseline(forward, input_order="forward")
    generate_baseline(reverse, input_order="reverse")

    assert _relative_files(forward) == list(GENERATED_FILENAMES)
    assert _relative_files(reverse) == list(GENERATED_FILENAMES)
    for relative_path in GENERATED_FILENAMES:
        assert (forward / relative_path).read_bytes() == (
            reverse / relative_path
        ).read_bytes()

    manifest = yaml.safe_load(
        (BASELINE_ROOT / "manifest.yaml").read_text(encoding="utf-8")
    )
    intended_paths = {
        row["path"]
        for row in manifest["fixtures"]
        if row["classification"] == "intended"
    }
    for relative_path in intended_paths:
        assert (forward / relative_path).read_bytes() == (
            BASELINE_ROOT / relative_path
        ).read_bytes()


def test_module_command_generates_report_and_check_detects_drift(
    tmp_path: Path,
) -> None:
    output = tmp_path / "command-output"
    command = [
        sys.executable,
        "-m",
        "unrest_harness.baseline",
        "--output",
        str(output),
        "--order",
        "reverse",
    ]
    generated = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert generated.returncode == 0
    assert "generated 12 baseline artifacts" in generated.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["report_id"] == "BATCH-0-BASELINE"

    checked = subprocess.run(
        [*command[:-2], "--check"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0
    assert "baseline artifacts match (12 files)" in checked.stdout

    changed = output / "fixtures" / "gate-aggregation.json"
    changed.write_text("{}\n", encoding="utf-8")
    missing = output / "fixtures" / "storage-state.json"
    missing.unlink()
    (output / "fixtures" / "stale.json").write_text("{}\n", encoding="utf-8")
    differences = check_baseline(output)
    assert differences == [
        "changed: fixtures/gate-aggregation.json",
        "missing: fixtures/storage-state.json",
        "unexpected: fixtures/stale.json",
    ]


def test_generation_does_not_serialize_secret_sentinel(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    sentinel = "B0_SECRET_VALUE_MUST_NOT_APPEAR_7f31"
    monkeypatch.setenv("B0_PRIVATE_TOKEN", sentinel)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", sentinel)

    output = tmp_path / "secret-scan"
    generate_baseline(output)

    corpus = b"".join(
        path.read_bytes()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    )
    assert sentinel.encode() not in corpus
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["checks"]["secret_values_serialized"] is False


def test_manifest_matches_kickoff_and_hashes_every_classified_fixture() -> None:
    manifest = yaml.safe_load(
        (BASELINE_ROOT / "manifest.yaml").read_text(encoding="utf-8")
    )

    assert manifest["schema_version"] == 1
    assert manifest["baseline"] == {
        "batch": 0,
        "approved_commit": BASE_SHA,
        "python_matrix": ["3.11", "3.12", "3.13"],
        "provider_independent": True,
        "live_provider_credentials_required": False,
    }
    assert manifest["kickoff_record"] == KICKOFF_RECORD
    assert manifest["classification_vocabulary"] == list(CLASSIFICATIONS)
    assert manifest["provider_independent_configuration"] == {
        "node_dispatch": "in-process controlled dispatcher",
        "terminal_review": "in-process controlled reviewer",
        "credentials": "not read or required",
        "network": "not used",
        "parallelism": {
            "default_recorded": 4,
            "serial_scenarios": 1,
            "blocking_scheduler_scenario": 2,
        },
    }

    fixture_rows = manifest["fixtures"]
    assert [row["path"] for row in fixture_rows] == sorted(
        row["path"] for row in fixture_rows
    )
    assert len(fixture_rows) == 10
    for row in fixture_rows:
        fixture_path = BASELINE_ROOT / row["path"]
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        assert fixture["fixture_id"] == row["fixture_id"]
        assert fixture["classification"] == row["classification"]
        assert fixture["classification"] in CLASSIFICATIONS
        assert fixture["source_commit"] == BASE_SHA
        assert row["sha256"] == _sha256(fixture_path)


def test_typed_handoffs_round_trip_and_task_defaults_remain_strict() -> None:
    fixture = _json_fixture("typed-handoffs-and-task-list.json")
    observations = fixture["observations"]

    assert fixture["classification"] == "intended"
    assert observations["task_order"] == [
        "work-z",
        "work-a",
        "validate-z",
        "gate-z",
    ]
    assert observations["round_trips"] == {
        "TerminalReviewHandoff": True,
        "ValidateHandoff": True,
        "WorkHandoff": True,
    }
    assert set(observations["unknown_field_rejections"].values()) == {
        "extra_forbidden"
    }

    tasks = observations["task_list"]["tasks"]
    assert tasks[0]["auto_merge"] is True
    assert tasks[0]["depends_on"] == []
    assert tasks[2]["depends_on"] == ["work-z"]
    assert tasks[3]["skill"] is None
    assert observations["handoffs"]["work"]["request_attention"] is False
    assert observations["handoffs"]["validation"]["passed"] is True
    assert observations["handoffs"]["terminal"] == {
        "done": False,
        "report": "One blocking gap.",
    }


def test_storage_fixture_preserves_paths_initial_state_and_authored_order() -> None:
    fixture = _json_fixture("storage-state.json")
    observations = fixture["observations"]

    assert fixture["classification"] == "intended"
    assert observations["durable_root"] == ".unrest"
    assert observations["runtime_root"] == ".unrest-runtime"
    assert observations["contract_assertion_order"] == ["VAL-A", "VAL-B"]
    assert observations["project_record"]["workspace_dir"] == "<workspace>"
    assert observations["authored_task_order"] == [
        "work-b",
        "work-a",
    ]
    assert set(observations["initial_task_state"]["tasks"]) == {
        "work-a",
        "work-b",
    }
    assert observations["initial_contract_state"] == {
        "items": {
            "VAL-A": {"status": "pending"},
            "VAL-B": {"status": "pending"},
        }
    }

    artifact_paths = [artifact["path"] for artifact in observations["artifacts"]]
    assert artifact_paths == [
        ".unrest/AGENTS.md",
        ".unrest/MEMORY.md",
        ".unrest/brief.md",
        ".unrest-runtime/missions/mission-001/contract-state.json",
        ".unrest-runtime/missions/mission-001/task-state.json",
        ".unrest-runtime/missions/mission-001/tasks.json",
        ".unrest-runtime/state.json",
    ]
    for artifact in observations["artifacts"]:
        assert hashlib.sha256(artifact["content"].encode()).hexdigest() == artifact[
            "sha256"
        ]


def test_attempt_decision_and_terminal_review_layout_has_durable_mirrors() -> None:
    fixture = _json_fixture("attempts-decisions-terminal-storage.json")
    observations = fixture["observations"]
    artifacts = observations["artifacts"]
    paths = [artifact["path"] for artifact in artifacts]

    assert fixture["classification"] == "intended"
    assert observations["decision_filenames"] == ["001-first.md", "002-second.md"]
    assert any(
        path.startswith(".unrest-runtime/") and path.endswith("__work-a.json")
        for path in paths
    )
    assert any(
        path.startswith(".unrest/") and path.endswith("__work-a.md")
        for path in paths
    )
    assert any(
        path.startswith(".unrest-runtime/") and "/terminal-reviews/" in path
        for path in paths
    )
    assert any(
        path.startswith(".unrest/") and "/terminal-reviews/" in path
        for path in paths
    )

    heuristic = _json_fixture("attempt-kind-heuristic.json")
    assert heuristic["classification"] == "observed_legacy"
    assert set(heuristic["observations"]["parsed_types"].values()) == {
        "ValidateHandoff",
        "WorkHandoff",
    }
    assert "not a future compatibility promise" in heuristic["description"]


def test_gate_fixture_covers_checkpoint_missing_item_and_dissent() -> None:
    fixture = _json_fixture("gate-aggregation.json")
    observations = fixture["observations"]

    assert fixture["classification"] == "intended"
    assert observations["success"]["gate_status"] == "cleared"
    assert observations["success"]["attention"][0]["kind"] == "gate_checkpoint"
    for scenario in ("missing", "dissent"):
        assert observations[scenario]["gate_status"] == "failed"
        assert observations[scenario]["attention"][0]["kind"] == "gate_failed"
        assert observations[scenario]["result"] == "attention_needed"
        assert observations[scenario]["contract_state"]["items"]["VAL-A"] == {
            "status": "passed"
        }
    assert observations["missing"]["upstream_validators"] == [
        "validate-direct",
        "validate-transitive",
    ]
    assert "missing: validate-transitive" in observations["missing"]["attention"][0][
        "report"
    ]
    assert "dissent: validate-transitive" in observations["dissent"]["attention"][0][
        "report"
    ]


def test_blocking_scheduler_and_unrestricted_defaults_are_not_normative() -> None:
    selection = _json_fixture("blocking-scheduler-selection.json")
    concurrent = _json_fixture("concurrent-writers.json")
    unrestricted = _json_fixture("implicit-unrestricted-defaults.json")

    assert selection["classification"] == "observed_legacy"
    assert selection["observations"] == {
        "authored_order": ["work-b", "work-a", "work-c"],
        "result": "batch cleared: work-b, work-a",
        "selected": ["work-b", "work-a"],
    }
    assert concurrent["classification"] == "known_defect"
    assert concurrent["observations"]["selected"] == ["work-b", "work-a"]
    assert concurrent["observations"]["running_before_dispatch"] == [
        "work-a",
        "work-b",
    ]
    assert concurrent["observations"]["max_active"] == 2
    assert concurrent["observations"]["overlap_observed"] is True
    assert concurrent["observations"]["repaired_behavior_contract"] == "VAL-SCHED-*"

    assert unrestricted["classification"] == "known_defect"
    assert unrestricted["observations"]["repaired_behavior_contract"] == "VAL-CAP-*"
    assert unrestricted["observations"]["codex"]["approval_policy"] == "never"
    assert unrestricted["observations"]["codex"]["sandbox_mode"] == "danger-full-access"


def test_resume_fixture_covers_landed_missing_and_missing_cursor_recovery() -> None:
    fixture = _json_fixture("resume-reconciliation.json")
    observations = fixture["observations"]

    assert fixture["classification"] == "intended"
    landed = observations["attempt_landed"]
    assert landed["result"] == {
        "kind": "advanced",
        "detail": "reconciled pending attempts",
    }
    assert landed["task_state"]["tasks"]["work-a"]["status"] == "cleared"
    assert landed["attention"] == []

    for scenario in ("attempt_missing", "attempt_and_cursor_missing"):
        recovery = observations[scenario]
        assert recovery["result"] == {
            "kind": "attention_needed",
            "detail": "resume_attention",
        }
        assert recovery["task_state"]["tasks"]["work-a"]["status"] == "failed"
        assert recovery["attention"][0]["kind"] == "node_failed"
        assert recovery["contract_state"]["items"]["VAL-A"]["status"] == "pending"

    assert observations["attempt_missing"]["attempt_files"] == [
        "2026-07-21T15-00-00Z-resume__work-a.json"
    ]
    assert observations["attempt_and_cursor_missing"]["attempt_files"] == [
        "2026-07-21T15-00-00Z__work-a.json"
    ]


def test_terminal_review_fixture_seals_only_successful_review() -> None:
    fixture = _json_fixture("terminal-review-closure.json")
    observations = fixture["observations"]

    assert fixture["classification"] == "intended"
    success = observations["success"]
    assert success["result"] == {"kind": "terminal", "detail": "done"}
    assert success["project_state"] == {"state": "done"}
    assert success["attention"] == []
    assert success["closeout"]["path"] == (
        ".unrest/missions/mission-001/closeout.md"
    )
    assert "- sealed_at: 2026-07-21T15:00:00Z" in success["closeout"]["content"]

    for scenario, detail in (
        ("false", "terminal_review"),
        ("crash", "terminal_review_crash"),
    ):
        recovery = observations[scenario]
        assert recovery["result"] == {
            "kind": "attention_needed",
            "detail": detail,
        }
        assert recovery["closeout"] is None
        assert recovery["project_state"]["state"] == "attention_needed"
        assert recovery["attention"][0]["kind"] == "terminal_review"
        assert len(recovery["review_artifacts"]) == 2


def test_report_maps_all_base_contracts_to_concrete_scenarios() -> None:
    report = json.loads(
        (BASELINE_ROOT / "report.json").read_text(encoding="utf-8")
    )

    assert report["approved_commit"] == BASE_SHA
    assert report["manifest_sha256"] == _sha256(
        BASELINE_ROOT / "manifest.yaml"
    )
    assert report["summary"] == {
        "fixture_count": 10,
        "classifications": {
            "observed_legacy": 2,
            "intended": 6,
            "known_defect": 2,
        },
    }
    assert report["checks"] == {
        "all_fixtures_classified": True,
        "kickoff_base_matches": True,
        "known_defects_not_intended": True,
        "provider_independent": True,
        "secret_values_serialized": False,
        "unknown_fields_rejected": True,
    }
    assert set(report["contract_coverage"]) == {
        "VAL-BASE-001",
        "VAL-BASE-002",
        "VAL-BASE-003",
        "VAL-BASE-004",
        "VAL-BASE-005",
        "VAL-BASE-006",
    }
    assert report["scenario_results"]["gate"]["success"] == {
        "attention_kind": "gate_checkpoint",
        "gate_status": "cleared",
        "result": "attention_needed",
    }
    assert report["scenario_results"]["resume"]["attempt_missing"][
        "task_status"
    ] == "failed"
    assert report["scenario_results"]["terminal_review"]["success"][
        "closeout_written"
    ] is True
    assert report["scheduler_boundary"] == {
        "characterized_fixture": "BASE-SCHEDULER-DEFECT-001",
        "classification": "known_defect",
        "repaired_scheduler_oracle": "VAL-SCHED-*",
    }


def test_generated_file_list_is_closed_and_stably_sorted() -> None:
    assert list(GENERATED_FILENAMES) == sorted(GENERATED_FILENAMES)
    assert _relative_files(BASELINE_ROOT) == list(GENERATED_FILENAMES)
