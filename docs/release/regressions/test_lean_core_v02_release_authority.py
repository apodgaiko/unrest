"""Focused release-authority regressions outside the frozen binding surface."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RELEASE_ROOT = ROOT / "docs/release"
GOVERNED = (
    "lean-core-v0.2-attached-review-claims.json",
    "lean-core-v0.2-evidence-crosswalk.json",
    "lean-core-v0.2-manifest.json",
    "lean-core-v0.2-measurements.json",
    "lean-core-v0.2-measurements.md",
    "lean-core-v0.2-review-audit.json",
    "lean-core-v0.2-rollback.md",
    "lean-core-v0.2.md",
)
MACHINE_CARRIERS = GOVERNED[1:3] + (GOVERNED[5],)
PROSE_CARRIERS = (GOVERNED[6], GOVERNED[7])
LOCAL_PROBE_RESULT = "919 passed, 7 skipped, 2 failed in 220.56s; exit 1"
FAILURES = [
    "tests/test_documentation_contract.py::test_review_audit_and_executable_crosswalk_are_release_carriers",
    "tests/test_release_binding.py::test_all_five_carriers_agree_with_tracked_binding_and_keep_chronology",
]


def _expected_authority() -> dict[str, object]:
    return {
        "decision": "Decision 001",
        "local_probe": {
            "status": "failed-ordering-probe",
            "command": "env -u CODEX_PATH uv run pytest -q",
            "result": LOCAL_PROBE_RESULT,
            "invocations": 1,
            "reruns": 0,
            "failing_nodeids": FAILURES,
            "evidence_source": "mission attempt W-FREEZE 2026-08-13T13-25-57Z",
        },
        "clean_frozen_candidate_verdict": {
            "status": "pending",
            "owner": "VAL-CI-EXACT",
            "surface": "exact-head Python 3.13 CI",
        },
    }


def test_governed_release_files_are_exhaustive_and_machine_local_path_free() -> None:
    observed = tuple(path.name for path in sorted(RELEASE_ROOT.glob("lean-core-v0.2*")))
    assert observed == GOVERNED
    prohibited = ("/Users/", "/private/", "/tmp/", "/var/folders/", "aleksandrpodgaiko")
    for name in GOVERNED:
        text = (RELEASE_ROOT / name).read_text(encoding="utf-8")
        assert not any(value in text for value in prohibited), name


def test_all_five_carriers_agree_on_decision_001_checkpoint_authority() -> None:
    expected = _expected_authority()
    for name in MACHINE_CARRIERS:
        carrier = json.loads((RELEASE_ROOT / name).read_text(encoding="utf-8"))
        assert carrier["commit_reproducible_finalization"]["checkpoint_authority"] == expected
        superseded = carrier["commit_reproducible_finalization"]["superseded_checkpoint"]
        assert superseded["status"] == "historical-superseded-chronology-only"
        assert superseded["result"].startswith("899 passed, 7 skipped, 0 failed")

    for name in PROSE_CARRIERS:
        normalized = " ".join((RELEASE_ROOT / name).read_text(encoding="utf-8").split())
        assert "Decision 001 defines checkpoint authority" in normalized
        assert "919 passed, 7 documented live-provider skips" in normalized
        assert "exactly 2 carrier-currentness failures" in normalized
        assert "pending and belongs to exact-head Python 3.13 `VAL-CI-EXACT`" in normalized
        assert "historical, superseded chronology only" in normalized


def test_workspace_boundary_uses_only_durable_observable_evidence() -> None:
    audit = json.loads((RELEASE_ROOT / GOVERNED[5]).read_text(encoding="utf-8"))
    evidence = audit["workspace_boundary"]
    assert evidence["status"] == "durable-observable-evidence-only"
    assert evidence["protected_root"] == "validator-regressions/"
    assert evidence["root_stat"] == {
        "type": "directory",
        "mode": "drwxr-xr-x",
        "size": 288,
        "mtime_ns": 1784912858897834195,
        "ctime_ns": 1784912858897834195,
        "relation": "identical to retained pre-work evidence",
    }
    assert evidence["status_observation"] == "sole untracked entry"
    assert evidence["index_observation"].startswith("protected root absent;")
    assert evidence["commit_tree_observation"] == "absent from HEAD"
    assert "do not prove" in evidence["limitation"]
    assert "unlogged historical filesystem read" in evidence["limitation"]
