"""Focused public release-record contracts for v0.3.0."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = ROOT / "docs/release"
MANIFEST_PATH = RELEASE_ROOT / "lean-core-v0.3.0-manifest.json"
RELEASE_PATH = RELEASE_ROOT / "lean-core-v0.3.0.md"
ROLLBACK_PATH = RELEASE_ROOT / "lean-core-v0.3.0-rollback.md"


def test_v030_manifest_names_the_exact_public_scope_and_non_goals() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["release"] == "unrest-v0.3.0"
    assert manifest["version"] == "0.3.0"
    assert manifest["base"]["candidate_ref"] == "refs/heads/codex/v0.3.0-release"
    assert manifest["base"]["release_tag_ref"] == "refs/tags/v0.3.0"
    assert manifest["scope"]["fm000_status"] == "proposed groundwork only"
    assert manifest["scope"]["dependencies_added"] == []
    assert manifest["scope"]["migration_required"] is False
    assert manifest["compatibility"]["new_contention_errors"] == [
        "project_busy",
        "project_lock_error",
    ]
    assert "general-thinker runtime" in manifest["scope"]["not_implemented"]
    assert "asynchronous run admission and attach" in manifest["scope"][
        "not_implemented"
    ]


def test_v030_release_notes_explain_the_minor_version_boundary() -> None:
    release = RELEASE_PATH.read_text(encoding="utf-8")
    normalized = " ".join(release.lower().split())

    for phrase in (
        "foundation & safety",
        "six proposed adrs",
        "all five mutating orchestrator mcp operations",
        "caller cancellation",
        "no dependency family",
        "does not include",
        "general-thinker runtime",
    ):
        assert phrase in normalized
    assert "lean-core-v0.3.0-manifest.json" in release
    assert "lean-core-v0.3.0-rollback.md" in release


def test_v030_rollback_preserves_records_and_needs_no_migration() -> None:
    rollback = ROLLBACK_PATH.read_text(encoding="utf-8")
    normalized = " ".join(rollback.lower().split())

    assert "adds no data migration" in normalized
    assert "v0.2.0" in rollback
    assert "v0.2.1" in rollback
    assert ".unrest/" in rollback and ".unrest-runtime/" in rollback


def test_v030_carriers_have_no_unfinished_binding_placeholders() -> None:
    for path in (MANIFEST_PATH, RELEASE_PATH, ROLLBACK_PATH):
        assert "TO_BE_FILLED_FROM_FINAL_CANDIDATE" not in path.read_text(
            encoding="utf-8"
        )
