"""Focused release-record contracts for v0.4.0."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "docs/release"


def test_v040_release_records_are_coherent() -> None:
    manifest = json.loads(
        (RELEASE / "lean-core-v0.4.0-manifest.json").read_text(encoding="utf-8")
    )
    notes = (RELEASE / "lean-core-v0.4.0.md").read_text(encoding="utf-8")
    rollback = (RELEASE / "lean-core-v0.4.0-rollback.md").read_text(encoding="utf-8")

    assert manifest["release"] == "unrest-v0.4.0"
    assert manifest["version"] == "0.4.0"
    assert manifest["base"]["predecessor_tag"] == "v0.3.1"
    assert manifest["compatibility"]["python"] == ">=3.13"
    assert manifest["scope"]["dependencies_added"] == []
    assert manifest["scope"]["migration_required"] is False
    assert manifest["scope"]["high_level_adapters"] == [
        "run-improvement",
        "run-project",
        "run-task",
    ]
    assert "Composition Adapters" in notes
    assert "v0.3.1" in rollback
