"""Focused release-record contracts for v0.3.1."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "docs/release"


def test_v031_release_records_are_coherent() -> None:
    manifest = json.loads(
        (RELEASE / "lean-core-v0.3.1-manifest.json").read_text(encoding="utf-8")
    )
    burden = json.loads(
        (RELEASE / "lean-core-v0.3.1-burden.json").read_text(encoding="utf-8")
    )
    notes = (RELEASE / "lean-core-v0.3.1.md").read_text(encoding="utf-8")
    rollback = (RELEASE / "lean-core-v0.3.1-rollback.md").read_text(encoding="utf-8")

    assert manifest["release"] == "unrest-v0.3.1"
    assert manifest["version"] == "0.3.1"
    assert manifest["base"]["predecessor_tag"] == "v0.3.0"
    assert manifest["scope"]["new_public_methods"] == 23
    assert manifest["scope"]["dependencies_added"] == []
    assert burden["reference"]["commit"] == manifest["base"]["predecessor_commit"]
    assert burden["installation"]["dependencies"] == 5
    if burden["status"] == "complete":
        assert burden["candidate"]["source_suite_invocations"] == 1
    else:
        assert burden["status"] == "candidate checkpoint pending"
        assert burden["candidate"]["source_suite_invocations"] == 0
    assert "Foundation Runtime" in notes
    assert "v0.3.0" in rollback
