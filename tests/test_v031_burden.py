"""Focused installation and routine-verification burden contracts for v0.3.1."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests/fixtures/v031_compatibility/v030-burden-baseline.v1.json"


def test_no_extra_install_keeps_the_v030_dependency_and_python_perimeter() -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert project["dependencies"] == baseline["dependencies"]
    assert sorted(project.get("optional-dependencies", {})) == baseline[
        "optional_dependency_groups"
    ]
    assert project["requires-python"] == ">=3.11"


def test_ordinary_ci_never_executes_the_provider_baseline() -> None:
    workflow_path = ROOT / ".github/workflows/ci.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    assert workflow_text.count("env -u CODEX_PATH uv run pytest -q") == 1
    assert "measure-baseline" not in workflow_text
    assert "${{ secrets." not in workflow_text


def test_measurement_results_are_the_only_product_digest_exclusion() -> None:
    mission = (ROOT / "docs/v03/v0.3.1/mission.md").read_text(encoding="utf-8")
    normalized = " ".join(mission.split())

    assert "except `docs/v03/measurement/results/**`" in normalized
