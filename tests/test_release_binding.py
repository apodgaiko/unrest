"""Commit-reproducible Lean Core release binding and report contracts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_binding", ROOT / "tools/release_binding.py"
)
assert SPEC is not None and SPEC.loader is not None
release_binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_binding)

CARRIERS = (
    ROOT / "docs/release/lean-core-v0.2-manifest.json",
    ROOT / "docs/release/lean-core-v0.2-review-audit.json",
    ROOT / "docs/release/lean-core-v0.2-evidence-crosswalk.json",
    ROOT / "docs/release/lean-core-v0.2.md",
    ROOT / "docs/release/lean-core-v0.2-rollback.md",
)


def _computed() -> dict[str, object]:
    paths = release_binding.tracked_regular_paths(ROOT)
    return release_binding.inventory(ROOT, paths)


def test_binding_uses_only_git_tracked_regular_files() -> None:
    paths = release_binding.tracked_regular_paths(ROOT)
    assert paths == sorted(paths, key=lambda value: value.encode("utf-8"))
    assert "pyproject.toml" in paths and "uv.lock" in paths
    assert all(".egg-info/" not in path for path in paths)
    assert all((ROOT / path).is_file() and not (ROOT / path).is_symlink() for path in paths)

    ignored_generated = ROOT / "src/unrest_harness.egg-info/PKG-INFO"
    assert ignored_generated.exists(), "the ignored-file exclusion probe must be present"
    assert ignored_generated.relative_to(ROOT).as_posix() not in paths


def test_binding_rejects_missing_tracked_file(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="tracked binding file is missing"):
        release_binding.inventory(tmp_path, ["pyproject.toml", "uv.lock"])


def test_binding_rejects_coherent_fake_digest() -> None:
    computed = _computed()
    fake = {"files": computed["files"], "sha256": "0" * 64}
    with pytest.raises(ValueError, match="binding declaration mismatch"):
        release_binding.assert_declaration_matches(fake, computed)


def test_all_five_carriers_agree_with_tracked_binding_and_keep_chronology() -> None:
    computed = _computed()
    manifest = json.loads(CARRIERS[0].read_text(encoding="utf-8"))
    audit = json.loads(CARRIERS[1].read_text(encoding="utf-8"))
    crosswalk = json.loads(CARRIERS[2].read_text(encoding="utf-8"))
    declarations = (
        manifest["source"]["final_product_package_test"],
        audit["candidate_binding"],
        crosswalk["candidate"],
    )
    expected = {"files": computed["files"], "sha256": computed["sha256"]}
    for declaration in declarations:
        assert {"files": declaration["files"], "sha256": declaration["sha256"]} == expected
    for carrier in CARRIERS:
        text = carrier.read_text(encoding="utf-8")
        assert str(computed["sha256"]) in text
        assert "35e21ed3a3a70f6687d35ad7fa8d03d7601d77935a72fabfdbf86a05f5e166e1" in text
        assert "superseded" in text.lower()

    drifted = json.loads(json.dumps(audit))
    drifted["candidate_binding"]["sha256"] = "f" * 64
    with pytest.raises(AssertionError):
        assert drifted["candidate_binding"] == manifest["source"]["final_product_package_test"]


def test_complete_measurement_report_machine_data() -> None:
    report = json.loads(
        (ROOT / "docs/release/lean-core-v0.2-measurements.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["reference"]["commit"] == "93c59e4378407f3d7cfb918cf86c8bdc81daa141"
    for revision in ("reference", "candidate"):
        assert len(report[revision]["largest_functions"]) == 5
        assert len(report[revision]["c901_top_five"]) == 5
        for module in ("cli", "server"):
            samples = report["imports"][revision][module]["samples_seconds"]
            assert len(samples) == 7
            assert min(samples) == report["imports"][revision][module]["range_seconds"][0]
            assert max(samples) == report["imports"][revision][module]["range_seconds"][1]
    assert len(report["imports"]["interleaving_order"]) == 28
    assert report["loc"]["production"]["reference"] - report["loc"]["production"][
        "candidate"
    ] == report["loc"]["production"]["reduction"]
    assert report["loc"]["maintained"]["reference"] - report["loc"]["maintained"][
        "candidate"
    ] == report["loc"]["maintained"]["reduction"]
    for revision in ("reference", "candidate"):
        assert set(report["archives"][revision]) == {"wheel", "sdist"}
        for archive in report["archives"][revision].values():
            assert archive["bytes"] > 0
            assert len(archive["sha256"]) == 64
            assert archive["members"]
