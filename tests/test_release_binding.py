"""Commit-reproducible Lean Core release binding and report contracts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_binding", ROOT / "tools/release_binding.py"
)
assert SPEC is not None and SPEC.loader is not None
release_binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_binding)

HISTORICAL_CARRIERS = (
    ROOT / "docs/release/lean-core-v0.2-manifest.json",
    ROOT / "docs/release/lean-core-v0.2-review-audit.json",
    ROOT / "docs/release/lean-core-v0.2-evidence-crosswalk.json",
    ROOT / "docs/release/lean-core-v0.2.md",
    ROOT / "docs/release/lean-core-v0.2-rollback.md",
)
ACTIVE_MANIFEST = ROOT / release_binding.ACTIVE_RELEASE_MANIFEST
ACTIVE_PROSE_CARRIERS = (
    ROOT / "docs/release/lean-core-v0.2.1.md",
    ROOT / "docs/release/lean-core-v0.2.1-rollback.md",
)


def _computed() -> dict[str, object]:
    paths = release_binding.candidate_regular_paths(ROOT)
    return release_binding.inventory(ROOT, paths)


def test_binding_uses_only_candidate_regular_files() -> None:
    paths = release_binding.candidate_regular_paths(ROOT)
    assert paths == sorted(paths, key=lambda value: value.encode("utf-8"))
    assert "pyproject.toml" in paths and "uv.lock" in paths
    assert all(".egg-info/" not in path for path in paths)
    assert all((ROOT / path).is_file() and not (ROOT / path).is_symlink() for path in paths)
    assert "src/unrest_harness/project_lock.py" in paths

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


def test_v02_carriers_are_byte_identical_to_the_v020_tag() -> None:
    for carrier in HISTORICAL_CARRIERS:
        relative = carrier.relative_to(ROOT).as_posix()
        tagged = subprocess.run(
            ("git", "show", f"v0.2.0:{relative}"),
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        assert carrier.read_bytes() == tagged


def test_v021_manifest_owns_the_live_candidate_binding() -> None:
    computed = _computed()
    manifest = json.loads(ACTIVE_MANIFEST.read_text(encoding="utf-8"))
    declaration = release_binding.declared_binding(manifest)
    expected = {"files": computed["files"], "sha256": computed["sha256"]}
    assert {"files": declaration["files"], "sha256": declaration["sha256"]} == expected
    assert manifest["release"] == "unrest-v0.2.1"
    assert manifest["history"]["v0.2_carriers"] == "immutable bytes from tag v0.2.0"
    assert str(release_binding.ACTIVE_RELEASE_MANIFEST) == ACTIVE_MANIFEST.relative_to(
        ROOT
    ).as_posix()
    for carrier in ACTIVE_PROSE_CARRIERS:
        text = carrier.read_text(encoding="utf-8")
        assert str(computed["sha256"]) in text
        assert "0.2.1" in text
        assert "proposed" in text.lower()

    drifted = json.loads(json.dumps(manifest))
    drifted["source"]["final_product_package_test"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="binding declaration mismatch"):
        release_binding.assert_declaration_matches(
            release_binding.declared_binding(drifted), computed
        )


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
