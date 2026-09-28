"""Source-only release records; these checks never build release archives."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "docs/release"
MANIFEST = RELEASE / "lean-core-v0.4.5-manifest.json"
PREDECESSOR = "8decbecf7cad32552dfd7d48e069d4050e04ffd3"


# Audited source-preparation notes: any byte change requires a fresh whole-notes
# review against approval and pending gates. This is not a prose truth classifier.
AUDITED_NOTES_SHA256 = "ffa890adf57c1fe8f3b73f4ed8285f9fdd574cc35e7e8010e27e03a102c97282"


def _audited_notes() -> str:
    content = (RELEASE / "lean-core-v0.4.5.md").read_bytes()
    assert hashlib.sha256(content).hexdigest() == AUDITED_NOTES_SHA256, (
        "Release-preparation notes changed; review the complete notes before updating the snapshot"
    )
    return content.decode("utf-8")


def test_v045_release_identity_scope_and_predecessor() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["release"] == "unrest-v0.4.5"
    assert manifest["version"] == "0.4.5"
    assert manifest["base"] == {
        "candidate_ref": "refs/heads/codex/v045-release-r2",
        "predecessor_commit": PREDECESSOR,
        "predecessor_tag": "v0.4.0",
        "release_tag_ref": "refs/tags/v0.4.5",
    }
    assert manifest["history"]["active_binding_owner"] == MANIFEST.relative_to(ROOT).as_posix()
    assert manifest["compatibility"]["python"] == ">=3.13"
    assert manifest["scope"]["dependencies_added"] == []
    assert manifest["scope"]["locked_dependency_upgrades"] == []
    assert manifest["scope"]["metadata_stage"] == "source-only"
    assert "pending external gates" in manifest["status"]
    assert "not benchmark certified or release eligible" in manifest["status"]
    assert set(manifest["source"]) == {"binding_algorithm", "final_product_package_test"}
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    assert "date-released" not in citation


def test_v045_ci_archive_contract_and_required_gates() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    assert artifacts == {
        "checksums": "SHA256SUMS",
        "ci_bundle": "unrest-v0.4.5-python313",
        "sdist": "unrest_harness-0.4.5.tar.gz",
        "wheel": "unrest_harness-0.4.5-py3-none-any.whl",
    }
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["primary"]["steps"]
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == artifacts["ci_bundle"]
    assert upload["with"]["path"].splitlines() == [
        f"dist/{artifacts['wheel']}", f"dist/{artifacts['sdist']}", "dist/SHA256SUMS"
    ]
    assert upload["with"]["if-no-files-found"] == "error"
    checksum = next(step["run"] for step in steps if "build-local checksums" in step.get("name", ""))
    for kind in ("wheel", "sdist"):
        assert f"test -f dist/{artifacts[kind]}" in checksum
        assert artifacts[kind] in checksum.split("sha256sum \\\n", 1)[1]
    assert "sha256sum --check --strict SHA256SUMS" in checksum
    commands = [step["run"] for step in steps if "run" in step]
    for command in (
        "uv run ruff check .", "uv run mypy src", "uv run unrest check-repository",
        "env -u CODEX_PATH uv run pytest -q", "uv build",
        "uv run python tools/check_distribution.py dist",
    ):
        assert command in commands
    installed = next(command for command in commands if "installed_wheel_check" in command)
    assert 'cd "$(mktemp -d)"' in installed
    assert 'test "$status" -ne 0' in installed
    assert 'test "$output" = "unrest-server: startup configuration rejected"' in installed
    setup = next(step for step in steps if step.get("uses", "").startswith("astral-sh/setup-uv@"))
    assert setup["with"]["python-version"] == "3.13"


def test_v045_notes_and_rollback_keep_pending_scope_and_resolvable_links() -> None:
    notes = _audited_notes()
    rollback = (RELEASE / "lean-core-v0.4.5-rollback.md").read_text(encoding="utf-8")
    for term in ("Inquiry", "Evidence-frontier", "supervision", "ACP", "Dogfood", "end_node"):
        assert term in notes
    for term in (
        "provider_approval_required", "pending external gates", "historical correctness-run retry policy",
        "is not completed validation",
        "does not verify those future archives",
    ):
        assert term in notes
    for term in (
        PREDECESSOR, "unrest_harness-0.4.0-py3-none-any.whl",
        "unrest_harness-0.4.0.tar.gz", "shasum -a 256 -c SHA256SUMS",
        "pre-upgrade", "Do not\n   delete", "no supported reverse-migration promise",
    ):
        assert term in rollback
    for text in (notes, rollback):
        assert "lean-core-v0.4.5-manifest.json" in text
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if target.startswith("https://"):
                assert target == "https://github.com/apodgaiko/unrest/releases/tag/v0.4.0"
            else:
                assert (RELEASE / target).is_file(), target


def test_v040_release_carriers_remain_exact_tag_bytes() -> None:
    for path in sorted(RELEASE.glob("lean-core-v0.4.0*")):
        tagged = subprocess.run(
            ["git", "show", f"v0.4.0:{path.relative_to(ROOT).as_posix()}"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout
        assert path.read_bytes() == tagged


def test_binding_cli_accepts_active_manifest_and_refuses_wrong_digest(tmp_path: Path) -> None:
    command = [sys.executable, "-B", str(ROOT / "tools/release_binding.py"),
               "--repository", str(ROOT), "--check-manifest"]
    success = subprocess.run([*command, str(MANIFEST)], cwd=ROOT, capture_output=True, text=True)
    assert success.returncode == 0, success.stderr
    computed = json.loads(success.stdout)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert computed["sha256"] == manifest["source"]["final_product_package_test"]["sha256"]
    manifest["source"]["final_product_package_test"]["sha256"] = "0" * 64
    wrong = tmp_path / "wrong-manifest.json"
    wrong.write_text(json.dumps(manifest), encoding="utf-8")
    refusal = subprocess.run([*command, str(wrong)], cwd=ROOT, capture_output=True, text=True)
    assert refusal.returncode != 0
    assert "binding declaration mismatch" in refusal.stderr


def test_v045_approved_profile_has_exact_closed_values_and_types() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected = {'id': 'v045-correctness-release-exception-1',
     'approval_sha256': '63f089865e5d507c68f936728d8c9e63521b49a203d2a0aa1f52cf21f699a449',
     'approved_proposal_sha256': 'dbfe1888f84cc86d4071aed1ec409a5e9b5650f342c4b6bad386017a41e69758',
     'approval_status': 'approved',
     'benchmark_certified': False,
     'improvement_claims': [],
     'deferred_campaigns': ['quality', 'mission-speed', 'resource', 'historical-workflow'],
     'correctness_cases': 52,
     'unchanged_targets': 66,
     'qualified_targets': ['ACT006', 'CROSS005', 'EVAL001', 'EVAL002'],
     'retry': {'unit': 'whole_correctness_run',
               'maximum_infrastructure_retries': 1,
               'provider_free_limits': {'maximum_executions': 180,
                                        'maximum_execution_seconds': 1200,
                                        'maximum_total_seconds': 21600},
               'both_attempts_counted': True},
     'live_smoke': {'route': 'installed-library-codex-subscription',
                    'model': 'gpt-6-astra',
                    'reasoning_effort': 'medium',
                    'maximum_branches': 2,
                    'maximum_syntheses': 1,
                    'maximum_attempts': 3,
                    'maximum_total_seconds': 600,
                    'maximum_response_bytes': 65536,
                    'max_steps': 8,
                    'step_semantics': 'reported_and_validated',
                    'automatic_retries': 0},
     'remaining_gates': ['public-profile-and-ABI',
                         'fresh-planning-acceptance',
                         'external-runner-and-ruler',
                         'integration',
                         'independent-functional',
                         'correctness52',
                         'live-inquiry',
                         'python313-source-suite',
                         'archive-and-installed',
                         'release-decision-and-CI',
                         'publication']}
    # The original approval remains immutable history; the later amendment is effective.
    assert json.dumps(manifest["release_profile"], sort_keys=True) == json.dumps(
        expected, sort_keys=True
    )
    assert manifest["release_gate_amendment"] == {
        "id": "v045-independent-integrated-validation-1",
        "status": "maintainer-approved",
        "decision_date": "2026-09-28",
        "decision_record": "docs/release/lean-core-v0.4.5-gate-amendment.md",
        "superseded_gates": ["correctness", "runner", "ruler"],
        "replacement_gate": "independent-integrated-70",
        "product_target_verdicts": 67,
        "qualified_governance_target_verdicts": ["CROSS005", "EVAL001", "EVAL002"],
        "benchmark_certified": False,
        "improvement_claims": [],
        "live_inquiry_required": True,
        "release_decision_required": True,
    }


def test_v045_notes_preserve_approval_limits_and_pending_validation() -> None:
    notes = _audited_notes()
    for term in (
        "66 unchanged", "four qualified targets", "all 52 correctness cases", "one whole run",
        "nine historical CLI scenarios", "45 assertions",
        "Both attempts", "180 executions", "1200 seconds", "21600 seconds",
        "three attempts", "600 seconds", "65536 response bytes", "max_steps=8",
        "reported\nand validated", "No automatic live replay", "API fallback",
        "installed public-library", "provider_approval_required",
        "Fresh applicable planning acceptance", "all 15 extracted-sdist",
        "admission waits for the amended planning and independent integrated validation",
        "release eligibility and publication remain pending",
    ):
        assert term in notes
    for stale in (
        "approval and credentials remain unresolved", "v0.4.5 ships",
        "This is a frozen source candidate", "benchmark_certified: true",
    ):
        assert stale not in notes
