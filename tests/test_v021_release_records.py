"""Focused history, foundation, and release-record contracts for v0.2.1."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
FM000 = "2b17a613b99ef182c9bae18b8171efc17e8fe8d2"
ADR_PATHS = tuple(
    f"docs/decisions/ADR-030{index}-{name}.md"
    for index, name in enumerate(
        ("authority", "identity", "inquiry", "workspace", "evolution", "compatibility")
    )
)
CONTRACT_ROOT = "docs/v03/contracts"
FIXTURE_ROOT = "tests/fixtures/v03_decisions"
RELEASE_ROOT = ROOT / "docs/release"
FINAL_CARRIERS = (
    RELEASE_ROOT / "lean-core-v0.2.1-manifest.json",
    RELEASE_ROOT / "lean-core-v0.2.1.md",
    RELEASE_ROOT / "lean-core-v0.2.1-rollback.md",
    RELEASE_ROOT / "unrest-v0.2.1-parent-handoff.md",
    RELEASE_ROOT / "unrest-v0.2.1-forensics.md",
)


def _git(*args: str) -> bytes:
    return subprocess.run(
        ("git", *args), cwd=ROOT, check=True, stdout=subprocess.PIPE
    ).stdout


def _fm000_tree(root: str) -> dict[str, str]:
    records = _git("ls-tree", "-r", FM000, "--", root).decode("utf-8").splitlines()
    return {
        record.split("\t", 1)[1]: record.split(" ", 2)[2].split("\t", 1)[0]
        for record in records
    }


def test_fm000_proposal_artifacts_are_exact_and_still_proposed() -> None:
    subprocess.run(
        ("git", "merge-base", "--is-ancestor", FM000, "HEAD"), cwd=ROOT, check=True
    )
    expected_contracts = _fm000_tree(CONTRACT_ROOT)
    expected_fixtures = _fm000_tree(FIXTURE_ROOT)
    assert len(expected_contracts) == 8
    assert expected_fixtures
    current_contracts = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / CONTRACT_ROOT).rglob("*")
        if path.is_file()
    }
    current_fixtures = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / FIXTURE_ROOT).rglob("*")
        if path.is_file()
    }
    assert current_contracts == set(expected_contracts)
    assert current_fixtures == set(expected_fixtures)

    for relative, expected_blob in {
        **_fm000_tree("docs/decisions"),
        **expected_contracts,
        **expected_fixtures,
    }.items():
        if relative.startswith("docs/decisions/ADR-030") or relative.startswith(
            (f"{CONTRACT_ROOT}/", f"{FIXTURE_ROOT}/")
        ):
            actual_blob = _git("hash-object", relative).decode("ascii").strip()
            assert actual_blob == expected_blob, relative

    current_adrs = tuple(
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "docs/decisions").glob("ADR-030*.md"))
    )
    assert current_adrs == ADR_PATHS
    for relative in ADR_PATHS:
        assert "status: proposed" in (ROOT / relative).read_text(encoding="utf-8")


def test_candidate_diff_has_no_forbidden_v03_runtime_surface() -> None:
    changed = set(_git("diff", "--name-only", FM000).decode("utf-8").splitlines())
    changed.update(
        _git("ls-files", "--others", "--exclude-standard")
        .decode("utf-8")
        .splitlines()
    )
    forbidden_parts = (
        "custody",
        "telemetry",
        "general-thinker",
        "capability_policy",
        "role-capabilities",
        "benchmarks/v03",
        "docs/v03/measurement",
        "tests/v03_measurement",
        "tools/v03_measurement",
    )
    assert not {
        relative
        for relative in changed
        if any(part in relative.lower() for part in forbidden_parts)
    }
    assert {
        relative for relative in changed if relative.startswith("src/unrest_harness/")
    } == {
        "src/unrest_harness/__init__.py",
        "src/unrest_harness/project_lock.py",
        "src/unrest_harness/server.py",
        "src/unrest_harness/storage.py",
    }


def test_v021_records_bound_the_narrow_delta_without_promoting_fm010() -> None:
    manifest = json.loads(
        (RELEASE_ROOT / "lean-core-v0.2.1-manifest.json").read_text(encoding="utf-8")
    )
    release = (RELEASE_ROOT / "lean-core-v0.2.1.md").read_text(encoding="utf-8")
    rollback = (RELEASE_ROOT / "lean-core-v0.2.1-rollback.md").read_text(
        encoding="utf-8"
    )
    forensics = (RELEASE_ROOT / "unrest-v0.2.1-forensics.md").read_text(
        encoding="utf-8"
    )

    assert manifest["version"] == "0.2.1"
    assert manifest["base"]["fm000_commit"] == FM000
    assert manifest["scope"]["implemented"] == [
        "cross-process per-project mutation exclusion"
    ]
    assert manifest["scope"]["fm000_status"] == "proposed groundwork only"
    for text in (release, rollback, forensics):
        normalized = " ".join(text.lower().split())
        assert "fm-000" in normalized
        assert "proposed" in normalized
        assert "fm-010" in normalized
        assert "untrusted research" in normalized
        assert "not implemented" in normalized

    assert "206 task definitions" in forensics
    assert "106 attempt reports" in forensics
    assert "61 task definitions" in forensics
    assert "38 attempt reports" in forensics
    assert "468 task definitions" in forensics
    assert "214 attempt reports" in forensics
    normalized_forensics = " ".join(forensics.split())
    assert "106 and 214 are top-level attempt-report" in normalized_forensics
    assert "both work and validation reports" in normalized_forensics
    assert "neither number is a validator-only count" in normalized_forensics
    assert "no canonical handoff or commit" in forensics


def test_final_carriers_reject_unfinished_identity_and_verification_states() -> None:
    forbidden = (
        "<fill-after-verification>",
        "pending-freeze-verification",
        '"status": "pending"',
        "candidate commit and archive checks remain owned",
    )
    for carrier in FINAL_CARRIERS:
        text = carrier.read_text(encoding="utf-8").lower()
        assert not any(value in text for value in forbidden), carrier.name


def test_parent_handoff_has_symbolic_authority_and_exact_external_plan_targets() -> None:
    handoff = (RELEASE_ROOT / "unrest-v0.2.1-parent-handoff.md").read_text(
        encoding="utf-8"
    )
    assert "CANDIDATE_REF=refs/heads/codex/v0.2.1-foundation-safety" in handoff
    assert "TAG_REF=refs/tags/v0.2.1" in handoff
    assert 'CANDIDATE_COMMIT=$(git rev-parse "$CANDIDATE_REF^{commit}")' in handoff
    assert 'CANDIDATE_TREE=$(git rev-parse "$CANDIDATE_REF^{tree}")' in handoff
    assert "mission-002/evidence/candidate-release-receipt.json" in handoff
    assert "finalized post-tag handoff evidence" in handoff
    assert "git merge --ff-only" in handoff
    assert "git reset" not in handoff
    assert "git clean" not in handoff
    assert "uv tool install --editable --force" in handoff
    for relative in (
        "04-program-plan.md",
        "05-parallel-future-missions.md",
        "06-validation-metrics-and-risks.md",
        "07-decision-register.md",
        "mission-packets/FM-010-measurement-baseline.md",
        "registries/future-mission-registry.json",
        "registries/ownership-matrix.md",
        "registries/risk-register.md",
    ):
        assert relative in handoff
