"""Focused documentation authority checks retained by Lean Core."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_adr_0002_and_scope_package_are_accepted_and_registered() -> None:
    adr = (ROOT / "docs/decisions/ADR-0002-lean-core-v0.2.md").read_text(encoding="utf-8")
    decision_index = (ROOT / "docs/decisions/index.md").read_text(encoding="utf-8")
    architecture_index = (ROOT / "docs/architecture/index.md").read_text(encoding="utf-8")
    scope = (ROOT / "docs/proposals/batch-0.5/README.md").read_text(encoding="utf-8")
    assert "status: accepted" in adr
    assert "ADR-0002-lean-core-v0.2.md" in decision_index
    assert "related_decisions:\n  - ADR-0002" in architecture_index
    assert "Status: accepted 2026-08-09" in scope


def test_accepted_scope_documents_no_longer_disclaim_authority() -> None:
    for name in (
        "README.md",
        "behavior-contract.md",
        "deletion-ledger.md",
        "measurement-protocol.md",
        "security-contract.md",
    ):
        text = (ROOT / "docs/proposals/batch-0.5" / name).read_text(encoding="utf-8")
        first_lines = "\n".join(text.splitlines()[:6]).lower()
        assert "review draft" not in first_lines
        assert "implementation is not authorized" not in first_lines


def test_public_status_migration_note_matches_schema_v2_cli() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    for required in (
        "unrest observe-project PROJECT_ID",
        "unrest observe-project --all --strict --format json",
        "closed schema-v2",
        "aggregate and exits nonzero",
        "no legacy output flag or version negotiation",
        "require no data migration",
    ):
        assert required in readme


def test_maintained_bindings_match_repository_hard_cuts() -> None:
    current_documents = {
        "README.md": ("check-governance", "check-commit", "generated baselines"),
        "docs/v5/10-implementation-plan.md": ("test_baseline.py",),
        "docs/decisions/ADR-0001-observe-before-optimizing.md": (
            "docs/architecture/change-governance.md",
            "policy/protected-surfaces.yaml",
        ),
    }
    for relative, stale_bindings in current_documents.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for stale_binding in stale_bindings:
            assert stale_binding not in text, f"{relative} retains {stale_binding}"

    manifest = json.loads(
        (ROOT / "docs/release/batch-0-release-manifest.json").read_text(encoding="utf-8")
    )
    assert "included_path_groups" not in manifest
    assert manifest["record_status"].startswith("historical-pre-lean-core-candidate")
    assert "historical_included_path_groups" in manifest


def test_withdrawn_governance_and_deleted_evidence_bindings_are_retired() -> None:
    current_documents = {
        "docs/decisions/index.md": ("protected-surface review",),
        "docs/templates/adr.md": ("protected_surfaces", "Human-Reviewers:"),
    }
    for relative, withdrawn_bindings in current_documents.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for binding in withdrawn_bindings:
            assert binding not in text, f"{relative} retains active {binding}"

    adr = (ROOT / "docs/decisions/ADR-0002-lean-core-v0.2.md").read_text(
        encoding="utf-8"
    )
    assert "Historical acceptance record (non-operative)" in adr
    assert "Human-Reviewers:" not in adr
    assert "protected_surfaces:" not in adr

    for name in (
        "telemetry-cold-start-rollback.md",
        "telemetry-cold-start-rollback-v2.md",
        "telemetry-cold-start-rollback-v3.md",
    ):
        text = (ROOT / "docs/release" / name).read_text(encoding="utf-8")
        assert "non-operative record" in text
        assert "rollback-transcript" not in text
        assert "product-tree-manifest" not in text
        assert "implementation-tree-manifest" not in text


def test_review_audit_and_executable_crosswalk_are_release_carriers() -> None:
    audit = json.loads(
        (ROOT / "docs/release/lean-core-v0.2-review-audit.json").read_text(
            encoding="utf-8"
        )
    )
    crosswalk = json.loads(
        (ROOT / "docs/release/lean-core-v0.2-evidence-crosswalk.json").read_text(
            encoding="utf-8"
        )
    )
    assert audit["audit_date"] == "2026-08-12"
    assert "external publication unverified" in audit["compatibility_disposition"][
        "root_schemas"
    ].lower()
    assert len(
        [identifier for identifier in crosswalk["mappings"] if identifier.startswith("SEC-SINK-")]
    ) == 17
    assert all(
        record["candidate_result"] == "pass"
        for record in crosswalk["mappings"].values()
    )
