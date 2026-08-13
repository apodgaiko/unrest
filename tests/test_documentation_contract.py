"""Focused documentation authority checks retained by Lean Core."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RELEASE_BINDING_SPEC = importlib.util.spec_from_file_location(
    "release_binding", ROOT / "tools/release_binding.py"
)
assert RELEASE_BINDING_SPEC is not None and RELEASE_BINDING_SPEC.loader is not None
release_binding = importlib.util.module_from_spec(RELEASE_BINDING_SPEC)
RELEASE_BINDING_SPEC.loader.exec_module(release_binding)


def _assert_external_publication_carrier(
    publication: dict[str, object], carrier_texts: tuple[str, ...]
) -> None:
    assert publication["status"] == "external-evidence-required"
    assert publication["evidence_owner"] == "pull-request-6-body"
    assert publication["carrier_role"] == "immutable-procedure-and-local-checkpoint"
    assert publication["exact_head_procedure"] == (
        "resolve the live PR #6 head SHA; require local HEAD, tracking ref, live PR "
        "head, and successful ci.yml run headSha to equal it; download the named "
        "artifact from that run and verify its SHA256SUMS before installation"
    )
    impossible_self_fields = {
        "head_sha",
        "publication_commit",
        "github_run_id",
        "github_artifact_id",
    }
    assert impossible_self_fields.isdisjoint(publication)

    normalized = " ".join(carrier_texts).lower()
    assert "awaiting-exact-head-ci" not in normalized
    assert "awaiting exact publication" not in normalized
    assert "required-null" not in normalized


def test_external_publication_carrier_schema_rejects_pending_null_and_self_reference(
) -> None:
    external_model: dict[str, object] = {
        "status": "external-evidence-required",
        "evidence_owner": "pull-request-6-body",
        "carrier_role": "immutable-procedure-and-local-checkpoint",
        "exact_head_procedure": (
            "resolve the live PR #6 head SHA; require local HEAD, tracking ref, live "
            "PR head, and successful ci.yml run headSha to equal it; download the "
            "named artifact from that run and verify its SHA256SUMS before installation"
        ),
    }
    _assert_external_publication_carrier(
        external_model,
        (
            "Immutable carrier; current commit/run/artifact evidence is in PR #6.",
            "Use the deterministic exact-head procedure.",
        ),
    )

    invalid_models = (
        {**external_model, "status": "awaiting-exact-head-ci"},
        {**external_model, "head_sha": None},
        {**external_model, "github_run_id": None},
        {**external_model, "github_artifact_id": 123456},
        {**external_model, "publication_commit": "deadbeef"},
    )
    for invalid_model in invalid_models:
        with pytest.raises(AssertionError):
            _assert_external_publication_carrier(invalid_model, ("carrier",))

    for invalid_text in (
        "status: awaiting-exact-head-ci",
        "awaiting exact publication commit",
        "required-null publication identifiers are final",
    ):
        with pytest.raises(AssertionError):
            _assert_external_publication_carrier(external_model, (invalid_text,))


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


def test_canonical_mcp_docs_enumerate_all_four_isolated_modes() -> None:
    mcp_surface = (ROOT / "docs/v5/08-mcp-surface.md").read_text(encoding="utf-8")
    runtime = (ROOT / "docs/v5/07-runtime-architecture.md").read_text(
        encoding="utf-8"
    )

    assert "--mode orchestrator|worker|validator|terminal-reviewer" in mcp_surface
    for heading in (
        "### Orchestrator mode",
        "### Worker mode",
        "### Validator mode",
        "### Terminal-reviewer mode",
    ):
        assert heading in mcp_surface
    assert "server identity `unrest-validator`" in mcp_surface
    assert "`Mode: validator` instructions" in mcp_surface
    assert (
        "does not inherit worker identity, instructions, or authority" in mcp_surface
    )
    assert (
        "orchestrator, worker, validator, and terminal-reviewer modes" in runtime
    )
    assert "strict `end_node` completion protocol" in runtime


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
    manifest = json.loads(
        (ROOT / "docs/release/lean-core-v0.2-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    release = (ROOT / "docs/release/lean-core-v0.2.md").read_text(encoding="utf-8")
    rollback = (ROOT / "docs/release/lean-core-v0.2-rollback.md").read_text(
        encoding="utf-8"
    )

    tracked_paths = release_binding.tracked_regular_paths(ROOT)
    computed = release_binding.inventory(ROOT, tracked_paths)
    computed_binding = {
        "files": computed["files"],
        "sha256": computed["sha256"],
        "paths": ["pyproject.toml", "uv.lock", "src/**", "tests/**", "tools/**"],
    }

    def assert_carrier_bindings(
        candidate_manifest: dict[str, object],
        candidate_audit: dict[str, object],
        candidate_crosswalk: dict[str, object],
    ) -> None:
        current = candidate_manifest["source"]["final_product_package_test"]  # type: ignore[index]
        assert current == computed_binding
        assert candidate_audit["candidate_binding"] == current
        assert candidate_crosswalk["candidate"] == current

    assert_carrier_bindings(manifest, audit, crosswalk)

    zero_digest = "0" * 64
    zero_manifest = json.loads(json.dumps(manifest))
    zero_audit = json.loads(json.dumps(audit))
    zero_crosswalk = json.loads(json.dumps(crosswalk))
    zero_manifest["source"]["final_product_package_test"]["sha256"] = zero_digest
    zero_audit["candidate_binding"]["sha256"] = zero_digest
    zero_crosswalk["candidate"]["sha256"] = zero_digest
    with pytest.raises(AssertionError):
        assert_carrier_bindings(zero_manifest, zero_audit, zero_crosswalk)

    single_carrier_audit = json.loads(json.dumps(audit))
    single_carrier_audit["candidate_binding"]["sha256"] = zero_digest
    with pytest.raises(AssertionError):
        assert_carrier_bindings(manifest, single_carrier_audit, crosswalk)

    superseded = manifest["superseded_evidence"]
    assert superseded["repository_head_at_checkpoint"].startswith("6cf713c")
    assert superseded["product_package_test"]["sha256"] == (
        "cc9ec091838a4c8ac2845a2bdcba44ed151b50e92e833e6d4531b665e1e2ef3a"
    )
    assert superseded["artifacts"]["wheel"]["sha256"] == (
        "44808498624b50bf7e44eff8c80ecc5fe0021b445f6e4a8204ff8387addbab97"
    )
    assert superseded["status"] == "historical-superseded"
    assert manifest["source"]["repository_head_at_checkpoint"].startswith("d5fff4d")
    for carrier in (release, rollback):
        normalized = " ".join(carrier.split())
        assert "6cf713c..HEAD" not in carrier
        assert "6cf713c` was the checked-out commit" in normalized
        assert "not the content identity" in normalized
        assert "historical and superseded" in normalized
    assert "exact publication commit and successful exact-head CI" in " ".join(
        release.split()
    )

    assert audit["audit_date"] == "2026-08-13"
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
