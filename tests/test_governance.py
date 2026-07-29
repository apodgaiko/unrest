"""Table-driven checks for Batch 0 change governance."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from unrest_harness.cli import cli
from unrest_harness.governance import (
    COMMIT_TRAILERS,
    REQUIRED_ACCOUNTABLE_ROLES,
    REQUIRED_EVALUATION_TIERS,
    REQUIRED_SELF_PROTECTION,
    WORKFLOW_TEMPLATE_CONTENT,
    WORKFLOW_TEMPLATE_FIELDS,
    GovernanceValidationError,
    check_commit_message,
    governance_report,
    load_component_paths,
    load_protected_surface_policy,
    render_policy_json_schema,
    resolve_path_category,
    validate_policy_components,
    validate_policy_data,
    validate_schema_change_data,
    validate_workflow_template,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "protected-surfaces.yaml"
COMPONENT_MAP_PATH = ROOT / "docs" / "architecture" / "component-map.json"
POLICY_SCHEMA_PATH = ROOT / "schemas" / "protected-surfaces.schema.json"
PR_TEMPLATE_PATH = ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
ADR_TEMPLATE_PATH = ROOT / "docs" / "templates" / "adr.md"


def _policy_data() -> dict[str, Any]:
    data = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _diagnostic_codes(error: GovernanceValidationError) -> set[str]:
    return {diagnostic.code for diagnostic in error.diagnostics}


def _assert_policy_error(data: dict[str, Any], expected_code: str) -> None:
    with pytest.raises(GovernanceValidationError) as captured:
        validate_policy_data(data)
    assert expected_code in _diagnostic_codes(captured.value)


def _current_policy_and_components():
    policy = load_protected_surface_policy(POLICY_PATH)
    components = load_component_paths(COMPONENT_MAP_PATH)
    validate_policy_components(policy, components)
    return policy, components


def _commit_message(**overrides: str) -> str:
    values = {
        "Task-ID": "B0-T3",
        "Contract-Targets": "VAL-GOV-001, VAL-GOV-002",
        "Decision-IDs": "none",
        "Protected-Surfaces": "none",
        "Human-Reviewers": "none",
        "Evaluation-Evidence": "none",
        "Schema-Change": "none",
        "Rollback-Plan": "none",
    }
    values.update(overrides)
    trailers = "\n".join(f"{key}: {values[key]}" for key in COMMIT_TRAILERS)
    return f"docs(governance): document change controls\n\n{trailers}\n"


def _schema_packet(mode: str, root: Path) -> dict[str, Any]:
    def write(relative: str, payload: bytes) -> str:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    previous_fixture = {
        "path": "tests/fixtures/schema/v1.json",
        "version": 1,
        "sha256": write(
            "tests/fixtures/schema/v1.json",
            b'{"schema_version":1,"value":"previous"}\n',
        ),
    }
    current_fixture = {
        "path": "tests/fixtures/schema/v2.json",
        "version": 2,
        "sha256": write(
            "tests/fixtures/schema/v2.json",
            b'{"schema_version":2,"value":"current"}\n',
        ),
    }

    def evidence(
        evidence_mode: str,
        fixture: dict[str, Any],
        observed_result: str,
        artifact_name: str,
    ) -> dict[str, Any]:
        artifact_path = f"evidence/schema/{artifact_name}.json"
        artifact_hash = write(
            artifact_path,
            (
                json.dumps(
                    {
                        "fixture_path": fixture["path"],
                        "mode": evidence_mode,
                        "observed_result": observed_result,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )
        write(
            f"evidence/schema/{artifact_name}.sh",
            (
                "#!/bin/sh\n"
                "set -eu\n"
                f"test -f {artifact_path}\n"
            ).encode(),
        )
        return {
            "mode": evidence_mode,
            "fixture_path": fixture["path"],
            "fixture_version": fixture["version"],
            "fixture_sha256": fixture["sha256"],
            "exact_check": f"sh evidence/schema/{artifact_name}.sh",
            "observed_result": observed_result,
            "exit_code": 0,
            "status": "passed",
            "artifact_path": artifact_path,
            "artifact_sha256": artifact_hash,
        }

    proof_result = (
        "old-fixtures-readable"
        if mode == "backward-compatible"
        else "unsupported-version-rejected"
    )
    return {
        "packet_version": 1,
        "change_id": f"SCHEMA-CHANGE-{mode.upper().replace('-', '-')}",
        "schema_id": "SCHEMA-PROTECTED-SURFACES-001",
        "from_version": 1,
        "to_version": 2,
        "compatibility": mode,
        "reason_code": (
            "SCHEMA-BACKWARD-COMPATIBLE"
            if mode == "backward-compatible"
            else "SCHEMA-HARD-CUT-UNSUPPORTED-V1"
        ),
        "reader_strategy": "explicit-version",
        "fixtures": {
            "previous": [previous_fixture],
            "current": [current_fixture],
        },
        "compatibility_proof": {
            "behavior": proof_result,
            "records": [
                evidence(
                    "compatibility",
                    previous_fixture,
                    proof_result,
                    "compatibility",
                )
            ],
        },
        "migration": evidence(
            "migration",
            current_fixture,
            "migration-complete",
            "migration",
        ),
        "recovery": evidence(
            "recovery",
            previous_fixture,
            "recovery-complete",
            "recovery",
        ),
        "rollback": evidence(
            "rollback",
            previous_fixture,
            "rollback-complete",
            "rollback",
        ),
    }


def test_checked_in_policy_schema_and_path_category_report_are_deterministic() -> None:
    policy, components = _current_policy_and_components()
    assert POLICY_SCHEMA_PATH.read_text(encoding="utf-8") == render_policy_json_schema()
    json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))

    paths = (
        "src/unrest_harness/coordinator.py",
        "src/unrest_harness/storage.py",
        "policy/capabilities/default.yaml",
        "evals/baseline/manifest.yaml",
        "policy/protected-surfaces.yaml",
        "policy/promotion/default.yaml",
        "policy/rollback/default.yaml",
        "schemas/protected-surfaces.schema.json",
    )
    report = governance_report(policy, components, tuple(reversed(paths)))
    assert report["path_categories"] == {
        "evals/baseline/manifest.yaml": "evaluation-holdouts",
        "policy/capabilities/default.yaml": "capability-policy",
        "policy/promotion/default.yaml": "promotion-policy",
        "policy/protected-surfaces.yaml": "governance-self-protection",
        "policy/rollback/default.yaml": "rollback-controls",
        "schemas/protected-surfaces.schema.json": "governance-self-protection",
        "src/unrest_harness/coordinator.py": "coordinator-semantics",
        "src/unrest_harness/storage.py": "storage-migrations",
    }
    assert list(report["path_categories"]) == sorted(report["path_categories"])
    assert set(report["self_protection"]) == set(REQUIRED_SELF_PROTECTION)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("unknown_key", "GOV-POLICY-FIELD-UNKNOWN"),
        ("wrong_type", "GOV-POLICY-VALUE-UNSUPPORTED"),
        ("missing_category", "GOV-POLICY-CATEGORIES-INCOMPLETE"),
        ("empty_selectors", "GOV-POLICY-VALUE-INVALID"),
        ("path_escape", "GOV-POLICY-PATH-INVALID"),
        ("ambiguous_selector", "GOV-POLICY-SELECTOR-AMBIGUOUS"),
        ("agent_accountable", "GOV-POLICY-VALUE-UNSUPPORTED"),
        ("missing_forbidden_kind", "GOV-POLICY-FORBIDDEN-KINDS-INCOMPLETE"),
        ("rollback_disabled", "GOV-POLICY-VALUE-UNSUPPORTED"),
        ("weak_evaluation", "GOV-POLICY-EVALUATION-WEAKENED"),
    ],
)
def test_policy_valid_invalid_table(mutation: str, expected_code: str) -> None:
    data = copy.deepcopy(_policy_data())
    if mutation == "unknown_key":
        data["owner"] = "agent"
    elif mutation == "wrong_type":
        data["schema_version"] = "1"
    elif mutation == "missing_category":
        data["protected_surfaces"].pop()
    elif mutation == "empty_selectors":
        data["protected_surfaces"][0]["selectors"] = []
    elif mutation == "path_escape":
        data["protected_surfaces"][0]["selectors"][0] = {
            "kind": "path",
            "value": "../outside",
        }
    elif mutation == "ambiguous_selector":
        surface = next(
            item for item in data["protected_surfaces"] if item["id"] == "promotion-policy"
        )
        surface["selectors"] = [
            {"kind": "path", "value": "policy/protected-surfaces.yaml"},
            {"kind": "path-prefix", "value": "policy/promotion/"},
        ]
    elif mutation == "agent_accountable":
        data["accountable_roles"][0]["kind"] = "agent"
    elif mutation == "missing_forbidden_kind":
        data["forbidden_approver_kinds"] = ["agent"]
    elif mutation == "rollback_disabled":
        data["protected_surfaces"][0]["rollback_plan_required"] = False
    else:
        surface = data["protected_surfaces"][0]
        surface["evaluation"]["tiers"].remove(
            sorted(REQUIRED_EVALUATION_TIERS[surface["id"]])[0]
        )
    _assert_policy_error(data, expected_code)


@pytest.mark.parametrize("control_id", sorted(REQUIRED_SELF_PROTECTION))
def test_each_self_protection_control_cannot_be_removed(control_id: str) -> None:
    data = copy.deepcopy(_policy_data())
    data["self_protection"] = [
        item for item in data["self_protection"] if item["id"] != control_id
    ]
    _assert_policy_error(data, "GOV-POLICY-SELF-PROTECTION-INCOMPLETE")


@pytest.mark.parametrize("control_id", sorted(REQUIRED_SELF_PROTECTION))
def test_each_self_protection_control_cannot_be_redirected(control_id: str) -> None:
    data = copy.deepcopy(_policy_data())
    control = next(item for item in data["self_protection"] if item["id"] == control_id)
    control["selector"]["value"] = (
        "docs/" if control["selector"]["kind"] == "path-prefix" else "README.md"
    )
    _assert_policy_error(data, "GOV-POLICY-SELF-PROTECTION-WEAKENED")


@pytest.mark.parametrize(
    ("weakening", "expected_code"),
    [
        ("reviewers", "GOV-POLICY-REVIEWERS-INCOMPLETE"),
        ("evaluation", "GOV-POLICY-EVALUATION-WEAKENED"),
        ("rollback", "GOV-POLICY-VALUE-UNSUPPORTED"),
    ],
)
@pytest.mark.parametrize("surface_index", range(7))
def test_each_category_rejects_review_evaluation_or_rollback_weakening(
    surface_index: int,
    weakening: str,
    expected_code: str,
) -> None:
    data = copy.deepcopy(_policy_data())
    surface = data["protected_surfaces"][surface_index]
    if weakening == "reviewers":
        surface["reviewer_roles"] = ["release-maintainer"]
    elif weakening == "evaluation":
        surface["evaluation"]["tiers"].remove(
            sorted(REQUIRED_EVALUATION_TIERS[surface["id"]])[0]
        )
    else:
        surface["rollback_plan_required"] = False
    _assert_policy_error(data, expected_code)


def test_unknown_component_and_runtime_path_ambiguity_fail_closed() -> None:
    data = copy.deepcopy(_policy_data())
    coordinator = next(
        item for item in data["protected_surfaces"] if item["id"] == "coordinator-semantics"
    )
    coordinator["selectors"][0]["value"] = "COMP-NOT-REGISTERED"
    policy = validate_policy_data(data)
    with pytest.raises(GovernanceValidationError) as unknown:
        validate_policy_components(policy, load_component_paths(COMPONENT_MAP_PATH))
    assert "GOV-POLICY-COMPONENT-UNKNOWN" in _diagnostic_codes(unknown.value)

    policy, components = _current_policy_and_components()
    ambiguous_components = dict(components)
    ambiguous_components["COMP-STORAGE"] = (
        *ambiguous_components["COMP-STORAGE"],
        "src/unrest_harness/coordinator.py",
    )
    with pytest.raises(GovernanceValidationError) as ambiguous:
        resolve_path_category(
            policy,
            ambiguous_components,
            "src/unrest_harness/coordinator.py",
        )
    assert "GOV-POLICY-PATH-AMBIGUOUS" in _diagnostic_codes(ambiguous.value)


def test_ordinary_and_protected_commit_messages_are_valid() -> None:
    policy, components = _current_policy_and_components()
    ordinary = check_commit_message(
        _commit_message(),
        changed_paths=("README.md",),
        policy=policy,
        component_paths=components,
    )
    assert ordinary.protected_surfaces == ()

    protected = check_commit_message(
        _commit_message(
            **{
                "Protected-Surfaces": "governance-self-protection",
                "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                "Evaluation-Evidence": "evidence/governance/full-gate.json",
                "Rollback-Plan": "docs/rollback/governance.md",
            }
        ),
        changed_paths=("policy/protected-surfaces.yaml",),
        policy=policy,
        component_paths=components,
    )
    assert protected.protected_surfaces == ("governance-self-protection",)

    schema_change = check_commit_message(
        _commit_message(
            **{
                "Protected-Surfaces": "governance-self-protection",
                "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                "Evaluation-Evidence": "evidence/governance/full-gate.json",
                "Schema-Change": "evidence/governance/schema-change.yaml",
                "Rollback-Plan": "docs/rollback/governance.md",
            }
        ),
        changed_paths=("schemas/protected-surfaces.schema.json",),
        policy=policy,
        component_paths=components,
    )
    assert schema_change.protected_surfaces == ("governance-self-protection",)


@pytest.mark.parametrize("missing_trailer", COMMIT_TRAILERS)
def test_each_required_commit_trailer_has_stable_missing_diagnostic(
    missing_trailer: str,
) -> None:
    policy, components = _current_policy_and_components()
    message = _commit_message()
    line = next(
        line for line in message.splitlines() if line.startswith(f"{missing_trailer}:")
    )
    message = message.replace(f"{line}\n", "", 1)
    with pytest.raises(GovernanceValidationError) as captured:
        check_commit_message(
            message,
            changed_paths=("README.md",),
            policy=policy,
            component_paths=components,
        )
    assert "GOV-COMMIT-TRAILER-MISSING" in _diagnostic_codes(captured.value)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("duplicate", "GOV-COMMIT-TRAILER-DUPLICATE"),
        ("unknown", "GOV-COMMIT-TRAILER-UNKNOWN"),
        ("order", "GOV-COMMIT-TRAILER-ORDER"),
        ("format", "GOV-COMMIT-TRAILER-FORMAT"),
        ("summary", "GOV-COMMIT-SUBJECT-SUMMARY"),
        ("length", "GOV-COMMIT-SUBJECT-LENGTH"),
    ],
)
def test_commit_grammar_mutations_have_stable_diagnostics(
    mutation: str,
    expected_code: str,
) -> None:
    policy, components = _current_policy_and_components()
    message = _commit_message()
    if mutation == "duplicate":
        message = message.replace("Task-ID: B0-T3\n", "Task-ID: B0-T3\nTask-ID: B0-T3\n")
    elif mutation == "unknown":
        message = message.replace("Task-ID: B0-T3\n", "Task-ID: B0-T3\nOwner: nobody\n")
    elif mutation == "order":
        lines = message.splitlines()
        task_index = lines.index("Task-ID: B0-T3")
        contract_index = lines.index("Contract-Targets: VAL-GOV-001, VAL-GOV-002")
        lines[task_index], lines[contract_index] = lines[contract_index], lines[task_index]
        message = "\n".join(lines) + "\n"
    elif mutation == "format":
        message = message.replace("Task-ID: B0-T3", "Task-ID = B0-T3")
    elif mutation == "summary":
        message = message.replace(
            "docs(governance): document change controls",
            "docs(governance): Document change controls.",
        )
    else:
        message = message.replace(
            "docs(governance): document change controls",
            "docs(governance): document change controls with a subject that is far too long",
        )
    with pytest.raises(GovernanceValidationError) as captured:
        check_commit_message(
            message,
            changed_paths=("README.md",),
            policy=policy,
            component_paths=components,
        )
    assert expected_code in _diagnostic_codes(captured.value)


@pytest.mark.parametrize(
    ("message", "changed_path", "expected_code"),
    [
        (
            _commit_message().replace(
                "docs(governance): document change controls",
                "Document governance",
            ),
            "README.md",
            "GOV-COMMIT-SUBJECT-FORMAT",
        ),
        (
            _commit_message().replace("docs(governance)", "unknown(governance)"),
            "README.md",
            "GOV-COMMIT-SUBJECT-TYPE",
        ),
        (
            _commit_message(
                **{
                    "Protected-Surfaces": "none",
                    "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                    "Evaluation-Evidence": "evidence/full-gate.json",
                    "Rollback-Plan": "docs/rollback.md",
                }
            ),
            "policy/protected-surfaces.yaml",
            "GOV-COMMIT-PROTECTED-SURFACES-MISMATCH",
        ),
        (
            _commit_message(
                **{
                    "Protected-Surfaces": "governance-self-protection",
                    "Human-Reviewers": "agent-worker, release-maintainer",
                    "Evaluation-Evidence": "evidence/full-gate.json",
                    "Rollback-Plan": "docs/rollback.md",
                }
            ),
            "policy/protected-surfaces.yaml",
            "GOV-COMMIT-APPROVER-KIND-FORBIDDEN",
        ),
        (
            _commit_message(
                **{
                    "Protected-Surfaces": "governance-self-protection",
                    "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                    "Evaluation-Evidence": "none",
                    "Rollback-Plan": "docs/rollback.md",
                }
            ),
            "policy/protected-surfaces.yaml",
            "GOV-COMMIT-PROTECTED-EVALUATION",
        ),
        (
            _commit_message(
                **{
                    "Protected-Surfaces": "governance-self-protection",
                    "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                    "Evaluation-Evidence": "evidence/full-gate.json",
                    "Rollback-Plan": "none",
                }
            ),
            "policy/protected-surfaces.yaml",
            "GOV-COMMIT-PROTECTED-ROLLBACK",
        ),
        (
            _commit_message(
                **{
                    "Protected-Surfaces": "governance-self-protection",
                    "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                    "Evaluation-Evidence": "evidence/full-gate.json",
                    "Rollback-Plan": "docs/rollback.md",
                }
            ),
            "schemas/protected-surfaces.schema.json",
            "GOV-COMMIT-SCHEMA-PACKET-MISSING",
        ),
    ],
)
def test_invalid_commit_table_has_stable_errors(
    message: str,
    changed_path: str,
    expected_code: str,
) -> None:
    policy, components = _current_policy_and_components()
    with pytest.raises(GovernanceValidationError) as captured:
        check_commit_message(
            message,
            changed_paths=(changed_path,),
            policy=policy,
            component_paths=components,
        )
    assert expected_code in _diagnostic_codes(captured.value)


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
def test_workflow_templates_parse_and_each_field_has_stable_diagnostic(
    template_kind: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    validate_workflow_template(template_kind, text)
    for field in WORKFLOW_TEMPLATE_FIELDS[template_kind]:
        mutated = text.replace(f"<!-- GOV-FIELD:{field} -->", "", 1)
        with pytest.raises(GovernanceValidationError) as captured:
            validate_workflow_template(template_kind, mutated)
        assert "GOV-TEMPLATE-FIELD-MISSING" in _diagnostic_codes(captured.value)


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
def test_marker_only_workflow_templates_are_rejected(
    template_kind: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    marker_only = "\n".join(
        line
        for line in text.splitlines()
        if line.startswith("<!-- GOV-FIELD:")
    )

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, marker_only)

    assert _diagnostic_codes(captured.value) == {"GOV-TEMPLATE-FIELD-MISSING"}


@pytest.mark.parametrize(
    ("template_kind", "field"),
    [
        (template_kind, field)
        for template_kind in sorted(WORKFLOW_TEMPLATE_FIELDS)
        for field in WORKFLOW_TEMPLATE_FIELDS[template_kind]
    ],
)
def test_workflow_field_content_cannot_be_replaced_by_a_comment(
    template_kind: str,
    field: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    required_content = WORKFLOW_TEMPLATE_CONTENT[template_kind][field][0]
    mutated = text.replace(required_content, f"<!-- {required_content} -->", 1)

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, mutated)

    diagnostics = [
        diagnostic
        for diagnostic in captured.value.diagnostics
        if diagnostic.location == f"{template_kind}.{field}"
    ]
    assert {diagnostic.code for diagnostic in diagnostics} == {
        "GOV-TEMPLATE-FIELD-MISSING"
    }


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
@pytest.mark.parametrize("container", ["fence", "comment"])
def test_workflow_fields_inside_fences_or_comments_are_not_operational(
    template_kind: str,
    container: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    hidden = (
        f"```markdown\n{text}```\n"
        if container == "fence"
        else f"<!--\n{text}\n-->\n"
    )

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, hidden)

    assert "GOV-TEMPLATE-FIELD-MISSING" in _diagnostic_codes(captured.value)


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
@pytest.mark.parametrize("container", ["blockquote", "list"])
def test_workflow_fields_require_top_level_commonmark_ancestry(
    template_kind: str,
    container: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    nested = (
        "\n".join(f"> {line}" for line in text.splitlines()) + "\n"
        if container == "blockquote"
        else "- workflow example\n\n  " + text.replace("\n", "\n  ")
    )

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, nested)

    assert "GOV-TEMPLATE-FIELD-MISSING" in _diagnostic_codes(captured.value)


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
def test_fenced_markers_do_not_satisfy_visible_workflow_content(
    template_kind: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    field = WORKFLOW_TEMPLATE_FIELDS[template_kind][0]
    marker = f"<!-- GOV-FIELD:{field} -->"
    mutated = text.replace(marker, f"```markdown\n{marker}\n```", 1)

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, mutated)

    diagnostics = [
        diagnostic
        for diagnostic in captured.value.diagnostics
        if diagnostic.location == f"{template_kind}.{field}"
    ]
    assert {diagnostic.code for diagnostic in diagnostics} == {
        "GOV-TEMPLATE-FIELD-MISSING"
    }


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
def test_inline_comment_marker_is_not_an_operative_workflow_field(
    template_kind: str,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    field = WORKFLOW_TEMPLATE_FIELDS[template_kind][0]
    marker = f"<!-- GOV-FIELD:{field} -->"
    mutated = text.replace(marker, f"prose {marker} prose", 1)

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, mutated)

    assert any(
        diagnostic.code == "GOV-TEMPLATE-FIELD-MISSING"
        and diagnostic.location == f"{template_kind}.{field}"
        for diagnostic in captured.value.diagnostics
    )


@pytest.mark.parametrize("template_kind", sorted(WORKFLOW_TEMPLATE_FIELDS))
@pytest.mark.parametrize("fence_character", ["`", "~"])
@pytest.mark.parametrize("fence_length", [3, 4, 5])
def test_commonmark_pseudo_closing_fences_hide_all_workflow_fields(
    template_kind: str,
    fence_character: str,
    fence_length: int,
) -> None:
    path = ADR_TEMPLATE_PATH if template_kind == "adr" else PR_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    fence = fence_character * fence_length
    payload = f"{fence}markdown\n{fence}not-a-close\n{text}\n{fence}\n"

    with pytest.raises(GovernanceValidationError) as captured:
        validate_workflow_template(template_kind, payload)

    missing_locations = {
        diagnostic.location
        for diagnostic in captured.value.diagnostics
        if diagnostic.code == "GOV-TEMPLATE-FIELD-MISSING"
    }
    assert missing_locations == {
        f"{template_kind}.{field}" for field in WORKFLOW_TEMPLATE_FIELDS[template_kind]
    }


@pytest.mark.parametrize("indent", [" ", "  ", "   "])
def test_commonmark_indented_atx_and_setext_workflow_headings_are_operative(
    indent: str,
) -> None:
    pull_request = PR_TEMPLATE_PATH.read_text(encoding="utf-8").replace(
        "## Scope and stable IDs",
        f"{indent}## Scope and stable IDs",
        1,
    )
    validate_workflow_template("pull-request", pull_request)

    adr = ADR_TEMPLATE_PATH.read_text(encoding="utf-8").replace(
        "## Scope",
        "Scope\n-----",
        1,
    )
    validate_workflow_template("adr", adr)


@pytest.mark.parametrize("mode", ["backward-compatible", "hard-cut"])
def test_schema_evolution_compatible_and_hard_cut_packets_are_valid(
    mode: str,
    tmp_path: Path,
) -> None:
    packet = validate_schema_change_data(
        _schema_packet(mode, tmp_path),
        repository_root=tmp_path,
    )
    assert packet.to_version > packet.from_version
    assert packet.reader_strategy == "explicit-version"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("same_version", "GOV-SCHEMA-VERSION-NOT-INCREMENTED"),
        ("heuristic_reader", "GOV-SCHEMA-VALUE-UNSUPPORTED"),
        ("missing_fixtures", "GOV-SCHEMA-FIELD-MISSING"),
        ("empty_migration", "GOV-SCHEMA-VALUE-INVALID"),
        ("missing_recovery", "GOV-SCHEMA-FIELD-MISSING"),
        ("missing_rollback", "GOV-SCHEMA-FIELD-MISSING"),
        ("unstable_reason", "GOV-SCHEMA-VALUE-UNSUPPORTED"),
        ("contradictory_reason", "GOV-SCHEMA-REASON-CONTRADICTORY"),
        ("overlapping_fixtures", "GOV-SCHEMA-FIXTURES-OVERLAP"),
        ("identical_fixtures", "GOV-SCHEMA-FIXTURES-OVERLAP"),
        ("placeholder_evidence", "GOV-SCHEMA-EVIDENCE-CHECK-INVALID"),
        ("proof_mode", "GOV-SCHEMA-PROOF-MODE-MISMATCH"),
        ("proof_version", "GOV-SCHEMA-PROOF-FIXTURE-MISMATCH"),
        ("proof_fixture", "GOV-SCHEMA-PROOF-FIXTURE-UNKNOWN"),
        ("operation_mode", "GOV-SCHEMA-EVIDENCE-MODE-MISMATCH"),
        ("reused_artifact", "GOV-SCHEMA-EVIDENCE-REUSED"),
        ("unknown_field", "GOV-SCHEMA-FIELD-UNKNOWN"),
    ],
)
def test_schema_evolution_invalid_table_has_stable_errors(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    data = _schema_packet("hard-cut", tmp_path)
    if mutation == "same_version":
        data["to_version"] = data["from_version"]
    elif mutation == "heuristic_reader":
        data["reader_strategy"] = "guess-from-shape"
    elif mutation == "missing_fixtures":
        data.pop("fixtures")
    elif mutation == "empty_migration":
        data["migration"]["exact_check"] = ""
    elif mutation == "missing_recovery":
        data.pop("recovery")
    elif mutation == "missing_rollback":
        data.pop("rollback")
    elif mutation == "unstable_reason":
        data["reason_code"] = "temporary reason"
    elif mutation == "contradictory_reason":
        data["reason_code"] = "SCHEMA-BACKWARD-COMPATIBLE"
    elif mutation == "overlapping_fixtures":
        data["fixtures"]["current"] = list(data["fixtures"]["previous"])
    elif mutation == "identical_fixtures":
        data["fixtures"]["current"][0]["sha256"] = data["fixtures"]["previous"][0][
            "sha256"
        ]
    elif mutation == "placeholder_evidence":
        data["migration"]["exact_check"] = "will attach the report later"
    elif mutation == "proof_mode":
        data["compatibility_proof"]["records"][0][
            "observed_result"
        ] = "old-fixtures-readable"
    elif mutation == "proof_version":
        data["compatibility_proof"]["records"][0]["fixture_version"] = 0
    elif mutation == "proof_fixture":
        data["compatibility_proof"]["records"][0][
            "fixture_path"
        ] = "tests/fixtures/schema/v0.json"
    elif mutation == "operation_mode":
        data["recovery"]["mode"] = "rollback"
    elif mutation == "reused_artifact":
        data["rollback"]["artifact_path"] = data["recovery"]["artifact_path"]
        data["rollback"]["artifact_sha256"] = data["recovery"]["artifact_sha256"]
    else:
        data["reader_fallback"] = True
    with pytest.raises(GovernanceValidationError) as captured:
        validate_schema_change_data(data, repository_root=tmp_path)
    assert expected_code in _diagnostic_codes(captured.value)


@pytest.mark.parametrize("mode", ["backward-compatible", "hard-cut"])
@pytest.mark.parametrize(
    "deferred_value",
    [
        "TBD once schema tests exist",
        "TODO - replace with a concrete procedure",
        "TO-DO after the migration is implemented",
        "placeholder evidence to be supplied later",
        "Evidence will be supplied later",
        "Evidence coming soon",
        "not yet available",
        "once the tests are available",
        "pending reviewer evidence",
        "uv run pytest tests/test_schema.py will confirm later",
        "artifact reports readable",
    ],
)
def test_schema_evolution_rejects_semantically_deferred_evidence(
    mode: str,
    deferred_value: str,
    tmp_path: Path,
) -> None:
    data = _schema_packet(mode, tmp_path)
    data["migration"]["exact_check"] = deferred_value

    with pytest.raises(GovernanceValidationError) as captured:
        validate_schema_change_data(data, repository_root=tmp_path)

    assert "GOV-SCHEMA-EVIDENCE-CHECK-INVALID" in _diagnostic_codes(captured.value)


@pytest.mark.parametrize(
    ("mode", "field", "value"),
    [
        (
            "backward-compatible",
            "observed_result",
            "unsupported-version-rejected",
        ),
        (
            "hard-cut",
            "observed_result",
            "old-fixtures-readable",
        ),
        ("backward-compatible", "exit_code", 1),
        ("hard-cut", "status", "pending"),
        ("hard-cut", "artifact_sha256", "not-a-hash"),
    ],
)
def test_schema_compatibility_proof_requires_typed_mode_specific_results(
    mode: str,
    field: str,
    value: object,
    tmp_path: Path,
) -> None:
    data = _schema_packet(mode, tmp_path)
    data["compatibility_proof"]["records"][0][field] = value

    with pytest.raises(GovernanceValidationError) as captured:
        validate_schema_change_data(data, repository_root=tmp_path)

    assert _diagnostic_codes(captured.value)


@pytest.mark.parametrize("mode", ["backward-compatible", "hard-cut"])
def test_schema_compatibility_proof_exposes_complete_typed_evidence(
    mode: str,
    tmp_path: Path,
) -> None:
    data = _schema_packet(mode, tmp_path)

    packet = validate_schema_change_data(data, repository_root=tmp_path)
    record = packet.compatibility_proof.records[0]

    assert record.mode == "compatibility"
    assert record.exit_code == 0
    assert record.status == "passed"
    assert len(record.fixture_sha256) == len(record.artifact_sha256) == 64
    assert record.exact_check.startswith("sh evidence/schema/")


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_fixture", "GOV-SCHEMA-FIXTURE-FILE-MISSING"),
        ("wrong_fixture_hash", "GOV-SCHEMA-FIXTURE-HASH-MISMATCH"),
        ("missing_artifact", "GOV-SCHEMA-EVIDENCE-FILE-MISSING"),
        ("wrong_artifact_hash", "GOV-SCHEMA-EVIDENCE-HASH-MISMATCH"),
        ("fake_true", "GOV-SCHEMA-EVIDENCE-CHECK-INVALID"),
        ("fake_false", "GOV-SCHEMA-EVIDENCE-CHECK-INVALID"),
        ("missing_command", "GOV-SCHEMA-EVIDENCE-CHECK-INVALID"),
        ("failing_check", "GOV-SCHEMA-EVIDENCE-CHECK-FAILED"),
        ("unsafe_check", "GOV-SCHEMA-EVIDENCE-CHECK-UNSAFE"),
        ("unbound_check", "GOV-SCHEMA-EVIDENCE-CHECK-UNSAFE"),
        ("same_path_different_hash", "GOV-SCHEMA-EVIDENCE-RELATIONSHIP-CONFLICT"),
        ("same_hash_different_path", "GOV-SCHEMA-EVIDENCE-RELATIONSHIP-CONFLICT"),
        ("repeated_separator", "GOV-SCHEMA-FIXTURE-PATH-INVALID"),
    ],
)
def test_schema_evidence_provenance_rejects_unbound_or_false_claims(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    data = _schema_packet("backward-compatible", tmp_path)
    previous = data["fixtures"]["previous"][0]
    compatibility = data["compatibility_proof"]["records"][0]
    if mutation == "missing_fixture":
        previous["path"] = "tests/fixtures/schema/missing.json"
        for record in (compatibility, data["recovery"], data["rollback"]):
            record["fixture_path"] = previous["path"]
    elif mutation == "wrong_fixture_hash":
        previous["sha256"] = "9" * 64
        for record in (compatibility, data["recovery"], data["rollback"]):
            record["fixture_sha256"] = previous["sha256"]
    elif mutation == "missing_artifact":
        compatibility["artifact_path"] = "evidence/schema/missing.json"
        compatibility["exact_check"] = "sh evidence/schema/missing.sh"
    elif mutation == "wrong_artifact_hash":
        compatibility["artifact_sha256"] = "9" * 64
    elif mutation == "fake_true":
        compatibility["exact_check"] = "true --pretend-compatibility"
    elif mutation == "fake_false":
        compatibility["exact_check"] = "/bin/false"
    elif mutation == "missing_command":
        compatibility["exact_check"] = "missing-schema-check --verify"
    elif mutation == "failing_check":
        artifact = tmp_path / compatibility["artifact_path"]
        artifact.write_bytes(b"")
        compatibility["artifact_sha256"] = hashlib.sha256(b"").hexdigest()
        (tmp_path / "evidence/schema/compatibility.sh").write_text(
            "#!/bin/sh\nset -eu\ntest -s evidence/schema/compatibility.json\n",
            encoding="utf-8",
        )
    elif mutation == "unsafe_check":
        (tmp_path / "evidence/schema/compatibility.sh").write_text(
            "#!/bin/sh\ntouch evidence/schema/unsafe-side-effect\n",
            encoding="utf-8",
        )
    elif mutation == "unbound_check":
        (tmp_path / "evidence/schema/compatibility.sh").write_text(
            "#!/bin/sh\nset -eu\ntest -f tests/fixtures/schema/v1.json\n",
            encoding="utf-8",
        )
    elif mutation == "same_path_different_hash":
        data["rollback"]["artifact_path"] = data["recovery"]["artifact_path"]
        data["rollback"]["artifact_sha256"] = "9" * 64
        data["rollback"]["exact_check"] = "sh evidence/schema/recovery.sh"
    elif mutation == "same_hash_different_path":
        data["rollback"]["artifact_sha256"] = data["recovery"]["artifact_sha256"]
    else:
        previous["path"] = "tests//fixtures/schema/v1.json"
        for record in (compatibility, data["recovery"], data["rollback"]):
            record["fixture_path"] = previous["path"]

    with pytest.raises(GovernanceValidationError) as captured:
        validate_schema_change_data(data, repository_root=tmp_path)

    assert expected_code in _diagnostic_codes(captured.value)
    assert str(tmp_path) not in str(captured.value)
    assert not (tmp_path / "evidence/schema/unsafe-side-effect").exists()


def test_cli_governance_report_and_commit_check_exercise_real_commands(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    report = runner.invoke(
        cli,
        [
            "check-governance",
            "--policy",
            str(POLICY_PATH),
            "--component-map",
            str(COMPONENT_MAP_PATH),
            "--path",
            "policy/protected-surfaces.yaml",
        ],
    )
    assert report.exit_code == 0, report.output
    assert json.loads(report.output)["path_categories"] == {
        "policy/protected-surfaces.yaml": "governance-self-protection"
    }

    message_path = tmp_path / "COMMIT_EDITMSG"
    message_path.write_text(
        _commit_message(
            **{
                "Protected-Surfaces": "governance-self-protection",
                "Human-Reviewers": ", ".join(REQUIRED_ACCOUNTABLE_ROLES),
                "Evaluation-Evidence": "evidence/governance/full-gate.json",
                "Rollback-Plan": "docs/rollback/governance.md",
            }
        ),
        encoding="utf-8",
    )
    commit = runner.invoke(
        cli,
        [
            "check-commit",
            "--message-file",
            str(message_path),
            "--changed-path",
            "policy/protected-surfaces.yaml",
            "--policy",
            str(POLICY_PATH),
            "--component-map",
            str(COMPONENT_MAP_PATH),
        ],
    )
    assert commit.exit_code == 0, commit.output
    assert json.loads(commit.output) == {
        "protected_surfaces": ["governance-self-protection"],
        "status": "ok",
    }


def test_governance_does_not_claim_nonexistent_promotion_runtime() -> None:
    text = (
        ROOT / "docs" / "architecture" / "change-governance.md"
    ).read_text(encoding="utf-8")
    assert "does not implement a promotion service" in " ".join(text.split())
    assert "deliberately does not add" in text
    assert not (ROOT / "src" / "unrest_harness" / "promotion.py").exists()
