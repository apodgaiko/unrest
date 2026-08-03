"""Focused checks for the Batch 0 guidance and documentation contract."""
from __future__ import annotations

import copy
import glob
import io
import json
import os
import re
import subprocess
import tokenize
from pathlib import Path
from typing import Any

import pytest

from unrest_harness.assets import parse_frontmatter
from unrest_harness.governance import parse_commonmark
from unrest_harness.repository_contract import _identity_private_marker_categories


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE_DIR = ROOT / "docs" / "architecture"
NORMATIVE_POLICY_PATH = ARCHITECTURE_DIR / "normative-documents.json"
COMPONENT_MAP_PATH = ARCHITECTURE_DIR / "component-map.json"
ID_REGISTRY_PATH = ARCHITECTURE_DIR / "id-registry.json"
REMOVAL_REGISTRY_PATH = ARCHITECTURE_DIR / "removal-registry.json"
ANNOTATION_POLICY_PATH = ARCHITECTURE_DIR / "annotation-policy.json"

EXPECTED_GUIDANCE = {
    "AGENTS.md",
    "evals/AGENTS.md",
    "src/unrest_harness/AGENTS.md",
    "src/unrest_harness/bundled/AGENTS.md",
    "tests/AGENTS.md",
}
EXPECTED_INDEX_TARGETS = {
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/architecture/annotation-policy.json",
    "docs/architecture/annotations.md",
    "docs/architecture/change-governance.md",
    "docs/architecture/component-map.json",
    "docs/architecture/evidence-policy.json",
    "docs/architecture/historical-record-policy.json",
    "docs/architecture/id-registry.json",
    "docs/architecture/normative-documents.json",
    "docs/architecture/removal-registry.json",
    "docs/decisions/index.md",
    "docs/architecture/template-heading-policy.json",
    "docs/templates/adr.md",
    "docs/templates/change-closeout.md",
    "docs/templates/implementation-plan.md",
    "docs/templates/task-packet.md",
    "docs/v5/07-runtime-architecture.md",
    "docs/v5/08-mcp-surface.md",
    "docs/v5/10-implementation-plan.md",
    "policy/protected-surfaces.yaml",
    "schemas/protected-surfaces.schema.json",
    "specs/memory_v2/PRODUCT.md",
    "specs/task_list/PRODUCT.md",
}
TEMPLATE_FIELDS = {
    "TPL-ADR-001": (
        "## Record metadata",
        "## Scope",
        "## Context",
        "## Decision",
        "## Alternatives considered",
        "## Consequences",
        "## Protected-surface review",
        "## Rollback",
        "## Implementation and verification",
        "## References",
    ),
    "TPL-CLOSEOUT-001": (
        "task_id:",
        "status:",
        "base_sha:",
        "result_sha:",
        "scope_completed:",
        "files_changed:",
        "public_or_persisted_changes:",
        "invariants_and_decisions:",
        "contract_targets:",
        "verification:",
        "evaluation_or_evidence:",
        "risks_or_unknowns:",
        "rollback:",
        "follow_ons:",
        "required:",
        "optional:",
    ),
    "TPL-PLAN-001": (
        "## Plan identity",
        "## Objective and success criteria",
        "## Current behavior and evidence",
        "## Scope and non-goals",
        "## Surface and file map",
        "## Invariants, compatibility, and security",
        "## Dependency and execution order",
        "## Implementation steps",
        "## Rollback",
        "## Verification and evidence",
        "## Risks, decisions, and follow-ons",
    ),
    "TPL-TASK-001": (
        "## Task identity",
        "## Objective",
        "## Read first",
        "## Current behavior and evidence",
        "## Scope",
        "## Invariants and risks",
        "## Implementation requirements",
        "## Verification and evidence",
        "## Handoff requirements",
    ),
}


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _repo_path(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _tracked_paths() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return {
        raw.decode("utf-8")
        for raw in result.stdout.split(b"\0")
        if raw
    }


def _guidance_chain(
    root: Path,
    target: Path,
    *,
    root_tracked: bool,
) -> list[str]:
    root = root.resolve()
    target = target.resolve()
    try:
        relative_parent = target.parent.relative_to(root)
    except ValueError as exc:
        raise ValueError("target_outside_repository") from exc

    directories = [root]
    cursor = root
    for part in relative_parent.parts:
        cursor /= part
        directories.append(cursor)

    chain: list[str] = []
    for directory in directories:
        candidate = directory / "AGENTS.md"
        if not os.path.lexists(candidate):
            continue
        if candidate.is_symlink():
            raise ValueError(f"guidance_symlink:{candidate}")
        if not candidate.is_file():
            raise ValueError(f"guidance_not_regular:{candidate}")
        if directory == root and not root_tracked:
            raise ValueError("root_guidance_untracked")
        chain.append(candidate.relative_to(root).as_posix())
    if not chain or chain[0] != "AGENTS.md":
        raise ValueError("root_guidance_missing")
    return chain


def _matching_repo_paths(pattern: str) -> list[Path]:
    candidate = Path(pattern)
    if candidate.is_absolute() or ".." in candidate.parts or not pattern.strip():
        return []
    return sorted(
        Path(match)
        for match in glob.glob(str(ROOT / pattern), recursive=True)
        if Path(match).exists()
    )


def _accepted_decision_ids() -> set[str]:
    text = (ROOT / "docs" / "decisions" / "index.md").read_text(encoding="utf-8")
    section = text.partition("## Accepted decisions")[2].partition("\n## ")[0]
    return set(re.findall(r"\bADR-[0-9]{4}\b", section))


def _metadata_errors(
    policy: dict[str, Any],
    documents: list[tuple[str, str, dict[str, Any]]],
) -> list[str]:
    rules = policy["frontmatter_policy"]
    required = set(rules["required_fields"])
    supported_statuses = set(rules["supported_statuses"])
    supported_versions = set(rules["supported_schema_versions"])
    accepted_decisions = _accepted_decision_ids()
    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()

    for declared_id, path, metadata in documents:
        fields = set(metadata)
        for field in sorted(required - fields):
            errors.append(f"metadata_missing:{path}:{field}")
        if not rules["allow_unknown_fields"]:
            for field in sorted(fields - required):
                errors.append(f"metadata_unknown:{path}:{field}")
        actual_id = metadata.get("id")
        if actual_id != declared_id:
            errors.append(f"metadata_id_mismatch:{path}")
        if actual_id in seen_ids:
            errors.append(f"metadata_duplicate_id:{actual_id}")
        if path in seen_paths:
            errors.append(f"metadata_duplicate_path:{path}")
        if isinstance(actual_id, str):
            seen_ids.add(actual_id)
        seen_paths.add(path)
        if metadata.get("status") not in supported_statuses:
            errors.append(f"metadata_unsupported_status:{path}")
        if metadata.get("schema_version") not in supported_versions:
            errors.append(f"metadata_unsupported_schema:{path}")

        for field in ("applies_to", "verified_by"):
            values = metadata.get(field)
            if not isinstance(values, list) or not values:
                errors.append(f"metadata_invalid_list:{path}:{field}")
                continue
            for value in values:
                if not isinstance(value, str):
                    errors.append(f"metadata_invalid_path:{path}:{field}")
                elif Path(value).is_absolute() or ".." in Path(value).parts:
                    errors.append(f"metadata_absolute_or_escape:{path}:{field}")
                elif not _matching_repo_paths(value):
                    errors.append(f"metadata_unresolved:{path}:{field}:{value}")

        related = metadata.get("related_decisions")
        if not isinstance(related, list):
            errors.append(f"metadata_invalid_list:{path}:related_decisions")
        else:
            for decision_id in related:
                if decision_id not in accepted_decisions:
                    errors.append(f"metadata_unresolved_decision:{path}:{decision_id}")
    return errors


def _normative_documents() -> list[tuple[str, str, dict[str, Any]]]:
    policy = _load_json(NORMATIVE_POLICY_PATH)
    documents: list[tuple[str, str, dict[str, Any]]] = []
    for entry in policy["documents"]:
        path = ROOT / entry["path"]
        metadata, _ = parse_frontmatter(path.read_text(encoding="utf-8"))
        documents.append((entry["id"], entry["path"], metadata))
    return documents


def _heading_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for heading in parse_commonmark(path.read_text(encoding="utf-8")).headings:
        normalized = re.sub(r"[^\w\s-]", "", heading.text.casefold())
        base = re.sub(r"[\s-]+", "-", normalized).strip("-")
        count = counts.get(base, 0)
        counts[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def _markdown_destinations(path: Path, *, text: str | None = None) -> set[str]:
    text = path.read_text(encoding="utf-8") if text is None else text
    destinations: set[str] = set()
    for raw in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        if raw.startswith(("http://", "https://", "mailto:")):
            continue
        relative, _, anchor = raw.partition("#")
        target = path.parent if not relative else path.parent / relative
        resolved = target.resolve()
        assert resolved.exists(), f"{_repo_path(path)} links missing target {raw!r}"
        assert resolved == ROOT or ROOT in resolved.parents
        if anchor:
            assert resolved.is_file()
            assert anchor in _heading_anchors(resolved), (
                f"{_repo_path(path)} links missing anchor {raw!r}"
            )
        destinations.add(_repo_path(resolved))
    return destinations


def _component_errors(component_map: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    components = component_map.get("components")
    if not isinstance(components, list):
        return ["component_list_invalid"]
    seen_ids: set[str] = set()
    accepted_decisions = _accepted_decision_ids()
    id_records = {entry["id"] for entry in _load_json(ID_REGISTRY_PATH)["ids"]}
    expected_fields = {
        "decisions",
        "id",
        "invariants",
        "paths",
        "specifications",
        "tests",
    }

    for component in components:
        if set(component) != expected_fields:
            errors.append(f"component_fields_invalid:{component.get('id')}")
        component_id = component.get("id")
        if component_id in seen_ids:
            errors.append(f"component_id_duplicate:{component_id}")
        seen_ids.add(component_id)
        for field in ("paths", "specifications", "tests", "invariants", "decisions"):
            values = component.get(field)
            if not isinstance(values, list):
                errors.append(f"component_list_invalid:{component_id}:{field}")
                continue
            if values != sorted(values) or len(values) != len(set(values)):
                errors.append(f"component_order_or_duplicate:{component_id}:{field}")
        for pattern in component.get("paths", []):
            if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
                errors.append(f"component_path_invalid:{component_id}:{pattern}")
            elif not _matching_repo_paths(pattern):
                errors.append(f"component_path_unresolved:{component_id}:{pattern}")
        for field in ("specifications", "tests"):
            for path in component.get(field, []):
                candidate = ROOT / path
                if candidate.is_symlink() or not candidate.is_file():
                    errors.append(f"component_edge_unresolved:{component_id}:{field}:{path}")
        for invariant in component.get("invariants", []):
            if invariant not in id_records:
                errors.append(f"component_invariant_unresolved:{component_id}:{invariant}")
        for decision in component.get("decisions", []):
            if decision not in accepted_decisions:
                errors.append(f"component_decision_unresolved:{component_id}:{decision}")
    ids = [component["id"] for component in components]
    if ids != sorted(ids):
        errors.append("component_order_invalid")
    return errors


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_canonicalize(item) for item in value]
        if all(isinstance(item, dict) and "id" in item for item in normalized):
            return sorted(normalized, key=lambda item: item["id"])
        if all(isinstance(item, dict) and "kind" in item for item in normalized):
            return sorted(normalized, key=lambda item: item["kind"])
        if all(isinstance(item, (str, int)) for item in normalized):
            return sorted(normalized, key=str)
        return normalized
    return value


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(_canonicalize(value), indent=2, sort_keys=True) + "\n"


def _reverse_enumeration(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _reverse_enumeration(item)
            for key, item in reversed(list(value.items()))
        }
    if isinstance(value, list):
        return [_reverse_enumeration(item) for item in reversed(value)]
    return value


def _python_comments(path: Path) -> list[str]:
    tokens = tokenize.generate_tokens(io.StringIO(path.read_text(encoding="utf-8")).readline)
    return [token.string for token in tokens if token.type == tokenize.COMMENT]


def _annotation_errors(comments: list[str]) -> list[str]:
    annotation_policy = _load_json(ANNOTATION_POLICY_PATH)
    id_entries = _load_json(ID_REGISTRY_PATH)["ids"]
    id_kinds = {entry["id"]: entry["kind"] for entry in id_entries}
    removal = _load_json(REMOVAL_REGISTRY_PATH)
    issues = {entry["id"] for entry in removal["issues"]}
    conditions = {entry["id"] for entry in removal["removal_conditions"]}
    accepted_decisions = _accepted_decision_ids()
    approved = {entry["kind"] for entry in annotation_policy["annotations"]}
    kind_mapping = {
        "COMPAT": "compatibility",
        "INVARIANT": "invariant",
        "SECURITY": "security",
    }
    simple_re = re.compile(
        r"^(COMPAT|INVARIANT|SECURITY|WHY)\[([^\]]+)\]:\s+\S.*$"
    )
    todo_re = re.compile(
        r"^TODO\[(#[1-9][0-9]*); remove-after=([a-z0-9][a-z0-9-]*)\]:\s+\S.*$"
    )
    structured_re = re.compile(r"^([A-Z][A-Z0-9_-]*)\[")
    errors: list[str] = []

    for raw in comments:
        comment = raw.removeprefix("#").strip()
        structured = structured_re.match(comment)
        if structured and structured.group(1) not in approved:
            errors.append(f"annotation_unknown_kind:{structured.group(1)}")
            continue
        if comment.startswith("TODO"):
            match = todo_re.fullmatch(comment)
            if match is None:
                errors.append("annotation_malformed:TODO")
                continue
            issue, condition = match.groups()
            if issue not in issues:
                errors.append(f"annotation_unresolved_issue:{issue}")
            if condition not in conditions:
                errors.append(f"annotation_unresolved_removal:{condition}")
            continue
        if comment.startswith(("COMPAT", "INVARIANT", "SECURITY", "WHY")):
            match = simple_re.fullmatch(comment)
            if match is None:
                errors.append("annotation_malformed")
                continue
            kind, record_id = match.groups()
            if kind == "WHY":
                if record_id not in accepted_decisions:
                    errors.append(f"annotation_unresolved_decision:{record_id}")
            elif id_kinds.get(record_id) != kind_mapping[kind]:
                errors.append(f"annotation_unresolved_id:{kind}:{record_id}")
    return errors


def _template_errors(
    template_id: str,
    body: str,
    policy: dict[str, Any],
) -> list[str]:
    errors = [
        f"template_missing:{template_id}:{field}"
        for field in TEMPLATE_FIELDS[template_id]
        if field not in body
    ]
    matching = [entry for entry in policy["documents"] if entry["id"] == template_id]
    if len(matching) != 1:
        errors.append(f"template_canonical_count:{template_id}:{len(matching)}")
    return errors


def test_guidance_hierarchy_resolves_exact_root_to_leaf_chains() -> None:
    tracked = _tracked_paths()
    assert EXPECTED_GUIDANCE <= tracked
    root_agents = ROOT / "AGENTS.md"
    assert root_agents.is_file() and not root_agents.is_symlink()

    found = {
        _repo_path(path)
        for path in ROOT.rglob("AGENTS.md")
        if not any(part.startswith(".") for part in path.relative_to(ROOT).parts)
    }
    assert found == EXPECTED_GUIDANCE
    expected = {
        "README.md": ["AGENTS.md"],
        "src/unrest_harness/storage.py": [
            "AGENTS.md",
            "src/unrest_harness/AGENTS.md",
        ],
        "src/unrest_harness/bundled/skills/agent-browser/SKILL.md": [
            "AGENTS.md",
            "src/unrest_harness/AGENTS.md",
            "src/unrest_harness/bundled/AGENTS.md",
        ],
        "tests/test_storage.py": ["AGENTS.md", "tests/AGENTS.md"],
        "evals/baseline/manifest.yaml": ["AGENTS.md", "evals/AGENTS.md"],
    }
    for path, chain in expected.items():
        assert _guidance_chain(ROOT, ROOT / path, root_tracked=True) == chain


def test_guidance_resolver_rejects_baseline_ignored_external_symlink_trap(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    external = tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    (repository / ".git" / "info").mkdir(parents=True)
    (repository / ".git" / "info" / "exclude").write_text("AGENTS.md\n")
    (external / "AGENTS.md").write_text("# external\n")
    (repository / "AGENTS.md").symlink_to(external / "AGENTS.md")
    (repository / "source.py").write_text("value = 1\n")

    with pytest.raises(ValueError, match="guidance_symlink"):
        _guidance_chain(repository, repository / "source.py", root_tracked=False)


def test_claude_guidance_is_thin_indirection() -> None:
    text = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert text.splitlines() == ["# Claude repository guidance", "", "@AGENTS.md"]
    assert "## Engineering rules" not in text


def test_source_normative_references_and_required_sections_resolve() -> None:
    reference_re = re.compile(
        r"(specs/(?:task_list|memory_v2)/PRODUCT\.md"
        r"|docs/v5/(?:07-runtime-architecture|08-mcp-surface|10-implementation-plan)\.md)"
    )
    referenced: set[str] = set()
    for root in (ROOT / "src", ROOT / "tests"):
        for path in sorted(root.rglob("*.py")):
            referenced.update(reference_re.findall(path.read_text(encoding="utf-8")))
    assert referenced == {
        "docs/v5/07-runtime-architecture.md",
        "docs/v5/08-mcp-surface.md",
        "docs/v5/10-implementation-plan.md",
        "specs/memory_v2/PRODUCT.md",
        "specs/task_list/PRODUCT.md",
    }
    for path in referenced:
        assert (ROOT / path).is_file()

    task_spec = (ROOT / "specs/task_list/PRODUCT.md").read_text(encoding="utf-8")
    for heading in ("Flow", "Authoring", "Goal G4", "Patching", "Dispatch", "Edge Cases"):
        assert re.search(rf"^#+ .*{re.escape(heading)}", task_spec, re.MULTILINE)
    runtime = (ROOT / "docs/v5/07-runtime-architecture.md").read_text(encoding="utf-8")
    assert re.search(r"^## 9\.", runtime, re.MULTILINE)
    plan = (ROOT / "docs/v5/10-implementation-plan.md").read_text(encoding="utf-8")
    assert re.search(r"^## 2\. Phase 7", plan, re.MULTILINE)


def test_all_normative_markdown_links_and_architecture_reachability() -> None:
    policy = _load_json(NORMATIVE_POLICY_PATH)
    for entry in policy["documents"]:
        _markdown_destinations(ROOT / entry["path"])
    index_destinations = _markdown_destinations(ARCHITECTURE_DIR / "index.md")
    assert EXPECTED_INDEX_TARGETS <= index_destinations


@pytest.mark.parametrize(
    "broken_link",
    [
        "[missing](../v5/does-not-exist.md)",
        "[missing](../v5/07-runtime-architecture.md#does-not-exist)",
    ],
)
def test_missing_normative_file_or_anchor_mutations_fail(broken_link: str) -> None:
    index = ARCHITECTURE_DIR / "index.md"
    mutated = index.read_text(encoding="utf-8") + f"\n{broken_link}\n"
    with pytest.raises(AssertionError, match="links missing"):
        _markdown_destinations(index, text=mutated)


def test_known_defect_fixtures_are_not_normative_records() -> None:
    manifest = json.loads(
        (ROOT / "evals/baseline/report.json").read_text(encoding="utf-8")
    )
    known_defects = {
        entry["fixture_id"]
        for entry in manifest["fixtures"]
        if entry["classification"] == "known_defect"
    }
    registered_ids = {entry["id"] for entry in _load_json(ID_REGISTRY_PATH)["ids"]}
    component_map = _load_json(COMPONENT_MAP_PATH)
    component_records = {
        record
        for component in component_map["components"]
        for field in ("invariants", "decisions")
        for record in component[field]
    }
    assert known_defects.isdisjoint(registered_ids | component_records)
    assert "not an invariant or compatibility promise" in (
        ROOT / "specs/task_list/PRODUCT.md"
    ).read_text(encoding="utf-8")
    assert "non-normative" in (
        ROOT / "docs/v5/07-runtime-architecture.md"
    ).read_text(encoding="utf-8")


def test_normative_metadata_is_strict_unique_and_resolving() -> None:
    policy = _load_json(NORMATIVE_POLICY_PATH)
    assert policy["schema_version"] == 1
    documents = _normative_documents()
    assert not _metadata_errors(policy, documents)
    assert [item[0] for item in documents] == sorted(item[0] for item in documents)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", "metadata_missing:"),
        ("unknown", "metadata_unknown:"),
        ("duplicate", "metadata_duplicate_id:"),
        ("unsupported_status", "metadata_unsupported_status:"),
        ("unsupported_schema", "metadata_unsupported_schema:"),
        ("absolute", "metadata_absolute_or_escape:"),
        ("unresolved", "metadata_unresolved:"),
    ],
)
def test_normative_metadata_mutations_fail(
    mutation: str,
    expected_code: str,
) -> None:
    policy = _load_json(NORMATIVE_POLICY_PATH)
    documents = copy.deepcopy(_normative_documents())
    declared_id, path, metadata = documents[0]
    if mutation == "missing":
        metadata.pop("status")
    elif mutation == "unknown":
        metadata["owner"] = "nobody"
    elif mutation == "duplicate":
        other_id, other_path, other_metadata = documents[1]
        documents[1] = (declared_id, other_path, other_metadata | {"id": declared_id})
        assert other_id != declared_id
    elif mutation == "unsupported_status":
        metadata["status"] = "unknown"
    elif mutation == "unsupported_schema":
        metadata["schema_version"] = 999
    elif mutation == "absolute":
        metadata["applies_to"] = ["/tmp/outside"]
    else:
        metadata["verified_by"] = ["tests/does-not-exist.py"]
    documents[0] = (declared_id, path, metadata)

    errors = _metadata_errors(policy, documents)
    assert any(error.startswith(expected_code) for error in errors)


def test_component_map_edges_are_unique_ordered_and_resolving() -> None:
    component_map = _load_json(COMPONENT_MAP_PATH)
    assert component_map["schema_version"] == 1
    assert not _component_errors(component_map)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_edge", "component_edge_unresolved:"),
        ("bad_glob", "component_path_unresolved:"),
        ("absolute_glob", "component_path_invalid:"),
        ("duplicate_component", "component_id_duplicate:"),
        ("unknown_invariant", "component_invariant_unresolved:"),
    ],
)
def test_component_map_mutations_fail(mutation: str, expected_code: str) -> None:
    component_map = copy.deepcopy(_load_json(COMPONENT_MAP_PATH))
    component = component_map["components"][0]
    if mutation == "missing_edge":
        component["tests"] = ["tests/does-not-exist.py"]
    elif mutation == "bad_glob":
        component["paths"] = ["src/does-not-exist/**/*.py"]
    elif mutation == "absolute_glob":
        component["paths"] = ["/tmp/**/*.py"]
    elif mutation == "duplicate_component":
        component_map["components"].append(copy.deepcopy(component))
    else:
        component["invariants"] = ["ARCH-NOT-REGISTERED"]

    errors = _component_errors(component_map)
    assert any(error.startswith(expected_code) for error in errors)


def test_machine_readable_architecture_is_canonical_and_order_independent() -> None:
    paths = (
        ANNOTATION_POLICY_PATH,
        COMPONENT_MAP_PATH,
        ID_REGISTRY_PATH,
        NORMATIVE_POLICY_PATH,
        REMOVAL_REGISTRY_PATH,
    )
    for path in paths:
        value = _load_json(path)
        assert path.read_text(encoding="utf-8") == _canonical_json(value)
        reversed_value = _reverse_enumeration(value)
        assert _canonical_json(reversed_value) == _canonical_json(value)


def test_stable_id_comment_and_removal_registries_resolve() -> None:
    id_registry = _load_json(ID_REGISTRY_PATH)
    records = id_registry["ids"]
    assert [entry["id"] for entry in records] == sorted(entry["id"] for entry in records)
    assert len({entry["id"] for entry in records}) == len(records)
    assert {entry["kind"] for entry in records} <= set(id_registry["kinds"])
    for entry in records:
        source = ROOT / entry["source"]
        assert source.is_file()
        assert entry["id"] in source.read_text(encoding="utf-8")

    removal = _load_json(REMOVAL_REGISTRY_PATH)
    for field in ("issues", "removal_conditions"):
        values = removal[field]
        assert [entry["id"] for entry in values] == sorted(
            entry["id"] for entry in values
        )
        assert len({entry["id"] for entry in values}) == len(values)

    policy = _load_json(ANNOTATION_POLICY_PATH)
    references = {entry["kind"]: entry["reference"] for entry in policy["annotations"]}
    assert references == {
        "COMPAT": "id-registry.json#kind=compatibility",
        "INVARIANT": "id-registry.json#kind=invariant",
        "SECURITY": "id-registry.json#kind=security",
        "TODO": "removal-registry.json#issues+removal_conditions",
        "WHY": "../decisions/index.md#accepted-decisions",
    }
    decision_index = ROOT / "docs/decisions/index.md"
    assert "accepted-decisions" in _heading_anchors(decision_index)


def test_annotation_vocabulary_and_checked_in_annotations_resolve() -> None:
    policy = _load_json(ANNOTATION_POLICY_PATH)
    assert {item["kind"] for item in policy["annotations"]} == {
        "COMPAT",
        "INVARIANT",
        "SECURITY",
        "TODO",
        "WHY",
    }
    assert policy["banned_content"] == {
        "identity_attribution_grammar": {
            "identity_slot": {
                "kind": "open-token-sequence",
                "maximum_tokens": 6,
                "minimum_tokens": 1,
            },
            "known_identity_examples": [
                "assistant",
                "chatgpt",
                "claude",
                "codex",
                "copilot",
                "gemini",
                "gpt",
            ],
            "private_reasoning_concepts": [
                "chain of thought",
                "hidden reasoning",
                "private reasoning",
                "scratchpad",
            ],
            "visible_label_forms": [
                "<identity> says: <private-reasoning-concept>",
                "<identity>: <private-reasoning-concept>",
            ],
        },
        "normalization": [
            "casefold",
            "collapse-token-separators",
            "html-entity-decode",
            "strip-unicode-format-controls",
            "unicode-nfkc",
        ],
        "out_of_scope_containers": [
            "arbitrary-prose",
            "fenced-code",
            "html-comment",
            "link-destination",
            "source-comment",
        ],
        "supported_containers": [
            {
                "id": "html-attribute-value",
                "kind": "compound-identity-private-concept",
                "names": ["class", "data-*", "id", "name"],
            },
            {
                "compound_tag_name": True,
                "id": "html-private-concept-tag",
                "identity_attribute_names": [
                    "agent",
                    "data-agent",
                    "data-identity",
                    "data-model",
                    "data-provider",
                    "identity",
                    "model",
                    "provider",
                ],
                "kind": "private-concept-plus-identity-attribute",
            },
            {
                "id": "html-visible-label",
                "kind": "visible-label",
                "tags": [
                    "dd",
                    "div",
                    "dt",
                    "h1",
                    "h2",
                    "h3",
                    "h4",
                    "h5",
                    "h6",
                    "li",
                    "p",
                    "span",
                ],
            },
            {
                "id": "markdown-attribute-value",
                "kind": "compound-identity-private-concept",
                "names": ["class", "data-*", "id", "name"],
            },
            {
                "id": "markdown-visible-label",
                "kind": "visible-label",
                "structures": [
                    "block-quote",
                    "heading",
                    "list-item",
                    "paragraph",
                ],
            },
        ],
    }
    comments: list[str] = []
    for root in (ROOT / "src", ROOT / "tests"):
        for path in sorted(root.rglob("*.py")):
            comments.extend(_python_comments(path))
    assert not _annotation_errors(comments)

    for _doc_id, path, _metadata in _normative_documents():
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not _identity_private_marker_categories(
            text,
            policy["banned_content"],
        )


@pytest.mark.parametrize(
    ("comment", "expected_code"),
    [
        ("# NOTE[ARCH-STATE-001]: conversational alias", "annotation_unknown_kind:"),
        ("# INVARIANT[ARCH-MISSING-001]: unknown", "annotation_unresolved_id:"),
        ("# SECURITY[ARCH-STATE-001]: wrong registry kind", "annotation_unresolved_id:"),
        ("# COMPAT[COMPAT-PATCH-001] missing colon", "annotation_malformed"),
        (
            "# TODO[#99; remove-after=trace-v2]: remove projection",
            "annotation_unresolved_issue:",
        ),
    ],
)
def test_malformed_broken_or_conversational_annotations_fail(
    comment: str,
    expected_code: str,
) -> None:
    errors = _annotation_errors([comment])
    assert any(error.startswith(expected_code) for error in errors)


@pytest.mark.parametrize(
    "comment",
    [
        "# Claude provider settings are explicit.",
        "# Codex and ChatGPT are supported provider names.",
        "# Gemini and Copilot adapters are optional integrations.",
        "# Reasoning tags are rejected by the annotation scanner.",
        "# Thinking through recovery requires explicit evidence.",
        "# The monologue tag is not part of public documentation.",
        "# assistant: try changing this later",
        "# Claude says: private implementation thoughts",
        "# chatgpt: private implementation thoughts",
        "# **Claude:** private implementation thoughts",
        "# - **ChatGPT:** private implementation thoughts",
        "# Gemini: private implementation thoughts",
        "# Copilot says: private implementation thoughts",
        "# Marlowe: private implementation thoughts",
        "# - **DeepSeek:** hidden implementation notes",
        "# **qwen:** private implementation notes",
        "# Llama: secret work notes",
        "# <reasoning>private implementation thoughts",
        "# <analysis/> private implementation thoughts",
        "# <THINKING>private implementation thoughts",
        "# </monologue> private implementation thoughts",
        "# <scratchpad>private implementation thoughts",
        "# <private-thoughts>implementation detail",
        "# chain_of_thought: private implementation thoughts",
        "# internal monologue: private implementation thoughts",
    ],
)
def test_source_comments_are_outside_private_marker_classification(
    comment: str,
) -> None:
    assert not _annotation_errors([comment])


@pytest.mark.parametrize("template_id", sorted(TEMPLATE_FIELDS))
def test_templates_have_one_canonical_copy_and_all_required_fields(
    template_id: str,
) -> None:
    policy = _load_json(NORMATIVE_POLICY_PATH)
    entry = next(item for item in policy["documents"] if item["id"] == template_id)
    _metadata, body = parse_frontmatter(
        (ROOT / entry["path"]).read_text(encoding="utf-8")
    )
    assert not _template_errors(template_id, body, policy)


@pytest.mark.parametrize("template_id", sorted(TEMPLATE_FIELDS))
def test_template_missing_field_and_duplicate_canon_mutations_fail(
    template_id: str,
) -> None:
    policy = copy.deepcopy(_load_json(NORMATIVE_POLICY_PATH))
    entry = next(item for item in policy["documents"] if item["id"] == template_id)
    _metadata, body = parse_frontmatter(
        (ROOT / entry["path"]).read_text(encoding="utf-8")
    )
    body_without_field = body.replace(TEMPLATE_FIELDS[template_id][0], "", 1)
    assert any(
        error.startswith("template_missing:")
        for error in _template_errors(template_id, body_without_field, policy)
    )

    policy["documents"].append(copy.deepcopy(entry))
    assert any(
        error.startswith("template_canonical_count:")
        for error in _template_errors(template_id, body, policy)
    )
