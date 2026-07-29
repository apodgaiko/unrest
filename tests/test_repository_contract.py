"""Real-command and isolated-mutation checks for the repository contract."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner, Result

from unrest_harness.cli import cli
from unrest_harness.repository_contract import (
    CANONICAL_COMMAND,
    check_repository,
)

ROOT = Path(__file__).resolve().parents[1]
COPY_PATHS = (
    ".github",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "README.md",
    "docs",
    "evals",
    "policy",
    "pyproject.toml",
    "schemas",
    "specs",
    "src",
    "tests",
    "uv.lock",
)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    destination = tmp_path / "repository"
    destination.mkdir()
    ignored = shutil.ignore_patterns(
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "*.pyc",
    )
    for relative in COPY_PATHS:
        source = ROOT / relative
        target = destination / relative
        if source.is_dir():
            shutil.copytree(source, target, ignore=ignored)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    _git(destination, "init", "-q")
    _git(destination, "add", "-f", ".")
    _git(
        destination,
        "-c",
        "user.name=Repository Contract",
        "-c",
        "user.email=contract@example.invalid",
        "commit",
        "-qm",
        "test fixture",
    )
    return destination


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def _status(repository: Path) -> set[str]:
    result = _git(repository, "status", "--porcelain=v1", "-z")
    paths: set[str] = set()
    records = [record for record in result.stdout.split("\0") if record]
    index = 0
    while index < len(records):
        record = records[index]
        paths.add(record[3:])
        if record[:2] in {"R ", "C ", "RM", "CM"}:
            index += 1
            paths.add(records[index])
        index += 1
    return paths


def _run_cli(repository: Path, monkeypatch: pytest.MonkeyPatch) -> Result:
    monkeypatch.chdir(repository)
    return CliRunner().invoke(cli, ["check-repository"])


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _snapshot_worktree(repository: Path) -> dict[str, tuple[int, str]]:
    snapshot: dict[str, tuple[int, str]] = {}
    for directory, dirnames, filenames in os.walk(repository):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        for dirname in dirnames:
            path = Path(directory) / dirname
            relative = path.relative_to(repository).as_posix() + "/"
            snapshot[relative] = (path.lstat().st_mode, "directory")
        for filename in filenames:
            path = Path(directory) / filename
            relative = path.relative_to(repository).as_posix()
            if path.is_symlink():
                payload = f"symlink:{os.readlink(path)}".encode()
            else:
                payload = path.read_bytes()
            snapshot[relative] = (
                path.lstat().st_mode,
                hashlib.sha256(payload).hexdigest(),
            )
    return snapshot


def _apply_mutation(repository: Path, mutation: str) -> str:
    if mutation == "guidance_symlink":
        path = repository / "AGENTS.md"
        path.unlink()
        path.symlink_to("README.md")
        return "AGENTS.md"
    if mutation == "guidance_untracked":
        _git(repository, "rm", "--cached", "-q", "AGENTS.md")
        return "AGENTS.md"
    if mutation == "markdown_file":
        path = repository / "docs/architecture/index.md"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n[broken repository contract](does-not-exist.md)\n",
            encoding="utf-8",
        )
        return "docs/architecture/index.md"
    if mutation == "normative_file":
        path = repository / "docs/architecture/repository-contract.md"
        path.unlink()
        return "docs/architecture/repository-contract.md"
    if mutation == "markdown_anchor":
        path = repository / "docs/architecture/index.md"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n[broken repository contract](repository-contract.md#absent-anchor)\n",
            encoding="utf-8",
        )
        return "docs/architecture/index.md"
    if mutation == "source_anchor":
        path = repository / "src/unrest_harness/repository_contract.py"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n# See docs/architecture/repository-contract.md#absent-anchor.\n",
            encoding="utf-8",
        )
        return "src/unrest_harness/repository_contract.py"
    if mutation == "test_reference":
        path = repository / "tests/test_storage.py"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n# See docs/v5/does-not-exist.md#absent-anchor.\n",
            encoding="utf-8",
        )
        return "tests/test_storage.py"
    if mutation == "global_id":
        path = repository / "docs/architecture/id-registry.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        record = next(item for item in value["ids"] if item["id"] == "ARCH-MCP-001")
        record["source"] = "docs/architecture/index.md"
        _write_json(path, value)
        return "docs/architecture/id-registry.json"
    if mutation == "duplicate_canon":
        path = repository / "docs/architecture/normative-documents.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["documents"].append(
            {
                "id": "ARCH-REPOSITORY-CONTRACT-DUPLICATE-001",
                "path": "docs/architecture/repository-contract.md",
            }
        )
        value["documents"].sort(key=lambda item: item["id"])
        _write_json(path, value)
        return "docs/architecture/normative-documents.json"
    if mutation == "frontmatter":
        path = repository / "docs/architecture/repository-contract.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace("status: active\n", "", 1),
            encoding="utf-8",
        )
        return "docs/architecture/repository-contract.md"
    if mutation == "frontmatter_duplicate":
        path = repository / "docs/architecture/repository-contract.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "status: active\n",
                "status: active\nstatus: active\n",
                1,
            ),
            encoding="utf-8",
        )
        return "docs/architecture/repository-contract.md"
    if mutation == "annotation":
        path = repository / "src/unrest_harness/repository_contract.py"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n# INVARIANT[ARCH-NOT-REGISTERED-001]: rejected fixture.\n",
            encoding="utf-8",
        )
        return "src/unrest_harness/repository_contract.py"
    if mutation == "codex_reasoning_marker":
        path = repository / "src/unrest_harness/repository_contract.py"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n# codex: private reasoning about the next implementation step.\n",
            encoding="utf-8",
        )
        return "src/unrest_harness/repository_contract.py"
    if mutation == "component_edge":
        path = repository / "docs/architecture/component-map.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        component = next(
            item
            for item in value["components"]
            if item["id"] == "COMP-REPOSITORY-CONTRACT"
        )
        component["tests"] = ["tests/does-not-exist.py"]
        _write_json(path, value)
        return "docs/architecture/component-map.json"
    if mutation == "component_policy_ambiguity":
        path = repository / "docs/architecture/component-map.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        component = next(
            item
            for item in value["components"]
            if item["id"] == "COMP-COORDINATOR"
        )
        component["paths"].append("policy/protected-surfaces.yaml")
        component["paths"].sort()
        _write_json(path, value)
        return "docs/architecture/component-map.json"
    if mutation == "template_heading_comment":
        path = repository / "docs/templates/task-packet.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "## Task identity",
                "<!-- ## Task identity -->",
                1,
            ),
            encoding="utf-8",
        )
        return "docs/templates/task-packet.md"
    if mutation == "protected_policy":
        path = repository / "policy/protected-surfaces.yaml"
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value["protected_surfaces"][0]["rollback_plan_required"] = False
        path.write_text(
            yaml.safe_dump(value, sort_keys=False),
            encoding="utf-8",
        )
        return "policy/protected-surfaces.yaml"
    if mutation == "schema_metaschema":
        path = repository / "schemas/protected-surfaces.schema.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["$schema"] = "https://json-schema.org/draft/2099-01/schema"
        _write_json(path, value)
        return "schemas/protected-surfaces.schema.json"
    if mutation == "schema_invalid":
        path = repository / "schemas/protected-surfaces.schema.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["$defs"] = []
        _write_json(path, value)
        return "schemas/protected-surfaces.schema.json"
    if mutation == "generated_schema":
        path = repository / "schemas/protected-surfaces.schema.json"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        return "schemas/protected-surfaces.schema.json"
    if mutation == "generated_baseline":
        path = repository / "evals/baseline/report.json"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        return "evals/baseline/report.json"
    if mutation == "canonical_json":
        path = repository / "docs/architecture/id-registry.json"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        return "docs/architecture/id-registry.json"
    if mutation == "ci_supported_version":
        path = repository / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'python-version: ["3.11", "3.12", "3.13"]',
                'python-version: ["3.11", "3.12"]',
                1,
            ),
            encoding="utf-8",
        )
        return ".github/workflows/ci.yml"
    raise AssertionError(f"unknown mutation {mutation}")


@pytest.mark.parametrize(
    ("mutation", "reason", "diagnostic_path"),
    [
        ("guidance_symlink", "REPO-GUIDANCE-SYMLINK", "AGENTS.md"),
        ("guidance_untracked", "REPO-GUIDANCE-UNTRACKED", "AGENTS.md"),
        (
            "markdown_file",
            "REPO-MARKDOWN-TARGET-MISSING",
            "docs/architecture/index.md",
        ),
        (
            "normative_file",
            "REPO-FILE-UNREADABLE",
            "docs/architecture/repository-contract.md",
        ),
        (
            "markdown_anchor",
            "REPO-MARKDOWN-ANCHOR-MISSING",
            "docs/architecture/index.md",
        ),
        (
            "source_anchor",
            "REPO-SOURCE-ANCHOR-MISSING",
            "src/unrest_harness/repository_contract.py",
        ),
        (
            "test_reference",
            "REPO-SOURCE-REFERENCE-MISSING",
            "tests/test_storage.py",
        ),
        (
            "global_id",
            "REPO-GLOBAL-ID-CANONICAL-CONFLICT",
            "docs/architecture/id-registry.json",
        ),
        (
            "duplicate_canon",
            "REPO-CANONICAL-PATH-DUPLICATE",
            "docs/architecture/normative-documents.json",
        ),
        (
            "frontmatter",
            "REPO-FRONTMATTER-FIELD-MISSING",
            "docs/architecture/repository-contract.md",
        ),
        (
            "frontmatter_duplicate",
            "REPO-FRONTMATTER-KEY-DUPLICATE",
            "docs/architecture/repository-contract.md",
        ),
        (
            "annotation",
            "REPO-ANNOTATION-ID-UNKNOWN",
            "src/unrest_harness/repository_contract.py",
        ),
        (
            "codex_reasoning_marker",
            "REPO-ANNOTATION-BANNED-MARKER",
            "src/unrest_harness/repository_contract.py",
        ),
        (
            "component_edge",
            "REPO-COMPONENT-EDGE-UNRESOLVED",
            "docs/architecture/component-map.json",
        ),
        (
            "component_policy_ambiguity",
            "GOV-POLICY-PATH-AMBIGUOUS",
            "docs/architecture/component-map.json",
        ),
        (
            "template_heading_comment",
            "REPO-TEMPLATE-FIELD-MISSING",
            "docs/templates/task-packet.md",
        ),
        (
            "protected_policy",
            "GOV-POLICY-VALUE-UNSUPPORTED",
            "policy/protected-surfaces.yaml",
        ),
        (
            "schema_metaschema",
            "REPO-SCHEMA-METASCHEMA-UNSUPPORTED",
            "schemas/protected-surfaces.schema.json",
        ),
        (
            "schema_invalid",
            "REPO-SCHEMA-INVALID",
            "schemas/protected-surfaces.schema.json",
        ),
        (
            "generated_schema",
            "REPO-GENERATED-SCHEMA-DRIFT",
            "schemas/protected-surfaces.schema.json",
        ),
        (
            "generated_baseline",
            "REPO-GENERATED-OUTPUT-DRIFT",
            "evals/baseline/report.json",
        ),
        (
            "canonical_json",
            "REPO-CANONICAL-JSON-DRIFT",
            "docs/architecture/id-registry.json",
        ),
        (
            "ci_supported_version",
            "REPO-CI-PYTHON-VERSIONS-MISMATCH",
            ".github/workflows/ci.yml",
        ),
    ],
)
def test_one_mutation_per_failure_family_has_stable_cli_diagnostic(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    reason: str,
    diagnostic_path: str,
) -> None:
    changed_path = _apply_mutation(repository, mutation)
    assert changed_path == diagnostic_path
    before = _status(repository)
    assert before == {changed_path}

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert reason in result.output
    assert diagnostic_path in result.output
    assert str(repository) not in result.output
    assert _status(repository) == before


def test_check_mode_is_read_only_and_reports_only_declared_stdout(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _snapshot_worktree(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["command"] == CANONICAL_COMMAND
    assert report["repository"] == "."
    assert report["status"] == "ok"
    assert _snapshot_worktree(repository) == before
    assert _status(repository) == set()


def test_reverse_enumeration_produces_identical_report_hash(repository: Path) -> None:
    forward = check_repository(repository, enumeration_order="forward").render()
    reverse = check_repository(repository, enumeration_order="reverse").render()

    assert forward == reverse
    assert hashlib.sha256(forward.encode()).hexdigest() == hashlib.sha256(
        reverse.encode()
    ).hexdigest()


@pytest.mark.parametrize(
    ("relative_path", "field", "commented_field"),
    [
        (
            "docs/templates/adr.md",
            "## Record metadata",
            "<!-- ## Record metadata -->",
        ),
        (
            "docs/templates/change-closeout.md",
            "task_id:",
            "# task_id:",
        ),
        (
            "docs/templates/implementation-plan.md",
            "## Plan identity",
            "<!-- ## Plan identity -->",
        ),
        (
            "docs/templates/task-packet.md",
            "## Task identity",
            "<!-- ## Task identity -->",
        ),
    ],
)
def test_required_template_fields_must_be_real_markdown_or_yaml_structure(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    field: str,
    commented_field: str,
) -> None:
    path = repository / relative_path
    path.write_text(
        path.read_text(encoding="utf-8").replace(field, commented_field, 1),
        encoding="utf-8",
    )
    before = _status(repository)
    assert before == {relative_path}

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output
    assert relative_path in result.output
    assert str(repository) not in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "anchor",
    [
        "",
        "ABSENT-ANCHOR",
        "Absent-Anchor",
        "absent_anchor",
        "purpose/extra",
    ],
)
def test_source_reference_parser_rejects_the_complete_case_preserved_fragment(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    anchor: str,
) -> None:
    path = repository / "tests/test_storage.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"\n# See docs/architecture/repository-contract.md#{anchor}.\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-SOURCE-ANCHOR-MISSING" in result.output
    assert ("empty anchor" if not anchor else repr(anchor)) in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "reference",
    [
        "Docs/architecture/repository-contract.md#purpose",
        "docs/architecture/repository-contract.MD#purpose",
        "xdocs/architecture/repository-contract.md#purpose",
        "src/docs/architecture/repository-contract.md#purpose",
        "docs/architecture/repository-contract.mdx#purpose",
        "docs/architecture/repository-contract.md.bak#purpose",
        "docs/architecture/repository-contract.md #purpose",
        "docs/architecture/repository-contract.md#purpose/extra",
        "/docs/architecture/repository-contract.md#purpose",
        "docs//architecture/repository-contract.md#purpose",
        "docs/architecture//repository-contract.md#purpose",
        "docs///architecture/repository-contract.md#purpose",
        "./docs/architecture/repository-contract.md#purpose",
        "../docs/architecture/repository-contract.md#purpose",
        "docs\\architecture\\repository-contract.md#purpose",
    ],
)
def test_source_reference_exact_grammar_rejects_generated_lookalikes(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
) -> None:
    path = repository / "tests/test_storage.py"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n# See {reference}.\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert (
        "REPO-SOURCE-REFERENCE-INVALID" in result.output
        or "REPO-SOURCE-ANCHOR-MISSING" in result.output
    )
    assert "tests/test_storage.py" in result.output
    assert _status(repository) == before


def test_source_reference_parser_accepts_a_complete_resolving_fragment(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / "tests/test_storage.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n# See docs/architecture/repository-contract.md#purpose.\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/docs/guide.md",
        "http://example.invalid/specs/design.md#section",
    ],
)
def test_source_reference_parser_leaves_external_urls_external(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
) -> None:
    path = repository / "tests/test_storage.py"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n# See {reference}.\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("defect_id", "classification"),
    [
        ("BASE-SCHEDULER-DEFECT-001", "known_defect"),
        ("BASE-STORAGE-LEGACY-001", "observed_legacy"),
    ],
)
def test_baseline_non_normative_records_cannot_become_component_invariants(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect_id: str,
    classification: str,
) -> None:
    source_path = "docs/v5/07-runtime-architecture.md"
    registry_path = repository / "docs/architecture/id-registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["ids"].append(
        {
            "id": defect_id,
            "kind": "invariant",
            "source": source_path,
            "statement": f"{classification} is promoted to a runtime invariant.",
        }
    )
    registry["ids"].sort(key=lambda item: item["id"])
    _write_json(registry_path, registry)

    source = repository / source_path
    source.write_text(
        source.read_text(encoding="utf-8")
        + f"\n- `{defect_id}`: the baseline classification is normative.\n",
        encoding="utf-8",
    )
    component_path = repository / "docs/architecture/component-map.json"
    components = json.loads(component_path.read_text(encoding="utf-8"))
    baseline = next(
        component
        for component in components["components"]
        if component["id"] == "COMP-BASELINE"
    )
    baseline["invariants"].append(defect_id)
    baseline["invariants"].sort()
    _write_json(component_path, components)
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-BASELINE-NONNORMATIVE-ID" in result.output
    assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
    assert "REPO-COMPONENT-NONNORMATIVE-INVARIANT" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "promotion",
    [
        (
            "BASE-SCHEDULER-DEFECT-001 is not merely a historical "
            "characterization; it is the normative runtime invariant all "
            "implementations must preserve."
        ),
        (
            "Although known_defect was once a characterization, "
            "BASE-SCHEDULER-DEFECT-001 now defines canonical scheduler behavior."
        ),
        (
            "BASE-SCHEDULER-DEFECT-001 is no longer just characterization "
            "evidence; implementations should retain it as authoritative behavior."
        ),
        (
            "The normative source of truth is BASE-SCHEDULER-DEFECT-001, "
            "despite its historical known_defect label."
        ),
    ],
)
def test_baseline_non_normative_promotion_cannot_hide_behind_negation(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    promotion: str,
) -> None:
    path = repository / "docs/v5/07-runtime-architecture.md"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{promotion}\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "content",
    [
        "Claude: private implementation reasoning",
        "CHATGPT says: hidden implementation reasoning",
        "codex says : hidden implementation reasoning",
        "**Claude:** hidden implementation reasoning",
        "- **ChatGPT:** hidden implementation reasoning",
        "Gemini: hidden implementation reasoning",
        "Copilot says: hidden implementation reasoning",
        "Marlowe: private implementation reasoning",
        "- **DeepSeek:** hidden implementation notes",
        "**qwen:** private implementation notes",
        "<REASONING type=\"private\">hidden implementation thoughts",
        "<analysis/> hidden implementation thoughts",
        "<THINKING>hidden implementation thoughts",
        "</monologue>",
        "</analysis>",
        "<scratchpad private=\"true\">hidden implementation thoughts</scratchpad>",
        "<private-thoughts>hidden implementation notes</private-thoughts>",
        "chain_of_thought: hidden implementation thoughts",
        "internal monologue: hidden implementation thoughts",
    ],
)
def test_normalized_agent_identity_and_reasoning_categories_reject_variants(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    path = repository / "src/unrest_harness/repository_contract.py"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n# {content}\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-ANNOTATION-BANNED-MARKER" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "content",
    [
        "Claude provider support uses explicit settings.",
        "Codex and ChatGPT names are ordinary technical prose.",
        "Gemini and Copilot adapters use explicit settings.",
        "Reasoning tags are filtered by the repository policy.",
        "Thinking about recovery is ordinary engineering prose.",
        "A monologue tag would not be public documentation.",
    ],
)
def test_agent_names_and_reasoning_in_ordinary_prose_remain_valid(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    path = repository / "src/unrest_harness/repository_contract.py"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n# {content}\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("relative_path", "heading"),
    [
        ("docs/templates/adr.md", "## Scope"),
        ("docs/templates/implementation-plan.md", "## Rollback"),
        ("docs/templates/task-packet.md", "## Scope"),
    ],
)
def test_duplicate_required_template_headings_are_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    heading: str,
) -> None:
    path = repository / relative_path
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"\n{heading}\n\n`<competing field copy>`\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-DUPLICATE" in result.output
    assert heading in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("relative_path", "heading"),
    [
        ("docs/templates/adr.md", "Scope"),
        ("docs/templates/implementation-plan.md", "Rollback"),
        ("docs/templates/task-packet.md", "Scope"),
    ],
)
def test_duplicate_setext_headings_are_rejected_structurally(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    heading: str,
) -> None:
    path = repository / relative_path
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"\n{heading}\n{'-' * max(3, len(heading))}\n\nCompeting field copy.\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-DUPLICATE" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("indent", [" ", "  ", "   "])
def test_commonmark_indented_atx_template_heading_remains_valid(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    indent: str,
) -> None:
    path = repository / "docs/templates/task-packet.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("## Scope", f"{indent}## Scope", 1),
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before


@pytest.mark.parametrize("fence_character", ["`", "~"])
@pytest.mark.parametrize("fence_length", [3, 4, 5])
def test_commonmark_pseudo_closing_fence_cannot_expose_template_body(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    fence_character: str,
    fence_length: int,
) -> None:
    path = repository / "docs/templates/task-packet.md"
    text = path.read_text(encoding="utf-8")
    frontmatter_start, frontmatter, body = text.split("---", 2)
    assert frontmatter_start == ""
    fence = fence_character * fence_length
    path.write_text(
        f"---{frontmatter}---\n"
        f"{fence}markdown\n{fence}not-a-close\n{body}\n{fence}\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        (
            "task_id: <stable task id>",
            "task_id: <first stable task id>\ntask_id: <second stable task id>",
        ),
        (
            "follow_ons:\n  required:",
            "follow_ons:\n  required:\n  required:",
        ),
    ],
)
def test_duplicate_closeout_yaml_keys_are_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    path = repository / "docs/templates/change-closeout.md"
    text = path.read_text(encoding="utf-8")
    assert text.count(field) == 1
    path.write_text(text.replace(field, replacement, 1), encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-YAML-KEY-DUPLICATE" in result.output
    assert _status(repository) == before


def test_closeout_required_key_repeated_in_a_second_yaml_fence_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / "docs/templates/change-closeout.md"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n```yaml\ntask_id: <competing stable task id>\n```\n",
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-DUPLICATE" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("relative_path", "heading"),
    [
        ("docs/templates/adr.md", "## Scope"),
        ("docs/templates/implementation-plan.md", "## Rollback"),
        ("docs/templates/task-packet.md", "## Scope"),
    ],
)
def test_required_headings_inside_fences_do_not_count(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    heading: str,
) -> None:
    path = repository / relative_path
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace(heading, f"```markdown\n{heading}\n```", 1),
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("container", ["blockquote", "list"])
@pytest.mark.parametrize(
    ("relative_path", "heading"),
    [
        ("docs/templates/adr.md", "## Scope"),
        ("docs/templates/implementation-plan.md", "## Rollback"),
        ("docs/templates/task-packet.md", "## Scope"),
    ],
)
def test_required_template_headings_must_be_top_level(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    heading: str,
    container: str,
) -> None:
    path = repository / relative_path
    nested = f"> {heading}" if container == "blockquote" else f"- example\n\n  {heading}"
    path.write_text(
        path.read_text(encoding="utf-8").replace(heading, nested, 1),
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("container", ["blockquote", "list"])
def test_closeout_yaml_body_must_be_top_level(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    container: str,
) -> None:
    path = repository / "docs/templates/change-closeout.md"
    text = path.read_text(encoding="utf-8")
    start = text.index("```yaml")
    end = text.index("```", start + len("```yaml")) + len("```")
    yaml_fence = text[start:end]
    nested = (
        "\n".join(f"> {line}" for line in yaml_fence.splitlines())
        if container == "blockquote"
        else "- example packet\n\n  " + yaml_fence.replace("\n", "\n  ")
    )
    path.write_text(text[:start] + nested + text[end:], encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("mutation", ["removed", "substituted", "after_build"])
def test_ci_source_removal_or_substitution_is_rejected_by_the_command(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    step = (
        "      - name: Repository contract\n"
        f"        run: {CANONICAL_COMMAND}\n"
    )
    assert text.count(step) == 1
    if mutation == "removed":
        text = text.replace(step, "", 1)
        expected = "REPO-CI-COMMAND-MISSING"
    elif mutation == "substituted":
        text = text.replace(
            CANONICAL_COMMAND,
            "uv run python -m unrest_harness.repository_contract",
            1,
        )
        expected = "REPO-CI-COMMAND-SUBSTITUTED"
    else:
        text = text.replace(step, "", 1)
        marker = "      - name: Smoke-test installed wheel\n"
        text = text.replace(marker, step + marker, 1)
        expected = "REPO-CI-COMMAND-ORDER"
    path.write_text(text, encoding="utf-8")
    before = _status(repository)
    assert before == {".github/workflows/ci.yml"}

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert expected in result.output
    assert ".github/workflows/ci.yml#jobs.checks" in result.output
    assert str(repository) not in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "build_command",
    [
        "uv build --wheel",
        "uv build --sdist",
        "env UV_NATIVE_TLS=true uv build --wheel",
        "python -m build --wheel",
        "sh -c 'uv build --wheel'",
    ],
)
def test_ci_contract_must_precede_option_bearing_build_commands(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    build_command: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    contract = (
        "      - name: Repository contract\n"
        f"        run: {CANONICAL_COMMAND}\n"
    )
    standard_build = (
        "      - name: Build wheel and source distribution\n"
        "        run: uv build\n"
    )
    option_build = standard_build.replace("uv build", build_command)
    text = text.replace(contract, "", 1).replace(
        standard_build,
        option_build + contract,
        1,
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-COMMAND-ORDER" in result.output
    assert _status(repository) == before


def test_ci_contract_must_precede_publish_commands(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    contract = (
        "      - name: Repository contract\n"
        f"        run: {CANONICAL_COMMAND}\n"
    )
    test_step = "      - name: Test (pytest)\n        run: uv run pytest -q\n"
    publish_step = "      - name: Publish check\n        run: uv publish --dry-run\n"
    text = text.replace(contract, "", 1).replace(
        test_step,
        test_step + publish_step + contract,
        1,
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-COMMAND-ORDER" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            '        python-version: ["3.11", "3.12", "3.13"]',
            '        python-version: ["3.11", "3.12", "3.13"]\n'
            "        exclude:\n"
            '          - python-version: "3.13"',
            "REPO-CI-PYTHON-COVERAGE-MISSING",
        ),
        (
            '        python-version: ["3.11", "3.12", "3.13"]',
            '        python-version: ["3.11", "3.12", "3.13"]\n'
            "        exclude:\n"
            "          - python-version: ${{ matrix.disabled-version }}",
            "REPO-CI-MATRIX-INVALID",
        ),
        (
            "      - name: Repository contract\n"
            f"        run: {CANONICAL_COMMAND}",
            "      - name: Repository contract\n"
            "        if: matrix.python-version != '3.13'\n"
            f"        run: {CANONICAL_COMMAND}",
            "REPO-CI-COMMAND-CONDITIONAL",
        ),
        (
            "      - name: Repository contract\n"
            f"        run: {CANONICAL_COMMAND}",
            "      - name: Repository contract\n"
            "        continue-on-error: true\n"
            f"        run: {CANONICAL_COMMAND}",
            "REPO-CI-COMMAND-CONTINUE-ON-ERROR",
        ),
        (
            "    runs-on: ubuntu-latest",
            "    if: matrix.python-version != '3.13'\n"
            "    runs-on: ubuntu-latest",
            "REPO-CI-JOB-CONDITIONAL",
        ),
        (
            "    runs-on: ubuntu-latest",
            "    continue-on-error: ${{ matrix.experimental }}\n"
            "    runs-on: ubuntu-latest",
            "REPO-CI-JOB-CONTINUE-ON-ERROR",
        ),
    ],
)
def test_ci_effective_coverage_rejects_lane_skipping_and_softening(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    old: str,
    new: str,
    expected: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert expected in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("control", ["literal_controls", "partial_exclusion"])
def test_ci_effective_coverage_accepts_non_skipping_controls(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    control: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    if control == "literal_controls":
        text = text.replace(
            "    runs-on: ubuntu-latest",
            "    if: ${{ true }}\n"
            "    continue-on-error: false\n"
            "    runs-on: ubuntu-latest",
            1,
        ).replace(
            "      - name: Repository contract\n"
            f"        run: {CANONICAL_COMMAND}",
            "      - name: Repository contract\n"
            "        if: always()\n"
            "        continue-on-error: ${{ false }}\n"
            f"        run: {CANONICAL_COMMAND}",
            1,
        )
    else:
        text = text.replace(
            '        python-version: ["3.11", "3.12", "3.13"]',
            '        python-version: ["3.11", "3.12", "3.13"]\n'
            '        os: ["ubuntu", "macos"]\n'
            "        exclude:\n"
            '          - python-version: "3.13"\n'
            '            os: "macos"',
            1,
        )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "blocker",
    [
        "conditional-skip",
        "exit-1",
        "exit-2",
        "exit-127",
        "bin-false",
        "shell-exit",
        "step-conditional",
        "step-soft-fail",
    ],
)
def test_ci_dependency_reachability_rejects_impossible_needs(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocker: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    blocker_job = (
        "  blocker:\n"
        + ("    if: ${{ false }}\n" if blocker == "conditional-skip" else "")
        + "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        + (
            "      - if: ${{ false }}\n"
            if blocker == "step-conditional"
            else (
                "      - continue-on-error: true\n"
                if blocker == "step-soft-fail"
                else "      - "
            )
        )
        + (
            "        run: "
            if blocker in {"step-conditional", "step-soft-fail"}
            else "run: "
        )
        + {
            "conditional-skip": "echo skipped",
            "exit-1": "exit 1",
            "exit-2": "exit 2",
            "exit-127": "exit 127",
            "bin-false": "/bin/false",
            "shell-exit": "sh -c 'exit 9'",
            "step-conditional": "echo skipped",
            "step-soft-fail": "/bin/false",
        }[blocker]
        + "\n"
    )
    text = text.replace("jobs:\n", f"jobs:\n{blocker_job}", 1).replace(
        "  checks:\n",
        "  checks:\n    needs: blocker\n",
        1,
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-NEEDS-UNREACHABLE" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    "run",
    [
        "uv run coverage run -m pytest",
        "uv run python -m coverage run -m pytest",
        "coverage run -m pytest",
        "env COVERAGE_FILE=/tmp/coverage uv run coverage run -m pytest",
        "uv build --wheel",
        "python -m build --sdist",
    ],
)
def test_ci_equivalent_python_surfaces_cannot_bypass_matrix_enforcement(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    run: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text += (
        "\n  alternate-python:\n"
        "    runs-on: ubuntu-latest\n"
        "    strategy:\n"
        "      matrix:\n"
        '        runtime: ["3.11", "3.12", "3.13"]\n'
        "    steps:\n"
        "      - uses: astral-sh/setup-uv@v8.3.2\n"
        "        with:\n"
        "          python-version: ${{ matrix.runtime }}\n"
        "      - name: Alternate Python surface\n"
        f"        run: {run}\n"
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-COMMAND-MISSING" in result.output
    assert ".github/workflows/ci.yml#jobs.alternate-python" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize("matrix_key", ["python", "runtime"])
def test_ci_alternate_python_matrix_cannot_test_or_build_without_enforcement(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    matrix_key: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text += (
        "\n  alternate-python:\n"
        "    runs-on: ubuntu-latest\n"
        "    strategy:\n"
        "      matrix:\n"
        f'        {matrix_key}: ["3.11", "3.12", "3.13"]\n'
        "    steps:\n"
        "      - uses: astral-sh/setup-uv@v8.3.2\n"
        "        with:\n"
        f"          python-version: ${{{{ matrix.{matrix_key} }}}}\n"
        "      - run: uv run pytest -q\n"
        "      - run: uv build\n"
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-COMMAND-MISSING" in result.output
    assert ".github/workflows/ci.yml#jobs.alternate-python" in result.output
    assert _status(repository) == before


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            "      - name: Test (pytest)\n        run: uv run pytest -q",
            "      - name: Test (pytest)\n"
            "        if: matrix.python-version != '3.13'\n"
            "        run: uv run pytest -q",
            "REPO-CI-PYTHON-STEP-CONDITIONAL",
        ),
        (
            "      - name: Build wheel and source distribution\n        run: uv build",
            "      - name: Build wheel and source distribution\n"
            "        continue-on-error: true\n"
            "        run: uv build",
            "REPO-CI-PYTHON-STEP-CONTINUE-ON-ERROR",
        ),
    ],
)
def test_ci_python_test_and_build_steps_cannot_be_skipped_or_soft_failed(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    old: str,
    new: str,
    expected: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert expected in result.output
    assert _status(repository) == before


def test_ci_reachable_dependency_control_remains_valid(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "jobs:\n",
        "jobs:\n"
        "  prerequisite:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ready\n",
        1,
    ).replace(
        "  checks:\n",
        "  checks:\n    needs: prerequisite\n",
        1,
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before
