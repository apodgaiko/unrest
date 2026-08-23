"""Executable Lean/ADR/security crosswalk and candidate inventory audit."""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[2]
CROSSWALK_PATH = ROOT / "docs/release/lean-core-v0.2-evidence-crosswalk.json"
AUDIT_PATH = ROOT / "docs/release/lean-core-v0.2-review-audit.json"
CROSSWALK = json.loads(CROSSWALK_PATH.read_text(encoding="utf-8"))
V02_TAG = "v0.2.0"


def _tag_bytes(relative: str) -> bytes:
    return subprocess.run(
        ("git", "show", f"{V02_TAG}:{relative}"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def _tag_paths(root: str) -> list[str]:
    output = subprocess.run(
        ("git", "ls-tree", "-r", "--name-only", V02_TAG, "--", root),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    return sorted(output.splitlines())


def _record_nodes(record: dict[str, object]) -> tuple[str, ...]:
    if "nodes" in record:
        nodes = record["nodes"]
        assert isinstance(nodes, list) and nodes
        assert all(isinstance(node, str) for node in nodes)
        return tuple(nodes)
    node = record["node"]
    assert isinstance(node, str)
    return (node,)


SCENARIOS = tuple(
    (f"{identifier}:{index}", identifier, node)
    for identifier, record in CROSSWALK["mappings"].items()
    for index, node in enumerate(_record_nodes(record))
) + tuple(
    (f"hard-cut:{record['surface']}", record["surface"], record["node"])
    for record in CROSSWALK["hard_cut_results"]
)


def _catalog(pattern: str, relative: str) -> set[str]:
    text = (ROOT / relative).read_text(encoding="utf-8")
    return set(re.findall(pattern, text, re.MULTILINE))


def _dependency_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9_.-]+", requirement)
    assert match is not None
    return match.group().lower()


def test_crosswalk_is_complete_and_every_mapped_node_passes(lean_reference_run) -> None:
    behavior = _catalog(
        r"^### (LEAN-[A-Z0-9-]+):",
        "docs/proposals/batch-0.5/behavior-contract.md",
    )
    adr = _catalog(
        r"^  - (VAL-LEAN-[A-Z0-9-]+)$",
        "docs/decisions/ADR-0002-lean-core-v0.2.md",
    )
    sinks = _catalog(
        r"^\| (SEC-SINK-[A-Z0-9-]+) \|",
        "docs/proposals/batch-0.5/security-contract.md",
    )
    mappings = CROSSWALK["mappings"]
    assert set(mappings) == behavior | adr | sinks
    assert len(sinks) == 17
    assert all(
        set(record) in ({"node", "candidate_result"}, {"nodes", "candidate_result"})
        for record in mappings.values()
    )
    expected_nodes = {
        node for record in mappings.values() for node in _record_nodes(record)
    }
    expected_nodes.update(record["node"] for record in CROSSWALK["hard_cut_results"])
    assert expected_nodes == set(lean_reference_run.nodes)
    assert all(
        record["candidate_result"] == "pass"
        for record in CROSSWALK["hard_cut_results"]
    )
    assert lean_reference_run.returncode == 0, lean_reference_run.output


def test_v02_source_import_dependency_and_hard_cut_inventories_are_historical() -> None:
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    source_paths = [
        path
        for path in _tag_paths("src/unrest_harness")
        if Path(path).parent.as_posix() == "src/unrest_harness"
        and path.endswith(".py")
    ]
    assert source_paths == audit["source_inventory"]

    first_party_modules = {Path(path).stem for path in source_paths}
    first_party_modules.add("unrest_harness")
    imported: set[str] = set()
    for relative in source_paths:
        tree = ast.parse(_tag_bytes(relative).decode("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
    assert sorted(imported & first_party_modules) == audit["first_party_import_inventory"]

    project = tomllib.loads(_tag_bytes("pyproject.toml").decode("utf-8"))
    runtime = sorted(_dependency_name(value) for value in project["project"]["dependencies"])
    development = sorted(
        _dependency_name(value) for value in project["dependency-groups"]["dev"]
    )
    dependencies = audit["direct_dependency_inventory"]
    assert runtime == dependencies["runtime"]
    assert development == dependencies["development"]
    assert not (set(runtime) | set(development)) & set(dependencies["removed_direct"])

    tag_inventory = set(_tag_paths("."))
    assert not set(audit["hard_cut_absence_inventory"]) & tag_inventory


def test_v02_package_inventory_is_bound_to_the_v020_tag() -> None:
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    expected = {
        path.removeprefix("src/") for path in audit["source_inventory"]
    }
    expected.add("unrest_harness/py.typed")
    expected.update(path.removeprefix("src/") for path in _tag_paths(
        "src/unrest_harness/bundled"
    ))
    tag_product = {
        path.removeprefix("src/")
        for path in _tag_paths("src/unrest_harness")
        if path.endswith(".py")
        or path == "src/unrest_harness/py.typed"
        or path.startswith("src/unrest_harness/bundled/")
    }
    assert tag_product == expected

    forbidden = audit["package_input_inventory"]["forbidden_archive_fragments"]
    archive_hits = [
        member
        for member in tag_product
        if any(fragment in member.lower() for fragment in forbidden)
    ]
    assert archive_hits == []


def test_schema_consumer_disposition_and_supported_provider_docs_are_honest() -> None:
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    disposition = audit["compatibility_disposition"]
    assert "external publication unverified" in disposition["root_schemas"].lower()
    assert "external publication and consumers unverified" in disposition[
        "observer_v1"
    ].lower()

    for relative in (
        "docs/decisions/ADR-0002-lean-core-v0.2.md",
        "docs/proposals/batch-0.5/deletion-ledger.md",
        "docs/release/lean-core-v0.2.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8").lower()
        assert "external publication" in text and "unverified" in text

    supported_surfaces = (
        ROOT / ".github/ISSUE_TEMPLATE/bug_report.md",
        ROOT / "README.md",
        ROOT / "pyproject.toml",
        *(ROOT / "src/unrest_harness").glob("*.py"),
    )
    removed_provider = base64.b64decode("aGVybWVz").decode("ascii")
    removed_provider_hits = [
        path.relative_to(ROOT).as_posix()
        for path in supported_surfaces
        if removed_provider in path.read_text(encoding="utf-8").lower()
    ]
    assert removed_provider_hits == []

    troubleshooting = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "does not follow the link or overwrite its target" in troubleshooting
    assert "never credential values" in troubleshooting
    issue_template = (ROOT / ".github/ISSUE_TEMPLATE/bug_report.md").read_text(
        encoding="utf-8"
    )
    assert "Do not attach raw" in issue_template
    assert "credential values" in issue_template
