"""Closed Batch 0 capability-security model and sink-catalog contracts."""
from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from unrest_harness.capability_policy import (
    CAPABILITY_SINK_IDS,
    SECURITY_SEMANTIC_ROLE_IDS,
    SECURITY_TRANSFORM_IDS,
    CapabilityPolicyError,
    load_capability_policy,
    load_capability_security_model,
    load_capability_sink_catalog,
    validate_capability_model_anchors,
    validate_capability_sink_anchors,
)
from unrest_harness.models import TerminalReviewHandoff, ValidateHandoff, ValidationItem
from unrest_harness.storage import (
    atomic_write_json,
    atomic_write_text,
    attempt_to_markdown,
    terminal_review_to_markdown,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"
POLICIES = BUNDLED / "policies"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _mutated_bundled(
    tmp_path: Path,
    filename: str,
    mutate: Any,
) -> Path:
    bundled = tmp_path / "bundled"
    shutil.copytree(BUNDLED, bundled)
    path = bundled / "policies" / filename
    document = _load_json(path)
    mutate(document)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return bundled


@pytest.mark.parametrize(
    ("document_name", "schema_name"),
    (
        (
            "capability-security-model.v1.json",
            "capability-security-model.schema.json",
        ),
        ("capability-sinks.v1.json", "capability-sinks.schema.json"),
        ("role-capabilities.v1.json", "role-capabilities.schema.json"),
    ),
)
def test_packaged_capability_assets_match_strict_schemas(
    document_name: str,
    schema_name: str,
) -> None:
    schema = _load_json(ROOT / "schemas" / schema_name)
    document = _load_json(POLICIES / document_name)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


def test_closed_model_enumerates_exact_implementation_members_and_bounds() -> None:
    model = load_capability_security_model(BUNDLED)
    assert tuple(item.id for item in model.transforms) == SECURITY_TRANSFORM_IDS
    assert tuple(item.id for item in model.semantic_roles) == (
        SECURITY_SEMANTIC_ROLE_IDS
    )
    assert model.joins[0].model_dump() == {
        "commutative": True,
        "id": "sensitivity-provenance",
        "idempotent": True,
        "monotonic": True,
        "operation": "set-union",
    }
    assert model.ceilings.model_dump() == {
        "aggregate_work_bytes": 2 * 1024 * 1024,
        "decoded_bytes": 1024 * 1024,
        "expansion_nodes": 4096,
        "format_ast_depth": 4,
        "semantic_depth": 24,
        "semantic_nodes": 4096,
        "text_bytes": 256 * 1024,
        "transform_count": 24,
    }
    assert model.unsupported_behavior == "fail-closed"
    assert model.exhaustion_behavior == "fail-closed-with-concrete-provenance"


def test_sink_catalog_is_exact_and_every_anchor_resolves() -> None:
    model = load_capability_security_model(BUNDLED)
    catalog = load_capability_sink_catalog(BUNDLED)
    assert tuple(sink.id for sink in catalog.sinks) == CAPABILITY_SINK_IDS
    assert {sink.inventory for sink in catalog.sinks} == {
        "SensitiveValueInventory"
    }
    assert len(catalog.reachable_source_sha256) == 64
    assert validate_capability_model_anchors(ROOT, model) == ()
    assert validate_capability_sink_anchors(ROOT, catalog) == ()


@pytest.mark.parametrize(
    ("filename", "mutate", "loader"),
    (
        (
            "capability-security-model.v1.json",
            lambda value: value["transforms"].pop(),
            load_capability_security_model,
        ),
        (
            "capability-security-model.v1.json",
            lambda value: value["ceilings"].__setitem__("semantic_depth", 25),
            load_capability_security_model,
        ),
        (
            "capability-security-model.v1.json",
            lambda value: value.__setitem__("schema_version", 2),
            load_capability_security_model,
        ),
        (
            "capability-sinks.v1.json",
            lambda value: value["sinks"].append(value["sinks"][0]),
            load_capability_sink_catalog,
        ),
        (
            "capability-sinks.v1.json",
            lambda value: value["sinks"].pop(),
            load_capability_sink_catalog,
        ),
        (
            "capability-sinks.v1.json",
            lambda value: value["omissions"].pop(),
            load_capability_sink_catalog,
        ),
    ),
)
def test_closed_assets_reject_omission_drift_duplicates_and_versions(
    tmp_path: Path,
    filename: str,
    mutate: Any,
    loader: Any,
) -> None:
    bundled = _mutated_bundled(tmp_path, filename, mutate)
    with pytest.raises(CapabilityPolicyError):
        loader(bundled)


_CAPABILITY_ASSET_LOADERS = (
    ("role-capabilities.v1.json", load_capability_policy),
    ("capability-security-model.v1.json", load_capability_security_model),
    ("capability-sinks.v1.json", load_capability_sink_catalog),
)


@pytest.mark.parametrize(("filename", "loader"), _CAPABILITY_ASSET_LOADERS)
@pytest.mark.parametrize("duplicate_depth", ("top", "nested"))
def test_capability_asset_loaders_reject_duplicate_object_members_stably(
    tmp_path: Path,
    filename: str,
    loader: Any,
    duplicate_depth: str,
) -> None:
    bundled = tmp_path / "bundled"
    shutil.copytree(BUNDLED, bundled)
    path = bundled / "policies" / filename
    text = path.read_text(encoding="utf-8")
    if duplicate_depth == "top":
        text = text.replace("{", '{\n  "schema_version": 1,', 1)
    elif filename == "role-capabilities.v1.json":
        text = text.replace(
            '"behavior": "deny",',
            '"behavior": "deny",\n          "behavior": "deny",',
            1,
        )
    elif filename == "capability-security-model.v1.json":
        text = text.replace(
            '"semantic_depth": 24,',
            '"semantic_depth": 24,\n    "semantic_depth": 24,',
            1,
        )
    else:
        text = text.replace(
            '"id": "acp-cancel-client-cleanup",',
            (
                '"id": "acp-cancel-client-cleanup",\n'
                '      "id": "acp-cancel-client-cleanup",'
            ),
            1,
        )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CapabilityPolicyError) as caught:
        loader(bundled)

    diagnostic = str(caught.value)
    assert diagnostic.startswith("CAP-POLICY-001 ")
    assert f"resource {filename}" in diagnostic
    assert len(diagnostic.encode("utf-8")) < 256
    assert "schema_version" not in diagnostic
    assert "semantic_depth" not in diagnostic


@pytest.mark.parametrize(("filename", "loader"), _CAPABILITY_ASSET_LOADERS)
@pytest.mark.parametrize("mutation", ("missing", "unknown", "unsupported-version"))
def test_capability_asset_loaders_reject_strict_shape_controls(
    tmp_path: Path,
    filename: str,
    loader: Any,
    mutation: str,
) -> None:
    bundled = tmp_path / "bundled"
    shutil.copytree(BUNDLED, bundled)
    path = bundled / "policies" / filename
    document = _load_json(path)
    if mutation == "missing":
        document.pop("schema_version")
    elif mutation == "unknown":
        document["unsupported_member"] = True
    else:
        document["schema_version"] = 2
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CapabilityPolicyError):
        loader(bundled)


def test_sink_anchor_mutations_are_detected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    catalog = load_capability_sink_catalog(repository / "src/unrest_harness/bundled")
    path = repository / "src/unrest_harness/acp_runner.py"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "_redact_json_value(",
            "_untracked_json_value(",
        ),
        encoding="utf-8",
    )
    errors = validate_capability_sink_anchors(repository, catalog)
    assert any(
        error.startswith("acp-callback-errors:")
        or error.startswith("acp-callback-results:")
        or error.startswith("acp-request-errors:")
        or error.startswith("acp-request-results:")
        for error in errors
    )


def test_reachable_uncataloged_channels_fail_closed_model_validation(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _uncataloged_reachable_channel(value, markdown_path, archive_path, callback):
    import sys
    import zipfile
    print(value)
    print(value, file=sys.stderr)
    markdown_path.write_text(value, encoding="utf-8")
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("result.json", value)
    callback({"result": value, "progress": value, "error": value})
""",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    errors = validate_capability_sink_anchors(repository, catalog)
    assert len(
        [error for error in errors if "uncataloged output effect" in error]
    ) >= 5


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_file_writer(value, target):
    stream = target.open("w", encoding="utf-8")
    stream.write(value)
""",
        """
def _new_json_writer(value, target):
    import json as serializer
    with target.open("w", encoding="utf-8") as stream:
        serializer.dump(value, stream)
""",
        """
def _new_stdout_writer(value):
    import sys
    sys.stdout.write(value)
""",
        """
def _new_log_writer(value):
    import logging
    logging.getLogger("unrest").error(value)
""",
        """
def _new_descriptor_writer(value, descriptor):
    from os import write as emit
    emit(descriptor, value.encode())
""",
        """
def _new_acp_wire_writer(client, value):
    client._write(value)
""",
    ),
)
def test_semantically_equivalent_new_output_effects_require_governance(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        "reachable-sink-closure: uncataloged output effect" in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_rot_transform(value):
    import codecs
    return codecs.decode(value, "rot_13")
""",
        """
def _new_translation_transform(value, table):
    return value.translate(table)
""",
        """
def _new_compression_transform(value):
    from zlib import decompress
    return decompress(value)
""",
    ),
)
def test_new_reversible_transform_implementations_fail_closed(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        "reachable-transform-closure: unsupported reversible operation" in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


def test_declared_omission_cannot_gain_an_additional_primitive_writer(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    path = repository / "src/unrest_harness/baseline.py"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "def main() -> int:\n",
            "def main() -> int:\n    import sys\n    sys.stdout.write('alternate')\n",
            1,
        ),
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        "declared omission effect drift" in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


def test_unknown_new_computation_fails_normalized_source_closure(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _new_reversible_slice(value):
    return value[::-1]
""",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        error.startswith("reachable-capability-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


def test_handoff_and_terminal_review_artifacts_redact_brace_index_derivatives(
    tmp_path: Path,
) -> None:
    secret = "VCAP_bounded_persistence_secret"
    derivative = secret
    for _ in range(3):
        derivative = base64.urlsafe_b64encode(derivative.encode()).decode().rstrip("=")
    exploits = (
        f"{{mapping[head}}token={derivative}]!s:^12}}",
        f"{{mapping[head{{token={derivative}]!s:^12}}",
        f"{{mapping[token={derivative}}}tail]!s:^12}}",
        f"{{mapping[token={derivative}{{tail]!s:^12}}",
    )
    benign = "validator-benign-content"
    report = f"{benign}; sensitive=" + " | ".join(exploits)
    handoff = ValidateHandoff(
        node_id="validator-probe",
        done=True,
        report=report,
        items=[ValidationItem(item_id="VAL-PROBE", passed=False)],
        passed=False,
    )
    review = TerminalReviewHandoff(done=True, report=report)
    paths = (
        (tmp_path / "handoff.json", handoff.model_dump(mode="json"), True),
        (tmp_path / "attempt.md", attempt_to_markdown(handoff), False),
        (tmp_path / "review.json", review.model_dump(mode="json"), True),
        (tmp_path / "review.md", terminal_review_to_markdown(review), False),
    )
    for path, payload, structured in paths:
        if structured:
            atomic_write_json(path, payload)
            assert json.loads(path.read_text(encoding="utf-8"))
        else:
            assert isinstance(payload, str)
            atomic_write_text(path, payload)
        persisted = path.read_text(encoding="utf-8")
        assert benign in persisted
        assert derivative not in persisted
        assert not any(exploit in persisted for exploit in exploits)


@pytest.mark.parametrize(
    "constant_name",
    (
        "_FORMAT_AST_MAX_DEPTH",
        "_SEMANTIC_INSPECTION_MAX_DECODED_BYTES",
        "_SEMANTIC_INSPECTION_MAX_DEPTH",
        "_SEMANTIC_INSPECTION_MAX_EXPANSIONS",
        "_SEMANTIC_INSPECTION_MAX_NODES",
        "_SEMANTIC_INSPECTION_MAX_TEXT",
        "_SEMANTIC_INSPECTION_MAX_TRANSFORMS",
        "_SEMANTIC_INSPECTION_MAX_WORK",
    ),
)
def test_model_bound_implementation_mutations_are_detected(
    tmp_path: Path,
    constant_name: str,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    path = repository / "src/unrest_harness/capability_policy.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(f"{constant_name} =", f"{constant_name} = 1 +", 1)
    path.write_text(text, encoding="utf-8")
    model = load_capability_security_model(
        repository / "src/unrest_harness/bundled"
    )
    assert validate_capability_model_anchors(repository, model)
