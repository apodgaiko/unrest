"""Closed Batch 0 capability-security model and sink-catalog contracts."""
from __future__ import annotations

import ast
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
    build_reachable_capability_source_graph,
    load_capability_policy,
    load_capability_security_model,
    load_capability_sink_catalog,
    normalized_external_egress_records,
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


def _capability_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    (repository / "docs/architecture").mkdir(parents=True)
    shutil.copy2(
        ROOT / "docs/architecture/component-map.json",
        repository / "docs/architecture/component-map.json",
    )
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    return repository


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


def _copy_capability_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    architecture = repository / "docs" / "architecture"
    architecture.mkdir(parents=True)
    shutil.copy2(
        ROOT / "docs" / "architecture" / "component-map.json",
        architecture / "component-map.json",
    )
    return repository


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


def test_capability_source_graph_has_exact_roots_closure_and_initializer() -> None:
    catalog = load_capability_sink_catalog(BUNDLED)
    graph = build_reachable_capability_source_graph(ROOT, catalog)
    assert graph == tuple(sorted(graph))
    assert len(graph) == 21
    assert "src/unrest_harness/__init__.py" in graph
    assert "src/unrest_harness/capability_policy.py" in graph
    assert "src/unrest_harness/__main__.py" not in graph


def test_new_imported_helper_enters_graph_and_egress_projection(tmp_path: Path) -> None:
    repository = _capability_repository(tmp_path)
    root = repository / "src/unrest_harness/capability_policy.py"
    root.write_text(
        "from . import capability_helper\n" + root.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    helper = repository / "src/unrest_harness/capability_helper.py"
    helper.write_text("def relay(value):\n    return value\n", encoding="utf-8")
    catalog = load_capability_sink_catalog(repository / "src/unrest_harness/bundled")
    graph = build_reachable_capability_source_graph(repository, catalog)
    assert "src/unrest_harness/capability_helper.py" in graph
    helper.write_text(
        "import httpx\n\ndef relay(value):\n    httpx.post('https://example', content=value)\n",
        encoding="utf-8",
    )
    assert any(
        error.startswith("reachable-capability-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "source",
    (
        "import httpx\ndef relay(value):\n httpx.post('https://x', content=value)\n",
        "import urllib.request\ndef relay(value):\n request=urllib.request.Request('https://x', data=value)\n urllib.request.urlopen(request)\n",
        "import subprocess\ndef relay(value):\n subprocess.run(['tool'], input=value)\n",
        "def relay(connection, value):\n connection.execute('insert', value)\n",
        "def relay(queue, value):\n emit=queue.send\n emit(value)\n",
        "import httpx\ndef relay(value):\n emit=httpx.post\n emit('https://x', content=value)\n",
        "import httpx\ndef relay(value):\n getattr(httpx, 'post')('https://x', content=value)\n",
    ),
)
def test_normalized_projection_catches_atomic_external_egress(source: str) -> None:
    records = normalized_external_egress_records("src/unrest_harness/helper.py", ast.parse(source))
    assert records
    assert all(record["path"] == "src/unrest_harness/helper.py" for record in records)


def test_projection_is_semantic_deterministic_and_path_bound() -> None:
    plain = "def relay(value):\n return value > 0 and value != 2\n"
    formatted = "# comment\n\ndef relay( value ):\n    return (value > 0) and (value != 2)\n"
    assert normalized_external_egress_records("x.py", ast.parse(plain)) == ()
    assert normalized_external_egress_records("x.py", ast.parse(formatted)) == ()
    egress = ast.parse("def relay(queue, value):\n queue.send(value)\n")
    first = normalized_external_egress_records("a.py", egress)
    assert first == normalized_external_egress_records("a.py", egress)
    assert first != normalized_external_egress_records("b.py", egress)


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "escape", "malformed"))
def test_component_record_failures_close_source_graph(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = _capability_repository(tmp_path)
    path = repository / "docs/architecture/component-map.json"
    document = _load_json(path)
    component = next(
        item for item in document["components"] if item["id"] == "COMP-CAPABILITY"
    )
    if mutation == "missing":
        document["components"].remove(component)
    elif mutation == "duplicate":
        document["components"].append(component)
    elif mutation == "escape":
        component["paths"].append("../escape.py")
    else:
        component.pop("tests")
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    catalog = load_capability_sink_catalog(repository / "src/unrest_harness/bundled")
    errors = validate_capability_sink_anchors(repository, catalog)
    assert errors[0].startswith("reachable-capability-closure:")


def test_unimported_module_does_not_change_capability_closure(tmp_path: Path) -> None:
    repository = _capability_repository(tmp_path)
    path = repository / "src/unrest_harness/not_reachable.py"
    path.write_text(
        "import httpx\nvalue = httpx.post('https://example', content=b'x')\n",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(repository / "src/unrest_harness/bundled")
    assert validate_capability_sink_anchors(repository, catalog) == ()


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
    repository = _copy_capability_repository(tmp_path)
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
    repository = _copy_capability_repository(tmp_path)
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
    repository = _copy_capability_repository(tmp_path)
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
def _new_callback_alias(value, callback):
    middle = callback
    emit = middle
    emit(value)
""",
        """
def _new_callback_container_alias(value, callback):
    emitters = [callback]
    emitters[0](value)
""",
        """
class _NewStoredCallback:
    def __init__(self, callback):
        self.emit = callback

    def publish(self, value):
        self.emit(value)
""",
        """
def _new_bound_writer_alias(value, target):
    emit = target.write
    emit(value)
""",
        """
def _new_serializer_stream(value, target):
    import marshal
    serialize = marshal.dump
    serialize(value, target)
""",
        """
def _new_descriptor_vector_writer(value, descriptor):
    import os
    emit = os.writev
    emit(descriptor, [value])
""",
    ),
)
def test_output_aliases_and_new_stream_families_fail_closed(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        "reachable-sink-closure: uncataloged output effect" in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


def test_annotated_callback_escape_changes_semantic_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _new_callback_escape(callback: Callable[[str], None]):
    return {"emit": callback}
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


@pytest.mark.parametrize(
    ("addition", "diagnostic"),
    (
        (
            """
def _new_lambda_callback_wrapper(value, callback):
    deliver = lambda item: callback(item)
    return deliver(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_dynamic_descriptor_writer(value, descriptor):
    import os
    deliver = getattr(os, "write")
    deliver(descriptor, value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_dynamic_serializer(value, target):
    import pickle
    serialize = getattr(pickle, "dump")
    serialize(value, target)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_dynamic_base85_transform(value):
    import base64
    encode = getattr(base64, "b85encode")
    return encode(value)
""",
            "reachable-transform-closure: unsupported reversible operation",
        ),
        (
            """
def _new_joined_reversal(value):
    return "".join(reversed(value))
""",
            "reachable-transform-closure: unsupported reversible operation",
        ),
    ),
    ids=(
        "lambda-callback-wrapper",
        "dynamic-descriptor-writer",
        "dynamic-serializer",
        "dynamic-reversible-codec",
        "joined-reversal",
    ),
)
def test_neutral_wrapper_and_dynamic_capability_bypasses_fail_closed(
    tmp_path: Path,
    addition: str,
    diagnostic: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        diagnostic in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    ("addition", "diagnostic"),
    (
        (
            """
def _new_constant_descriptor_writer(value, descriptor):
    import os
    operation = "write"
    invoke = getattr(os, operation)
    invoke(descriptor, value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_constant_serializer(value, target):
    import pickle
    operation = "dump"
    invoke = getattr(pickle, operation)
    invoke(value, target)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_constant_transform(value):
    import base64
    operation = "b85encode"
    invoke = getattr(base64, operation)
    return invoke(value)
""",
            "reachable-transform-closure: unsupported reversible operation",
        ),
        (
            """
def _new_nested_callback_wrapper(value, callback):
    def deliver(item):
        callback(item)

    invoke = deliver
    return invoke(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_module_dict_descriptor_writer(value, descriptor):
    import os
    invoke = os.__dict__["write"]
    invoke(descriptor, value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_module_dict_serializer(value, target):
    import pickle
    invoke = pickle.__dict__["dump"]
    invoke(value, target)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_module_dict_transform(value):
    import base64
    invoke = base64.__dict__["b85encode"]
    return invoke(value)
""",
            "reachable-transform-closure: unsupported reversible operation",
        ),
        *(
            (
                f"""
def _new_{materializer}_reversal(value):
    return {materializer}(reversed(value))
""",
                "reachable-transform-closure: unsupported reversible operation",
            )
            for materializer in ("bytearray", "bytes", "list", "tuple")
        ),
    ),
    ids=(
        "constant-descriptor-writer",
        "constant-serializer",
        "constant-transform",
        "nested-callback-wrapper",
        "module-dict-descriptor-writer",
        "module-dict-serializer",
        "module-dict-transform",
        "bytearray-reversal",
        "bytes-reversal",
        "list-reversal",
        "tuple-reversal",
    ),
)
def test_scoped_indirect_capability_acquisition_fails_closed(
    tmp_path: Path,
    addition: str,
    diagnostic: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        diagnostic in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    ("addition", "diagnostic"),
    (
        (
            """
def _new_returned_callback(value, callback):
    return callback(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_lambda_default_callback(value, callback):
    invoke = lambda item, fn=callback: fn(item)
    return invoke(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_nested_default_callback(value, callback):
    def deliver(item, fn=callback):
        return fn(item)

    invoke = deliver
    return invoke(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_nested_outer_alias_callback(value, callback):
    fn = callback

    def deliver(item):
        return fn(item)

    invoke = deliver
    return invoke(value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        *(
            (
                f"""
def _new_{lookup}_{family}(value, target):
    import {module}
    invoke = {expression}
    return invoke(target, value) if {is_writer!r} else invoke(value, target)
""",
                diagnostic,
            )
            for lookup, expression_template in (
                ("module_dict_get", "{module}.__dict__.get({operation!r})"),
                ("vars_lookup", "vars({module})[{operation!r}]"),
            )
            for family, module, operation, diagnostic, is_writer in (
                (
                    "descriptor_writer",
                    "os",
                    "write",
                    "reachable-sink-closure: uncataloged output effect",
                    True,
                ),
                (
                    "serializer",
                    "pickle",
                    "dump",
                    "reachable-sink-closure: uncataloged output effect",
                    False,
                ),
                (
                    "transform",
                    "base64",
                    "b85encode",
                    "reachable-transform-closure: unsupported reversible operation",
                    False,
                ),
            )
            for expression in (
                expression_template.format(module=module, operation=operation),
            )
        ),
    ),
    ids=(
        "returned-callback",
        "lambda-default-callback",
        "nested-default-callback",
        "nested-outer-alias-callback",
        "module-dict-get-descriptor",
        "module-dict-get-serializer",
        "module-dict-get-transform",
        "vars-descriptor",
        "vars-serializer",
        "vars-transform",
    ),
)
def test_returned_callbacks_and_mapping_style_acquisition_fail_closed(
    tmp_path: Path,
    addition: str,
    diagnostic: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        diagnostic in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    ("addition", "diagnostic"),
    (
        (
            """
def _new_list_serializer(value, target):
    import pickle
    emitters = [pickle.dump]
    return emitters[0](value, target)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_dict_transform(value):
    import base64
    transforms = {"encode": base64.b85encode}
    return transforms["encode"](value)
""",
            "reachable-transform-closure: unsupported reversible operation",
        ),
        (
            """
def _new_tuple_descriptor_writer(value, descriptor):
    import os
    emitters = (os.write,)
    return emitters[0](descriptor, value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_list_bound_writer(value, target):
    emitters = [target.write]
    return emitters[0](value)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
        (
            """
def _new_singleton_set_serializer(value, target):
    import pickle
    emitters = {pickle.dump}
    emit = next(iter(emitters))
    return emit(value, target)
""",
            "reachable-sink-closure: uncataloged output effect",
        ),
    ),
    ids=(
        "list-serializer",
        "dict-transform",
        "tuple-descriptor",
        "list-bound-writer",
        "singleton-set-serializer",
    ),
)
def test_literal_container_capability_aliases_fail_closed(
    tmp_path: Path,
    addition: str,
    diagnostic: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        diagnostic in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_returned_transform_slot():
    import base64
    transforms = [base64.b85encode]
    return transforms[0]
""",
        """
def _new_returned_serializer_slot():
    import pickle
    serializers = {"dump": pickle.dump}
    return serializers["dump"]
""",
        """
def _new_returned_descriptor_slot():
    import os
    writers = (os.write,)
    return writers[0]
""",
        """
def _new_returned_writer_slot():
    writers = [print]
    return writers[0]
""",
        """
def _new_returned_singleton_writer():
    import os
    writers = {os.write}
    return next(iter(writers))
""",
    ),
    ids=(
        "transform-list-slot",
        "serializer-dict-slot",
        "descriptor-tuple-slot",
        "writer-list-slot",
        "writer-singleton-slot",
    ),
)
def test_returned_literal_container_capabilities_change_closure(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        error.startswith("reachable-capability-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_constant_index_descriptor_slot():
    import os
    slot = 0
    writers = [os.write]
    return writers[slot]
""",
        """
def _new_constant_key_serializer_slot():
    import pickle
    slot = "dump"
    serializers = {"dump": pickle.dump}
    return serializers[slot]
""",
        """
def _new_constant_index_transform_slot():
    import base64
    slot = 0
    transforms = [base64.b85encode]
    return transforms[slot]
""",
        """
def _new_nested_transform_slot():
    import base64
    transforms = [[base64.b85encode]]
    return transforms[0][0]
""",
        """
def _new_nested_serializer_slot():
    import pickle
    serializers = {"formats": [pickle.dump]}
    return serializers["formats"][0]
""",
        """
def _new_nested_writer_slot():
    writers = [[print]]
    return writers[0][0]
""",
        """
def _new_destructured_serializer():
    import pickle
    (emit,) = (pickle.dump,)
    return emit
""",
        """
def _new_destructured_transform():
    import base64
    [encode] = [base64.b85encode]
    return encode
""",
        """
def _new_destructured_writer():
    (emit,) = (print,)
    return emit
""",
    ),
    ids=(
        "constant-index-descriptor",
        "constant-key-serializer",
        "constant-index-transform",
        "nested-transform",
        "nested-serializer",
        "nested-writer",
        "destructured-serializer",
        "destructured-transform",
        "destructured-writer",
    ),
)
def test_bounded_nested_and_destructured_capability_aliases_change_closure(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        error.startswith("reachable-capability-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_returned_writer_container():
    import os
    writers = [os.write]
    return writers
""",
        """
def _new_returned_serializer_container():
    import pickle
    serializers = (pickle.dump,)
    return serializers
""",
        """
def _new_returned_transform_container():
    import base64
    transforms = {"encode": base64.b85encode}
    return transforms
""",
        """
def _new_returned_singleton_container():
    writers = {print}
    return writers
""",
        """
def _new_returned_nested_container():
    import base64
    transforms = [[base64.b85encode]]
    return transforms
""",
        """
def _new_yielded_transform_container():
    import base64
    transforms = {"decode": (base64.b85decode,)}
    yield transforms
""",
        """
class _NewStoredCapabilityContainer:
    def store(self):
        import pickle
        serializers = [pickle.dump]
        self.serializers = serializers
""",
        """
def _new_passed_capability_container(register):
    import os
    writers = {"write": os.write}
    register(writers)
""",
    ),
    ids=(
        "returned-list-writer",
        "returned-tuple-serializer",
        "returned-dict-transform",
        "returned-singleton-set",
        "returned-nested-list",
        "yielded-nested-transform",
        "stored-serializer-list",
        "passed-writer-dict",
    ),
)
def test_escaped_literal_capability_containers_change_closure(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        error.startswith("reachable-capability-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
class _NewDestructuredWriterState:
    def store(self):
        import os
        self.writers, label = ([os.write], "fixed")
""",
        """
class _NewDestructuredSerializerState:
    def store(self):
        import pickle
        [self.serializers, label] = ({"nested": [pickle.dump]}, "fixed")
""",
        """
class _NewNestedDestructuredTransformState:
    def store(self):
        import base64
        ((self.encoder,), label) = ((base64.b85encode,), "fixed")
""",
        """
def _new_destructured_subscript_state(state):
    import os
    state["writers"], label = ([os.write], "fixed")
""",
    ),
    ids=(
        "attribute-writer-container",
        "attribute-serializer-container",
        "nested-attribute-transform",
        "subscript-writer-container",
    ),
)
def test_exact_destructuring_into_state_changes_closure(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        error.startswith("reachable-capability-closure:")
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
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert any(
        "reachable-transform-closure: unsupported reversible operation" in error
        for error in validate_capability_sink_anchors(repository, catalog)
    )


@pytest.mark.parametrize(
    "addition",
    (
        """
def _new_base85_transform(value):
    import base64
    encode = base64.b85encode
    return encode(value)
""",
        """
def _new_percent_transform(value):
    from urllib.parse import quote_plus as encode
    return encode(value)
""",
        """
def _new_transform_callable_escape():
    import base64
    import functools
    return functools.partial(base64.urlsafe_b64encode)
""",
    ),
)
def test_reversible_entry_points_and_callable_escapes_fail_closed(
    tmp_path: Path,
    addition: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    errors = validate_capability_sink_anchors(repository, catalog)
    assert any(
        error.startswith("reachable-transform-closure:")
        or error.startswith("reachable-capability-closure:")
        for error in errors
    )


def test_declared_omission_cannot_gain_an_additional_primitive_writer(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
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


def test_unknown_new_reversible_computation_fails_semantic_effect_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
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
        error.startswith("reachable-transform-closure:")
        for error in validate_capability_sink_anchors(repository, catalog)
    )


def test_unrelated_new_computation_does_not_change_capability_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _unrelated_arithmetic(left, right):
    return (left * 7) + right
""",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert validate_capability_sink_anchors(repository, catalog) == ()


def test_unrelated_aliases_predicates_and_write_attributes_do_not_change_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _unrelated_local_flow(
    value,
    predicate: Callable[[int], bool],
    declaration,
    ):
        import math as json
        magnitude = abs
        accepted = value if predicate(value) else 0
        return magnitude(value), accepted, declaration.write, json.sqrt(value)
""",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert validate_capability_sink_anchors(repository, catalog) == ()


def test_unrelated_dynamic_callables_and_composition_do_not_change_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _unrelated_dynamic_callables(owner, attribute, value):
    import math
    dynamic = getattr(owner, attribute)
    square_root = getattr(math, "sqrt")
    increment = lambda item: item + 1
    return dynamic(value), square_root(value), increment(value)


def _unrelated_ordering(value):
    return (
        "".join(sorted(value)),
        tuple(sorted(value)),
        bytes(sorted(value)),
        list(sorted(value)),
    )


def _unrelated_dynamic_and_module_dict(owner, operation, value):
    import math
    dynamic = getattr(owner, operation)
    harmless_name = "sqrt"
    square_root = math.__dict__[harmless_name]
    return dynamic(value), square_root(value)


def _unrelated_nested_function(value):
    def adjust(item):
        return item + 1

    invoke = adjust
    return invoke(value)


def _unrelated_mapping_lookups(value):
    import math
    from_dict = math.__dict__.get("sqrt")
    from_vars = vars(math)["sqrt"]
    return from_dict(value), from_vars(value)


def _unrelated_literal_containers(value, index, key):
    import math
    sequence = [math.sqrt, abs]
    tupled = (math.floor, math.ceil)
    mapped = {"sqrt": math.sqrt, "floor": math.floor}
    singleton = {math.sqrt}
    selected = next(iter(singleton))
    return (
        sequence[index](value),
        tupled[0](value),
        mapped[key](value),
        selected(value),
    )


def _unrelated_returned_container_slots():
    import math
    sequence = [math.sqrt]
    mapped = {"floor": math.floor}
    singleton = {math.ceil}
    return sequence[0], mapped["floor"], next(iter(singleton))


def _unrelated_bounded_container_flow():
    import math
    slot = 0
    key = "sqrt"
    nested = [[math.sqrt]]
    mapped = {"sqrt": math.sqrt}
    (floor,) = (math.floor,)
    [ceil] = [math.ceil]
    return nested[slot][0], mapped[key], floor, ceil


class _UnrelatedStoredContainer:
    def store(self):
        import math
        helpers = [math.sqrt]
        self.helpers = helpers


class _UnrelatedDestructuredState:
    def store(self, state):
        import math
        self.helpers, label = ([math.sqrt], "fixed")
        [state["rounding"], label] = ({"nested": [math.floor]}, "fixed")


def _unrelated_escaped_containers():
    import math
    sequence = [math.sqrt]
    nested = {"rounding": (math.floor, math.ceil)}
    singleton = {math.sqrt}
    tuple(nested)
    return sequence, singleton
""",
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    assert validate_capability_sink_anchors(repository, catalog) == ()


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
