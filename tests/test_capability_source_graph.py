"""Bounded source-graph and normalized external-egress closure contracts."""
from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest

from unrest_harness.capability_policy import (
    CapabilitySourceGraphError,
    build_reachable_capability_source_graph,
    load_capability_sink_catalog,
    normalized_external_egress_records,
    validate_capability_sink_anchors,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"


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


def _catalog(repository: Path):
    return load_capability_sink_catalog(repository / "src/unrest_harness/bundled")


def _append_to_capability_root(repository: Path, addition: str) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")


def _closure_errors(repository: Path) -> tuple[str, ...]:
    return validate_capability_sink_anchors(repository, _catalog(repository))


def test_current_capability_source_graph_has_exact_reviewed_closure() -> None:
    catalog = load_capability_sink_catalog(BUNDLED)
    graph = build_reachable_capability_source_graph(ROOT, catalog)

    assert graph == (
        "src/unrest_harness/__init__.py",
        "src/unrest_harness/acp_runner.py",
        "src/unrest_harness/assets.py",
        "src/unrest_harness/attention.py",
        "src/unrest_harness/baseline.py",
        "src/unrest_harness/capability_policy.py",
        "src/unrest_harness/cli.py",
        "src/unrest_harness/config.py",
        "src/unrest_harness/controller.py",
        "src/unrest_harness/coordinator.py",
        "src/unrest_harness/dispatcher.py",
        "src/unrest_harness/envelope.py",
        "src/unrest_harness/governance.py",
        "src/unrest_harness/installed_wheel_check.py",
        "src/unrest_harness/models.py",
        "src/unrest_harness/providers.py",
        "src/unrest_harness/repository_contract.py",
        "src/unrest_harness/server.py",
        "src/unrest_harness/storage.py",
        "src/unrest_harness/task_list_patch.py",
        "src/unrest_harness/task_validation.py",
    )
    assert "src/unrest_harness/__main__.py" not in graph


def test_new_import_adds_helper_and_executed_package_initializer(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    package = repository / "src/unrest_harness/cap_helpers"
    package.mkdir()
    (package / "__init__.py").write_text("PACKAGE_MARKER = True\n", encoding="utf-8")
    helper = package / "transport.py"
    helper.write_text(
        "def normalize(value):\n    return value.strip()\n",
        encoding="utf-8",
    )
    _append_to_capability_root(
        repository,
        "\nfrom .cap_helpers import transport as _cap_transport\n",
    )

    graph = build_reachable_capability_source_graph(repository, _catalog(repository))
    assert "src/unrest_harness/cap_helpers/__init__.py" in graph
    assert "src/unrest_harness/cap_helpers/transport.py" in graph
    assert _closure_errors(repository) == ()

    helper.write_text(
        "def publish(connection, value):\n    return connection.execute('event', value)\n",
        encoding="utf-8",
    )
    errors = _closure_errors(repository)
    assert len(errors) == 1
    assert errors[0].startswith(
        "reachable-capability-closure: effect graph"
    )


def test_imported_local_symlink_escaping_repository_fails_closed(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("def publish(value):\n    return value\n", encoding="utf-8")
    helper = repository / "src/unrest_harness/escaping_helper.py"
    helper.symlink_to(outside)
    _append_to_capability_root(repository, "\nfrom . import escaping_helper\n")

    with pytest.raises(CapabilitySourceGraphError, match="escapes the repository"):
        build_reachable_capability_source_graph(repository, _catalog(repository))
    assert _closure_errors(repository)[0].startswith("reachable-capability-closure:")


@pytest.mark.parametrize(
    "mutation",
    ("missing-map", "duplicate-component", "malformed-component", "escaping-path", "missing-path"),
)
def test_component_records_fail_closed(tmp_path: Path, mutation: str) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "docs/architecture/component-map.json"
    if mutation == "missing-map":
        path.unlink()
    else:
        document = json.loads(path.read_text(encoding="utf-8"))
        component = next(
            item for item in document["components"] if item["id"] == "COMP-CAPABILITY"
        )
        if mutation == "duplicate-component":
            document["components"].append(dict(component))
        elif mutation == "malformed-component":
            component.pop("paths")
        elif mutation == "escaping-path":
            component["paths"].append("../outside.py")
        else:
            component["paths"].append("src/unrest_harness/missing.py")
        path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CapabilitySourceGraphError):
        build_reachable_capability_source_graph(repository, _catalog(repository))
    assert _closure_errors(repository)[0].startswith("reachable-capability-closure:")


_ATOMIC_EGRESS_MUTATIONS = {
    "http": """
def _atomic_http(value):
    import httpx
    httpx.post("https://example.invalid", content=value)
""",
    "urllib": """
def _atomic_urllib(value):
    import urllib.request
    request = urllib.request.Request("https://example.invalid", data=value)
    urllib.request.urlopen(request)
""",
    "subprocess": """
def _atomic_subprocess(value):
    import subprocess
    subprocess.run(["consumer"], input=value)
""",
    "database-ipc": """
def _atomic_database(connection, value):
    connection.execute("insert event", value)
""",
    "alias": """
def _atomic_alias(value):
    import httpx
    dispatch = httpx.post
    dispatch("https://example.invalid", content=value)
""",
    "constant-getattr": """
def _atomic_constant_getattr(connection, value):
    getattr(connection, "execute")("insert event", value)
""",
}

_RESULT_USED_EGRESS_CALLS = {
    "http": ("import httpx", 'httpx.post("https://example.invalid", content=value)'),
    "urllib": (
        "import urllib.request\n"
        '    request = urllib.request.Request("https://example.invalid", data=value)',
        "urllib.request.urlopen(request)",
    ),
    "subprocess": (
        "import subprocess",
        'subprocess.run(["consumer"], input=value)',
    ),
    "database-execute": ("", 'connection.execute("insert event", value)'),
    "ipc-send": ("", "connection.send(value)"),
    "ipc-write": ("", "connection.write(value)"),
    "alias": (
        "import httpx\n    dispatch = httpx.post",
        'dispatch("https://example.invalid", content=value)',
    ),
    "bound-method": (
        "dispatch = connection.execute",
        'dispatch("insert event", value)',
    ),
    "constant-getattr": (
        "",
        'getattr(connection, "execute")("insert event", value)',
    ),
}

_RESULT_CONTEXTS = {
    "discarded": "{call}",
    "returned": "return {call}",
    "assigned": "result = {call}\n    return result",
    "awaited": "result = await {call}\n    return result",
    "nested": "return consume({call})",
}


_FIRST_POSITIONAL_EGRESS_CALLS = {
    "subprocess": """import subprocess
def publish(value):
    subprocess.run(value)
""",
    "aliased-http": """import httpx
def publish(value):
    dispatch = httpx.post
    dispatch(value)
""",
    "custom": """def publish(value):
    send_fds(value)
""",
    "bound": """def publish(channel, value):
    send_fds = channel.send_fds
    send_fds(value)
""",
}


@pytest.mark.parametrize("source", tuple(_FIRST_POSITIONAL_EGRESS_CALLS.values()))
def test_first_positional_external_egress_is_data_bearing(source: str) -> None:
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )

    assert len(records) == 1
    assert records[0]["arguments"] == [["name", "value"]]


@pytest.mark.parametrize(
    "source",
    (
        'import subprocess\ndef publish():\n    subprocess.run(["consumer"])\n',
        'import httpx\ndef publish():\n    httpx.post("https://example.invalid")\n',
        "def publish(channel):\n    channel.send_fds()\n",
        "def publish(channel):\n    send_fds = channel.send_fds\n    send_fds()\n",
    ),
)
def test_fixed_leading_literals_and_method_receivers_are_not_payloads(
    source: str,
) -> None:
    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    ) == ()


def test_pure_callable_provenance_is_not_external_egress() -> None:
    source = """def calculate(owner, attribute, value, predicate):
    import math
    magnitude = abs
    dynamic = getattr(owner, attribute)
    square_root = getattr(math, "sqrt")
    increment = lambda item: item + 1
    accepted = predicate

    def adjust(item):
        return item + 2

    invoke = adjust
    return (
        magnitude(value),
        dynamic(value),
        square_root(value),
        increment(value),
        invoke(value),
        accepted(value),
    )
"""

    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    ) == ()


@pytest.mark.parametrize(
    "selection",
    (
        "math.sqrt if predicate else abs",
        "next(iter([math.sqrt, abs, local_adjust]))",
    ),
    ids=("conditional", "literal-iterable-selector"),
)
def test_complete_pure_callable_composites_are_not_external_egress(
    selection: str,
) -> None:
    source = f"""def calculate(value, predicate):
    import math

    def local_adjust(item):
        return item + 1

    dispatch = {selection}
    return dispatch(value)
"""

    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    ) == ()


@pytest.mark.parametrize(
    "selection",
    (
        "factory()",
        "factory(math.sqrt)",
        "factory(math.sqrt, httpx.post)",
        "math.sqrt if predicate else httpx.post",
    ),
    ids=(
        "unknown-factory",
        "unknown-factory-pure-argument",
        "mixed-factory-arguments",
        "mixed-conditional",
    ),
)
def test_incomplete_callable_composites_remain_external_egress(
    selection: str,
) -> None:
    source = f"""def publish(factory, predicate, value):
    import httpx
    import math

    dispatch = {selection}
    dispatch(value)
"""

    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )
    assert len(records) == 1
    assert records[0]["callable"] == ["name", "dispatch"]


def test_direct_mixed_conditional_call_remains_external_egress() -> None:
    source = """def publish(predicate, value):
    import httpx
    import math
    (math.sqrt if predicate else httpx.post)(value)
"""

    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )
    assert len(records) == 1
    assert records[0]["callable"][0] == "if-expression"


@pytest.mark.parametrize(
    "body",
    (
        "return tuple(fn(value) for fn in callables)",
        "for fn in callables:\n        fn(value)",
    ),
    ids=("generator", "loop"),
)
def test_proven_pure_callable_iteration_is_not_external_egress(body: str) -> None:
    source = f"""def calculate(value):
    import math

    def local_adjust(item):
        return item + 1

    callables = [math.sqrt, abs, local_adjust]
    {body}
"""

    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    ) == ()


@pytest.mark.parametrize(
    ("setup", "iterable"),
    (
        ("", "callables"),
        ("", "factory()"),
        ("    import httpx\n", "[abs, httpx.post]"),
    ),
    ids=("unknown-iterable", "factory-result", "external-member"),
)
def test_unknown_callable_iteration_remains_external_egress(
    setup: str,
    iterable: str,
) -> None:
    source = f"""def publish(callables, factory, value):
{setup}    for dispatch in {iterable}:
        dispatch(value)
"""

    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )
    assert len(records) == 1
    assert records[0]["callable"] == ["name", "dispatch"]


@pytest.mark.parametrize("source", tuple(_FIRST_POSITIONAL_EGRESS_CALLS.values()))
def test_first_positional_external_egress_drifts_closure_deterministically(
    tmp_path: Path,
    source: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    _append_to_capability_root(repository, "\n" + source)

    first = _closure_errors(repository)
    repeated = _closure_errors(repository)
    assert first == repeated
    closure_errors = tuple(
        error
        for error in first
        if error.startswith("reachable-capability-closure: effect graph does not match")
    )
    assert len(closure_errors) == 1
    observed_digest = closure_errors[0].partition("observed sha256=")[2].removesuffix(")")
    assert len(observed_digest) == 64


def _result_used_egress_source(egress: str, context: str) -> str:
    setup, call = _RESULT_USED_EGRESS_CALLS[egress]
    statement = _RESULT_CONTEXTS[context].format(call=call)
    function_kind = "async def" if context == "awaited" else "def"
    setup_block = f"    {setup}\n" if setup else ""
    return (
        "def consume(result):\n"
        "    return result\n\n"
        f"{function_kind} publish(connection, value):\n"
        f"{setup_block}"
        f"    {statement}\n"
    )


@pytest.mark.parametrize("egress", tuple(_RESULT_USED_EGRESS_CALLS))
@pytest.mark.parametrize("context", tuple(_RESULT_CONTEXTS))
def test_external_egress_projection_is_independent_of_result_context(
    egress: str,
    context: str,
) -> None:
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(_result_used_egress_source(egress, context)),
    )
    discarded_records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(_result_used_egress_source(egress, "discarded")),
    )

    assert records
    assert records == discarded_records


@pytest.mark.parametrize("mutation", tuple(_ATOMIC_EGRESS_MUTATIONS))
def test_atomic_external_egress_mutations_drift_only_completeness_projection(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    _append_to_capability_root(repository, _ATOMIC_EGRESS_MUTATIONS[mutation])

    errors = _closure_errors(repository)
    assert len(errors) == 1
    assert errors[0].startswith(
        "reachable-capability-closure: effect graph does not match"
    )


def test_nonreachable_egress_arithmetic_and_external_compute_are_outside_graph(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/unimported_compute.py"
    path.write_text(
        """import math
def calculate(connection, value):
    total = value + 1
    root = math.sqrt(total)
    connection.execute("event", value)
    return root
""",
        encoding="utf-8",
    )
    assert "src/unrest_harness/unimported_compute.py" not in (
        build_reachable_capability_source_graph(repository, _catalog(repository))
    )
    assert _closure_errors(repository) == ()


def test_reachable_predicates_orderings_comments_and_formatting_are_normalized(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    path = repository / "src/unrest_harness/capability_policy.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "CAPABILITY_POLICY_VERSION = 1",
        "CAPABILITY_POLICY_VERSION   =   1  # normalized formatting",
        1,
    )
    text += """

def _pure_local_predicate_and_ordering(values, predicate):
    accepted = [item for item in values if predicate(item) and item > 0]
    return sorted(accepted, key=lambda item: (item % 2, item))
"""
    path.write_text(text, encoding="utf-8")
    assert _closure_errors(repository) == ()


def test_graph_and_projection_are_deterministic_and_path_bound(tmp_path: Path) -> None:
    repository = _copy_capability_repository(tmp_path)
    catalog = _catalog(repository)
    expected = build_reachable_capability_source_graph(repository, catalog)
    component_path = repository / "docs/architecture/component-map.json"
    document = json.loads(component_path.read_text(encoding="utf-8"))
    component = next(
        item for item in document["components"] if item["id"] == "COMP-CAPABILITY"
    )
    component["paths"] = list(reversed(component["paths"]))
    component_path.write_text(json.dumps(document), encoding="utf-8")
    assert build_reachable_capability_source_graph(repository, catalog) == expected

    source = _ATOMIC_EGRESS_MUTATIONS["http"]
    first = normalized_external_egress_records("src/unrest_harness/first.py", ast.parse(source))
    repeated = normalized_external_egress_records("src/unrest_harness/first.py", ast.parse(source))
    swapped = normalized_external_egress_records("src/unrest_harness/second.py", ast.parse(source))
    changed = normalized_external_egress_records(
        "src/unrest_harness/first.py",
        ast.parse(source.replace("content=value", "content=value + b'x'")),
    )
    assert first == repeated
    assert first != swapped
    assert first != changed


def test_custom_normalization_ignores_locations_type_comments_and_ignores() -> None:
    compact = """import httpx
def publish(value):
    httpx.post("x", content=value)
"""
    formatted = """import httpx

def publish(value):  # type: ignore[no-untyped-def]
    # location and formatting do not carry capability semantics
    httpx.post(
        "x",
        content=value,
    )
"""
    compact_records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(compact, type_comments=True),
    )
    formatted_records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(formatted, type_comments=True),
    )
    assert compact_records == formatted_records
    implementation = (ROOT / "src/unrest_harness/capability_policy.py").read_text(
        encoding="utf-8"
    )
    assert "ast.dump(" not in implementation
    assert "rglob(\"*.py\")" not in implementation


def test_awaited_payload_normalization_preserves_call_and_data_structure() -> None:
    original = """import httpx
async def publish(value):
    return httpx.post("x", content=await encode(value))
"""
    changed_callable = original.replace("encode(value)", "decode(value)")
    changed_data = original.replace("encode(value)", "encode(value.payload)")

    def records(source: str):
        return normalized_external_egress_records(
            "src/unrest_harness/helper.py",
            ast.parse(source),
        )

    original_records = records(original)
    assert original_records != records(changed_callable)
    assert original_records != records(changed_data)
    assert original_records[0]["keywords"] == [
        [
            "content",
            ["await", ["call", ["name", "encode"], [["name", "value"]], []]],
        ]
    ]


def test_awaited_payload_mutation_drifts_reviewed_repository_closure(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    addition = """
async def _awaited_payload(value):
    import httpx
    return httpx.post("https://example.invalid", content=await encode(value))
"""
    _append_to_capability_root(repository, addition)
    errors = _closure_errors(repository)
    assert len(errors) == 1
    observed_digest = errors[0].partition("observed sha256=")[2].removesuffix(")")
    assert len(observed_digest) == 64

    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_text = catalog_path.read_text(encoding="utf-8")
    catalog_path.write_text(
        catalog_text.replace(_catalog(repository).reachable_source_sha256, observed_digest),
        encoding="utf-8",
    )
    assert _closure_errors(repository) == ()

    capability_path = repository / "src/unrest_harness/capability_policy.py"
    capability_path.write_text(
        capability_path.read_text(encoding="utf-8").replace(
            "content=await encode(value)",
            "content=await decode(value)",
        ),
        encoding="utf-8",
    )
    drift_errors = _closure_errors(repository)
    assert len(drift_errors) == 1
    assert drift_errors[0].startswith(
        "reachable-capability-closure: effect graph does not match"
    )


def test_comprehension_payload_normalization_preserves_data_transform_not_predicate() -> None:
    original = """import httpx
def publish(values, predicate):
    httpx.post("x", content=[encode(item) for item in values if predicate(item)])
"""
    changed_transform = original.replace("encode(item)", "decode(item)")
    changed_predicate = original.replace("predicate(item)", "item > 0")

    def records(source: str):
        return normalized_external_egress_records(
            "src/unrest_harness/helper.py",
            ast.parse(source),
        )

    assert records(original) != records(changed_transform)
    assert records(original) == records(changed_predicate)
