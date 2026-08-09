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
        "src/unrest_harness/runtime_observability.py",
        "src/unrest_harness/server.py",
        "src/unrest_harness/storage.py",
        "src/unrest_harness/task_list_patch.py",
        "src/unrest_harness/task_validation.py",
    )
    assert "src/unrest_harness/__main__.py" not in graph


def test_observer_gate_order_primitive_adds_no_authority_effect() -> None:
    task_tree = ast.parse(
        (ROOT / "src/unrest_harness/task_validation.py").read_text(encoding="utf-8")
    )
    primitive = next(
        node
        for node in task_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "gates_in_order"
    )
    assert not any(isinstance(node, ast.Call) for node in ast.walk(primitive))

    observer_tree = ast.parse(
        (ROOT / "src/unrest_harness/runtime_observability.py").read_text(
            encoding="utf-8"
        )
    )
    forbidden_authority_modules = {
        "acp_runner",
        "controller",
        "coordinator",
        "dispatcher",
        "server",
    }
    imported_local_modules = {
        (node.module or "").split(".")[0]
        for node in observer_tree.body
        if isinstance(node, ast.ImportFrom) and node.level
    }
    assert imported_local_modules.isdisjoint(forbidden_authority_modules)
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith(("save_", "create_", "dispatch", "step"))
        for node in ast.walk(observer_tree)
    )


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


def test_transitively_imported_helper_enters_and_identical_unimported_helper_stays_out(
    tmp_path: Path,
) -> None:
    repository = _copy_capability_repository(tmp_path)
    package = repository / "src/unrest_harness/egress_helpers"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    payload_source = (
        "import httpx\n"
        "def publish():\n"
        '    httpx.post("https://example.invalid", content=b"payload")\n'
    )
    (package / "reachable.py").write_text(payload_source, encoding="utf-8")
    (package / "unimported.py").write_text(payload_source, encoding="utf-8")
    (package / "bridge.py").write_text(
        "from . import reachable\n",
        encoding="utf-8",
    )

    assert _closure_errors(repository) == ()
    _append_to_capability_root(repository, "\nfrom .egress_helpers import bridge\n")

    graph = build_reachable_capability_source_graph(repository, _catalog(repository))
    assert "src/unrest_harness/egress_helpers/bridge.py" in graph
    assert "src/unrest_harness/egress_helpers/reachable.py" in graph
    assert "src/unrest_harness/egress_helpers/unimported.py" not in graph
    errors = _closure_errors(repository)
    assert len(errors) == 1
    assert errors[0].startswith(
        "reachable-capability-closure: effect graph does not match"
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
    source = """def calculate(attribute, value):
    import math
    magnitude = abs
    dynamic = getattr(math, attribute)
    square_root = getattr(math, "sqrt")
    increment = lambda item: item + 1

    def adjust(item):
        return item + 2

    invoke = adjust
    return (
        magnitude(value),
        dynamic(value),
        square_root(value),
        increment(value),
        invoke(value),
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
    if selection.startswith("factory"):
        assert records[0]["callable"][:2] == ["call", ["name", "factory"]]
    else:
        assert records[0]["callable"] == [
            "if-expression",
            ["name", "predicate"],
            ["attribute", ["name", "math"], "sqrt"],
            ["attribute", ["name", "httpx"], "post"],
        ]


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


@pytest.mark.parametrize(
    "source",
    (
        'import httpx\npayload = b"module-secret"\n'
        'httpx.post("https://example.invalid", content=payload)\n',
        'import httpx\nURL = "https://example.invalid"\n'
        'PAYLOAD = b"module-secret"\nhttpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = "https://example.invalid"\n'
        'PAYLOAD = b"module-secret"\ndef publish():\n'
        '    return httpx.post(URL, content=PAYLOAD)\n',
        'import subprocess\nCOMMAND = ["consumer"]\nPAYLOAD = b"module-secret"\n'
        'subprocess.run(COMMAND, input=PAYLOAD)\n',
        'import httpx\nURL = "https://example.invalid"\nURL_ALIAS = URL\n'
        'PAYLOAD = b"module-secret"\nPAYLOAD_ALIAS = PAYLOAD\n'
        'httpx.post(URL_ALIAS, content=PAYLOAD_ALIAS)\n',
        'import httpx\nURL = "https://example.invalid"\nURL = choose_url()\n'
        'PAYLOAD = b"module-secret"\nhttpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = choose_url()\nPAYLOAD = b"module-secret"\n'
        'httpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = "https://example.invalid"\n'
        'PAYLOAD = b"module-secret"\nPAYLOAD = load_payload()\n'
        'httpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = "https://example.invalid"\nURL = choose_url()\n'
        'PAYLOAD = b"module-secret"\nPAYLOAD = load_payload()\n'
        'httpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = choose_url()\nPAYLOAD = load_payload()\n'
        'httpx.post(URL, content=PAYLOAD)\n',
        'import httpx\nURL = choose_url() if enabled() else alternate_url()\n'
        'PAYLOAD = load_payload() if enabled() else alternate_payload()\n'
        'httpx.post(URL, content=PAYLOAD)\n',
        'def publish(channel):\n    payload = load_payload()\n'
        '    return channel.send(payload)\n',
        'import httpx\ndef publish():\n'
        '    return httpx.post("https://example.invalid", content=b"literal-secret")\n',
        'import httpx\ndef publish():\n'
        '    payload = "constant-secret"\n'
        '    return httpx.post("https://example.invalid", content=payload)\n',
    ),
    ids=(
        "module-scope",
        "named-url-and-payload",
        "inherited-named-url-and-payload",
        "named-command-and-payload",
        "named-aliases",
        "reassigned-context",
        "mixed-unknown-context",
        "reassigned-payload",
        "both-reassigned",
        "both-unknown",
        "mixed-selectors",
        "bound-unknown-payload",
        "literal-payload",
        "constant-binding",
    ),
)
def test_external_egress_covers_module_scope_and_constant_payloads(
    source: str,
) -> None:
    first = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )
    repeated = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )

    assert len(first) == 1
    assert first == repeated


_CALLBACK_RESULT_CONTEXTS = {
    "discarded": "{call}",
    "assigned": "result = {call}\n    return result",
    "returned": "return {call}",
    "awaited": "result = await {call}\n    return result",
    "nested": "return consume({call})",
}


def _callback_parameter_source(flavor: str, context: str) -> str:
    signature = "value, callback=print" if flavor == "default" else "value, callback"
    setup = "    dispatch = callback\n" if flavor == "aliased" else ""
    callable_name = "dispatch" if flavor == "aliased" else "callback"
    statement = _CALLBACK_RESULT_CONTEXTS[context].format(
        call=f"{callable_name}(value)"
    )
    function_kind = "async def" if context == "awaited" else "def"
    return (
        "def consume(result):\n"
        "    return result\n\n"
        f"{function_kind} publish({signature}):\n"
        f"{setup}"
        f"    {statement}\n"
    )


@pytest.mark.parametrize("flavor", ("direct", "aliased", "default"))
@pytest.mark.parametrize("context", tuple(_CALLBACK_RESULT_CONTEXTS))
def test_unknown_callback_parameters_fail_closed_in_every_result_context(
    flavor: str,
    context: str,
) -> None:
    source = _callback_parameter_source(flavor, context)
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )
    returned = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(_callback_parameter_source(flavor, "returned")),
    )

    assert len(records) == 1
    assert records == returned


def _egress_record(
    *,
    anchor: str,
    callable_expression: list[object],
    arguments: list[list[object]] | None = None,
    keywords: list[list[object]] | None = None,
    control: list[list[object]] | None = None,
    via: list[list[object]] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "anchor": anchor,
        "arguments": arguments or [],
        "callable": callable_expression,
        "keywords": keywords or [],
        "path": "src/unrest_harness/helper.py",
    }
    if control is not None:
        record["control"] = control
    if via is not None:
        record["via"] = via
    return record


_INLINE_BYTES = ["constant", {"bytes_hex": "696e6c696e65"}]
_PAYLOAD_BYTES = ["constant", {"bytes_hex": "7061796c6f6164"}]


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            'transport(b"inline")\n',
            _egress_record(
                anchor="<module>",
                callable_expression=["name", "transport"],
                arguments=[_INLINE_BYTES],
            ),
        ),
        (
            'from transport_lib import ship\ndef publish():\n    return ship("payload")\n',
            _egress_record(
                anchor="publish",
                callable_expression=["name", "ship"],
                arguments=[["constant", "payload"]],
            ),
        ),
        (
            "from transport_lib import ship as dispatch\n"
            'PAYLOAD = b"payload"\nALIAS = PAYLOAD\n'
            "def publish():\n    result = dispatch(ALIAS)\n    return result\n",
            _egress_record(
                anchor="publish",
                callable_expression=["name", "dispatch"],
                arguments=[_PAYLOAD_BYTES],
            ),
        ),
        (
            "import transport_lib as transport\n"
            "def consume(result):\n    return result\n"
            "def publish(value):\n"
            "    return consume(transport.ship(payload=value))\n",
            _egress_record(
                anchor="publish",
                callable_expression=["attribute", ["name", "transport"], "ship"],
                keywords=[["payload", ["name", "value"]]],
            ),
        ),
        (
            "def consume(result):\n    return result\n"
            "def outer(callback, value):\n"
            "    def publish():\n"
            "        return consume(callback(value))\n"
            "    return publish()\n",
            _egress_record(
                anchor="outer.publish",
                callable_expression=["name", "callback"],
                arguments=[["name", "value"]],
            ),
        ),
        (
            "async def publish(factory, value):\n"
            "    dispatch = factory()\n"
            "    result = await dispatch(value)\n"
            "    return result\n",
            _egress_record(
                anchor="publish",
                callable_expression=["call", ["name", "factory"], [], []],
                arguments=[["name", "value"]],
            ),
        ),
        (
            'def publish(callback):\n    callback(payload=b"inline")\n',
            _egress_record(
                anchor="publish",
                callable_expression=["name", "callback"],
                keywords=[["payload", _INLINE_BYTES]],
            ),
        ),
        (
            "import httpx\n"
            "def publish():\n"
            '    return httpx.post("https://example.invalid", content=b"inline")\n',
            _egress_record(
                anchor="publish",
                callable_expression=["attribute", ["name", "httpx"], "post"],
                arguments=[["constant", "https://example.invalid"]],
                keywords=[["content", _INLINE_BYTES]],
            ),
        ),
        (
            "import subprocess\n"
            'COMMAND = ["consumer"]\nPAYLOAD = b"payload"\n'
            "subprocess.run(COMMAND, input=PAYLOAD)\n",
            _egress_record(
                anchor="<module>",
                callable_expression=["attribute", ["name", "subprocess"], "run"],
                arguments=[["list", [["constant", "consumer"]]]],
                keywords=[["input", _PAYLOAD_BYTES]],
            ),
        ),
        (
            'PAYLOAD = b"payload"\nPAYLOAD = load_payload()\n'
            "def publish(callback):\n    callback(PAYLOAD)\n",
            _egress_record(
                anchor="publish",
                callable_expression=["name", "callback"],
                arguments=[["name", "PAYLOAD"]],
            ),
        ),
        (
            "def publish(callback, enabled):\n"
            '    callback(load_payload() if enabled else b"inline")\n',
            _egress_record(
                anchor="publish",
                callable_expression=["name", "callback"],
                arguments=[[
                    "if-expression",
                    ["name", "enabled"],
                    ["call", ["name", "load_payload"], [], []],
                    _INLINE_BYTES,
                ]],
            ),
        ),
    ),
    ids=(
        "module-direct-inline",
        "from-import-returned-literal",
        "aliased-import-assigned-constant-alias",
        "module-attribute-nested-keyword-parameter",
        "nested-callback-parameter",
        "awaited-factory-callable",
        "sole-keyword-inline",
        "http-context-plus-inline-payload",
        "subprocess-context-plus-constant-payload",
        "reassigned-payload-fail-closed",
        "mixed-payload-fail-closed",
    ),
)
def test_external_egress_callable_payload_scope_matrix_has_exact_records(
    source: str,
    expected: dict[str, object],
) -> None:
    first = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    repeated = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    assert first == (expected,)
    assert repeated == first


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            'channel.relay_frame(b"inline")\n',
            _egress_record(
                anchor="<module>",
                callable_expression=["attribute", ["name", "channel"], "relay_frame"],
                arguments=[_INLINE_BYTES],
            ),
        ),
        (
            'PAYLOAD = b"payload"\n'
            "def publish(connection):\n    connection.execute(PAYLOAD)\n",
            _egress_record(
                anchor="publish",
                callable_expression=["attribute", ["name", "connection"], "execute"],
                arguments=[_PAYLOAD_BYTES],
            ),
        ),
        (
            "def publish(channel, value):\n"
            "    dispatch = channel.relay_frame\n"
            "    return dispatch(payload=value)\n",
            _egress_record(
                anchor="publish",
                callable_expression=["attribute", ["name", "channel"], "relay_frame"],
                keywords=[["payload", ["name", "value"]]],
            ),
        ),
        (
            "def outer(receiver, value):\n"
            "    def publish():\n"
            "        return receiver.transmit(value)\n"
            "    return publish()\n",
            _egress_record(
                anchor="outer.publish",
                callable_expression=["attribute", ["name", "receiver"], "transmit"],
                arguments=[["name", "value"]],
            ),
        ),
        (
            "def publish(left, right, enabled, value):\n"
            "    return (left if enabled else right).forward(value)\n",
            _egress_record(
                anchor="publish",
                callable_expression=[
                    "attribute",
                    [
                        "if-expression",
                        ["name", "enabled"],
                        ["name", "left"],
                        ["name", "right"],
                    ],
                    "forward",
                ],
                arguments=[["name", "value"]],
            ),
        ),
    ),
    ids=(
        "module-receiver-literal",
        "receiver-stable-constant",
        "bound-alias-keyword-parameter",
        "nested-custom-receiver",
        "conditional-receiver-fail-closed",
    ),
)
def test_receiver_and_bound_alias_matrix_has_exact_records(
    source: str,
    expected: dict[str, object],
) -> None:
    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    ) == (expected,)


@pytest.mark.parametrize(
    ("source", "expected_callable"),
    (
        (
            'def publish(receiver, value):\n    getattr(receiver, "relay")(value)\n',
            ["call", ["name", "getattr"], [["name", "receiver"], ["constant", "relay"]], []],
        ),
        (
            'METHOD = "relay"\n'
            "def publish(receiver, value):\n    getattr(receiver, METHOD)(value)\n",
            ["call", ["name", "getattr"], [["name", "receiver"], ["constant", "relay"]], []],
        ),
        (
            'METHOD = "relay"\nPAYLOAD = b"payload"\n'
            "def publish(receiver):\n"
            "    dispatch = getattr(receiver, METHOD)\n"
            "    return dispatch(payload=PAYLOAD)\n",
            ["call", ["name", "getattr"], [["name", "receiver"], ["constant", "relay"]], []],
        ),
        (
            "def publish(receiver, method, value):\n"
            "    getattr(receiver, method)(value)\n",
            ["call", ["name", "getattr"], [["name", "receiver"], ["name", "method"]], []],
        ),
        (
            'METHOD = "relay"\nMETHOD = choose_method()\n'
            'def publish(receiver):\n    getattr(receiver, METHOD)(b"inline")\n',
            ["call", ["name", "getattr"], [["name", "receiver"], ["name", "METHOD"]], []],
        ),
    ),
    ids=(
        "literal-method",
        "stable-named-method",
        "assigned-alias-keyword-constant",
        "dynamic-method-fail-closed",
        "reassigned-method-fail-closed",
    ),
)
def test_getattr_matrix_retains_exact_callable_provenance(
    source: str,
    expected_callable: list[object],
) -> None:
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    assert len(records) == 1
    assert records[0]["anchor"] == "publish"
    assert records[0]["callable"] == expected_callable
    assert records[0]["path"] == "src/unrest_harness/helper.py"


def test_stable_constant_value_changes_projection_and_alias_spelling_does_not() -> None:
    template = 'PAYLOAD = b"{payload}"\nALIAS = PAYLOAD\ndef publish(callback):\n    callback({name})\n'
    direct = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(template.format(payload="first", name="PAYLOAD")),
    )
    aliased = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(template.format(payload="first", name="ALIAS")),
    )
    changed = normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(template.format(payload="second", name="ALIAS")),
    )
    assert direct == aliased
    assert direct != changed


def test_projection_sorting_and_duplicate_multiplicity_are_stable() -> None:
    first = """def publish(callback):
    callback(b"second")
    callback(b"first")
"""
    reordered = """def publish(callback):
    callback(b"first")
    callback(b"second")
"""
    duplicated = """def publish(callback):
    callback(b"same")
    callback(b"same")
"""
    first_records = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(first)
    )
    assert first_records == normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(reordered)
    )
    duplicate_records = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(duplicated)
    )
    assert len(duplicate_records) == 2
    assert duplicate_records[0] == duplicate_records[1]


@pytest.mark.parametrize(
    "source",
    (
        'import httpx\nhttpx.post("https://example.invalid")\n',
        'import httpx\nURL = "https://example.invalid"\nhttpx.post(URL)\n',
        'import subprocess\ndef run():\n    subprocess.run(["consumer"])\n',
        'import subprocess\nCOMMAND = ["consumer"]\nsubprocess.run(COMMAND)\n',
        "def notify(channel):\n    channel.send()\n",
        "def notify():\n    external_callback()\n",
        "def publish(value):\n"
        "    def local_callback(item):\n"
        "        return item\n"
        "    return local_callback(value)\n",
        "def calculate(value):\n"
        "    def adjust(item):\n"
        "        return item + 1\n"
        "    return adjust(value)\n",
        "def select(values):\n"
        "    def keep(value):\n"
        "        return bool(value)\n"
        "    return [value for value in values if keep(value)]\n",
    ),
    ids=(
        "module-fixed-url",
        "named-fixed-url",
        "fixed-command",
        "named-fixed-command",
        "receiver-only",
        "external-no-arguments",
        "local-with-payload",
        "local",
        "predicate",
    ),
)
def test_scope_and_callback_completeness_preserves_benign_controls(
    source: str,
) -> None:
    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    ) == ()


@pytest.mark.parametrize(
    ("source", "expected_callable", "expected_argument"),
    (
        (
            "def select(value):\n    if nebula_emit(value):\n        return value\n",
            ["name", "nebula_emit"],
            "value",
        ),
        (
            "from nebula_bus import poll as orbit_poll\n"
            "def await_signal(value):\n"
            "    while orbit_poll(value):\n"
            "        break\n",
            ["name", "orbit_poll"],
            "value",
        ),
        (
            "def select(values, callback):\n"
            "    return [value for value in values if callback(value)]\n",
            ["name", "callback"],
            "value",
        ),
        (
            "import nebula_bus as constellation\n"
            "def select(values):\n"
            "    return {value for value in values if constellation.accept(value)}\n",
            ["attribute", ["name", "constellation"], "accept"],
            "value",
        ),
        (
            "def select(values, callback):\n"
            "    predicate = callback\n"
            "    return {value: value for value in values if predicate(value)}\n",
            ["name", "callback"],
            "value",
        ),
        (
            "from nebula_bus import permits\n"
            "def select(values):\n"
            "    return (value for value in values if permits(value))\n",
            ["name", "permits"],
            "value",
        ),
    ),
    ids=(
        "if-direct",
        "while-import-alias",
        "list-comprehension-callback",
        "set-comprehension-module-import",
        "dict-comprehension-callback-alias",
        "generator-comprehension-from-import",
    ),
)
def test_unknown_data_bearing_predicates_retain_external_egress_records(
    source: str,
    expected_callable: list[object],
    expected_argument: str,
) -> None:
    first = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    repeated = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )

    assert first == (
        _egress_record(
            anchor=next(
                node.name
                for node in ast.parse(source).body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            callable_expression=expected_callable,
            arguments=[["name", expected_argument]],
        ),
    )
    assert repeated == first


@pytest.mark.parametrize(
    "source",
    (
        "from nebula_bus import permits\n"
        "permits = lambda value: bool(value)\n"
        "permits(1)\n",
        "from nebula_bus import permits as accept\n"
        "def select(value):\n"
        "    def accept(item):\n"
        "        return bool(item)\n"
        "    return accept(value)\n",
        "from nebula_bus import permits as dispatch\n"
        "def select(value):\n"
        "    def local_accept(item):\n"
        "        return bool(item)\n"
        "    dispatch = local_accept\n"
        "    return dispatch(value)\n",
        "from nebula_bus import permits\n"
        "def outer():\n"
        "    permits = lambda item: bool(item)\n"
        "    def inner(value):\n"
        "        return permits(value)\n"
        "    return inner\n",
    ),
    ids=(
        "module-lambda-shadow",
        "local-function-shadow",
        "local-function-alias-shadow",
        "inherited-lambda-shadow",
    ),
)
def test_proven_local_callable_shadowing_overrides_import_provenance(
    source: str,
) -> None:
    assert normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    ) == ()


def test_reassigned_import_shadow_remains_fail_closed() -> None:
    source = """from nebula_bus import permits
def select(value):
    permits = lambda item: bool(item)
    permits = choose_callable()
    return permits(value)
"""
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    assert len(records) == 1
    assert records[0]["callable"] == ["name", "permits"]


def test_callback_parameter_shadowing_module_local_remains_fail_closed() -> None:
    source = """def permits(value):
    return bool(value)
def select(permits, value):
    return permits(value)
"""
    records = normalized_external_egress_records(
        "src/unrest_harness/helper.py", ast.parse(source)
    )
    assert len(records) == 1
    assert records[0]["callable"] == ["name", "permits"]


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

def _pure_local_predicate_and_ordering(values):
    def predicate(item):
        return bool(item)
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
def publish(values):
    def predicate(item):
        return bool(item)
    httpx.post("x", content=[encode(item) for item in values if predicate(item)])
"""
    changed_transform = original.replace("encode(item)", "decode(item)")
    changed_predicate = original.replace("if predicate(item)", "if item > 0")

    def records(source: str):
        return normalized_external_egress_records(
            "src/unrest_harness/helper.py",
            ast.parse(source),
        )

    assert records(original) != records(changed_transform)
    assert records(original) == records(changed_predicate)


def _fixed_control_records(source: str) -> tuple[dict[str, object], ...]:
    return normalized_external_egress_records(
        "src/unrest_harness/helper.py",
        ast.parse(source),
    )


def test_guarded_fixed_http_projection_has_exact_branch_semantics() -> None:
    guarded = """import httpx
def publish(secret):
    if secret:
        httpx.get("https://first.invalid")
"""
    expected = _egress_record(
        anchor="publish",
        callable_expression=["attribute", ["name", "httpx"], "get"],
        arguments=[["constant", "https://first.invalid"]],
        control=[["if", ["name", "secret"], "body"]],
    )
    assert _fixed_control_records(guarded) == (expected,)
    assert _fixed_control_records(guarded) == _fixed_control_records(guarded)

    equal_arms = guarded.replace(
        '        httpx.get("https://first.invalid")\n',
        '        httpx.get("https://first.invalid")\n'
        "    else:\n"
        '        httpx.get("https://first.invalid")\n',
    )
    assert _fixed_control_records(equal_arms) == ()

    different_arms = equal_arms.replace(
        '        httpx.get("https://first.invalid")\n',
        '        httpx.get("https://second.invalid")\n',
        1,
    )
    swapped = different_arms.replace("if secret:", "if not secret:")
    different_records = _fixed_control_records(different_arms)
    assert len(different_records) == 2
    assert different_records != _fixed_control_records(swapped)
    assert {record["control"][0][-1] for record in different_records} == {
        "body",
        "else",
    }


def test_equal_helper_and_direct_arms_compare_only_external_effects() -> None:
    source = """import httpx
def helper():
    httpx.get("https://same.invalid")
def publish(secret):
    if secret:
        helper()
    else:
        httpx.get("https://same.invalid")
"""
    swapped = source.replace(
        "        helper()\n    else:\n        httpx.get(\"https://same.invalid\")",
        "        httpx.get(\"https://same.invalid\")\n    else:\n        helper()",
    )

    assert _fixed_control_records(source) == ()
    assert _fixed_control_records(swapped) == ()
    assert _fixed_control_records(source) == _fixed_control_records(swapped)


@pytest.mark.parametrize(
    "changed_else",
    (
        'httpx.post("https://same.invalid")',
        'httpx.get("https://different.invalid")',
        "pass",
        'httpx.get("https://same.invalid")\n        httpx.get("https://same.invalid")',
    ),
    ids=("callable", "destination", "presence", "static-site-multiplicity"),
)
def test_helper_and_direct_arm_observable_differences_remain_guarded(
    changed_else: str,
) -> None:
    source = """import httpx
def helper():
    httpx.get("https://same.invalid")
def publish(secret):
    if secret:
        helper()
    else:
        REPLACEMENT
""".replace("REPLACEMENT", changed_else)

    records = _fixed_control_records(source)
    assert records
    assert all(record["control"][0][0] == "if" for record in records)


@pytest.mark.parametrize(
    "guard",
    ("True", "False", "ENABLED"),
)
def test_fixed_context_proven_boolean_and_unconditional_controls_stay_clean(
    guard: str,
) -> None:
    prefix = "ENABLED = True\n" if guard == "ENABLED" else ""
    source = (
        "import httpx\n"
        f"{prefix}"
        "def publish():\n"
        f"    if {guard}:\n"
        '        httpx.get("https://example.invalid")\n'
    )
    assert _fixed_control_records(source) == ()
    assert _fixed_control_records(
        'import httpx\nhttpx.get("https://example.invalid")\n'
    ) == ()


@pytest.mark.parametrize(
    ("command", "guard", "frame"),
    (
        ('["consumer", "--once"]', "if enabled", "if"),
        ('("consumer", "--once")', "while enabled", "while"),
        ("COMMAND", "if enabled", "if"),
    ),
    ids=("list-if", "tuple-while", "named-list-if"),
)
def test_guarded_fixed_command_forms_have_exact_static_records(
    command: str,
    guard: str,
    frame: str,
) -> None:
    declaration = 'COMMAND = ["consumer", "--once"]\n' if command == "COMMAND" else ""
    source = (
        "import subprocess\n"
        f"{declaration}"
        "def publish(enabled):\n"
        f"    {guard}:\n"
        f"        subprocess.run({command})\n"
    )
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert records[0]["callable"] == [
        "attribute",
        ["name", "subprocess"],
        "run",
    ]
    assert records[0]["control"][0][0] == frame
    assert records[0]["arguments"] == [
        ["list" if command != '("consumer", "--once")' else "tuple", [
            ["constant", "consumer"],
            ["constant", "--once"],
        ]]
    ]


@pytest.mark.parametrize(
    ("body", "expected_kinds"),
    (
        (
            "if enabled:\n        httpx.get(URL)",
            ("if",),
        ),
        (
            "for item in values:\n        httpx.get(URL)",
            ("for",),
        ),
        (
            "while enabled:\n        httpx.get(URL)",
            ("while",),
        ),
        (
            "enabled and httpx.get(URL)",
            ("boolean",),
        ),
        (
            "enabled or httpx.get(URL)",
            ("boolean",),
        ),
        (
            "return httpx.get(URL) if enabled else None",
            ("if-expression",),
        ),
        (
            "return [httpx.get(URL) for item in values if enabled]",
            ("comprehension-iterator", "comprehension-filter"),
        ),
        (
            "match enabled:\n"
            "        case True if values:\n"
            "            httpx.get(URL)",
            ("match",),
        ),
    ),
    ids=(
        "if",
        "for",
        "while",
        "and",
        "or",
        "if-expression",
        "comprehension",
        "match",
    ),
)
def test_direct_structured_control_forms_project_fixed_egress(
    body: str,
    expected_kinds: tuple[str, ...],
) -> None:
    source = (
        "import httpx\n"
        'URL = "https://example.invalid"\n'
        "def publish(enabled, values):\n"
        f"    {body}\n"
    )
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert tuple(frame[0] for frame in records[0]["control"]) == expected_kinds


def test_async_for_iterator_projects_fixed_egress() -> None:
    source = """import httpx
async def publish(values):
    async for value in values:
        httpx.get("https://example.invalid")
"""
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert records[0]["control"] == [["async-for", ["name", "values"], "body"]]


@pytest.mark.parametrize("subject", ("True", "ENABLED"))
def test_proven_boolean_match_subject_is_benign(subject: str) -> None:
    declaration = "ENABLED = True\n" if subject == "ENABLED" else ""
    source = (
        "import httpx\n"
        f"{declaration}"
        "def publish():\n"
        f"    match {subject}:\n"
        "        case True:\n"
        '            httpx.get("https://example.invalid")\n'
    )
    assert _fixed_control_records(source) == ()


def test_nested_control_order_and_external_predicate_record_are_preserved() -> None:
    source = """import httpx
def publish(secret, callback):
    if callback(secret):
        secret and httpx.get("https://example.invalid")
"""
    records = _fixed_control_records(source)
    assert len(records) == 2
    predicate_record = next(record for record in records if "control" not in record)
    guarded_record = next(record for record in records if "control" in record)
    assert predicate_record["callable"] == ["name", "callback"]
    assert [frame[0] for frame in guarded_record["control"]] == ["if", "boolean"]
    assert guarded_record["control"][0][1] == [
        "call",
        ["name", "callback"],
        [["name", "secret"]],
        [],
    ]


@pytest.mark.parametrize(
    ("setup", "predicate"),
    (
        ("", "secret"),
        ("    condition = secret\n", "condition"),
        ("", "secret == token"),
        (
            "    def local_predicate(value):\n"
            "        return bool(value)\n",
            "local_predicate(secret)",
        ),
    ),
    ids=("parameter", "aliased", "derived", "proven-local-predicate"),
)
def test_parameter_derived_and_local_predicates_retain_fixed_control(
    setup: str,
    predicate: str,
) -> None:
    source = (
        "import httpx\n"
        "def publish(secret, token):\n"
        f"{setup}"
        f"    if {predicate}:\n"
        '        httpx.get("https://example.invalid")\n'
    )
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert records[0]["control"][0][0] == "if"
    if "local_predicate" in predicate:
        assert all(record["callable"] != ["name", "local_predicate"] for record in records)


@pytest.mark.parametrize(
    ("exit_statement", "expected"),
    (("return", "return"), ("break", "break"), ("continue", "continue")),
)
def test_nonancestor_early_exits_have_exact_continuation_control(
    exit_statement: str,
    expected: str,
) -> None:
    if exit_statement == "return":
        body = (
            "    if secret:\n"
            "        return\n"
            '    httpx.get("https://example.invalid")\n'
        )
    else:
        body = (
            "    for item in values:\n"
            "        if secret:\n"
            f"            {exit_statement}\n"
            '        httpx.get("https://example.invalid")\n'
        )
    source = "import httpx\ndef publish(secret, values):\n" + body
    records = _fixed_control_records(source)
    assert len(records) == 1
    early = next(frame for frame in records[0]["control"] if frame[0] == "early-exit")
    assert early == ["early-exit", expected, ["name", "secret"], "else"]


@pytest.mark.parametrize(
    "callable_setup",
    (
        "import httpx\nCALL = httpx.get",
        "from httpx import get as CALL",
        "receiver-bound",
        "def bind(receiver):\n    return receiver.send",
    ),
    ids=(
        "assigned-import",
        "direct-import-alias",
        "receiver-bound",
        "receiver-bound-factory",
    ),
)
def test_guarded_fixed_callable_provenance_fails_closed(
    callable_setup: str,
) -> None:
    if callable_setup == "receiver-bound":
        source = (
            "def publish(receiver, secret):\n"
            "    CALL = receiver.send\n"
            '    if secret:\n        CALL("https://example.invalid")\n'
        )
    elif "bind" in callable_setup:
        source = (
            f"{callable_setup}\n"
            "def publish(receiver, secret):\n"
            "    CALL = bind(receiver)\n"
            '    if secret:\n        CALL("https://example.invalid")\n'
        )
    else:
        source = (
            f"{callable_setup}\n"
            "def publish(secret):\n"
            '    if secret:\n        CALL("https://example.invalid")\n'
        )
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert records[0]["control"] == [["if", ["name", "secret"], "body"]]


def test_constant_and_dynamic_getattr_fixed_calls_retain_provenance() -> None:
    template = """import httpx
def publish(secret, method):
    if secret:
        getattr(httpx, {method})("https://example.invalid")
"""
    constant = _fixed_control_records(template.format(method='"get"'))
    dynamic = _fixed_control_records(template.format(method="method"))
    assert len(constant) == len(dynamic) == 1
    assert constant[0]["callable"] != dynamic[0]["callable"]
    assert constant[0]["control"] == dynamic[0]["control"]


def test_guarded_local_helper_summaries_propagate_to_static_callsites() -> None:
    source = """import httpx
def leaf():
    httpx.get("https://example.invalid")
def bridge():
    leaf()
def publish(secret):
    bridge()
    if secret:
        alias = bridge
        alias()
"""
    records = _fixed_control_records(source)
    assert len(records) == 1
    assert records[0]["control"] == [["if", ["name", "secret"], "body"]]
    assert records[0]["via"] == [
        ["callsite", "publish", ["name", "alias"]],
        ["callsite", "bridge", ["name", "leaf"]],
    ]

    nested = """import httpx
def publish(secret):
    def helper():
        httpx.get("https://example.invalid")
    if secret:
        helper()
"""
    nested_records = _fixed_control_records(nested)
    assert len(nested_records) == 1
    assert nested_records[0]["via"] == [
        ["callsite", "publish", ["name", "helper"]]
    ]


def test_local_helper_multiple_callsites_and_cycles_are_bounded_and_stable() -> None:
    multiple = """import httpx
def helper():
    httpx.get("https://example.invalid")
def publish(first, second):
    if first:
        helper()
    if second:
        helper()
"""
    records = _fixed_control_records(multiple)
    assert len(records) == 2
    assert records[0] != records[1]

    duplicated_site = multiple.replace("if second:", "if first:")
    duplicate_records = _fixed_control_records(duplicated_site)
    assert len(duplicate_records) == 2
    assert duplicate_records[0] == duplicate_records[1]

    cycle = """import httpx
def first(secret):
    if secret:
        httpx.get("https://example.invalid")
    second(secret)
def second(secret):
    first(secret)
"""
    assert len(_fixed_control_records(cycle)) == 1
    assert _fixed_control_records(cycle) == _fixed_control_records(cycle)


def test_fixed_control_projection_ignores_formatting_paths_and_locations() -> None:
    compact = 'import httpx\ndef publish(secret):\n if secret: httpx.get("https://example.invalid")\n'
    formatted = """import httpx

def publish(secret):
    # Structural formatting is not semantic.
    if secret:
        httpx.get(
            "https://example.invalid",
        )
"""
    first = _fixed_control_records(compact)
    second = _fixed_control_records(formatted)
    assert first == second
    assert tuple(sorted(first, key=lambda item: json.dumps(item, sort_keys=True))) == first
