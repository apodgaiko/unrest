"""Real-command and isolated-mutation checks for the repository contract."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from itertools import product
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner, Result

from unrest_harness.capability_policy import (
    load_capability_sink_catalog,
    validate_capability_sink_anchors,
)
from unrest_harness.cli import cli
from unrest_harness.repository_contract import (
    CANONICAL_COMMAND,
    COMPATIBILITY_TEST_COMMAND,
    DISTRIBUTION_CHECK_COMMAND,
    FULL_SOURCE_SUITE_COMMAND,
    _shell_command_string,
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


def test_check_repository_cli_rejects_reachable_atomic_http_egress(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _atomic_http_egress(value):
    import httpx
    return httpx.post("https://example.invalid", content=value)
""",
        encoding="utf-8",
    )
    result = _run_cli(repository, monkeypatch)
    assert result.exit_code != 0
    assert "reachable-capability-closure:" in result.output


@pytest.mark.parametrize(
    "source",
    (
        """def _first_positional_subprocess(value):
    import subprocess
    subprocess.run(value)
""",
        """def _first_positional_aliased_http(value):
    import httpx
    dispatch = httpx.post
    dispatch(value)
""",
        """def _first_positional_bound(channel, value):
    send_fds = channel.send_fds
    send_fds(value)
""",
    ),
)
def test_check_repository_cli_rejects_first_positional_external_egress(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)
    assert result.exit_code != 0
    assert "reachable-capability-closure:" in result.output


@pytest.mark.parametrize(
    "source",
    (
        'transport(b"inline")\n',
        'from transport_lib import ship\ndef publish():\n    return ship("payload")\n',
        "from transport_lib import ship as dispatch\n"
        'PAYLOAD = b"payload"\nALIAS = PAYLOAD\n'
        "def publish():\n    result = dispatch(ALIAS)\n    return result\n",
        "import transport_lib as transport\n"
        "def publish(value):\n    return consume(transport.ship(payload=value))\n",
        "def consume(result):\n    return result\n"
        "def outer(callback, value):\n"
        "    def publish():\n        return consume(callback(value))\n"
        "    return publish()\n",
        "async def publish(factory, value):\n"
        "    dispatch = factory()\n"
        "    result = await dispatch(value)\n"
        "    return result\n",
        'channel.relay_frame(b"inline")\n',
        'PAYLOAD = b"payload"\n'
        "def publish(connection):\n    connection.execute(PAYLOAD)\n",
        "def publish(channel, value):\n"
        "    dispatch = channel.relay_frame\n"
        "    return dispatch(payload=value)\n",
        'METHOD = "relay"\n'
        "def publish(receiver, value):\n    getattr(receiver, METHOD)(value)\n",
        'METHOD = "relay"\nPAYLOAD = b"payload"\n'
        "def publish(receiver):\n"
        "    dispatch = getattr(receiver, METHOD)\n"
        "    return dispatch(payload=PAYLOAD)\n",
        "def publish(receiver, method, value):\n"
        "    getattr(receiver, method)(value)\n",
    ),
    ids=(
        "direct-inline",
        "from-import-literal",
        "aliased-import-constant-alias",
        "module-attribute-keyword-parameter",
        "nested-callback",
        "awaited-factory",
        "module-receiver-inline",
        "receiver-constant",
        "bound-custom-keyword",
        "named-getattr",
        "assigned-named-getattr",
        "dynamic-getattr-fail-closed",
    ),
)
def test_check_repository_cli_external_egress_matrix_has_exact_output(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )
    catalog = load_capability_sink_catalog(
        repository / "src/unrest_harness/bundled"
    )
    errors = validate_capability_sink_anchors(repository, catalog)
    assert len(errors) == 1
    sink_id, _, reason = errors[0].partition(": ")
    expected = (
        "Error: REPO-CAPABILITY-SINK-CATALOG:"
        "src/unrest_harness/bundled/policies/capability-sinks.v1.json#"
        f"{sink_id}: {reason}\n"
    )

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == 1
    assert first.output == expected
    assert repeated.exit_code == first.exit_code
    assert repeated.output == first.output


def test_check_repository_cli_bounds_transitively_imported_tracked_helper(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _git(repository, "config", "--local", "user.name", "Repository Contract")
    _git(
        repository,
        "config",
        "--local",
        "user.email",
        "contract@example.invalid",
    )
    package = repository / "src/unrest_harness/egress_helpers"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = (
        "import httpx\n"
        "def publish():\n"
        '    httpx.post("https://example.invalid", content=b"payload")\n'
    )
    (package / "reachable.py").write_text(source, encoding="utf-8")
    (package / "unimported.py").write_text(source, encoding="utf-8")
    (package / "bridge.py").write_text(
        "from . import reachable\n",
        encoding="utf-8",
    )
    _git(repository, "add", "src/unrest_harness/egress_helpers")
    _git(repository, "commit", "-qm", "add bounded helper controls")

    clean = _run_cli(repository, monkeypatch)
    assert clean.exit_code == 0
    assert json.loads(clean.output)["status"] == "ok"

    capability_path = repository / "src/unrest_harness/capability_policy.py"
    capability_path.write_text(
        capability_path.read_text(encoding="utf-8")
        + "\nfrom .egress_helpers import bridge\n",
        encoding="utf-8",
    )
    _git(repository, "add", "src/unrest_harness/capability_policy.py")
    _git(repository, "commit", "-qm", "import tracked helper")

    result = _run_cli(repository, monkeypatch)
    assert result.exit_code == 1
    assert result.output.count("reachable-capability-closure:") == 1


@pytest.mark.parametrize(
    "source",
    (
        'import httpx\n_payload = b"module-secret"\n'
        'httpx.post("https://example.invalid", content=_payload)\n',
        'import httpx\n_named_url = "https://example.invalid"\n'
        '_named_payload = b"module-secret"\n'
        'httpx.post(_named_url, content=_named_payload)\n',
        'import subprocess\n_named_command = ["consumer"]\n'
        '_command_payload = b"module-secret"\n'
        'subprocess.run(_named_command, input=_command_payload)\n',
        'import httpx\n_alias_url = "https://example.invalid"\n'
        '_url_reference = _alias_url\n_alias_payload = b"module-secret"\n'
        '_payload_reference = _alias_payload\n'
        'httpx.post(_url_reference, content=_payload_reference)\n',
        'import httpx\n_reassigned_url = "https://example.invalid"\n'
        '_reassigned_url = _select_url()\n_reassigned_payload = b"module-secret"\n'
        'httpx.post(_reassigned_url, content=_reassigned_payload)\n',
        'import httpx\n_reassigned_url = "https://example.invalid"\n'
        '_reassigned_url = _select_url()\n_reassigned_payload = b"module-secret"\n'
        '_reassigned_payload = _load_payload()\n'
        'httpx.post(_reassigned_url, content=_reassigned_payload)\n',
        'import httpx\n_unknown_url = _select_url()\n'
        '_unknown_payload = _load_payload()\n'
        'httpx.post(_unknown_url, content=_unknown_payload)\n',
        'import httpx\n_selected_url = _select_url() if _enabled() else _alternate_url()\n'
        '_selected_payload = ('
        '_load_payload() if _enabled() else _alternate_payload())\n'
        'httpx.post(_selected_url, content=_selected_payload)\n',
        'def _bound_unknown_payload(channel):\n'
        '    payload = _load_payload()\n'
        '    return channel.send(payload)\n',
        'import httpx\ndef _constant_http():\n'
        '    return httpx.post("https://example.invalid", content=b"literal-secret")\n',
        "def _assigned_callback(value, callback):\n"
        "    result = callback(value)\n"
        "    return result\n",
        "def _returned_callback_alias(value, callback):\n"
        "    dispatch = callback\n"
        "    return dispatch(value)\n",
        "def _default_callback(value, callback=print):\n"
        "    return callback(value)\n",
    ),
    ids=(
        "module-http",
        "named-url-and-payload",
        "named-command-and-payload",
        "named-aliases",
        "reassigned-context",
        "both-reassigned",
        "both-unknown",
        "mixed-selectors",
        "bound-unknown-payload",
        "constant-http",
        "assigned-callback",
        "returned-callback-alias",
        "default-callback",
    ),
)
def test_check_repository_cli_rejects_scope_and_callback_egress(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = catalog_path.read_bytes()
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 1
    assert first.output == repeated.output
    assert "reachable-capability-closure:" in first.output
    assert catalog_path.read_bytes() == catalog_before


@pytest.mark.parametrize(
    "source",
    (
        'import httpx\n_fixed_url = "https://example.invalid"\nhttpx.post(_fixed_url)\n',
        'import subprocess\n_fixed_command = ["consumer"]\n'
        'subprocess.run(_fixed_command)\n',
    ),
    ids=("named-fixed-url", "named-fixed-command"),
)
def test_check_repository_cli_accepts_named_fixed_external_context(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "ok"


@pytest.mark.parametrize(
    "source",
    (
        "import httpx\n"
        "def _guarded_fixed_http(secret):\n"
        "    if secret:\n"
        '        httpx.get("https://guarded.invalid")\n',
        "import subprocess\n"
        "def _guarded_fixed_command(secret):\n"
        "    while secret:\n"
        '        subprocess.run(["consumer", "--once"])\n'
        "        break\n",
        "import httpx\n"
        "def _guarded_match(secret):\n"
        "    match secret:\n"
        "        case True:\n"
        '            httpx.get("https://match.invalid")\n',
        "import httpx\n"
        "def _guarded_early_exit(secret):\n"
        "    if secret:\n"
        "        return\n"
        '    httpx.get("https://continuation.invalid")\n',
        "import httpx\n"
        "def _fixed_helper():\n"
        '    httpx.get("https://helper.invalid")\n'
        "def _guarded_helper(secret):\n"
        "    if secret:\n"
        "        _fixed_helper()\n",
        "import httpx\n"
        "def _guarded_getattr(secret, method):\n"
        "    if secret:\n"
        '        getattr(httpx, method)("https://dynamic.invalid")\n',
    ),
    ids=("http", "subprocess", "match", "early-exit", "helper", "getattr"),
)
def test_check_repository_cli_rejects_control_dependent_fixed_egress(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    path.write_text(path.read_text(encoding="utf-8") + "\n" + source, encoding="utf-8")

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 1
    assert first.output == repeated.output
    assert first.output.count("REPO-CAPABILITY-SINK-CATALOG") == 1
    assert first.output.count("reachable-capability-closure:") == 1
    assert hashlib.sha256(catalog_path.read_bytes()).hexdigest() == catalog_before


@pytest.mark.parametrize(
    "source",
    (
        'import httpx\nhttpx.get("https://unconditional.invalid")\n',
        "import subprocess\n"
        "ENABLED = True\n"
        "def _constant_fixed_command():\n"
        "    if ENABLED:\n"
        '        subprocess.run(["consumer"])\n',
    ),
    ids=("unconditional-http", "proven-constant-command"),
)
def test_check_repository_cli_accepts_fixed_control_projection_controls(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    path.write_text(path.read_text(encoding="utf-8") + "\n" + source, encoding="utf-8")

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 0, first.output
    assert first.output == repeated.output
    assert json.loads(first.output)["status"] == "ok"
    assert hashlib.sha256(catalog_path.read_bytes()).hexdigest() == catalog_before


@pytest.mark.parametrize("swapped", (False, True), ids=("helper-first", "direct-first"))
def test_check_repository_cli_accepts_equal_helper_and_direct_fixed_arms(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    swapped: bool,
) -> None:
    helper_arm = "_equal_effect_helper()"
    direct_arm = 'httpx.get("https://equal-effect.invalid")'
    if swapped:
        helper_arm, direct_arm = direct_arm, helper_arm
    source = (
        "import httpx\n"
        "def _equal_effect_helper():\n"
        '    httpx.get("https://equal-effect.invalid")\n'
        "def _equal_effect_publish(secret):\n"
        "    if secret:\n"
        f"        {helper_arm}\n"
        "    else:\n"
        f"        {direct_arm}\n"
    )
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    path.write_text(path.read_text(encoding="utf-8") + "\n" + source, encoding="utf-8")

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 0, first.output
    assert first.output == repeated.output
    assert json.loads(first.output)["status"] == "ok"
    assert hashlib.sha256(catalog_path.read_bytes()).hexdigest() == catalog_before


@pytest.mark.parametrize(
    "direct_arm",
    (
        'httpx.post("https://equal-effect.invalid")',
        'httpx.get("https://different-effect.invalid")',
        "pass",
        'httpx.get("https://equal-effect.invalid"); httpx.get("https://equal-effect.invalid")',
    ),
    ids=("callable", "destination", "presence", "static-site-multiplicity"),
)
def test_check_repository_cli_rejects_helper_direct_effect_differences(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_arm: str,
) -> None:
    source = (
        "import httpx\n"
        "def _unequal_effect_helper():\n"
        '    httpx.get("https://equal-effect.invalid")\n'
        "def _unequal_effect_publish(secret):\n"
        "    if secret:\n"
        "        _unequal_effect_helper()\n"
        "    else:\n"
        f"        {direct_arm}\n"
    )
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    path.write_text(path.read_text(encoding="utf-8") + "\n" + source, encoding="utf-8")

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 1
    assert first.output == repeated.output
    assert first.output.count("REPO-CAPABILITY-SINK-CATALOG") == 1
    assert first.output.count("reachable-capability-closure:") == 1
    assert hashlib.sha256(catalog_path.read_bytes()).hexdigest() == catalog_before


@pytest.mark.parametrize(
    "source",
    (
        "def _receiver_only(channel):\n    channel.send()\n",
        "def _external_without_payload():\n    external_callback()\n",
        "def _local_with_payload(value):\n"
        "    def local_callback(item):\n"
        "        return item\n"
        "    return local_callback(value)\n",
    ),
    ids=("receiver-only", "external-no-arguments", "local-with-payload"),
)
def test_check_repository_cli_accepts_no_data_and_local_calls(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 0, first.output
    assert first.output == repeated.output
    assert json.loads(first.output)["status"] == "ok"


@pytest.mark.parametrize(
    "source",
    (
        "def _predicate_if(value):\n"
        "    if nebula_emit(value):\n"
        "        return value\n",
        "from nebula_bus import poll as orbit_poll\n"
        "def _predicate_while(value):\n"
        "    while orbit_poll(value):\n"
        "        break\n",
        "def _predicate_list(values, callback):\n"
        "    return [value for value in values if callback(value)]\n",
        "import nebula_bus as constellation\n"
        "def _predicate_set(values):\n"
        "    return {value for value in values if constellation.accept(value)}\n",
        "def _predicate_dict(values, callback):\n"
        "    predicate = callback\n"
        "    return {value: value for value in values if predicate(value)}\n",
        "from nebula_bus import permits\n"
        "def _predicate_generator(values):\n"
        "    return (value for value in values if permits(value))\n",
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
def test_check_repository_cli_rejects_unknown_data_bearing_predicates(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    catalog_path = (
        repository
        / "src/unrest_harness/bundled/policies/capability-sinks.v1.json"
    )
    catalog_before = catalog_path.read_bytes()
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 1
    assert first.output == repeated.output
    assert "reachable-capability-closure:" in first.output
    assert catalog_path.read_bytes() == catalog_before


@pytest.mark.parametrize(
    "source",
    (
        "from nebula_bus import permits\n"
        "permits = lambda value: bool(value)\n"
        "permits(1)\n",
        "from nebula_bus import permits as accept\n"
        "def _local_function_shadow(value):\n"
        "    def accept(item):\n"
        "        return bool(item)\n"
        "    return accept(value)\n",
        "from nebula_bus import permits as dispatch\n"
        "def _local_alias_shadow(value):\n"
        "    def local_accept(item):\n"
        "        return bool(item)\n"
        "    dispatch = local_accept\n"
        "    return dispatch(value)\n",
        "from nebula_bus import permits\n"
        "def _outer_shadow():\n"
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
def test_check_repository_cli_accepts_proven_local_import_shadows(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + source,
        encoding="utf-8",
    )

    first = _run_cli(repository, monkeypatch)
    repeated = _run_cli(repository, monkeypatch)
    assert first.exit_code == repeated.exit_code == 0, first.output
    assert first.output == repeated.output
    assert json.loads(first.output)["status"] == "ok"


def test_check_repository_cli_accepts_proven_pure_callable_composites(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + """

def _pure_callable_composites(value, predicate):
    import math

    def local_adjust(item):
        return item + 1

    dispatch = math.sqrt if predicate else abs
    selected = next(iter([math.sqrt, abs, local_adjust]))
    return (
        dispatch(value),
        selected(value),
        tuple(fn(value) for fn in [math.sqrt, abs, local_adjust]),
    )
""",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "ok"


@pytest.mark.parametrize(
    "selection",
    (
        "factory(math.sqrt)",
        "factory(math.sqrt, httpx.post)",
        "math.sqrt if predicate else httpx.post",
    ),
    ids=("unknown-factory", "mixed-factory", "mixed-conditional"),
)
def test_check_repository_cli_rejects_incomplete_callable_provenance(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    selection: str,
) -> None:
    path = repository / "src/unrest_harness/capability_policy.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"""

def _incomplete_callable_provenance(factory, predicate, value):
    import httpx
    import math
    dispatch = {selection}
    dispatch(value)
""",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)
    assert result.exit_code == 1
    assert "reachable-capability-closure:" in result.output


def test_repository_command_strictly_validates_each_capability_asset_content(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policies = repository / "src/unrest_harness/bundled/policies"
    cases = (
        (
            "role-capabilities.v1.json",
            "top-duplicate",
            lambda text: text.replace("{", '{\n  "schema_version": 1,', 1),
        ),
        (
            "role-capabilities.v1.json",
            "nested-duplicate",
            lambda text: text.replace(
                '"behavior": "deny",',
                '"behavior": "deny",\n          "behavior": "deny",',
                1,
            ),
        ),
        (
            "role-capabilities.v1.json",
            "unsupported-version",
            lambda text: text.replace('"schema_version": 1', '"schema_version": 2'),
        ),
        (
            "capability-security-model.v1.json",
            "top-duplicate",
            lambda text: text.replace("{", '{\n  "schema_version": 1,', 1),
        ),
        (
            "capability-security-model.v1.json",
            "nested-duplicate",
            lambda text: text.replace(
                '"semantic_depth": 24,',
                '"semantic_depth": 24,\n    "semantic_depth": 24,',
                1,
            ),
        ),
        (
            "capability-security-model.v1.json",
            "unsupported-version",
            lambda text: text.replace('"schema_version": 1', '"schema_version": 2'),
        ),
        (
            "capability-sinks.v1.json",
            "top-duplicate",
            lambda text: text.replace("{", '{\n  "schema_version": 1,', 1),
        ),
        (
            "capability-sinks.v1.json",
            "nested-duplicate",
            lambda text: text.replace(
                '"id": "acp-cancel-client-cleanup",',
                (
                    '"id": "acp-cancel-client-cleanup",\n'
                    '      "id": "acp-cancel-client-cleanup",'
                ),
                1,
            ),
        ),
        (
            "capability-sinks.v1.json",
            "unsupported-version",
            lambda text: text.replace('"schema_version": 1', '"schema_version": 2'),
        ),
    )
    originals = {
        filename: (policies / filename).read_text(encoding="utf-8")
        for filename, _, _ in cases
    }

    for filename, mutation_name, mutate in cases:
        path = policies / filename
        for original_name, original_text in originals.items():
            (policies / original_name).write_text(original_text, encoding="utf-8")
        mutated = mutate(originals[filename])
        assert mutated != originals[filename], (filename, mutation_name)
        path.write_text(mutated, encoding="utf-8")

        result = _run_cli(repository, monkeypatch)

        assert result.exit_code != 0, (filename, mutation_name, result.output)
        assert "REPO-CAPABILITY-ASSET-INVALID" in result.output
        assert f"src/unrest_harness/bundled/policies/{filename}" in result.output
        if "duplicate" in mutation_name:
            assert "REPO-JSON-DUPLICATE-KEY" in result.output

    for filename, original in originals.items():
        (policies / filename).write_text(original, encoding="utf-8")


def test_repository_command_rejects_semantically_equivalent_role_policy_drift(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        repository
        / "src/unrest_harness/bundled/policies/role-capabilities.v1.json"
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(
        json.dumps(document, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code != 0
    assert "REPO-CANONICAL-JSON-DRIFT" in result.output
    assert "role-capabilities.v1.json" in result.output


def test_v3_scope_adjudication_is_complete_and_versioned() -> None:
    path = (
        ROOT
        / "tests/fixtures/repository-contract-v3-scope-adjudication.json"
    )
    adjudication = json.loads(path.read_text(encoding="utf-8"))
    assert adjudication["schema_version"] == 1
    assert adjudication["sources"] == [
        {"case_count": 120, "id": "structural-v3-scrutiny"},
        {"case_count": 75, "id": "v3-surface"},
    ]

    records = adjudication["dispositions"]
    assert len(records) == 195
    assert len(
        {
            (record["source"], record["case_id"])
            for record in records
        }
    ) == 195
    assert {
        record["disposition"]
        for record in records
    } == {
        "benign-control",
        "explicitly-out-of-scope",
        "retained-in-scope",
    }
    assert {
        target: {
            disposition: sum(
                record["target"] == target
                and record["disposition"] == disposition
                for record in records
            )
            for disposition in {
                record["disposition"]
                for record in records
                if record["target"] == target
            }
        }
        for target in {
            record["target"]
            for record in records
        }
    } == {
        "VAL-DOC-001": {
            "benign-control": 16,
            "explicitly-out-of-scope": 21,
        },
        "VAL-DOC-002": {
            "benign-control": 11,
            "explicitly-out-of-scope": 18,
            "retained-in-scope": 16,
        },
        "VAL-DOC-003": {
            "benign-control": 14,
            "explicitly-out-of-scope": 15,
            "retained-in-scope": 11,
        },
        "VAL-DOC-004": {
            "benign-control": 23,
            "explicitly-out-of-scope": 32,
            "retained-in-scope": 18,
        },
    }


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
    if mutation == "component_protected_reclassification":
        path = repository / "docs/architecture/component-map.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        governance = next(
            item
            for item in value["components"]
            if item["id"] == "COMP-GOVERNANCE"
        )
        assets = next(
            item for item in value["components"] if item["id"] == "COMP-ASSETS"
        )
        governance["paths"].remove(".github/PULL_REQUEST_TEMPLATE.md")
        assets["paths"].append(".github/PULL_REQUEST_TEMPLATE.md")
        assets["paths"].sort()
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
                'python-version: "3.13"',
                'python-version: "3.14"',
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
            "component_protected_reclassification",
            "GOV-COMPONENT-PROTECTED-CATALOG-MISMATCH",
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


HISTORICAL_REFERENCES = (
    "BASE-CAPABILITY-DEFECT-001",
    "BASE-SCHEDULER-DEFECT-001",
    "BASE-SCHEDULER-LEGACY-001",
    "BASE-STORAGE-LEGACY-001",
    "known_defect",
    "observed_legacy",
)
HISTORICAL_ACTIVE_ROLES = (
    "canonical-template",
    "compatibility-rule",
    "component-invariant",
    "invariant-rule",
    "security-rule",
)
HISTORICAL_ACTIVE_ROLE_LOCATOR_MUTATIONS = (
    ("canonical-template", ("id",), "canonical-template-redirected"),
    (
        "canonical-template",
        ("registry_path",),
        "docs/architecture/component-map.json",
    ),
    ("canonical-template", ("collection_field",), "components"),
    ("canonical-template", ("record_filter", "field"), "status"),
    ("canonical-template", ("record_filter", "prefix"), "docs/decisions/"),
    ("canonical-template", ("value_field",), "path"),
    ("compatibility-rule", ("id",), "compatibility-rule-redirected"),
    (
        "compatibility-rule",
        ("registry_path",),
        "docs/architecture/component-map.json",
    ),
    ("compatibility-rule", ("collection_field",), "components"),
    ("compatibility-rule", ("record_filter", "field"), "statement"),
    ("compatibility-rule", ("record_filter", "equals"), "invariant"),
    ("compatibility-rule", ("value_field",), "statement"),
    ("component-invariant", ("id",), "component-invariant-redirected"),
    (
        "component-invariant",
        ("registry_path",),
        "docs/architecture/normative-documents.json",
    ),
    ("component-invariant", ("collection_field",), "decisions"),
    ("component-invariant", ("value_list_field",), "decisions"),
    ("invariant-rule", ("id",), "invariant-rule-redirected"),
    (
        "invariant-rule",
        ("registry_path",),
        "docs/architecture/component-map.json",
    ),
    ("invariant-rule", ("collection_field",), "components"),
    ("invariant-rule", ("record_filter", "field"), "statement"),
    ("invariant-rule", ("record_filter", "equals"), "security"),
    ("invariant-rule", ("value_field",), "statement"),
    ("security-rule", ("id",), "security-rule-redirected"),
    (
        "security-rule",
        ("registry_path",),
        "docs/architecture/component-map.json",
    ),
    ("security-rule", ("collection_field",), "components"),
    ("security-rule", ("record_filter", "field"), "statement"),
    ("security-rule", ("record_filter", "equals"), "compatibility"),
    ("security-rule", ("value_field",), "statement"),
)


def _link_historical_reference(
    repository: Path,
    *,
    active_role: str,
    reference: str,
) -> None:
    if active_role == "canonical-template":
        path = repository / "docs/architecture/normative-documents.json"
        policy = json.loads(path.read_text(encoding="utf-8"))
        template = next(
            item for item in policy["documents"] if item["id"] == "TPL-ADR-001"
        )
        template["id"] = reference
        _write_json(path, policy)
        return
    if active_role == "component-invariant":
        path = repository / "docs/architecture/component-map.json"
        catalog = json.loads(path.read_text(encoding="utf-8"))
        component = next(
            item
            for item in catalog["components"]
            if item["id"] == "COMP-BASELINE"
        )
        component["invariants"].append(reference)
        component["invariants"].sort()
        _write_json(path, catalog)
        return
    kinds = {
        "compatibility-rule": "compatibility",
        "invariant-rule": "invariant",
        "security-rule": "security",
    }
    source_path = "docs/v5/07-runtime-architecture.md"
    source = repository / source_path
    source.write_text(
        source.read_text(encoding="utf-8") + f"\n- `{reference}`\n",
        encoding="utf-8",
    )
    path = repository / "docs/architecture/id-registry.json"
    registry = json.loads(path.read_text(encoding="utf-8"))
    registry["ids"].append(
        {
            "id": reference,
            "kind": kinds[active_role],
            "source": source_path,
            "statement": "Current contract role fixture.",
        }
    )
    registry["ids"].sort(key=lambda item: item["id"])
    _write_json(path, registry)


@pytest.mark.parametrize(
    ("active_role", "reference", "authorization_state"),
    tuple(
        product(
            HISTORICAL_ACTIVE_ROLES,
            HISTORICAL_REFERENCES,
            ("absent", "separate-valid", "historical-current-contract"),
        )
    ),
)
def test_historical_reference_active_role_authorization_matrix(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_role: str,
    reference: str,
    authorization_state: str,
) -> None:
    _link_historical_reference(
        repository,
        active_role=active_role,
        reference=reference,
    )
    if authorization_state != "absent":
        path = repository / "docs/architecture/historical-record-policy.json"
        policy = json.loads(path.read_text(encoding="utf-8"))
        policy["authorizations"] = [
            {
                "active_role": active_role,
                "current_contract_id": (
                    "ARCH-REPOSITORY-CONTRACT-001"
                    if authorization_state == "separate-valid"
                    else reference
                ),
                "historical_reference": reference,
            }
        ]
        _write_json(path, policy)

    result = _run_cli(repository, monkeypatch)

    if authorization_state == "separate-valid":
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code == 1
        assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
        assert repr(active_role) in result.output
        if authorization_state == "historical-current-contract":
            assert "REPO-HISTORICAL-AUTHORIZATION-INVALID" in result.output


@pytest.mark.parametrize(
    ("active_role", "field_path", "replacement"),
    HISTORICAL_ACTIVE_ROLE_LOCATOR_MUTATIONS,
)
def test_historical_active_role_locators_are_pinned(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_role: str,
    field_path: tuple[str, ...],
    replacement: str,
) -> None:
    reference = "BASE-SCHEDULER-DEFECT-001"
    _link_historical_reference(
        repository,
        active_role=active_role,
        reference=reference,
    )
    path = repository / "docs/architecture/historical-record-policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    role = next(item for item in policy["active_roles"] if item["id"] == active_role)
    target = role
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = replacement
    _write_json(path, policy)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-HISTORICAL-ACTIVE-ROLE-INVALID" in result.output
    assert "active role locators must exactly match the version-1 contract" in (
        result.output
    )
    assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
    assert repr(active_role) in result.output


def test_historical_authorization_does_not_apply_to_a_different_active_role(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _link_historical_reference(
        repository,
        active_role="compatibility-rule",
        reference="known_defect",
    )
    path = repository / "docs/architecture/historical-record-policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["authorizations"] = [
        {
            "active_role": "invariant-rule",
            "current_contract_id": "ARCH-REPOSITORY-CONTRACT-001",
            "historical_reference": "known_defect",
        }
    ]
    _write_json(path, policy)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
    assert "REPO-ID-FORMAT" in result.output


def test_malformed_authorization_contract_cannot_enable_role_exceptions(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _link_historical_reference(
        repository,
        active_role="component-invariant",
        reference="BASE-SCHEDULER-DEFECT-001",
    )
    path = repository / "docs/architecture/historical-record-policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["authorization_contract"]["current_contract_registry"] = (
        "docs/architecture/normative-documents.json"
    )
    policy["authorizations"] = [
        {
            "active_role": "component-invariant",
            "current_contract_id": "ARCH-REPOSITORY-CONTRACT-001",
            "historical_reference": "BASE-SCHEDULER-DEFECT-001",
        }
    ]
    _write_json(path, policy)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-HISTORICAL-AUTHORIZATION-INVALID" in result.output
    assert "REPO-BASELINE-NONNORMATIVE-PROMOTED" in result.output
    assert "REPO-COMPONENT-INVARIANT-UNKNOWN" in result.output


def test_historical_exception_does_not_broaden_stable_id_grammar(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = "docs/v5/07-runtime-architecture.md"
    source = repository / source_path
    source.write_text(
        source.read_text(encoding="utf-8") + "\n- `arbitrary_legacy`\n",
        encoding="utf-8",
    )
    path = repository / "docs/architecture/id-registry.json"
    registry = json.loads(path.read_text(encoding="utf-8"))
    registry["ids"].append(
        {
            "id": "arbitrary_legacy",
            "kind": "compatibility",
            "source": source_path,
            "statement": "Uncataloged ID grammar control.",
        }
    )
    registry["ids"].sort(key=lambda item: item["id"])
    _write_json(path, registry)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-ID-FORMAT" in result.output


@pytest.mark.parametrize(
    "prose",
    [
        (
            "The historical record BASE-SCHEDULER-DEFECT-001 is now the "
            "definitive blueprint all schedulers must copy."
        ),
        (
            "Although known_defect was retired, present schedulers are "
            "compelled to reenact its behavior."
        ),
        (
            "observed_legacy is the authoritative record of what failed, not "
            "a current behavioral oracle."
        ),
        (
            "The old scheduler is a source of truth in this historical account."
        ),
    ],
)
def test_arbitrary_historical_prose_is_outside_the_bounded_role_oracle(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    prose: str,
) -> None:
    path = repository / "docs/v5/07-runtime-architecture.md"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{prose}\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output


PRIVATE_CONCEPT_VARIANTS = (
    "chain_of_thought",
    "hidden reasoning",
    "private-reasoning",
    "scratchpad",
)
PRIVATE_IDENTITIES = ("Orion", "Ｑｗｅｎ")
PRIVATE_CONTAINERS = (
    "html-attribute-value",
    "html-private-concept-tag",
    "html-visible-label",
    "markdown-attribute-value",
    "markdown-visible-label",
)


def _private_marker(container: str, identity: str, concept: str) -> str:
    compound = "-".join((*normalized_parts(identity), *normalized_parts(concept)))
    if container == "html-attribute-value":
        return f'<a data-note="{compound}"></a>'
    if container == "html-private-concept-tag":
        return f"<{compound}></{compound}>"
    if container == "html-visible-label":
        return f"<p>{identity} says： {concept}</p>"
    if container == "markdown-attribute-value":
        return f"## Review {{data-note={compound}}}"
    return f"- **{identity}:** {concept}"


def normalized_parts(value: str) -> tuple[str, ...]:
    return tuple(
        part
        for part in re.split(r"[^a-z0-9]+", value.casefold())
        if part
    ) or ("identity",)


@pytest.mark.parametrize(
    ("container", "identity", "concept"),
    tuple(product(PRIVATE_CONTAINERS, PRIVATE_IDENTITIES, PRIVATE_CONCEPT_VARIANTS)),
)
def test_open_identity_private_reasoning_grammar_covers_every_container(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    container: str,
    identity: str,
    concept: str,
) -> None:
    path = repository / "docs/architecture/repository-contract.md"
    marker = _private_marker(container, identity, concept)
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{marker}\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-NORMATIVE-BANNED-MARKER" in result.output


@pytest.mark.parametrize(
    ("relative_path", "control"),
    [
        (
            "docs/architecture/repository-contract.md",
            "Orion — private reasoning",
        ),
        (
            "docs/architecture/repository-contract.md",
            "The assistant's private scratchpad contains confidential notes.",
        ),
        (
            "docs/architecture/repository-contract.md",
            "<!-- Orion: private reasoning -->",
        ),
        (
            "docs/architecture/repository-contract.md",
            "```text\nOrion: private reasoning\n```",
        ),
        (
            "docs/architecture/repository-contract.md",
            "[public review](https://example.invalid/#orion-private-reasoning)",
        ),
        (
            "docs/architecture/repository-contract.md",
            "<analysis>identity-free tag</analysis>",
        ),
        (
            "src/unrest_harness/repository_contract.py",
            "# Orion: private reasoning",
        ),
    ],
)
def test_private_reasoning_out_of_scope_containers_and_prose_are_controls(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    control: str,
) -> None:
    path = repository / relative_path
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{control}\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("existing_syntax", "duplicate_syntax", "visible_label"),
    tuple(
        product(
            ("atx", "setext"),
            ("atx", "setext"),
            ("SCOPE", "Ｓｃｏｐｅ", "Sc\u200dope", "[Scope](task-packet.md#scope)"),
        )
    ),
)
def test_canonical_heading_atx_setext_visible_label_matrix(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_syntax: str,
    duplicate_syntax: str,
    visible_label: str,
) -> None:
    path = repository / "docs/templates/task-packet.md"
    text = path.read_text(encoding="utf-8")
    if existing_syntax == "setext":
        text = text.replace("## Scope", "Scope\n-----", 1)
    duplicate = (
        f"## {visible_label}"
        if duplicate_syntax == "atx"
        else f"{visible_label}\n{'-' * 10}"
    )
    path.write_text(text + f"\n{duplicate}\n", encoding="utf-8")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-DUPLICATE" in result.output


@pytest.mark.parametrize(
    "control",
    [
        "<!--\nScope\n-----\n-->",
        "```markdown\nScope\n-----\n```",
        "> Scope\n> -----",
        "    Scope\n    -----",
        "- example\n\n  Scope\n  -----",
        "<h2>Scope</h2>",
        "## Recovery procedure {#scope}",
        "## [Scope examples](task-packet.md#scope)",
        "## Scope examples",
        "### Scope",
    ],
)
def test_nonoperative_and_noncanonical_heading_controls_remain_valid(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    control: str,
) -> None:
    path = repository / "docs/templates/task-packet.md"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{control}\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "substitute",
    [
        "<!--\nScope\n-----\n-->",
        "```markdown\nScope\n-----\n```",
        "> Scope\n> -----",
        "    Scope\n    -----",
        "- example\n\n  Scope\n  -----",
        "<h2>Scope</h2>",
    ],
)
def test_nonoperative_heading_cannot_substitute_for_required_section(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    substitute: str,
) -> None:
    path = repository / "docs/templates/task-packet.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace("## Scope", substitute, 1),
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-TEMPLATE-FIELD-MISSING" in result.output


def _write_positive_evidence_record(repository: Path) -> tuple[Path, dict[str, Any]]:
    artifact_path = "evidence/bounded/result.txt"
    artifact = repository / artifact_path
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("bounded evidence\n", encoding="utf-8")
    record = {
        "artifact_path": artifact_path,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "exact_check": f"test -s {artifact_path}",
        "exit_code": 0,
        "mode": "evaluation",
        "observed_result": "checks-passed",
        "record_type": "evidence",
        "schema_version": 1,
        "status": "passed",
    }
    record_path = repository / "evidence/bounded/evaluation.json"
    _write_json(record_path, record)
    return record_path, record


def _bind_adr_evidence_field(repository: Path, value: str) -> None:
    path = repository / "docs/templates/adr.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "<strongest applicable tier and results>",
            value,
            1,
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "valid",
        "missing-artifact_path",
        "missing-artifact_sha256",
        "missing-exact_check",
        "missing-exit_code",
        "missing-mode",
        "missing-observed_result",
        "missing-record_type",
        "missing-schema_version",
        "missing-status",
        "artifact-missing",
        "artifact-hash",
        "check-unbound",
        "execution-failed",
        "mode-mismatch",
        "result-unrecognized",
        "status-nonpassing",
    ],
)
def test_positive_evidence_tuple_matrix(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    record_path, record = _write_positive_evidence_record(repository)
    if mutation.startswith("missing-"):
        record.pop(mutation.removeprefix("missing-"))
    elif mutation == "artifact-missing":
        record["artifact_path"] = "evidence/bounded/absent.txt"
        record["exact_check"] = "test -s evidence/bounded/absent.txt"
    elif mutation == "artifact-hash":
        record["artifact_sha256"] = "0" * 64
    elif mutation == "check-unbound":
        record["exact_check"] = "test -s evidence/bounded/other.txt"
    elif mutation == "execution-failed":
        record["exit_code"] = 1
    elif mutation == "mode-mismatch":
        record["mode"] = "rollback"
        record["observed_result"] = "rollback-complete"
    elif mutation == "result-unrecognized":
        record["observed_result"] = "promised-later"
    elif mutation == "status-nonpassing":
        record["status"] = "pending"
    _write_json(record_path, record)
    _bind_adr_evidence_field(repository, "evidence/bounded/evaluation.json")

    result = _run_cli(repository, monkeypatch)

    if mutation == "valid":
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code == 1
        assert "REPO-EVIDENCE-RECORD-INVALID" in result.output


@pytest.mark.parametrize("record_type", ["history", "limitation"])
def test_typed_evidence_disclosures_are_explicitly_nonpassing(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_type: str,
) -> None:
    record_path = repository / "evidence/bounded/evaluation.json"
    record_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(
        record_path,
        {
            "mode": "evaluation",
            "record_type": record_type,
            "schema_version": 1,
            "status": "non-passing",
            "summary": "Cataloged disclosure, not successful evidence.",
        },
    )
    _bind_adr_evidence_field(repository, "evidence/bounded/evaluation.json")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-EVIDENCE-NONPASSING" in result.output


@pytest.mark.parametrize(
    "prose",
    [
        "Evidence dossier: TBD after review.",
        "Evaluation evidence: expected by 2030-01-01 after approval.",
        "The audit result is to be made available when approval arrives.",
        "The scheduler result queue remains bounded.",
        "Verification material is merely aspirational at this stage.",
        "Evidence: evidence/future/report.json will appear later.",
    ],
)
def test_free_evidence_prose_is_not_a_protected_location_or_classification(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    prose: str,
) -> None:
    path = repository / "docs/v5/10-implementation-plan.md"
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n{prose}\n",
        encoding="utf-8",
    )

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output


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
    assert text.count(step) == 2
    if mutation == "removed":
        text = step.join(text.rsplit(step, 1)[:-1]) + text.rsplit(step, 1)[-1]
        expected = "REPO-CI-COMMAND-MISSING"
    elif mutation == "substituted":
        before, after = text.rsplit(step, 1)
        text = before + step.replace(
            CANONICAL_COMMAND,
            "uv run python -m unrest_harness.repository_contract",
            1,
        ) + after
        expected = "REPO-CI-COMMAND-SUBSTITUTED"
    else:
        before, after = text.rsplit(step, 1)
        text = before + after
        marker = "      - name: Smoke-test installed wheel\n"
        text = text.replace(marker, step + marker, 1)
        expected = "REPO-CI-COMMAND-ORDER"
    path.write_text(text, encoding="utf-8")
    before = _status(repository)
    assert before == {".github/workflows/ci.yml"}

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert expected in result.output
    assert ".github/workflows/ci.yml#jobs.primary" in result.output
    assert str(repository) not in result.output
    assert _status(repository) == before


def test_ci_has_one_full_suite_and_exact_tier_surfaces() -> None:
    workflow_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    compatibility = workflow["jobs"]["compatibility"]
    primary = workflow["jobs"]["primary"]

    assert compatibility["strategy"]["matrix"]["python-version"] == ["3.11", "3.12"]
    assert primary["steps"][1]["with"]["python-version"] == "3.13"
    commands = [
        step["run"].strip()
        for job in (compatibility, primary)
        for step in job["steps"]
        if "run" in step
    ]
    assert commands.count(FULL_SOURCE_SUITE_COMMAND) == 1
    assert commands.count(COMPATIBILITY_TEST_COMMAND) == 1
    assert commands.count(DISTRIBUTION_CHECK_COMMAND) == 1
    assert sum("pytest" in command for command in commands) == 2
    assert sum(command == "uv build" for command in commands) == 1
    assert workflow_text.count("-m unrest_harness.installed_wheel_check") == 1


@pytest.mark.parametrize(
    ("command", "expected"),
    (
        (("bash", "-c", "uv run pytest -q"), "uv run pytest -q"),
        (("bash", "-lc", "uv run pytest -q"), "uv run pytest -q"),
        (("sh", "-ec", "uv run pytest -q"), "uv run pytest -q"),
        (("zsh", "-fc", "uv run pytest -q"), "uv run pytest -q"),
        (
            ("bash", "-o", "pipefail", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "+o", "pipefail", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "-O", "extglob", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "+O", "extglob", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "-Oc", "extglob", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "-co", "pipefail", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "--noprofile", "--norc", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "--init-file", "/dev/null", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (
            ("bash", "--rcfile=/dev/null", "-c", "uv run pytest -q"),
            "uv run pytest -q",
        ),
        (("bash", "--", "-c", "uv run pytest -q"), None),
        (("bash", "script.sh", "-c", "uv run pytest -q"), None),
        (("bash", "-o", "-c", "uv run pytest -q"), None),
        (("bash", "+O", "-c", "uv run pytest -q"), None),
        (("bash", "--init-file", "-c", "uv run pytest -q"), None),
        (("bash", "--init-file=", "-c", "uv run pytest -q"), None),
        (("bash", "--help", "-c", "uv run pytest -q"), None),
        (("bash", "--unknown", "-c", "uv run pytest -q"), None),
        (("bash", "-q", "-c", "uv run pytest -q"), None),
        (("bash", "-c"), None),
        (("python", "-c", "uv run pytest -q"), None),
    ),
    ids=(
        "plain-command",
        "bash-combined",
        "sh-combined",
        "zsh-combined",
        "minus-o",
        "plus-o",
        "minus-O",
        "plus-O",
        "combined-Oc",
        "combined-co",
        "boolean-long",
        "separate-long-operand",
        "equals-long-operand",
        "option-terminator",
        "script-stop",
        "malformed-o-operand",
        "malformed-O-operand",
        "malformed-long-operand",
        "empty-equals-operand",
        "terminal-long-option",
        "unknown-long-option",
        "unknown-short-option",
        "missing-command-string",
        "not-a-shell",
    ),
)
def test_shell_command_string_uses_bounded_structural_option_grammar(
    command: tuple[str, ...],
    expected: str | None,
) -> None:
    assert _shell_command_string(command) == expected


@pytest.mark.parametrize(
    "extra_job",
    [
        "",
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: uv run pytest -q\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: python -m pytest ./tests/\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: sh -c 'uv run python -m pytest -q .'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash -lc 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: sh -ec 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: zsh -fc 'uv run pytest -q' ci-shell\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash -o pipefail -c 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash -O extglob -c 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash +o pipefail -c 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash +O extglob -c 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash -Oc extglob 'uv run pytest -q'\n"
        ),
        (
            "\n  duplicate-suite:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: bash --noprofile --rcfile=/dev/null -c 'uv run pytest -q'\n"
        ),
    ],
    ids=(
        "same-job",
        "direct",
        "python-module-tests",
        "nested-shell-dot",
        "bash-login-command",
        "sh-errexit-command",
        "zsh-fast-command",
        "bash-pipefail-command",
        "bash-extglob-command",
        "bash-plus-pipefail-command",
        "bash-plus-extglob-command",
        "bash-combined-option-operand-command",
        "bash-long-options-command",
    ),
)
def test_ci_rejects_any_additional_full_suite_spelling(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_job: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    if extra_job:
        text += extra_job
    else:
        marker = "      - name: Repository contract\n"
        duplicate = "      - name: Duplicate suite\n        run: uv run pytest -q\n"
        text = text.replace(marker, duplicate + marker, 1)
    path.write_text(text, encoding="utf-8")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-FULL-SUITE-COUNT" in result.output
    assert "REPO-CI-TEST-SURFACES-INVALID" in result.output


@pytest.mark.parametrize(
    "command",
    (
        "bash -o pipefail -c 'printf option-argument-control'",
        "bash +o pipefail -c 'printf plus-option-argument-control'",
        "bash -O extglob -c 'printf shopt-argument-control'",
        "bash +O extglob -c 'printf plus-shopt-argument-control'",
        "bash --rcfile=/dev/null -c 'printf long-option-control'",
        "bash -- -c 'uv run pytest -q'",
        "bash -o -c 'uv run pytest -q'",
        "bash --init-file -c 'uv run pytest -q'",
        "bash --unknown -c 'uv run pytest -q'",
        "bash -q -c 'uv run pytest -q'",
    ),
    ids=(
        "bash-pipefail",
        "bash-plus-pipefail",
        "bash-extglob",
        "bash-plus-extglob",
        "bash-long-equals",
        "option-terminator",
        "malformed-short-operand",
        "malformed-long-operand",
        "unknown-long-option",
        "unknown-short-option",
    ),
)
def test_ci_accepts_option_taking_shell_wrappers_without_pytest(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text += (
        "\n  shell-control:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: {command}\n"
    )
    path.write_text(text, encoding="utf-8")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "ok"


def test_ci_pytest_text_and_focused_selection_are_not_full_suite_invocations(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "      - name: Repository contract\n",
        "      - name: Harmless pytest controls\n"
        "        run: |\n"
        "          echo pytest\n"
        "          uv run pytest -q tests/test_assets.py -k impossible\n"
        "          bash -lc 'uv run pytest -q tests/test_config.py -k impossible'\n"
        "          sh scripts/pytest-smoke.sh\n"
        "      - name: Repository contract\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-TEST-SURFACES-INVALID" in result.output
    assert "REPO-CI-FULL-SUITE-COUNT" not in result.output


def test_root_ruff_excludes_only_runtime_validation_artifacts() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert configuration["tool"]["ruff"]["exclude"] == [
        ".validation",
        "validator-regressions",
    ]


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
    before, after = text.rsplit(contract, 1)
    text = (before + after).replace(
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
    test_step = (
        "      - name: Full source suite\n"
        "        run: env -u CODEX_PATH uv run pytest -q\n"
    )
    publish_step = "      - name: Publish check\n        run: uv publish --dry-run\n"
    before, after = text.rsplit(contract, 1)
    text = (before + after).replace(
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
            '        python-version: ["3.11", "3.12"]',
            '        python-version: ["3.11"]',
            "REPO-CI-PYTHON-COVERAGE-MISSING",
        ),
        (
            '        python-version: ["3.11", "3.12"]',
            '        python-version: ["3.11", "3.12"]\n'
            "        exclude:\n"
            "          - python-version: ${{ matrix.disabled-version }}",
            "REPO-CI-MATRIX-INVALID",
        ),
        (
            "      - name: Full source suite\n"
            "        run: env -u CODEX_PATH uv run pytest -q\n"
            "      - name: Repository contract\n"
            f"        run: {CANONICAL_COMMAND}",
            "      - name: Full source suite\n"
            "        run: env -u CODEX_PATH uv run pytest -q\n"
            "      - name: Repository contract\n"
            "        if: ${{ false }}\n"
            f"        run: {CANONICAL_COMMAND}",
            "REPO-CI-COMMAND-CONDITIONAL",
        ),
        (
            "      - name: Full source suite\n"
            "        run: env -u CODEX_PATH uv run pytest -q\n"
            "      - name: Repository contract\n"
            f"        run: {CANONICAL_COMMAND}",
            "      - name: Full source suite\n"
            "        run: env -u CODEX_PATH uv run pytest -q\n"
            "      - name: Repository contract\n"
            "        continue-on-error: true\n"
            f"        run: {CANONICAL_COMMAND}",
            "REPO-CI-COMMAND-CONTINUE-ON-ERROR",
        ),
        (
            "  primary:\n"
            "    name: primary source and package gate (py3.13)\n"
            "    runs-on: ubuntu-latest",
            "  primary:\n"
            "    name: primary source and package gate (py3.13)\n"
            "    if: ${{ false }}\n"
            "    runs-on: ubuntu-latest",
            "REPO-CI-JOB-CONDITIONAL",
        ),
        (
            "  primary:\n"
            "    name: primary source and package gate (py3.13)\n"
            "    runs-on: ubuntu-latest",
            "  primary:\n"
            "    name: primary source and package gate (py3.13)\n"
            "    continue-on-error: true\n"
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


def test_ci_effective_coverage_accepts_literal_non_skipping_controls(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
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
        "  primary:\n",
        "  primary:\n    needs: blocker\n",
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
            "      - name: Full source suite\n"
            "        run: env -u CODEX_PATH uv run pytest -q",
            "      - name: Full source suite\n"
            "        if: ${{ false }}\n"
            "        run: env -u CODEX_PATH uv run pytest -q",
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


def test_ci_requires_focused_distribution_check_after_build(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    post_build = (
        "      - name: Check distribution archives\n"
        "        run: uv run python tools/check_distribution.py dist\n"
    )
    assert text.count(post_build) == 1
    path.write_text(text.replace(post_build, "", 1), encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-DISTRIBUTION-CHECK-MISSING" in result.output
    assert _status(repository) == before


def test_ci_rejects_duplicate_post_build_full_pytest(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "      - name: Check distribution archives\n"
    duplicate = "      - name: Duplicate built-tree suite\n        run: uv run pytest -q\n"
    path.write_text(text.replace(marker, duplicate + marker, 1), encoding="utf-8")

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-POST-BUILD-PYTEST" in result.output


def test_ci_requires_installed_wheel_lifecycle_mission(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = repository / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    invocation = "-m unrest_harness.installed_wheel_check"
    assert text.count(invocation) == 1
    path.write_text(
        text.replace(invocation, "-m unrest_harness --help", 1),
        encoding="utf-8",
    )
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 1
    assert "REPO-CI-INSTALLED-MISSION-MISSING" in result.output
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
        "  primary:\n",
        "  primary:\n    needs: prerequisite\n",
        1,
    )
    path.write_text(text, encoding="utf-8")
    before = _status(repository)

    result = _run_cli(repository, monkeypatch)

    assert result.exit_code == 0, result.output
    assert _status(repository) == before
