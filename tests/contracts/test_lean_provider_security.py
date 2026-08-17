"""Immutable provider/security scenarios characterized at the fixed reference."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest


SCENARIOS = (
    (
        "VAL-PROVIDER-001",
        "claude-unsafe-authority-requires-exact-opt-in",
        "tests/test_capability_policy.py::test_only_explicit_unsafe_profile_emits_unrestricted_provider_settings",
    ),
    (
        "VAL-PROVIDER-002",
        "codex-safe-settings-override-ambient-unrestricted",
        "tests/test_capability_policy.py::test_safe_codex_subprocess_settings_override_ambient_unrestricted",
    ),
    (
        "VAL-PROVIDER-003",
        "unsupported-profile-fails-before-spawn",
        "tests/test_capability_policy.py::test_unsupported_profile_has_stable_provider_role_version_error",
    ),
    (
        "VAL-PROVIDER-004",
        "child-environment-is-finite-and-credential-named",
        "tests/test_capability_policy.py::test_role_environment_is_minimal_deterministic_and_credential_named",
    ),
    (
        "VAL-PROVIDER-005",
        "reviewer-timeout-cleans-child-pipes",
        "tests/test_acp_runner.py::test_terminal_review_timeout_cleans_acp_and_mcp_children",
    ),
    (
        "VAL-PROVIDER-006",
        "supported-provider-set-is-claude-codex-only",
        "tests/test_lean_provider_security_runtime.py::test_supported_provider_set_is_claude_and_codex_only",
    ),
    (
        "VAL-SEC-001",
        "filesystem-traversal-and-symlink-escapes-fail",
        "tests/test_capability_policy.py::test_filesystem_callbacks_enforce_absolute_traversal_symlink_and_read_only",
    ),
    (
        "VAL-SEC-002",
        "ambient-inventory-remains-finite",
        "tests/test_capability_policy.py::test_ambient_credential_inventory_is_provider_neutral_and_deterministic[0]",
    ),
    (
        "VAL-SEC-003",
        "short-token-neighbor-boundaries-are-preserved",
        "tests/test_capability_policy.py::test_credential_redaction_is_boundary_aware_and_deterministic",
    ),
    (
        "VAL-SEC-004",
        "stream-split-progress-redacts-known-values",
        "tests/test_capability_policy.py::test_progress_redaction_spans_chunks_callbacks_and_message_ids",
    ),
    (
        "VAL-SEC-005",
        "handoff-redaction-survives-restart-and-remirroring",
        "tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring",
    ),
    (
        "VAL-SEC-006",
        "cyclic-diagnostic-is-bounded-and-value-free",
        "tests/test_capability_policy.py::test_cyclic_containers_have_stable_value_free_boundary_diagnostics",
    ),
    (
        "VAL-SEC-007",
        "oversized-inventory-fd-payload-fails-closed",
        "local::oversized-inventory-fd-payload",
    ),
    (
        "VAL-SEC-008",
        "legacy-triple-base64-redaction-is-bound-for-inversion",
        "local::transform-enumeration-inventory-rejection",
    ),
    (
        "VAL-SEC-009",
        "codex-config-drops-credential-aliases",
        "tests/test_capability_policy.py::test_codex_structured_config_drops_exact_aliases_and_preserves_config",
    ),
    (
        "VAL-SEC-010",
        "raw-acp-write-path-redacts-known-values",
        "tests/test_capability_policy.py::test_raw_acp_terminal_protocol_redacts_credential_values",
    ),
    (
        "VAL-SEC-011",
        "malformed-terminal-request-fails-before-spawn",
        "tests/test_capability_policy.py::test_terminal_callbacks_enforce_process_cwd_and_environment",
    ),
    (
        "VAL-HARDCUT-CAPABILITY-001",
        "legacy-static-closure-is-bound-for-removal",
        "local::static-capability-responsibility-rejection",
    ),
)

ASSERTION_TO_SCENARIOS = {
    assertion_id: (scenario_id,) for assertion_id, scenario_id, _ in SCENARIOS
}


def _assert_capability_inventory_is_lean(
    symbols: set[str] | tuple[str, ...], forbidden_fragments: tuple[str, ...]
) -> None:
    hits = sorted(
        symbol
        for symbol in symbols
        if any(fragment in symbol for fragment in forbidden_fragments)
    )
    if hits:
        raise AssertionError(f"removed capability responsibility present: {hits}")


def _candidate_responsibility_inventory(
    root: Path,
    fragments: tuple[str, ...],
) -> tuple[str, ...]:
    hits: set[str] = set()
    for base in (root / "src", root / "tests"):
        for path in sorted(base.rglob("*")):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or "tests/contracts" in path.as_posix()
            ):
                continue
            relative = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if any(fragment in relative.lower() or fragment in text for fragment in fragments):
                hits.add(relative)
    return tuple(sorted(hits))


def _assert_transform_cut(
    *,
    exact_output: str,
    transformed_output: str,
    transformed: str,
) -> None:
    if "<redacted:" not in exact_output:
        raise AssertionError("exact-known positive control was not redacted")
    if transformed not in transformed_output:
        raise AssertionError(
            "triple-base64 legacy transform remains hidden: "
            f"output={transformed_output!r}"
        )


@pytest.mark.parametrize(
    ("assertion_id", "scenario_id", "reference_node"),
    SCENARIOS,
    ids=[f"{assertion_id}__{scenario_id}" for assertion_id, scenario_id, _ in SCENARIOS],
)
def test_reference_contract_scenario(
    assertion_id: str,
    scenario_id: str,
    reference_node: str,
    lean_reference_run,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert reference_node in lean_reference_run.nodes
    if reference_node == "local::oversized-inventory-fd-payload":
        import os
        import tempfile

        from unrest_harness.server import (
            _SENSITIVE_INVENTORY_MAX_BYTES,
            _read_sensitive_inventory_fd,
        )

        with tempfile.TemporaryFile() as payload:
            payload.write(b"x" * (_SENSITIVE_INVENTORY_MAX_BYTES + 1))
            payload.seek(0)
            with pytest.raises(RuntimeError, match="exceeds startup channel limit"):
                _read_sensitive_inventory_fd(os.dup(payload.fileno()))
    elif reference_node == "local::transform-enumeration-inventory-rejection":
        from unrest_harness.capability_policy import redact_sensitive_value

        secret = "triple-base64-fixed-reference-secret-0123456789"
        transformed = secret
        for _ in range(3):
            transformed = base64.urlsafe_b64encode(transformed.encode()).decode().rstrip("=")
        inventory = {"EXACT_KNOWN_CONTROL": secret}
        exact_output = redact_sensitive_value(secret, inventory)
        transformed_output = redact_sensitive_value(transformed, inventory)
        _assert_transform_cut(
            exact_output=exact_output,
            transformed_output=transformed_output,
            transformed=transformed,
        )
    elif reference_node == "local::static-capability-responsibility-rejection":
        forbidden = (
            "closed_model",
            "semantic_digest",
            "sink_catalog",
            "capability-security-model",
            "capability-sinks",
        )
        actual = _candidate_responsibility_inventory(repository_root, forbidden)
        _assert_capability_inventory_is_lean(actual, forbidden)
        with pytest.raises(AssertionError, match="closed_model"):
            _assert_capability_inventory_is_lean(
                (*actual, "src/unrest_harness/closed_model.py"),
                forbidden,
            )
    assert lean_reference_run.returncode == 0, lean_reference_run.output


def _clean_cli_environment() -> dict[str, str]:
    credential_markers = ("API_KEY", "TOKEN", "PASSWORD", "CREDENTIAL")
    environment = {
        name: value
        for name, value in os.environ.items()
        if not any(marker in name.upper() for marker in credential_markers)
    }
    environment.pop("PYTHONPATH", None)
    environment.pop("CODEX_PATH", None)
    return environment


def _run_cli_matrix(
    *,
    python: Path,
    bootstrap: str,
    cwd: Path,
    environment: dict[str, str],
) -> None:
    sentinel = "known-installed-choice-sentinel-8a17"
    ordinary = "ordinary-unsupported-provider"
    options = (
        "--agent",
        "--orchestrator-provider",
        "--worker-provider",
        "--validator-provider",
        "--terminal-reviewer-provider",
        "--worker-reasoning-effort",
        "--validator-reasoning-effort",
        "--terminal-reviewer-reasoning-effort",
        "--scope",
    )
    trap = cwd / "precommand-callback-trap"
    script = (
        bootstrap
        + "from pathlib import Path; from unrest_harness.cli import cli; "
        + f"trap=Path({str(trap)!r}); "
        + "cli.commands['init'].callback=lambda **kwargs: trap.write_text('called'); "
        + "cli.main()"
    )
    credential_environment = {**environment, "OPENAI_API_KEY": sentinel}
    for option in options:
        completed = subprocess.run(
            [str(python), "-S", "-c", script, "init", option, sentinel],
            cwd=cwd,
            env=credential_environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 2, (option, completed.stdout)
        assert sentinel not in completed.stdout
        assert "<redacted:OPENAI_API_KEY>" in completed.stdout
        assert "is not one of" in completed.stdout
        assert not trap.exists()

    ordinary_result = subprocess.run(
        [str(python), "-S", "-c", script, "init", "--worker-provider", ordinary],
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    assert ordinary_result.returncode == 2
    assert ordinary in ordinary_result.stdout
    assert "claude" in ordinary_result.stdout
    assert "codex" in ordinary_result.stdout
    assert not trap.exists()


def test_copied_source_and_installed_cli_protect_precommand_credentials(
    tmp_path: Path,
    repository_root: Path,
    built_distribution,
) -> None:
    copied_root = tmp_path / "copied-candidate"
    copied_source = copied_root / "src"
    shutil.copytree(repository_root / "src", copied_source)
    environment = _clean_cli_environment()
    dependency_site = str(built_distribution.dependency_site)

    _run_cli_matrix(
        python=Path(sys.executable),
        bootstrap=f"import sys; sys.path[:0]=[{str(copied_source)!r}, {dependency_site!r}]; ",
        cwd=copied_root,
        environment=environment,
    )
    _run_cli_matrix(
        python=built_distribution.installed_python,
        bootstrap=(
            "import sys; "
            f"sys.path[:0]=[{str(built_distribution.installed_site)!r}, {dependency_site!r}]; "
        ),
        cwd=built_distribution.directory,
        environment=environment,
    )


def test_removed_provider_literal_and_archive_inventory_is_empty(
    repository_root: Path,
    built_distribution,
) -> None:
    removed_literal = base64.b64decode("aGVybWVz").decode("ascii")
    maintained_roots = (
        repository_root / "src",
        repository_root / "tests",
        repository_root / "docs",
    )
    hits: list[str] = []
    for root in maintained_roots:
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                if removed_literal in path.read_text(
                    encoding="utf-8", errors="replace"
                ).lower():
                    hits.append(path.relative_to(repository_root).as_posix())
    for path in (repository_root / "README.md", repository_root / "pyproject.toml"):
        if removed_literal in path.read_text(encoding="utf-8").lower():
            hits.append(path.relative_to(repository_root).as_posix())

    archive_hits: list[str] = []
    with zipfile.ZipFile(built_distribution.wheel) as archive:
        for name in sorted(archive.namelist()):
            if removed_literal in name.lower() or removed_literal.encode() in archive.read(name).lower():
                archive_hits.append(f"wheel:{name}")
    with tarfile.open(built_distribution.sdist, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if removed_literal in member.name.lower():
                archive_hits.append(f"sdist:{member.name}")
            extracted = archive.extractfile(member) if member.isfile() else None
            if extracted is not None and removed_literal.encode() in extracted.read().lower():
                archive_hits.append(f"sdist:{member.name}")

    assert hits == []
    assert archive_hits == []


@pytest.mark.parametrize("provider", ("claude", "codex"))
def test_installed_supported_provider_matrix(
    provider: str,
    built_distribution,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / provider
    workspace.mkdir()
    unrest_home = tmp_path / f"{provider}-home"
    bootstrap = (
        "import sys; "
        f"sys.path[:0]=[{str(built_distribution.installed_site)!r}, "
        f"{str(built_distribution.dependency_site)!r}]; "
        "from unrest_harness.cli import cli; cli.main()"
    )
    completed = subprocess.run(
        [
            str(built_distribution.installed_python),
            "-S",
            "-c",
            bootstrap,
            "init",
            "--agent",
            provider,
            "--workspace-dir",
            str(workspace),
        ],
        cwd=built_distribution.directory,
        env={**_clean_cli_environment(), "UNREST_HOME": str(unrest_home)},
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout
    assert f"orchestrator={provider}" in completed.stdout
    if provider == "claude":
        generated = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
        assert generated["mcpServers"]["unrest"]["env"]["UNREST_WORKER_PROVIDER"] == provider
    else:
        generated = (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")
        assert f'UNREST_WORKER_PROVIDER = "{provider}"' in generated
