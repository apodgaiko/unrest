"""Regression coverage for ambient HarnessConfig isolation."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from unrest_harness.config import (
    DEFAULT_MAX_PARALLEL_NODES,
    DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS,
    HARNESS_CONFIG_ENV_VARS,
    HarnessConfig,
)

_UNRELATED_ENV = "UNREST_TEST_ISOLATION_UNRELATED_SENTINEL"
_PYTEST_RESTORE_PROBE = """
import os
import sys

import pytest

from unrest_harness.config import HARNESS_CONFIG_ENV_VARS

before = {variable: os.environ[variable] for variable in HARNESS_CONFIG_ENV_VARS}
status = pytest.main(sys.argv[1:])
after = {variable: os.environ[variable] for variable in HARNESS_CONFIG_ENV_VARS}
assert after == before
assert os.environ["UNREST_TEST_ISOLATION_UNRELATED_SENTINEL"] == (
    "outer-unrelated-value"
)
raise SystemExit(status)
"""


def _adversarial_environment() -> dict[str, str]:
    values = {
        variable: f"ambient-{index}-{variable.lower()}"
        for index, variable in enumerate(sorted(HARNESS_CONFIG_ENV_VARS), start=1)
    }
    values.update(
        {
            "UNREST_HOME": "ambient-path-contains-no-user-directory",
            "UNREST_PROJECTS_DIR": "ambient-projects-path-contains-no-user-directory",
            "UNREST_MAX_PARALLEL_NODES": "ambient-invalid-integer-parallelism",
            "UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS": "ambient-invalid-integer-timeout",
            "UNREST_ORCHESTRATOR_PROVIDER": "ambient-invalid-provider-orchestrator",
            "UNREST_WORKER_PROVIDER": "ambient-invalid-provider-worker",
            "UNREST_VALIDATOR_PROVIDER": "ambient-invalid-provider-validator",
            "UNREST_TERMINAL_REVIEWER_PROVIDER": "ambient-invalid-provider-reviewer",
            "UNREST_WORKER_REASONING_EFFORT": "ambient-invalid-model-effort-worker",
            "UNREST_VALIDATOR_REASONING_EFFORT": "ambient-invalid-model-effort-validator",
            "UNREST_TERMINAL_REVIEWER_REASONING_EFFORT": (
                "ambient-invalid-model-effort-reviewer"
            ),
            "UNREST_CAPABILITY_POLICY_VERSION": "ambient-invalid-policy-version",
            "UNREST_CAPABILITY_PROFILE": "ambient-invalid-policy-profile",
            "UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED": "ambient-invalid-policy-opt-in",
        }
    )
    return values


def test_autouse_fixture_scrubs_complete_authoritative_inventory() -> None:
    assert len(HARNESS_CONFIG_ENV_VARS) == 17
    assert HARNESS_CONFIG_ENV_VARS.isdisjoint(os.environ)

    config = HarnessConfig.discover()

    assert config.max_parallel_nodes == DEFAULT_MAX_PARALLEL_NODES
    assert (
        config.terminal_review_timeout_seconds
        == DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS
    )


def test_autouse_fixture_preserves_unrelated_environment() -> None:
    assert _UNRELATED_ENV not in HARNESS_CONFIG_ENV_VARS
    assert os.environ.get(_UNRELATED_ENV) in (None, "outer-unrelated-value")


def test_explicit_test_environment_wins_after_autouse_scrub(
    monkeypatch,
    tmp_path: Path,
) -> None:
    explicit_home = tmp_path / "explicit-home"
    explicit_projects = tmp_path / "explicit-projects"
    monkeypatch.setenv("UNREST_HOME", str(explicit_home))
    monkeypatch.setenv("UNREST_PROJECTS_DIR", str(explicit_projects))
    monkeypatch.setenv("UNREST_MAX_PARALLEL_NODES", "7")
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS", "41")
    monkeypatch.setenv("UNREST_ORCHESTRATOR_PROVIDER", "codex")
    monkeypatch.setenv("UNREST_WORKER_PROVIDER", "claude")
    monkeypatch.setenv("UNREST_CAPABILITY_POLICY_VERSION", "1")
    monkeypatch.setenv("UNREST_CAPABILITY_PROFILE", "safe")

    config = HarnessConfig.discover()

    assert config.harness_home == explicit_home.resolve()
    assert config.projects_dir == explicit_projects.resolve()
    assert config.max_parallel_nodes == 7
    assert config.terminal_review_timeout_seconds == 41
    assert config.orchestrator_provider_name == "codex"
    assert config.worker_provider_name == "claude"


def test_seeded_pytest_run_is_hermetic_and_restores_parent_environment() -> None:
    parent_before = dict(os.environ)
    adversarial_environment = _adversarial_environment()
    assert set(adversarial_environment) == HARNESS_CONFIG_ENV_VARS
    assert len(set(adversarial_environment.values())) == len(HARNESS_CONFIG_ENV_VARS)
    child_environment = parent_before | adversarial_environment
    child_environment[_UNRELATED_ENV] = "outer-unrelated-value"

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _PYTEST_RESTORE_PROBE,
            "-q",
            f"{__file__}::test_autouse_fixture_scrubs_complete_authoritative_inventory",
            f"{__file__}::test_autouse_fixture_preserves_unrelated_environment",
            "tests/test_config.py::test_discover_defaults_to_four_parallel_nodes",
        ],
        cwd=Path(__file__).parents[1],
        env=child_environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert os.environ == parent_before
