"""Harness configuration defaults."""
from __future__ import annotations

from pathlib import Path

import pytest

from unrest_harness.config import (
    DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS,
    HarnessConfig,
)

_EFFORT_ENV_VARS = (
    "UNREST_WORKER_REASONING_EFFORT",
    "UNREST_VALIDATOR_REASONING_EFFORT",
    "UNREST_TERMINAL_REVIEWER_REASONING_EFFORT",
)


def _clear_effort_env(monkeypatch) -> None:
    for var in _EFFORT_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_discover_defaults_to_four_parallel_nodes(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.delenv("UNREST_PROJECTS_DIR", raising=False)
    monkeypatch.delenv("UNREST_MAX_PARALLEL_NODES", raising=False)
    monkeypatch.delenv("UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS", raising=False)

    config = HarnessConfig.discover()

    assert config.max_parallel_nodes == 4
    assert config.terminal_review_timeout_seconds == DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS


def test_discover_terminal_review_timeout(monkeypatch, harness_home: Path) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS", "37")

    assert HarnessConfig.discover().terminal_review_timeout_seconds == 37


@pytest.mark.parametrize("value", ["0", "-1", "eventually"])
def test_discover_rejects_non_positive_terminal_review_timeout(
    monkeypatch, harness_home: Path, value: str
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS", value)

    with pytest.raises(ValueError, match="UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS"):
        HarnessConfig.discover()


def test_discover_explicit_one_uses_serial_parallelism(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.setenv("UNREST_MAX_PARALLEL_NODES", "1")

    config = HarnessConfig.discover()

    assert config.max_parallel_nodes == 1


def test_discover_invalid_parallelism_falls_back_to_default(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.setenv("UNREST_MAX_PARALLEL_NODES", "not-an-int")

    config = HarnessConfig.discover()

    assert config.max_parallel_nodes == 4


def test_discover_reasoning_effort_defaults_to_none(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    _clear_effort_env(monkeypatch)

    config = HarnessConfig.discover()

    assert config.worker_reasoning_effort is None
    assert config.validator_reasoning_effort is None
    assert config.terminal_reviewer_reasoning_effort is None


def test_discover_reasoning_effort_per_role(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "high")
    monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "medium")
    monkeypatch.setenv("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT", "max")

    config = HarnessConfig.discover()

    assert config.worker_reasoning_effort == "high"
    assert config.validator_reasoning_effort == "medium"
    assert config.terminal_reviewer_reasoning_effort == "max"


def test_discover_invalid_reasoning_effort_rejected(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    _clear_effort_env(monkeypatch)
    # Not silently ignored: the value lands in a shell command line, and a
    # A typo'd override would silently keep spending the medium default.
    monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "extra-high")

    with pytest.raises(ValueError, match="UNREST_VALIDATOR_REASONING_EFFORT"):
        HarnessConfig.discover()


def test_for_role_reasoning_effort_cascade(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    _clear_effort_env(monkeypatch)
    monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "medium")

    config = HarnessConfig.discover()

    # Unset roles inherit down the same chain as providers/commands:
    # terminal_reviewer -> validator -> worker.
    assert config.for_role("worker").worker_reasoning_effort == "medium"
    assert config.for_role("validator").worker_reasoning_effort == "medium"
    assert config.for_role("terminal_reviewer").worker_reasoning_effort == "medium"


def test_for_role_reasoning_effort_explicit_override_wins(
    monkeypatch,
    harness_home: Path,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    _clear_effort_env(monkeypatch)
    monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "xhigh")
    monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "low")

    config = HarnessConfig.discover()

    assert config.for_role("worker").worker_reasoning_effort == "xhigh"
    assert config.for_role("validator").worker_reasoning_effort == "low"
    # terminal_reviewer falls back to the validator setting first.
    assert config.for_role("terminal_reviewer").worker_reasoning_effort == "low"
