"""Harness configuration defaults."""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from unrest_harness.config import (
    DEFAULT_TERMINAL_REVIEW_TIMEOUT_SECONDS,
    HarnessConfig,
)
from unrest_harness.capability_policy import load_capability_policy
from unrest_harness.storage import ProjectStore

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


def test_credential_inventory_follows_each_selected_role_provider(
    harness_home: Path,
) -> None:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    config = HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="codex",
        worker_provider_name="claude",
        validator_provider_name="codex",
        terminal_reviewer_provider_name="claude",
        worker_acp_command=None,
        validator_acp_command=None,
        terminal_reviewer_acp_command=None,
    )
    environment = {
        name: f"sentinel-{name.lower()}"
        for name in (
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CODEX_API_KEY",
            "GLM_API_KEY",
            "OPENAI_API_KEY",
            "ZAI_API_KEY",
        )
    }

    assert set(config.credential_inventory(environment, role="orchestrator")) == {
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
    }
    assert set(config.credential_inventory(environment, role="worker")) == {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "GLM_API_KEY",
        "ZAI_API_KEY",
    }
    assert set(config.credential_inventory(environment, role="validator")) == {
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
    }
    assert set(config.credential_inventory(environment, role="terminal_reviewer")) == {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "GLM_API_KEY",
        "ZAI_API_KEY",
    }


def test_discovered_configuration_family_parses_policy_once_and_shares_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    fixture_root = tmp_path / "bundled"
    shutil.copytree(source, fixture_root)
    calls: list[Path] = []

    def instrumented_loader(root: Path):
        calls.append(root)
        return load_capability_policy(root)

    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    config = HarnessConfig.discover(
        bundled_dir=fixture_root,
        policy_loader=instrumented_loader,
    )
    store = ProjectStore(config)
    variants = tuple(
        config.for_role(role)
        for role in ("worker", "validator", "terminal_reviewer")
    )

    assert store.config.capability_policy is config.capability_policy
    assert all(variant.capability_policy is config.capability_policy for variant in variants)
    assert calls == [fixture_root]
    config.validate_capability_support()
    assert calls == [fixture_root]
    assert config.credential_inventory({}, role="worker") == {}
    assert calls == [fixture_root]


def test_discovered_configuration_families_isolate_distinct_policy_assets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    roots = (tmp_path / "first", tmp_path / "second")
    for root in roots:
        shutil.copytree(source, root)
    second_policy_path = roots[1] / "policies" / "role-capabilities.v1.json"
    second_policy = json.loads(second_policy_path.read_text(encoding="utf-8"))
    second_policy["profiles"]["safe"]["worker"]["environment"]["forward"] = [
        "PATH"
    ]
    second_policy_path.write_text(
        json.dumps(second_policy, indent=2) + "\n",
        encoding="utf-8",
    )
    calls: list[Path] = []

    def instrumented_loader(root: Path):
        calls.append(root)
        return load_capability_policy(root)

    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    configs = tuple(
        HarnessConfig.discover(bundled_dir=root, policy_loader=instrumented_loader)
        for root in roots
    )

    assert calls == list(roots)
    assert configs[0].capability_policy is not configs[1].capability_policy
    assert configs[0].capability_policy != configs[1].capability_policy
    assert "LANG" in configs[0].capability_policy.role(
        "safe", "worker"
    ).environment.forward
    assert configs[1].capability_policy.role("safe", "worker").environment.forward == (
        "PATH",
    )
    replaced_family = replace(configs[0], bundled_dir=roots[1])
    assert replaced_family.capability_policy is not configs[0].capability_policy
    assert replaced_family.capability_policy == configs[1].capability_policy
