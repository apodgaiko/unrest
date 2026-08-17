"""Immutable package scenarios characterized at the fixed reference."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

import pytest


SCENARIOS = (
    (
        "VAL-PACKAGE-001",
        "packaged-policy-is-versioned-and-loadable",
        "local::archive-rejects-deleted-product-surface",
    ),
    (
        "VAL-PACKAGE-002",
        "safe-init-never-persists-credential-values",
        "tests/test_capability_policy.py::test_cli_safe_init_round_trips_policy_and_never_persists_secrets",
    ),
    (
        "VAL-PACKAGE-003",
        "installed-lifecycle-restarts-and-persists",
        "local::installed-lifecycle-rejects-missing-restart-evidence",
    ),
    (
        "VAL-PACKAGE-004",
        "redacted-handoff-restart-keeps-sentinel-out",
        "tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring",
    ),
)

ASSERTION_TO_SCENARIOS = {
    assertion_id: (scenario_id,) for assertion_id, scenario_id, _ in SCENARIOS
}


def _assert_lean_archive(
    wheel_members: tuple[str, ...],
    sdist_members: tuple[str, ...],
) -> None:
    forbidden = (
        "baseline.py",
        "governance.py",
        "schemas/",
        "capability_closed_model",
        "capability-security-model",
    )
    hits = sorted(
        f"{archive}:{name}"
        for archive, members in (
            ("wheel", wheel_members),
            ("sdist", sdist_members),
        )
        for name in members
        if any(fragment in name.lower() for fragment in forbidden)
    )
    if hits:
        raise AssertionError(f"deleted product surface packaged: {hits}")


def _assert_complete_installed_lifecycle(observation: dict[str, object]) -> None:
    result = observation["lifecycle"]
    assert isinstance(result, dict)
    expected = {
        "state": "done",
        "restart_resume": True,
        "attempts": 2,
        "terminal_reviews": 1,
    }
    mismatches = {
        key: (expected_value, result.get(key))
        for key, expected_value in expected.items()
        if result.get(key) != expected_value
    }
    if mismatches:
        raise AssertionError(f"incomplete installed lifecycle: {mismatches}")
    if observation.get("corrupt_restart_error") is None:
        raise AssertionError("installed restart accepted a corrupted real state cursor")
    module_path = Path(str(observation["module"])).resolve()
    checkout = Path(str(observation["checkout"])).resolve()
    if checkout in module_path.parents:
        raise AssertionError(f"installed lifecycle imported source checkout: {module_path}")
    raw_sys_path = observation["sys_path"]
    assert isinstance(raw_sys_path, list)
    sys_path = tuple(Path(path).resolve() for path in raw_sys_path if isinstance(path, str) and path)
    if checkout in sys_path:
        raise AssertionError(f"source checkout present on installed sys.path: {sys_path}")


def _run_installed_lifecycle(built_distribution, repository_root: Path) -> dict[str, object]:
    probe_root = built_distribution.directory / "lifecycle-probe"
    probe_root.mkdir()
    script = r'''
import sys
sys.path[:0] = [sys.argv[3], sys.argv[4]]

import json
import pathlib

import unrest_harness
from unrest_harness.config import HarnessConfig
from unrest_harness.installed_wheel_check import _controller, run_installed_wheel_check

root = pathlib.Path(sys.argv[1])
workspace = root / "workspace"
workspace.mkdir()
discovered = HarnessConfig.discover()
config = HarnessConfig(
    bundled_dir=discovered.bundled_dir,
    harness_home=root / "home",
    projects_dir=root / "home" / "projects",
    orchestrator_provider_name="claude",
    worker_provider_name="claude",
    worker_acp_command=None,
    validator_provider_name=None,
    validator_acp_command=None,
    terminal_reviewer_provider_name=None,
    terminal_reviewer_acp_command=None,
    max_parallel_nodes=1,
)
lifecycle = run_installed_wheel_check()
controller = _controller(config)
started = controller.start_project("installed corruption boundary", str(workspace))
project_id = started.projectId
state_path = controller.store.unrest_runtime_dir(project_id) / "state.json"
tree_before = sorted(
    path.relative_to(config.projects_dir).as_posix()
    for path in config.projects_dir.rglob("*")
)
restarted = _controller(config)
good_state = restarted.store.load_state(project_id)
state_path.write_text('{"state":"corrupt"}\n', encoding="utf-8")
corrupt_restart_error = None
try:
    _controller(config).store.load_state(project_id)
except Exception as exc:
    corrupt_restart_error = f"{type(exc).__name__}:{exc}"
print(json.dumps({
    "lifecycle": lifecycle,
    "module": unrest_harness.__file__,
    "sys_path": sys.path,
    "checkout": sys.argv[2],
    "good_restart_state": good_state.state if good_state else None,
    "corrupt_restart_error": corrupt_restart_error,
    "tree_before_corruption": tree_before,
}, sort_keys=True))
'''
    credential_name = re.compile(
        r"(?:API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)",
        re.IGNORECASE,
    )
    child_env = {
        key: value
        for key, value in os.environ.items()
        if key != "PYTHONPATH" and not credential_name.search(key)
    }
    completed = subprocess.run(
        [
            str(built_distribution.installed_python),
            "-S",
            "-c",
            script,
            str(probe_root),
            str(repository_root),
            str(built_distribution.installed_site),
            str(built_distribution.dependency_site),
        ],
        cwd=built_distribution.directory,
        env=child_env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout
    return json.loads(completed.stdout.splitlines()[-1])


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
    built_distribution,
    repository_root: Path,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert reference_node in lean_reference_run.nodes
    if reference_node == "local::archive-rejects-deleted-product-surface":
        assert "distribution archives verified" in built_distribution.checker_output
        assert len(built_distribution.wheel_sha256) == 64
        assert len(built_distribution.sdist_sha256) == 64
        _assert_lean_archive(
            built_distribution.wheel_members,
            built_distribution.sdist_members,
        )
    elif reference_node == (
        "local::installed-lifecycle-rejects-missing-restart-evidence"
    ):
        observation = _run_installed_lifecycle(built_distribution, repository_root)
        _assert_complete_installed_lifecycle(observation)
        assert observation["good_restart_state"] == "mission_planning"
        raw_tree = observation["tree_before_corruption"]
        assert isinstance(raw_tree, list)
        assert any(
            path.endswith(".unrest-runtime/state.json")
            for path in raw_tree
            if isinstance(path, str)
        )
    assert lean_reference_run.returncode == 0, lean_reference_run.output
