"""Public release identity must remain exact across source carriers."""

from __future__ import annotations

from importlib.metadata import version as installed_version
from pathlib import Path
import tomllib
import sys

import pytest
import yaml

from unrest_harness import __version__


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.4.7"


def test_public_release_identity_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    locked_project = next(
        package for package in lock["package"] if package["name"] == "unrest-harness"
    )

    assert project["project"]["version"] == EXPECTED_VERSION
    assert locked_project["version"] == EXPECTED_VERSION
    assert citation["version"] == EXPECTED_VERSION
    assert __version__ == EXPECTED_VERSION
    assert installed_version("unrest-harness") == EXPECTED_VERSION

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "unrest_harness-0.4.7-py3-none-any.whl" in ci
    assert "unrest_harness-0.4.7.tar.gz" in ci
    assert "name: unrest-v0.4.7-python313" in ci
    assert "unrest_harness-0.2.0" not in ci


@pytest.mark.parametrize("role", ["work", "validate", "terminal_reviewer"])
async def test_acp_handshakes_derive_the_public_runtime_version(tmp_path, monkeypatch, role):
    from dataclasses import replace
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from unrest_harness import acp_runner
    from unrest_harness.assets import AssetLoader
    from unrest_harness.models import Task
    from tests.test_provider_review import controller_fixture

    _, store, _ = controller_fixture(tmp_path)
    config = replace(store.config, worker_acp_command=sys.executable,
                     validator_acp_command=sys.executable,
                     terminal_reviewer_acp_command=sys.executable)
    runner = acp_runner.ACPNodeRunner(config, AssetLoader(config))
    process = SimpleNamespace(returncode=0, stdin=None, stderr=None,
                              wait=AsyncMock(return_value=0))
    requests = []

    class HandshakeObserved(BaseException):
        pass

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def start(self):
            pass

        async def send_request(self, method, params):
            requests.append((method, params))
            raise HandshakeObserved

        async def cleanup(self, **kwargs):
            pass

    monkeypatch.setattr(runner, "_start_worker_mcp_server", AsyncMock(return_value=process))
    monkeypatch.setattr(runner, "_start_terminal_reviewer_mcp", AsyncMock(return_value=process))
    monkeypatch.setattr(runner, "_find_free_port", lambda: 43210)
    monkeypatch.setattr(runner, "_wait_for_server_ready", AsyncMock())
    monkeypatch.setattr(acp_runner, "spawn_launch", AsyncMock(return_value=process))
    monkeypatch.setattr(acp_runner, "ACPClient", Client)
    monkeypatch.setattr(acp_runner, "__version__", "runtime-version-sentinel")
    with pytest.raises(HandshakeObserved):
        if role == "terminal_reviewer":
            await runner.run_terminal_review("project", "mission-001", "attempt-1", store)
        else:
            await runner.run_node("project", "mission-001", Task(
                id="w1", type=role, body="identity probe", targets=[], skill="s"),
                "attempt-1", store)
    assert len(requests) == 1
    method, params = requests[0]
    assert method == "initialize"
    assert params["clientInfo"] == {"name": "unrest", "version": "runtime-version-sentinel"}


def test_development_identity_comes_from_this_checkout() -> None:
    from importlib.metadata import distribution
    import json
    from urllib.parse import unquote, urlparse

    import unrest_harness

    assert Path(unrest_harness.__file__).resolve() == ROOT / "src/unrest_harness/__init__.py"
    dist = distribution("unrest-harness")
    direct_url_text = dist.read_text("direct_url.json")
    assert direct_url_text is not None
    direct_url = json.loads(direct_url_text)
    assert direct_url["dir_info"]["editable"] is True
    assert Path(unquote(urlparse(direct_url["url"]).path)).resolve() == ROOT
    assert dist.version == __version__ == EXPECTED_VERSION


def test_release_risk_disclosure_matches_help_and_experimental_status() -> None:
    from click.testing import CliRunner

    from unrest_harness.cli import cli
    from unrest_harness.config import HarnessConfig
    from unrest_harness.experimental_cohort import LIMITATIONS
    from unrest_harness.experimental_model import Config

    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    help_text = " ".join(result.output.split())
    assert "disabled by default" in help_text
    assert "Genuine native approval, ACP live reuse and final-candidate timing" in help_text
    assert "UNVERIFIED" in help_text
    assert Config().enabled is False
    assert HarnessConfig.__dataclass_fields__["approval_recovery"].default is False
    assert LIMITATIONS["enabled_by_default"] is False
    for field in ("live_acceptance", "native_approval", "final_candidate_timing"):
        assert LIMITATIONS[field] == "unverified"
    for relative in (
        "README.md",
        "docs/release/lean-core-v0.4.7.md",
        "docs/architecture/experimental-cohort.md",
        "docs/architecture/experimental-lease.md",
        "docs/architecture/approval-recovery.md",
        "tools/V046_DESKTOP.md",
    ):
        text = " ".join((ROOT / relative).read_text().split()).lower()
        assert "unverified" in text, relative
        assert "default" in text, relative
        assert "timing" in text, relative
