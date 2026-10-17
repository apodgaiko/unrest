"""Public release identity must remain exact across source carriers."""

from __future__ import annotations

from importlib.metadata import version as installed_version
from pathlib import Path
import tomllib

import yaml

from unrest_harness import __version__


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.4.6"


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
    assert "unrest_harness-0.4.6-py3-none-any.whl" in ci
    assert "unrest_harness-0.4.6.tar.gz" in ci
    assert "name: unrest-v0.4.6-python313" in ci
    assert "unrest_harness-0.2.0" not in ci


def test_acp_handshakes_derive_the_public_runtime_version() -> None:
    source = (ROOT / "src/unrest_harness/acp_runner.py").read_text(encoding="utf-8")

    assert source.count('"clientInfo": {"name": "unrest", "version": __version__}') == 2
    assert '"version": "0.1.0"' not in source


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
        "docs/release/lean-core-v0.4.6.md",
        "docs/architecture/experimental-cohort.md",
        "docs/architecture/experimental-lease.md",
        "docs/architecture/approval-recovery.md",
        "tools/V046_DESKTOP.md",
    ):
        text = " ".join((ROOT / relative).read_text().split()).lower()
        assert "unverified" in text, relative
        assert "default" in text, relative
        assert "timing" in text, relative
