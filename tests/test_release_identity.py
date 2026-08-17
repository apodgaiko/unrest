"""Public release identity must remain exact across source carriers."""

from __future__ import annotations

from importlib.metadata import version as installed_version
from pathlib import Path
import tomllib

import yaml

from unrest_harness import __version__


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.2.0"


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


def test_acp_handshakes_derive_the_public_runtime_version() -> None:
    source = (ROOT / "src/unrest_harness/acp_runner.py").read_text(encoding="utf-8")

    assert source.count('"clientInfo": {"name": "unrest", "version": __version__}') == 2
    assert '"version": "0.1.0"' not in source
