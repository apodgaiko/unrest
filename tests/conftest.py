"""Shared test fixtures for v5."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def harness_home(tmp_path: Path) -> Path:
    home = tmp_path / ".unrest"
    home.mkdir()
    return home


@pytest.fixture
def contract_dir(workspace: Path) -> Path:
    d = workspace / ".unrest" / "missions" / "mission-001" / "contract"
    d.mkdir(parents=True)
    return d
