"""Provider-independent lifecycle exercised by the installed-wheel CI gate."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from unrest_harness import installed_wheel_check as checker
from unrest_harness.installed_wheel_check import run_installed_wheel_check


def test_installed_wheel_check_covers_restart_and_persistence() -> None:
    result = run_installed_wheel_check()

    assert result["state"] == "done"
    assert result["restart_resume"] is True
    assert result["attempts"] == 2
    assert result["terminal_reviews"] == 1


def test_owned_temporary_root_alias_is_canonical_before_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "temporary"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(alias))
    original = checker._controller
    roots: list[Path] = []

    def controller(config):
        assert config.harness_home == config.harness_home.resolve()
        assert config.projects_dir == config.projects_dir.resolve()
        roots.append(config.harness_home.parent)
        return original(config)

    monkeypatch.setattr(checker, "_controller", controller)
    result = run_installed_wheel_check()

    assert result["state"] == "done"
    assert result["restart_resume"] is True
    assert result["attempts"] == 2
    assert result["terminal_reviews"] == 1
    assert len(roots) == 3
    assert all(root.parent == target.resolve() for root in roots)
    assert all(not root.exists() for root in roots)
    assert alias.is_symlink()
    assert list(target.iterdir()) == []
