"""Codex ACP subprocess environment regression tests."""
from __future__ import annotations

import os
from pathlib import Path

from unrest_harness.acp_runner import _acp_subprocess_env
from unrest_harness.providers import PROVIDERS


def test_claude_env_unchanged() -> None:
    env = _acp_subprocess_env(PROVIDERS["claude"])
    assert env.get("PATH", "") == os.environ.get("PATH", "")
    # Claude provider must NOT receive codex-specific hints.
    assert "CODEX_SANDBOX" not in env
    assert "CODEX_DISABLE_SANDBOX" not in env


def test_codex_preserves_path_when_bwrap_is_present(tmp_path: Path, monkeypatch) -> None:
    fake_bwrap_dir = tmp_path / "bwrap-bin"
    fake_bwrap_dir.mkdir()
    (fake_bwrap_dir / "bwrap").write_text("#!/bin/sh\nexit 0\n")
    (fake_bwrap_dir / "bwrap").chmod(0o755)

    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "useful-tool").write_text("#!/bin/sh\nexit 0\n")
    (other_dir / "useful-tool").chmod(0o755)

    new_path = f"{fake_bwrap_dir}{os.pathsep}{other_dir}"
    monkeypatch.setenv("PATH", new_path)

    env = _acp_subprocess_env(PROVIDERS["codex"])
    parts = env["PATH"].split(os.pathsep)
    assert str(fake_bwrap_dir) in parts
    assert str(other_dir) in parts


def test_codex_with_no_bwrap_on_path_unchanged(monkeypatch, tmp_path: Path) -> None:
    only_other = tmp_path / "other"
    only_other.mkdir()
    monkeypatch.setenv("PATH", str(only_other))
    env = _acp_subprocess_env(PROVIDERS["codex"])
    assert env["PATH"] == str(only_other)


def test_codex_sets_env_var_hints() -> None:
    """Belt-and-suspenders hints: codex versions that respect either env
    var will skip bwrap regardless of PATH state.
    """
    env = _acp_subprocess_env(PROVIDERS["codex"])
    assert env.get("CODEX_SANDBOX") == "danger-full-access"
    assert env.get("CODEX_DISABLE_SANDBOX") == "1"
