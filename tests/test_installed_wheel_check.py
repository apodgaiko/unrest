"""Provider-independent lifecycle exercised by the installed-wheel CI gate."""
from __future__ import annotations

from unrest_harness.installed_wheel_check import run_installed_wheel_check


def test_installed_wheel_check_covers_restart_and_persistence() -> None:
    result = run_installed_wheel_check()

    assert result["state"] == "done"
    assert result["restart_resume"] is True
    assert result["attempts"] == 2
    assert result["terminal_reviews"] == 1
