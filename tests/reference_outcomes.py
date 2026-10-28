"""Bind contract crosswalks to complete, actual outcomes in this pytest session."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import pytest


class ReferenceRunError(AssertionError):
    """A required reference was absent, incomplete, or unsuccessful."""


def includes(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent + "::") or child.startswith(parent + "[") or child.startswith(parent.rstrip("/") + "/")


@dataclass(frozen=True)
class ReferenceSelection:
    nodes: frozenset[str]
    binder: ReferenceOutcomes

    def require_passed(self) -> None:
        self.binder.require(self.nodes)


class ReferenceOutcomes:
    def __init__(self) -> None:
        self.required: dict[str, tuple[str, ...]] = {}
        self.reports: dict[str, dict[str, bool]] = {}
        self.errors: list[str] = []
        self.failure: str | None = None

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, session, config, items):
        inventory = tuple(item.nodeid for item in items)
        yield
        modules = {item.module for item in items if "tests/contracts/" in item.nodeid}
        selectors = sorted({row[2] for module in modules for row in getattr(module, "SCENARIOS", ()) if not row[2].startswith("local::")})
        arguments = []
        for arg in config.args:
            path, *parts = arg.split("::")
            try:
                relative = Path(path).resolve().relative_to(config.rootpath).as_posix()
            except ValueError:
                continue
            arguments.append("::".join((relative, *parts)))
        for selector in selectors:
            matched = tuple(node for node in inventory if includes(selector, node))
            self.required[selector] = matched
            if (not matched or len(set(matched)) != len(matched)
                    or not any(includes(arg, selector) or arg == "." for arg in arguments)
                    or re.search(r"(?:^|[_-])(smoke|live)(?:[_-]|$)", selector)):
                self.errors.append(f"incomplete or forbidden reference selection: {selector}")
        selected = [item.nodeid for item in items]
        for selector, matched in self.required.items():
            if any(selected.count(node) != 1 for node in matched):
                self.errors.append(f"deselected or duplicate reference: {selector}")
        # All references finish before their crosswalk consumers, preserving each order.
        items.sort(key=lambda item: "tests/contracts/" in item.nodeid)

    def pytest_runtest_logreport(self, report):
        if not any(report.nodeid in nodes for nodes in self.required.values()):
            return
        phases = self.reports.setdefault(report.nodeid, {})
        if report.when in phases:
            self.errors.append(f"duplicate reference phase: {report.nodeid}:{report.when}")
        phases[report.when] = report.passed and not hasattr(report, "wasxfail")

    def require(self, selectors) -> None:
        errors = list(self.errors)
        for selector in selectors:
            if selector.startswith("local::"):
                continue
            nodes = self.required.get(selector, ())
            if not nodes:
                errors.append(f"missing reference: {selector}")
            for node in nodes:
                if self.reports.get(node) != {"setup": True, "call": True, "teardown": True}:
                    errors.append(f"reference did not pass every phase: {node}")
        if errors:
            raise ReferenceRunError("\n".join(errors))

    def pytest_sessionfinish(self, session, exitstatus):
        if session.config.option.collectonly:
            return
        try:
            self.require(self.required)
        except ReferenceRunError as exc:
            self.failure = str(exc)
            if session.exitstatus == 0:
                session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter):
        if self.failure:
            terminalreporter.section("incomplete contract references", red=True)
            terminalreporter.write_line(self.failure)
