"""Pinned original pytest cases and their privileged source callers."""
from __future__ import annotations

import signal
from pathlib import Path
import sys

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from preflight_cases import CASES as PREFLIGHT_ALL
from controlled_cases import ROOT_HTTP
from content_manifest import Refused


USER_SIGNAL = int(signal.SIGUSR1)









class OriginalCases:
    def __init__(self, policy):
        self.policy, self.items, self.reports, self.completed = policy, (), {}, []
        self.cases = tuple(policy.profile['cases'])

    def pytest_collection_finish(self, session):
        items = tuple(session.items)
        if tuple(item.nodeid for item in items) != self.cases or any(type(item) not in (Coroutine, Function) for item in items):
            raise Refused('root exact original collection')
        self.items = items

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        index = len(self.completed)
        if index >= len(self.cases) or not self.items or item is not self.items[index] or item.nodeid != self.cases[index]:
            raise Refused('root original case cursor')
        policy = self.policy
        policy.case = item.nodeid
        policy.client.request('case-start', {'case': item.nodeid})
        yield
        phases = self.reports.get(item.nodeid, {})
        if phases != {'setup': 'passed', 'call': 'passed', 'teardown': 'passed'}:
            raise Refused('root original assertions or cleanup failed')
        if item.nodeid in ROOT_HTTP:
            policy.calls.http.finish()
        policy.client.request('case-finish', {'case': item.nodeid})
        self.completed.append(item.nodeid)
        policy.case = None

    def pytest_runtest_logreport(self, report):
        if report.nodeid not in self.cases or report.when not in ('setup', 'call', 'teardown'):
            raise Refused('root unknown test report')
        phases = self.reports.setdefault(report.nodeid, {})
        if report.when in phases:
            raise Refused('root duplicate test phase')
        phases[report.when] = report.outcome
        if report.failed:
            # Preserve the initiating failure even when protocol finalization
            # correctly refuses; this stream is private and byte bounded.
            sys.stderr.write(report.longreprtext + '\n')
            for label, content in report.sections:
                sys.stderr.write(label + '\n' + content + '\n')


def main():
    from source_entry import ACTIVE
    policy = ACTIVE
    if policy is None or policy.profile['role'] != 'root':
        raise Refused('root native activation absent')
    policy.calls.install()
    plugin = OriginalCases(policy)
    from postbuild_root import CASES as ARCHIVE_CASES, run as archive_run
    if tuple(policy.profile['cases'])==ARCHIVE_CASES:
        return archive_run(policy,plugin)
    code = pytest.main(['-q', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock',
                       '--basetemp', str(Path(policy.profile['owned']) / 'pytest'), '-o',
                       'cache_dir=' + str(Path(policy.profile['owned']) / 'pytest-cache'), *(['tests/test_launch_preflight.py'] if tuple(policy.profile['cases']) == PREFLIGHT_ALL else policy.profile['cases'])], plugins=[plugin])
    if code != 0 or plugin.completed != policy.profile['cases'] or policy.poison:
        raise Refused('root original source cases failed')
    from source_profile import case_seal
    policy.client.request('root-finish', case_seal(plugin.completed))
    return 0
