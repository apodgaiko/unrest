"""Pinned original pytest cases and their privileged source callers."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from preflight_cases import CASES as PREFLIGHT_ALL
from controlled_cases import ROOT_HTTP
from content_manifest import Refused
from case_inventory import identity


class OriginalCases:
    normal_outcomes = False
    def __init__(self, policy):
        self.policy, self.items, self.reports, self.completed = policy, (), {}, []
        self.cases = tuple(policy.profile['cases'])
        self.skips=[]

    def pytest_collection_finish(self, session):
        items = tuple(session.items)
        if tuple(identity(item.nodeid) for item in items) != tuple(identity(node) for node in self.cases) or any(type(item) not in (Coroutine, Function) for item in items):
            raise Refused('root exact original collection')
        self.items = items
        from product_audit import CASES,CHILD_CASES,Order
        if any(case in (*CASES,*CHILD_CASES) for case in self.cases) and getattr(self.policy,'audit_order',None) is None:
            order=Order(self.policy)
            order.install()
            self.policy.audit_order=order

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self,item):
        from speed_inline import CASES
        if item.nodeid in CASES:
            self.policy.client.request('fixture-root',{'path':str(item.funcargs['tmp_path'])})

    def enter(self,case):
        self.policy.case=case
        self.policy.client.request('case-start',{'case':case})

    def leave(self,case,outcome,phases):
        payload={'case':case,'outcome':outcome,'phases':phases} if self.normal_outcomes else {'case':case}
        self.policy.client.request('case-finish',payload)
        self.policy.case=None

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        index=len(self.completed)
        case=identity(item.nodeid)
        if index>=len(self.cases) or not self.items or item is not self.items[index] or case!=self.cases[index]:
            raise Refused('root original case cursor')
        self.enter(case)
        yield
        phases=self.reports.get(case,{})
        skipped=phases in ({'setup':'skipped','teardown':'passed'},{'setup':'passed','call':'skipped','teardown':'passed'})
        passed=phases=={'setup':'passed','call':'passed','teardown':'passed'}
        if self.normal_outcomes:
            if self.policy.poison:
                raise Refused('full source forbidden effect')
            if skipped:
                self.skips.append(case)
        elif not passed:
            raise Refused('root original assertions or cleanup failed')
        if item.nodeid in ROOT_HTTP and passed:
            self.policy.calls.http.finish()
        self.leave(case,'skipped' if skipped else 'passed' if passed else 'failed',phases)
        self.completed.append(case)

    def pytest_runtest_logreport(self, report):
        self.record(report,identity(report.nodeid))

    def record(self, report, case):
        if case not in self.cases or report.when not in ('setup', 'call', 'teardown'):
            raise Refused('root unknown test report')
        phases = self.reports.setdefault(case, {})
        if report.when in phases:
            raise Refused('root duplicate test phase')
        phases[report.when] = report.outcome
        if report.failed:
            # Preserve the initiating failure even when protocol finalization
            # correctly refuses; this stream is private and byte bounded.
            sys.stderr.write(report.longreprtext + '\n')
            for label, content in report.sections:
                sys.stderr.write(label + '\n' + content + '\n')


def local_cases(policy,cases,*,normal_outcomes=False,on_last=None):
    """A local outcome cursor never changes its enclosing actor/case authority."""
    class Leaf(OriginalCases):
        def enter(self,case):
            pass
        def leave(self,case,outcome,phases):
            if on_last is not None and case==self.cases[-1]:
                on_last()
    result=Leaf(policy)
    result.cases=tuple(cases)
    result.normal_outcomes=normal_outcomes
    return result


def main():
    from source_entry import ACTIVE
    policy = ACTIVE
    if policy is None or policy.profile['role'] != 'root':
        raise Refused('root native activation absent')
    policy.calls.install()
    from prepared_distribution import Provider
    from package_cases import CASES as PACKAGE_CASES
    if any(case in PACKAGE_CASES for case in policy.profile['cases']):
        pytest_plugin=Provider(policy)
    else:
        pytest_plugin=None
    plugin = OriginalCases(policy)
    from postbuild_root import CASES as ARCHIVE_CASES, run as archive_run
    if tuple(policy.profile['cases'])==ARCHIVE_CASES:
        return archive_run(policy,plugin)
    from review_wire import CASES as REVIEW_CASES,NODES as REVIEW_NODES
    selected=REVIEW_NODES if tuple(policy.profile['cases'])==REVIEW_CASES else policy.profile['cases']
    if pytest_plugin is not None:
        class PreparedPlugin:
            def pytest_configure(self,config):
                config.pluginmanager.register(pytest_plugin,'release-prepared-distribution')
        prepared_plugin=[PreparedPlugin()]
    else:
        prepared_plugin=[]
    code = pytest.main(['-q', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock',
                       '--basetemp', str(Path(policy.profile['owned']) / 'pytest'), '-o',
                       'cache_dir=' + str(Path(policy.profile['owned']) / 'pytest-cache'), *(['tests/test_launch_preflight.py'] if tuple(policy.profile['cases']) == PREFLIGHT_ALL else selected)], plugins=[plugin,*prepared_plugin])
    if code != 0 or plugin.completed != policy.profile['cases'] or policy.poison:
        raise Refused('root original source cases failed')
    from source_profile import case_seal
    policy.client.request('root-finish', case_seal(plugin.completed))
    return 0
