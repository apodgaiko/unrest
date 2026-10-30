"""Pinned original pytest cases and their privileged source callers."""
from __future__ import annotations

import sys

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from content_manifest import Refused, refuse_if
from case_inventory import identity


class OriginalCases:
    normal_outcomes = False
    def __init__(self, policy):
        self.policy, self.items, self.reports, self.completed = policy, (), {}, []
        self.cases = tuple(policy.profile['cases'])

    def pytest_collection_finish(self, session):
        items = tuple(session.items)
        refuse_if(tuple(identity(item.nodeid) for item in items) != tuple(identity(node) for node in self.cases) or any(type(item) not in (Coroutine, Function) for item in items), 'root exact original collection')
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
        from cleanup_launch import ALL_CASES as CLEANUP_CASES
        self.policy.client.seconds=8 if case in CLEANUP_CASES else 4
        self.policy.case=case
        self.policy.client.request('case-start',{'case':case})

    def leave(self,case,outcome,phases):
        from git_policy import FIXTURE_SERVER_INQUIRY as SERVER_INQUIRY
        owned=[row['process'] for row in self.policy.children.values() if row['case']==case and row.get('wait_at_case_close') is True]
        if case==SERVER_INQUIRY and len(owned)!=1:
            raise Refused('source queued fixture actual parent completion')
        for child in owned:
            code=child.wait(timeout=5)
            if case==SERVER_INQUIRY and code!=0:
                raise Refused('source queued fixture actual parent completion')
        payload={'case':case,'outcome':outcome,'phases':phases} if self.normal_outcomes else {'case':case}
        self.policy.client.request('case-finish',payload)
        self.policy.case=None
        self.policy.client.seconds=4

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
            refuse_if(self.policy.poison, 'full source forbidden effect')
        elif not passed:
            raise Refused('root original assertions or cleanup failed')
        self.leave(case,'skipped' if skipped else 'passed' if passed else 'failed',phases)
        self.completed.append(case)

    def pytest_runtest_logreport(self, report):
        self.record(report,identity(report.nodeid))

    def record(self, report, case):
        refuse_if(case not in self.cases or report.when not in ('setup', 'call', 'teardown'), 'root unknown test report')
        phases = self.reports.setdefault(case, {})
        refuse_if(report.when in phases, 'root duplicate test phase')
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
