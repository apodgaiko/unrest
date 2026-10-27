"""Pinned original pytest cases and their privileged source callers."""
from __future__ import annotations

from dataclasses import replace
import importlib
from pathlib import Path
import sys
from typing import cast

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from bootstrap_cases import declaration
from bootstrap_configuration import Binding
from content_manifest import Refused
from controlled_startup import SESSION, SESSION_PIN, TEST, TEST_PIN, Startup, dictionary
from source_owner import Link, active_frames
from source_calls import TestSources, nested_signal


class BootstrapCalls(TestSources):
    def method(self, unit, module, cls, type_name, method):
        function = vars(cls)[method]
        return self.owner(unit, module, function, type_name + '.' + method,
                          (*self.startup.links, Link(module, type_name, cls), Link(cls, method, function)))

    def listener(self):
        frames = active_frames()
        try:
            matches = [(name, owner, frame) for name, owner, lines in self.listeners for frame in frames
                       if frame.f_code is owner.function.__code__ and lines[0] <= frame.f_lineno <= lines[1]]
            if len(matches) != 1:
                raise Refused('root original listener callsite')
            name, owner, frame = matches[0]
            owner.verify(frame)
            instance = frame.f_locals.get('self')
            if name == 'bridge':
                if type(instance) is not self.startup.bridge:
                    raise Refused('root original bridge type')
            else:
                if type(instance) not in (self.startup.synthetic, self.startup.base):
                    raise Refused('root original session type')
                values = dictionary(instance, self.startup.base)
                root = values.get('root')
                if (type(root) is not type(Path('/')) or not cast(Path, root).is_relative_to(Path(self.profile['owned']))
                        or values.get('controlled') is not True
                        or not declaration(self.policy.case).configured and values.get('provider_config') is not None
                        or type(values.get('transport')) is not self.startup.transport):
                    raise Refused('root owned controlled listener')
                if declaration(self.policy.case).configured:
                    self.startup.configuration.check(values.get('provider_config'), root, self.policy.case)
            nonce = None
            if name == 'bridge':
                nonce = dictionary(instance, self.startup.bridge).get('nonce')
            elif name == 'lifetime':
                lifetime = frame.f_locals.get('lifetime')
                if type(lifetime) is not self.startup.lifetime:
                    raise Refused('root original lifetime instance')
                nonce = dictionary(lifetime, self.startup.lifetime).get('nonce')
            if name != 'broker' and (type(nonce) is not str or len(nonce) != 64
                    or any(char not in '0123456789abcdef' for char in nonce)):
                raise Refused('root listener application nonce')
            return {'tag': name, 'nonce': nonce}
        finally:
            del frames

    def __init__(self, policy, item):
        super().__init__(policy, item, TEST, {SESSION: SESSION_PIN, TEST: TEST_PIN})
        checkout = Path(self.profile['checkout'])
        self.session = importlib.import_module('unrest_harness.experimental_session')
        self.session_unit = self.unit(SESSION, self.session, self.mode(self.session))
        self.startup = Startup(self.session, self.tests, self.session_unit, self.test_unit,
            checkout, Path(self.profile['owned']), Path(self.profile['native']), self.profile['native_sha256'],
            configuration_binding=Binding(checkout) if declaration(item.nodeid).configured else None)
        relay = importlib.import_module('unrest_harness.experimental_relay')
        relay_unit = self.unit('src/unrest_harness/experimental_relay.py', relay, self.mode(relay))
        base = self.startup.base
        self.listeners = (
            ('broker', self.method(self.session_unit, self.session, base, '_SessionOwner', 'start'), (378, 378)),
            ('lifetime', self.method(self.session_unit, self.session, base, '_SessionOwner', '_open_role_owned'), (500, 500)),
            ('bridge', self.method(relay_unit, relay, self.startup.bridge, 'Bridge', 'start'), (192, 193)))
        acp = importlib.import_module('unrest_harness.acp_runner')
        acp_unit = self.unit('src/unrest_harness/acp_runner.py', acp, self.mode(acp))
        self.acp_cleanup(acp, acp_unit)
        self.cleanup = (self.method(self.session_unit, self.session, base, '_SessionOwner', '_reap'), *self.cleanup)



class OrdinaryCalls(TestSources):
    def __init__(self, policy, item):
        from ordinary_acp import Ordinary, PINS, TEST as ORDINARY_TEST
        super().__init__(policy, item, ORDINARY_TEST, PINS)
        self.startup = Ordinary(self)
        acp = self.startup.module
        unit = self.startup.unit
        self.acp_cleanup(acp, unit)
        from ordinary_acp import CASES as ORDINARY_CASES
        if item.nodeid == ORDINARY_CASES[2]:
            cls = acp.ACPNodeRunner
            function = vars(cls)['run_node']
            owner = self.owner(unit, acp, function, 'ACPNodeRunner.run_node',
                               (Link(acp, 'ACPNodeRunner', cls), Link(cls, 'run_node', function)))
            self.cleanup = (*self.cleanup, replace(owner, call_lines=(1584, 1584)))

    def signal(self, pid, sig, group):
        return nested_signal(self, pid, sig, group)

    def listener(self):
        raise Refused('ordinary slice has no TCP listener')


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
        from ordinary_acp import ALL_CASES as ORDINARY_CASES
        from cleanup_launch import EXECUTION_CASES as CLEANUP_CASES
        from cleanup_effects import CleanupCalls
        from cleanup_inline import NO_LAUNCH, DECLARATIONS
        from fixed_inline import FixedCalls, CASES as FIXED_CASES
        from session_calls import SessionCalls
        from session_launch import CASES as SESSION_CASES
        from git_source import GitCalls
        from git_sites import CASES as GIT_CASES
        cls = FixedCalls if item.nodeid in FIXED_CASES else SessionCalls if item.nodeid in SESSION_CASES else GitCalls if item.nodeid in GIT_CASES else CleanupCalls if item.nodeid in (*CLEANUP_CASES, *NO_LAUNCH, *DECLARATIONS) else OrdinaryCalls if item.nodeid in ORDINARY_CASES else BootstrapCalls
        policy.case, policy.calls = item.nodeid, cls(policy, item)
        policy.client.request('case-start', {'case': item.nodeid})
        yield
        phases = self.reports.get(item.nodeid, {})
        if phases != {'setup': 'passed', 'call': 'passed', 'teardown': 'passed'}:
            raise Refused('root original assertions or cleanup failed')
        policy.client.request('case-finish', {'case': item.nodeid})
        self.completed.append(item.nodeid)
        policy.case, policy.calls = None, None

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
    plugin = OriginalCases(policy)
    code = pytest.main(['-q', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock',
                       '--basetemp', str(Path(policy.profile['owned']) / 'pytest'), '-o',
                       'cache_dir=' + str(Path(policy.profile['owned']) / 'pytest-cache'), *policy.profile['cases']], plugins=[plugin])
    if code != 0 or plugin.completed != policy.profile['cases'] or policy.poison:
        raise Refused('root original source cases failed')
    from source_profile import case_seal
    policy.client.request('root-finish', case_seal(plugin.completed))
    return 0
