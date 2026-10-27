"""Pinned original pytest cases and their privileged source callers."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import importlib
from pathlib import Path
import sys
import types
from typing import cast

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from bootstrap_cases import declaration
from bootstrap_configuration import Binding
from content_manifest import Refused
from controlled_startup import SESSION, SESSION_PIN, TEST, TEST_PIN, Startup, dictionary
from source_owner import Link, active_frames
from source_calls import Sources, nested_signal


class BootstrapCalls(Sources):
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
        super().__init__(policy, item)
        checkout = Path(self.profile['checkout'])
        if self.pins[SESSION] != SESSION_PIN or self.pins[TEST] != TEST_PIN:
            raise Refused('root original bootstrap files')
        self.session = importlib.import_module('unrest_harness.experimental_session')
        self.tests = item.module
        if type(self.tests) is not types.ModuleType or self.tests.__name__ != 'tests.test_experimental_bootstrap':
            raise Refused('root original test module')
        self.session_unit = self.unit(SESSION, self.session, self.mode(self.session))
        self.test_unit = self.unit(TEST, self.tests, 'pytest')
        self.startup = Startup(self.session, self.tests, self.session_unit, self.test_unit,
            checkout, Path(self.profile['owned']), Path(self.profile['native']), self.profile['native_sha256'],
            configuration_binding=Binding(checkout) if declaration(item.nodeid).configured else None)
        self.test_owner = self.owner(self.test_unit, self.tests, item.obj, item.originalname,
                                     (Link(self.tests, item.originalname, item.obj),))
        self.test_owner.verify_binding()
        relay = importlib.import_module('unrest_harness.experimental_relay')
        relay_unit = self.unit('src/unrest_harness/experimental_relay.py', relay, self.mode(relay))
        base = self.startup.base
        self.listeners = (
            ('broker', self.method(self.session_unit, self.session, base, '_SessionOwner', 'start'), (378, 378)),
            ('lifetime', self.method(self.session_unit, self.session, base, '_SessionOwner', '_open_role_owned'), (500, 500)),
            ('bridge', self.method(relay_unit, relay, self.startup.bridge, 'Bridge', 'start'), (192, 193)))
        acp = importlib.import_module('unrest_harness.acp_runner')
        acp_unit = self.unit('src/unrest_harness/acp_runner.py', acp, self.mode(acp))
        self.cleanup = (
            self.method(self.session_unit, self.session, base, '_SessionOwner', '_reap'),
            self.owner(acp_unit, acp, acp._close_subprocess, '_close_subprocess', (Link(acp, '_close_subprocess', acp._close_subprocess),)),
            self.owner(acp_unit, acp, acp._wait_for_process_exit, '_wait_for_process_exit', (Link(acp, '_wait_for_process_exit', acp._wait_for_process_exit),)))
        self.process_class = asyncio.subprocess.Process
        self.transport_class = vars(importlib.import_module('asyncio.unix_events'))['_UnixSubprocessTransport']



class OrdinaryCalls(Sources):
    def __init__(self, policy, item):
        from ordinary_acp import Ordinary, PINS, TEST as ORDINARY_TEST
        super().__init__(policy, item)
        if any(self.pins[name] != pin for name, pin in PINS.items()):
            raise Refused('ordinary original source bytes')
        self.tests = item.module
        if type(self.tests) is not types.ModuleType or self.tests.__name__ != 'tests.test_acp_runner':
            raise Refused('ordinary original test module')
        self.test_unit = self.unit(ORDINARY_TEST, self.tests, 'pytest')
        self.test_owner = self.owner(self.test_unit, self.tests, item.obj, item.originalname,
                                    (Link(self.tests, item.originalname, item.obj),))
        self.test_owner.verify_binding()
        self.startup = Ordinary(self)
        acp = self.startup.module
        unit = self.startup.unit
        self.cleanup = tuple(self.owner(unit, acp, vars(acp)[name], name,
                             (Link(acp, name, vars(acp)[name]),))
                             for name in ('_close_subprocess', '_wait_for_process_exit'))
        from ordinary_acp import CASES as ORDINARY_CASES
        if item.nodeid == ORDINARY_CASES[2]:
            cls = acp.ACPNodeRunner
            function = vars(cls)['run_node']
            owner = self.owner(unit, acp, function, 'ACPNodeRunner.run_node',
                               (Link(acp, 'ACPNodeRunner', cls), Link(cls, 'run_node', function)))
            self.cleanup = (*self.cleanup, replace(owner, call_lines=(1584, 1584)))
        self.process_class = asyncio.subprocess.Process
        self.transport_class = vars(importlib.import_module('asyncio.unix_events'))['_UnixSubprocessTransport']

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
        from cleanup_launch import ALL_CASES as CLEANUP_CASES
        from cleanup_effects import CleanupCalls
        from cleanup_inline import NO_LAUNCH
        cls = CleanupCalls if item.nodeid in (*CLEANUP_CASES, *NO_LAUNCH) else OrdinaryCalls if item.nodeid in ORDINARY_CASES else BootstrapCalls
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
    policy.client.request('root-finish', {'cases': list(plugin.completed)})
    return 0
