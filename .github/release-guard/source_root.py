"""The exact original original-bootstrap pytest root and its live privileged callers."""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
from typing import Any, cast

import pytest
from pytest_asyncio.plugin import Coroutine
from _pytest.python import Function

from bootstrap_cases import declaration
from bootstrap_configuration import Binding
from content_manifest import Refused
from controlled_startup import SESSION, SESSION_PIN, TEST, TEST_PIN, Startup, dictionary
from control_transport import unique
from source_owner import Link, Owner, active_frames, prepare


class Sources:
    cleanup: Any
    process_class: Any
    transport_class: Any
    def __init__(self, policy, item):
        self.policy, self.profile = policy, policy.profile
        raw = (policy.directory / 'source-manifest.json').read_bytes()
        if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != self.profile['source_sha256']:
            raise Refused('root source manifest reference')
        manifest = json.loads(raw, object_pairs_hook=unique)
        if type(manifest) is not dict or set(manifest) != {'schema', 'files'} or manifest['schema'] != 'unrest.guard-content.v1':
            raise Refused('root source manifest schema')
        self.pins = {row['path']: row['sha256'] for row in manifest['files']}
    @staticmethod
    def mode(module):
        loader = module.__loader__
        if type(loader).__name__ == 'BeartypeSourceFileLoader':
            return 'beartype-passive'  # prepare/Owner enforce exact type and passive fields.
        return 'plain'

    def unit(self, path, module, mode):
        file = Path(self.profile['checkout']) / path
        return prepare(file.read_bytes(), str(file), module.__name__, mode, self.pins[path])

    @staticmethod
    def owner(unit, module, function, qualified, links):
        if type(function) is not types.FunctionType:
            raise Refused('root original caller function')
        codes = [code for code in unit.codes if code.co_qualname == qualified]
        if len(codes) != 1:
            raise Refused('root original lexical function')
        defaults = function.__defaults__
        keywords = function.__kwdefaults__
        if keywords is not None and (type(keywords) is not dict or any(type(key) is not str for key in keywords)):
            raise Refused('root function keyword defaults')
        return Owner(unit, module, function, qualified, codes[0].co_firstlineno, (1, 100000),
                     links, closure=tuple(cell.cell_contents for cell in (function.__closure__ or ())),
                     cell_anchors=function.__closure__ or (), defaults=defaults,
                     keyword_defaults=tuple(sorted((keywords or {}).items())))

    def signal(self, pid, sig, group):
        if type(pid) is not int or pid not in self.policy.children or type(sig) is not int or sig not in (9, 15):
            raise Refused('root owned cleanup signal')
        frames = active_frames()
        try:
            matches = [(owner, frame) for owner in self.cleanup for frame in frames
                       if frame.f_code is owner.function.__code__]
            if not matches:
                raise Refused('root original cleanup caller')
            owner, frame = matches[0]
            owner.verify(frame)
            process = frame.f_locals.get('process')
            if process is None and owner.qualified == 'ACPNodeRunner.run_node.<locals>.finish_mcp':
                process = frame.f_locals.get('mcp_process')
            if type(process) is not self.process_class:
                raise Refused('root original cleanup process type')
            transport = vars(process).get('_transport')
            if type(transport) is not self.transport_class:
                raise Refused('root original cleanup transport type')
            values = vars(transport)
            if (type(values.get('_pid')) is not int or values['_pid'] != pid
                    or values.get('_proc') is not self.policy.children[pid]['process']):
                raise Refused('root original cleanup process generation')
            if group and owner.function.__qualname__ != '_SessionOwner._reap':
                raise Refused('root original group cleanup caller')
        finally:
            del frames


class Calls(Sources):
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
        self.process_class = asyncio.subprocess.Process
        self.transport_class = vars(importlib.import_module('asyncio.unix_events'))['_UnixSubprocessTransport']

    def signal(self, pid, sig, group):
        if group:
            raise Refused('ordinary inherited session has no group authority')
        frames = active_frames()
        try:
            for frame in frames:
                if (frame.f_globals is vars(self.startup.module)
                        and type(frame.f_code.co_qualname) is str
                        and frame.f_code.co_qualname == '_finish_owned_cleanup.<locals>.finish'):
                    step = frame.f_locals.get('step')
                    if type(step) is types.FunctionType and type(step.__qualname__) is str and step.__qualname__ in (
                            'ACPNodeRunner.run_node.<locals>.finish_mcp',
                            'ACPNodeRunner.run_node.<locals>.finish_agent'):
                        owner = self.owner(self.startup.unit, self.startup.module, step, step.__qualname__,
                                           (Link(frame, 'step', step, 'frame'),))
                        self.cleanup = (*self.cleanup, owner)
                        break
            super().signal(pid, sig, group)
        finally:
            # Keep no coroutine/closure frame alive between privileged calls.
            self.cleanup = self.cleanup[:2]
            del frames

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
        from ordinary_acp import CASES as ORDINARY_CASES
        policy.case, policy.calls = item.nodeid, (OrdinaryCalls if item.nodeid in ORDINARY_CASES else Calls)(policy, item)
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
