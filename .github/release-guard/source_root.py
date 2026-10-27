"""The exact original two-case pytest root and its live privileged callers."""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
from typing import cast

import pytest
from pytest_asyncio.plugin import Coroutine

from content_manifest import Refused
from controlled_startup import CASES, SESSION, SESSION_PIN, TEST, TEST_PIN, Startup, dictionary
from control_transport import unique
from source_owner import Link, Owner, active_frames, prepare


class Calls:
    def __init__(self, policy, item):
        self.policy, self.profile = policy, policy.profile
        checkout = Path(self.profile['checkout'])
        raw = (policy.directory / 'source-manifest.json').read_bytes()
        if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != self.profile['source_sha256']:
            raise Refused('root source manifest reference')
        manifest = json.loads(raw, object_pairs_hook=unique)
        if type(manifest) is not dict or set(manifest) != {'schema', 'files'} or manifest['schema'] != 'unrest.guard-content.v1':
            raise Refused('root source manifest schema')
        self.pins = {row['path']: row['sha256'] for row in manifest['files']}
        if self.pins[SESSION] != SESSION_PIN or self.pins[TEST] != TEST_PIN:
            raise Refused('root original bootstrap files')
        self.session = importlib.import_module('unrest_harness.experimental_session')
        self.tests = item.module
        if type(self.tests) is not types.ModuleType or self.tests.__name__ != 'tests.test_experimental_bootstrap':
            raise Refused('root original test module')
        self.session_unit = self.unit(SESSION, self.session, self.mode(self.session))
        self.test_unit = self.unit(TEST, self.tests, 'pytest')
        self.startup = Startup(self.session, self.tests, self.session_unit, self.test_unit,
            checkout, Path(self.profile['owned']), Path(self.profile['native']), self.profile['native_sha256'])
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
                     links, defaults=defaults, keyword_defaults=tuple(sorted((keywords or {}).items())))

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
                if type(instance) is not self.startup.synthetic:
                    raise Refused('root original session type')
                values = dictionary(instance, self.startup.base)
                root = values.get('root')
                if (type(root) is not type(Path('/')) or not cast(Path, root).is_relative_to(Path(self.profile['owned']))
                        or values.get('controlled') is not True or values.get('provider_config') is not None
                        or type(values.get('transport')) is not self.startup.transport):
                    raise Refused('root owned controlled listener')
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


class OriginalCases:
    def __init__(self, policy):
        self.policy, self.items, self.reports, self.completed = policy, (), {}, []

    def pytest_collection_finish(self, session):
        items = tuple(session.items)
        if tuple(item.nodeid for item in items) != CASES or any(type(item) is not Coroutine for item in items):
            raise Refused('root exact original collection')
        self.items = items

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        index = len(self.completed)
        if index >= 2 or not self.items or item is not self.items[index] or item.nodeid != CASES[index]:
            raise Refused('root original case cursor')
        policy = self.policy
        policy.case, policy.calls = item.nodeid, Calls(policy, item)
        policy.client.request('case-start', {'case': item.nodeid})
        yield
        phases = self.reports.get(item.nodeid, {})
        if phases != {'setup': 'passed', 'call': 'passed', 'teardown': 'passed'}:
            raise Refused('root original assertions or cleanup failed')
        policy.client.request('case-finish', {'case': item.nodeid})
        self.completed.append(item.nodeid)
        policy.case, policy.calls = None, None

    def pytest_runtest_logreport(self, report):
        if report.nodeid not in CASES or report.when not in ('setup', 'call', 'teardown'):
            raise Refused('root unknown test report')
        phases = self.reports.setdefault(report.nodeid, {})
        if report.when in phases:
            raise Refused('root duplicate test phase')
        phases[report.when] = report.outcome
        if report.failed:
            # Preserve the initiating failure even when protocol finalization
            # correctly refuses; this stream is private and byte bounded.
            sys.stderr.write(report.longreprtext + '\n')


def main():
    from source_entry import ACTIVE
    policy = ACTIVE
    if policy is None or policy.profile['role'] != 'root':
        raise Refused('root native activation absent')
    plugin = OriginalCases(policy)
    code = pytest.main(['-q', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock',
                       '--basetemp', str(Path(policy.profile['owned']) / 'pytest'), *CASES], plugins=[plugin])
    if code != 0 or tuple(plugin.completed) != CASES or policy.poison:
        raise Refused('root original source cases failed')
    policy.client.request('root-finish', {'cases': list(plugin.completed)})
    return 0
