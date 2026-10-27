"""Original root cleanup callers and the worker's sole completion Git query."""
from __future__ import annotations

import asyncio
import asyncio.unix_events
from dataclasses import replace
from pathlib import Path
import types

from cleanup_launch import CASES, Launches, PINS, SERVER, TEST, base_path, expected, sys_module, translated
from content_manifest import Refused
from controlled_startup import Intent
from launch_policy import Observation, match
from source_calls import Sources, nested_signal
from source_owner import Link, active_frames


class CleanupCalls(Sources):
    def __init__(self, policy, item):
        super().__init__(policy, item)
        if any(self.pins[name] != pin for name, pin in PINS.items()):
            raise Refused('cleanup original source bytes')
        self.tests = item.module
        if type(self.tests) is not types.ModuleType or self.tests.__name__ != 'tests.test_acp_cleanup':
            raise Refused('cleanup original test module')
        self.test_unit = self.unit(TEST, self.tests, 'pytest')
        self.test_owner = self.owner(self.test_unit, self.tests, item.obj, item.originalname,
                                    (Link(self.tests, item.originalname, item.obj),))
        self.test_owner.verify_binding()
        self.startup = Launches(self)
        module, unit = self.startup.module, self.startup.unit
        cls = module.ACPNodeRunner
        self.cleanup = tuple(self.owner(unit, module, vars(module)[name], name,
                                        (Link(module, name, vars(module)[name]),))
                             for name in ('_close_subprocess', '_wait_for_process_exit'))
        function = vars(cls)['run_node']
        owner = self.owner(unit, module, function, 'ACPNodeRunner.run_node',
                           (Link(module, 'ACPNodeRunner', cls), Link(cls, 'run_node', function)))
        self.cleanup = (*self.cleanup, replace(owner, call_lines=(1584, 1584)))
        self.process_class = asyncio.subprocess.Process
        self.transport_class = vars(asyncio.unix_events)['_UnixSubprocessTransport']
        static = vars(cls)['_find_free_port']
        if type(static) is not staticmethod:
            raise Refused('cleanup original free port descriptor')
        function = static.__func__
        self.probe = self.owner(unit, module, function, 'ACPNodeRunner._find_free_port',
            (Link(cls, '_find_free_port', static), Link(static, '__func__', function, 'static-function')))
        function = vars(cls)['_wait_for_server_ready']
        self.readiness = self.owner(unit, module, function, 'ACPNodeRunner._wait_for_server_ready',
                                   (Link(cls, '_wait_for_server_ready', function),))

    def signal(self, pid, sig, group):
        # Reuse the original nested finalizer binding; it adds no group right.
        return nested_signal(self, pid, sig, group)

    def listener(self):
        frames = active_frames()
        try:
            matches = [frame for frame in frames if frame.f_code is self.probe.function.__code__]
            if len(matches) != 1 or matches[0].f_lineno != 1317:
                raise Refused('cleanup original free port probe')
            self.probe.verify(matches[0])
            return {'tag': 'mcp-probe', 'nonce': None}
        finally:
            del frames

    def connection(self, port):
        frames = active_frames()
        try:
            matches = [frame for frame in frames if frame.f_code is self.readiness.function.__code__]
            if len(matches) != 1:
                raise Refused('cleanup original readiness connection')
            frame = matches[0]
            self.readiness.verify(frame)
            if type(frame.f_locals.get('port')) is not int or frame.f_locals['port'] != port:
                raise Refused('cleanup original readiness port')
            process = frame.f_locals.get('process')
            if type(process) is not self.process_class:
                raise Refused('cleanup readiness child type')
            transport = vars(process).get('_transport')
            if type(transport) is not self.transport_class:
                raise Refused('cleanup readiness transport type')
            values = vars(transport)
            pid = values.get('_pid')
            if type(pid) is not int or pid not in self.policy.children or values.get('_proc') is not self.policy.children[pid]['process']:
                raise Refused('cleanup readiness owned child')
        finally:
            del frames


class ModuleCalls(Sources):
    def __init__(self, policy, item):
        super().__init__(policy, item)
        if any(self.pins[name] != pin for name, pin in PINS.items()):
            raise Refused('cleanup module source bytes')
        self.startup = self

    def select(self, case, audit):
        if case not in CASES[:2]:
            raise Refused('cleanup no completion query case')
        executable, vector, cwd, env = audit
        module = sys_module('unrest_harness.server')
        unit = self.unit(SERVER, module, self.mode(module))
        function = vars(module)['_completion_context']
        owner = self.owner(unit, module, function, '_completion_context',
                           (Link(module, '_completion_context', function),))
        frames = active_frames()
        try:
            matches = [frame for frame in frames if frame.f_code is function.__code__ and frame.f_globals is vars(module)]
            if len(matches) != 1 or matches[0].f_lineno != 266:
                raise Refused('cleanup original completion query')
            owner.verify(matches[0])
            if (executable != 'git' or type(vector) is not list or vector != ['git', 'rev-parse', 'HEAD']
                    or type(cwd) is not type(Path('/')) or env is not None):
                raise Refused('cleanup original Git query operands')
            base = base_path(str(cwd.parent), Path(self.profile['owned']))
            result = expected(case, 'git-observe', base, self.profile['native'], self.profile['native_sha256'],
                Path(self.profile['checkout']), self.profile['environment'])
            import os
            observation = Observation(result.executable, result.executable_sha256, tuple(vector),
                tuple(sorted(dict(os.environ).items())), str(cwd), 'native', result.payload_sha256)
            match((result,), observation, result.owner, case)
            return Intent(result, translated(result, self.policy.directory), 266, result.payload_sha256)
        finally:
            del frames

    def signal(self, *args):
        raise Refused('cleanup module has no child signal route')
