"""Original root cleanup callers and the worker's sole completion Git query."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from cleanup_launch import git_completion, Launches, PINS, SERVER, TEST, base_path, expected, sys_module, translated
from content_manifest import Refused
from controlled_startup import Intent
from launch_policy import Observation, match
from source_calls import Sources, TestSources, nested_signal
from source_owner import Link, active_frames, _namespace


class CleanupCalls(TestSources):
    def __init__(self, policy, item):
        super().__init__(policy, item, TEST, PINS)
        from cleanup_inline import STARTUP, DECLARATIONS, Launches as InlineLaunches
        self.startup = InlineLaunches(self) if item.nodeid in DECLARATIONS else Launches(self)
        module, unit = self.startup.module, self.startup.unit
        cls = module.ACPNodeRunner
        self.acp_cleanup(module, unit)
        function = vars(cls)['run_node']
        owner = self.owner(unit, module, function, 'ACPNodeRunner.run_node',
                           (Link(module, 'ACPNodeRunner', cls), Link(cls, 'run_node', function)))
        self.cleanup = (*self.cleanup, replace(owner, call_lines=(1584, 1584)))
        if item.nodeid in STARTUP:
            function = vars(cls)['_close_mcp_process']
            owner = self.owner(unit, module, function, 'ACPNodeRunner._close_mcp_process',
                (Link(module, 'ACPNodeRunner', cls), Link(cls, '_close_mcp_process', function)))
            self.cleanup = (*self.cleanup, replace(owner, call_lines=(1281, 1281)))
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
        from cleanup_inline import CLIENT, INFLIGHT, Launches as InlineLaunches
        base = self.cleanup
        frames = active_frames()
        try:
            if self.policy.case in (*tuple(CLIENT)[1:], *INFLIGHT):
                wrapper = vars(self.startup.module)['_close_subprocess']
                name = self.case_item.originalname + '.<locals>.' + ('close_barrier' if self.policy.case in INFLIGHT else 'faulty_close')
                owner = self.owner(self.test_unit, self.tests, wrapper, name,
                                  (Link(self.startup.module, '_close_subprocess', wrapper),))
                matches = [frame for frame in frames if frame.f_code is wrapper.__code__]
                owner.verify_binding()
                if len(matches) > 1:
                    raise Refused('cleanup original close wrapper frame')
                if matches:
                    owner.verify(matches[0])
                values = dict(zip(wrapper.__code__.co_freevars, owner.closure, strict=True))
                if values.get('close') is not base[0].function:
                    raise Refused('cleanup original retained close')
                if type(self.startup) is not InlineLaunches:
                    raise Refused('cleanup original inline adapter')
                self.startup.children(values.get('children'), 3)
                key = 'settlement_fault' if self.policy.case in INFLIGHT else 'cancel'
                variant = _namespace(self.case_item.funcargs).get(key) if self.policy.case in INFLIGHT else values.get(key)
                if type(variant) is not bool or variant != self.policy.case.endswith('[True]'):
                    raise Refused('cleanup original close variant')
                link = Link(wrapper, wrapper.__code__.co_freevars.index('close'), base[0].function, 'cell')
                self.cleanup = (replace(base[0], links=(Link(self.startup.module, '_close_subprocess', wrapper), link)), *base[1:])
            return nested_signal(self, pid, sig, group)
        finally:
            self.cleanup = base
            del frames

    def listener(self):
        frames = active_frames()
        try:
            self.probe.current(frames, line=1317, reason='cleanup original free port probe')
            return {'tag': 'mcp-probe', 'nonce': None}
        finally:
            del frames

    def connection(self, port):
        frames = active_frames()
        try:
            frame = self.readiness.current(frames, reason='cleanup original readiness connection')
            if type(frame.f_locals.get('port')) is not int or frame.f_locals['port'] != port:
                raise Refused('cleanup original readiness port')
            self.process(frame.f_locals.get('process'))
        finally:
            del frames


class ModuleCalls(Sources):
    def __init__(self, policy, item):
        super().__init__(policy, item)
        if any(self.pins[name] != pin for name, pin in PINS.items()):
            raise Refused('cleanup module source bytes')
        self.startup = self

    def select(self, case, audit):
        if not git_completion(case):
            raise Refused('cleanup no completion query case')
        executable, vector, cwd, env = audit
        module = sys_module('unrest_harness.server')
        unit = self.unit(SERVER, module, self.mode(module))
        function = vars(module)['_completion_context']
        owner = self.owner(unit, module, function, '_completion_context',
                           (Link(module, '_completion_context', function),))
        frames = active_frames()
        try:
            owner.current(frames, line=266, reason='cleanup original completion query')
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
