"""Shared exact LaunchPlan and fixed-script descendant ownership."""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import types

from content_manifest import Refused
from controlled_startup import Intent
from launch_policy import Observation, match
from ordinary_acp import plain_environment
from session_launch import LIVE, PLAN, INVALID, PINS, PRODUCT, SCRIPT, TEST, TIMEOUT, expected, stream_limit
from source_calls import Sources, TestSources
from source_owner import Link, active_frames, frame_fields, instance_fields, _namespace, prepare


def plan_fields(plan):
    p = {key: object.__getattribute__(plan, key) for key in ('argv', 'cwd', 'environment', 'path')}
    if (type(p['argv']) is not tuple or not p['argv'] or any(type(v) is not str for v in p['argv'])
            or type(p['cwd']) is not str or type(p['environment']) is not types.MappingProxyType
            or type(p['path']) is not str):
        raise Refused('session immutable plan fields')
    environment = plain_environment(p['environment'])
    if p['path'] != environment.get('PATH'):
        raise Refused('session plan PATH')
    return p, environment


def constructor_options(options, plan, limit):
    kw = _namespace(options.get('kwds'))
    args = options.get('args')
    if (set(kw) != {'cwd', 'env', 'start_new_session'} or type(kw['cwd']) is not str
            or kw['cwd'] != plan['cwd'] or kw['env'] is not plan['environment']
            or kw['start_new_session'] is not True or type(options.get('program')) is not str
            or options['program'] != plan['argv'][0] or type(args) is not tuple
            or any(type(v) is not str for v in args) or args != plan['argv'][1:]
            or any(type(options.get(k)) is not int or options[k] != -1 for k in ('stdin', 'stdout', 'stderr'))
            or type(options.get('limit')) is not int or options['limit'] != limit):
        raise Refused('session original plan and pipe options')


def inherited_options(options):
    if (any(options.get(k) is not None for k in ('stdin', 'stdout', 'stderr', 'preexec_fn'))
            or options.get('shell') is not False or options.get('start_new_session') is not False
            or type(options.get('pass_fds')) is not tuple or options['pass_fds']):
        raise Refused('session child exact default options')


class SessionCalls(TestSources):
    def __init__(self, policy, item):
        import asyncio
        super().__init__(policy, item, TEST, PINS)
        self.startup = self
        self.module = importlib.import_module('unrest_harness.provider_sessions')
        self.unit = self.unit(PRODUCT, self.module, self.mode(self.module))
        self.plan_type = self.module.LaunchPlan
        self.constructor = asyncio.create_subprocess_exec
        self.constructor_code, self.constructor_globals = self.constructor.__code__, self.constructor.__globals__
        acp = importlib.import_module('unrest_harness.acp_runner')
        self.acp_cleanup(acp, self.unit_for_acp(acp))

    def unit_for_acp(self, module):
        return Sources.unit(self, 'src/unrest_harness/acp_runner.py', module, self.mode(module))

    def select(self, case, audit):
        import asyncio
        if type(case) is not str or case != self.case_item.nodeid or case not in LIVE:
            raise Refused('session active original launch case')
        frames = active_frames()
        try:
            self.test_owner.verify_binding()
            cancel = case.endswith('::test_cancel_event_returns_typed_result_and_stops_adapter')
            test = None if cancel else self.test_owner.current(frames)
            fixture = _namespace(self.case_item.funcargs).get('tmp_path')
            if type(fixture) is not type(Path('/')):
                raise Refused('session original selected fixture')
            function = test.f_locals.get('actual_spawn') if case in PLAN else vars(self.module).get('_spawn_provider_launch')
            link = Link(test, 'actual_spawn', function, 'frame') if case in PLAN else Link(self.module, '_spawn_provider_launch', function)
            owner = self.owner(self.unit, self.module, function, '_spawn_provider_launch', (link,))
            values = frame_fields(owner.current(frames, line=75))
            plan = values.get('plan')
            if type(plan) is not self.plan_type or self.module.LaunchPlan is not self.plan_type:
                raise Refused('session original plan type')
            p, environment = plan_fields(plan)
            if p['cwd'] != str(fixture / 'workspace') or type(values.get('limit')) is not int or values['limit'] != stream_limit(case):
                raise Refused('session original workspace and stream limit')
            if (self.constructor is not asyncio.create_subprocess_exec or self.constructor.__code__ is not self.constructor_code
                    or self.constructor.__globals__ is not self.constructor_globals):
                raise Refused('session asyncio constructor changed')
            constructors = [f for f in frames if f.f_code is self.constructor_code and f.f_globals is self.constructor_globals]
            if len(constructors) != 1:
                raise Refused('session original constructor frame')
            constructor_options(frame_fields(constructors[0]), p, stream_limit(case))
            executable, vector, cwd, env = audit
            if (type(vector) is not list or tuple(vector) != p['argv'] or cwd != p['cwd'] or env is not p['environment']):
                raise Refused('session audited plan identity')
            result = expected(case, cwd, Path(self.profile['checkout']), Path(self.profile['owned']),
                self.profile['native'], self.profile['native_sha256'], self.profile['environment'])
            match((result,), Observation(executable, result.executable_sha256, tuple(vector), tuple(sorted(environment.items())), cwd,
                result.payload_kind, result.payload_sha256), result.owner, case)
            return Intent(result, result.argv if case in INVALID else (result.argv[0], '-I', '-S', *result.argv[1:]), 75, result.payload_sha256)
        finally:
            del frames

    def signal(self, pid, sig, group):
        if type(pid) is not int or type(sig) is not int or type(group) is not bool or sig not in (9, 15) or not group:
            raise Refused('session exact process group cleanup')
        frames = active_frames()
        try:
            cls = self.module.ProviderSessionRunner
            descriptor = vars(cls)['_stop_process_group']
            if type(descriptor) is not staticmethod:
                raise Refused('session cleanup descriptor')
            function = descriptor.__func__
            owner = self.owner(self.unit, self.module, function, 'ProviderSessionRunner._stop_process_group',
                (Link(self.module, 'ProviderSessionRunner', cls), Link(cls, '_stop_process_group', descriptor), Link(descriptor, '__func__', function, 'static-function')))
            values = frame_fields(owner.current(frames))
            self.process(values.get('process'),pid=pid)
        finally:
            del frames

    def listener(self):
        raise Refused('session has no network listener')


class SessionChild(Sources):
    def __init__(self, policy):
        self.policy, self.profile, self.startup = policy, policy.profile, self
        self.module = sys.modules['__main__']
        file = Path(self.profile['checkout']) / SCRIPT
        self.unit = prepare(file.read_bytes(), str(file), '__main__', 'script', PINS[SCRIPT])
        self.process_type = __import__('subprocess').Popen

    def select(self, case, audit):
        frames = active_frames()
        try:
            function = vars(self.module).get('main')
            owner = self.owner(self.unit, self.module, function, 'main', (Link(self.module, 'main', function),))
            owner.current(frames, line=50)
            executable, vector, cwd, env = audit
            if cwd is not None or env is not None or type(vector) is not list:
                raise Refused('session child original inherited request')
            result = expected(case, self.profile['cwd'], Path(self.profile['checkout']), Path(self.profile['owned']),
                self.profile['native'], self.profile['native_sha256'], self.profile['environment'], child=True)
            constructors = [f for f in frames if f.f_code is self.policy.constructor_code and f.f_globals is self.policy.constructor_globals]
            if len(constructors) != 1:
                raise Refused('session child original constructor')
            options = frame_fields(constructors[0])
            inherited_options(options)
            if executable != result.executable or tuple(vector) != result.argv:
                raise Refused('session child exact default operands')
            return Intent(result, (result.argv[0], '-I', '-S', *result.argv[1:]), 50, result.payload_sha256)
        finally:
            del frames

    def signal(self, pid, sig, group):
        if self.policy.case != TIMEOUT or type(pid) is not int or sig not in (9, 15) or group:
            raise Refused('session descendant signal scope')
        frames = active_frames()
        try:
            cls = vars(self.module).get('_ChildOwner')
            function = vars(cls).get('cleanup') if type(cls) is type else None
            owner = self.owner(self.unit, self.module, function, '_ChildOwner.cleanup',
                (Link(self.module, '_ChildOwner', cls), Link(cls, 'cleanup', function)))
            values = frame_fields(owner.current(frames))
            instance = values.get('self')
            if type(instance) is not cls:
                raise Refused('session descendant cleanup owner')
            fields = instance_fields(instance)
            process = fields.get('child')
            if (type(process) is not self.process_type or type(process.pid) is not int or process.pid not in self.policy.children
                    or self.policy.children[process.pid]['process'] is not process):
                raise Refused('session descendant exact child handle')
            if pid == os.getpid():
                if sig != 15 or fields.get('waited') is not True or fields.get('termination_requested') is not True:
                    raise Refused('session self stop before actual cleanup')
                return True
            if pid != process.pid:
                raise Refused('session signal unrelated child')
            return False
        finally:
            del frames
