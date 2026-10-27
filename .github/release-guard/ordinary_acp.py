"""Original LaunchPlan identity and finite mock-agent/native-fixture launches.

The native fixture has kernel admission and actual reap evidence, never a
fabricated Python READY. Source selection does not grant group-signal authority.
"""
from __future__ import annotations

import asyncio
import gc
import importlib
import os
from pathlib import Path
import stat
import types

from content_manifest import Refused
from controlled_startup import Intent
from launch_policy import Observation, Rule, match, render
from source_owner import Link, active_frames

PRODUCT = 'src/unrest_harness/acp_runner.py'
TEST = 'tests/test_acp_runner.py'
MOCK = 'tests/mock_acp_agent.py'
PINS = {PRODUCT: '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f',
        TEST: '0edac8224b6b1760230026567fb1c3a1d591dc70d0b70e9990b0b52d68a71561',
        MOCK: '8141170328ff5fc28acf10dfd70bbf22f4062cceb1b2de8b8ea11ab0c17a48b6'}
CASES = tuple(TEST + '::' + name for name in (
    'test_owned_node_launch_uses_one_identical_plan[work]',
    'test_owned_node_launch_uses_one_identical_plan[validate]',
    'test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[claude]'))


def environment(case, base, root_environment):
    if case not in CASES:
        raise Refused('ordinary finite case')
    role = case.rsplit('[', 1)[1][:-1]
    node, spawn = ('v-good', '2026-08-10T07-05-00Z-0000') if role == 'claude' else (
        'plan-' + role, '2026-08-30T00-00-00Z-' + role)
    home = base / '.unrest'
    result = {key: root_environment[key] for key in ('HOME', 'TMPDIR', 'PATH')}
    result.update(UNREST_CAPABILITY_PROFILE='safe', UNREST_CAPABILITY_POLICY_VERSION='1',
        UNREST_HOME=str(home), UNREST_PROJECT_ID='p1', UNREST_MISSION_ID='mission-001',
        UNREST_NODE_ID=node, UNREST_NODE_TYPE='validate' if role == 'claude' else role,
        UNREST_HANDOFF_PATH=str(home / 'projects/p1/.unrest-runtime/missions/mission-001/attempts' / (spawn + '__' + node + '.json')))
    if role == 'claude':
        result['ANTHROPIC_API_KEY'] = 'batch-crash-known-value'  # Original public redaction canary.
    return result


def system_sleep():
    """The one declared system alias, checked from root to regular executable."""
    file = Path('/bin/sleep')
    if os.readlink('/bin') != 'usr/bin' or file.resolve(strict=True) != Path('/usr/bin/sleep'):
        raise Refused('ordinary system fixture alias')
    for member in (Path('/'), Path('/usr'), Path('/usr/bin'), Path('/usr/bin/sleep')):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('ordinary system fixture custody')
        if member == Path('/usr/bin/sleep'):
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise Refused('ordinary system fixture executable')
        elif not stat.S_ISDIR(info.st_mode):
            raise Refused('ordinary system fixture directory')
    from source_profile import digest
    return digest(Path('/usr/bin/sleep'))


def expected(case, role, cwd, checkout, native, native_pin, root_environment, owned):
    if case not in CASES or role not in ('mock-acp', 'sleep'):
        raise Refused('ordinary closed launch role')
    if role == 'sleep':
        if cwd != str(checkout):
            raise Refused('ordinary inherited fixture cwd')
        env = dict(root_environment)
        if case == CASES[2]:
            env['ANTHROPIC_API_KEY'] = 'batch-crash-known-value'
        vector, executable, pin, kind, payload = ('/bin/sleep', '30'), '/bin/sleep', system_sleep(), 'native', None
        owner = TEST + ':fixture-sleep'
    else:
        home = Path(cwd)
        if (not home.is_absolute() or str(home.resolve()) != cwd or home.name != 'workspace'
                or not home.parent.is_relative_to(owned / 'pytest') or home.parent == owned / 'pytest'):
            raise Refused('ordinary owned project workspace')
        env = environment(case, home.parent, root_environment)
        vector = (native, str(checkout / MOCK))
        executable, pin, kind, payload = native, native_pin, 'python-script', PINS[MOCK]
        owner = PRODUCT + ':spawn_launch'
    rule = Rule('ordinary:' + role, owner, (case,), executable, pin, vector,
                tuple(sorted(env.items())), cwd, kind, payload)
    return render(rule, case, owner, {}, {})


def plain_environment(value):
    if type(value) is types.MappingProxyType:
        referents = gc.get_referents(value)
        if len(referents) != 1 or type(referents[0]) is not dict:
            raise Refused('ordinary plan underlying dictionary')
        value = referents[0]
    if type(value) is not dict or any(type(k) is not str or type(v) is not str for k, v in value.items()):
        raise Refused('ordinary environment primitives')
    return dict(value)


def options(values, role, plan=None):
    kw = values.get('kwds')
    if type(kw) is not dict or any(type(key) is not str for key in kw):
        raise Refused('ordinary constructor keyword names')
    for key in ('stdout', 'stderr', 'limit'):
        if type(values.get(key)) is not int:
            raise Refused('ordinary constructor integer options')
    if role == 'mock-acp':
        if (type(plan) is not dict or set(plan) != {'argv', 'cwd', 'environment', 'path'}
                or type(plan['argv']) is not tuple or any(type(arg) is not str for arg in plan['argv'])
                or type(plan['cwd']) is not str or type(plan['environment']) is not types.MappingProxyType
                or type(plan['path']) not in (str, type(None))
                or set(kw) != {'cwd', 'env'} or type(kw['cwd']) is not str
                or kw['cwd'] != plan['cwd'] or kw['env'] is not plan['environment']
                or type(values.get('stdin')) is not int or values['stdin'] != -1
                or values['stdout'] != -1 or values['stderr'] != -1 or values['limit'] != 8 * 1024 * 1024):
            raise Refused('ordinary identical plan and original options')
        env = plain_environment(plan['environment'])
        if plan['path'] != env.get('PATH'):
            raise Refused('ordinary plan PATH snapshot')
        return env
    if role != 'sleep' or kw or values.get('stdin') is not None:
        raise Refused('ordinary native fixture original options')
    return None


class Ordinary:
    def __init__(self, calls):
        self.calls, self.profile = calls, calls.profile
        self.module = importlib.import_module('unrest_harness.acp_runner')
        self.unit = calls.unit(PRODUCT, self.module, calls.mode(self.module))
        self.plan_type = self.module.LaunchPlan
        self.constructor = asyncio.create_subprocess_exec
        self.constructor_code = self.constructor.__code__

    def select(self, case, audit):
        executable, vector, cwd, env = audit
        frames = active_frames()
        try:
            test_frames = [f for f in frames if f.f_code is self.calls.test_owner.function.__code__
                           and f.f_globals is vars(self.calls.tests)]
            if len(test_frames) != 1:
                raise Refused('ordinary active original test')
            test_frame = test_frames[0]
            self.calls.test_owner.verify(test_frame)
            constructors = [f for f in frames if f.f_code is self.constructor_code
                            and f.f_globals is self.constructor.__globals__]
            if len(constructors) != 1 or asyncio.create_subprocess_exec is not self.constructor:
                raise Refused('ordinary original asyncio constructor')
            values = constructors[0].f_locals
            if type(values.get('args')) is not tuple or type(values.get('kwds')) is not dict:
                raise Refused('ordinary constructor fields')
            kw = values['kwds']
            role = 'sleep' if executable == '/bin/sleep' else 'mock-acp'
            if role == 'mock-acp':
                fn = test_frame.f_locals.get('actual_spawn') if case != CASES[2] else vars(self.module).get('spawn_launch')
                if type(fn) is not types.FunctionType:
                    raise Refused('ordinary original spawn function')
                link = Link(self.module, 'spawn_launch', fn) if case == CASES[2] else Link(test_frame, 'actual_spawn', fn, 'frame')
                owner = self.calls.owner(self.unit, self.module, fn, 'spawn_launch', (link,))
                matches = [f for f in frames if f.f_code is fn.__code__ and f.f_globals is vars(self.module) and f.f_lineno == 409]
                if len(matches) != 1:
                    raise Refused('ordinary original LaunchPlan spawn')
                frame = matches[0]
                owner.verify(frame)
                plan = frame.f_locals.get('plan')
                if type(plan) is not self.plan_type or self.module.LaunchPlan is not self.plan_type:
                    raise Refused('ordinary exact plan type')
                p = {key: object.__getattribute__(plan, key) for key in ('argv', 'cwd', 'environment', 'path')}
                environment_snapshot = options(values, role, p)
                if (type(cwd) is not str or tuple(vector) != p['argv'] or cwd != p['cwd'] or env is not p['environment']):
                    raise Refused('ordinary original audit plan identity')
                actual_cwd = cwd
                site = 409
            else:
                name = '_start_fixture' if case == CASES[2] else 'no_op_server'
                fn = test_frame.f_locals.get(name)
                if type(fn) is not types.FunctionType:
                    raise Refused('ordinary original fixture function')
                qualified = self.calls.test_owner.qualified + '.<locals>.' + name
                # This test-created fixture is retained by its still-active
                # original test frame; its captured values are frozen here.
                owner = self.calls.owner(self.calls.test_unit, self.calls.tests, fn, qualified,
                                         (Link(test_frame, name, fn, 'frame'),))
                matches = [f for f in frames if f.f_code is fn.__code__ and f.f_globals is vars(self.calls.tests)]
                if len(matches) != 1 or cwd is not None or env is not None or values.get('stdin') is not None or kw:
                    raise Refused('ordinary original native fixture caller')
                owner.verify(matches[0])
                options(values, role)
                mode = -1 if case == CASES[2] else -3
                if values.get('stdout') != mode or values.get('stderr') != mode or values.get('limit') != 65536:
                    raise Refused('ordinary native fixture pipe options')
                actual_cwd = self.profile['checkout']
                environment_snapshot = plain_environment(dict(os.environ))
                site = matches[0].f_lineno
            result = expected(case, role, actual_cwd, Path(self.profile['checkout']), self.profile['native'],
                self.profile['native_sha256'], self.profile['environment'], Path(self.profile['owned']))
            if executable != result.executable or tuple(vector) != result.argv:
                raise Refused('ordinary original vector')
            observed = Observation(executable, result.executable_sha256, tuple(vector),
                tuple(sorted(environment_snapshot.items())), actual_cwd, result.payload_kind, result.payload_sha256)
            match((result,), observed, result.owner, case)
            translated = result.argv if role == 'sleep' else (result.argv[0], '-I', '-S', *result.argv[1:])
            return Intent(result, translated, site, result.payload_sha256)
        finally:
            del frames
