"""Original immutable LaunchPlan and constructor binding before any effect."""
from __future__ import annotations

import importlib
from pathlib import Path

from content_manifest import Refused
from controlled_startup import Intent
from launch_policy import Observation, match
from plan_launch import CASES, PRODUCT, TEST, expected
from session_calls import plan_fields, constructor_options
from source_calls import TestSources
from source_owner import Link, active_frames, frame_fields, _namespace

PINS = {
    'src/unrest_harness/acp_runner.py': '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f',
    'tests/test_launch_preflight.py': '0bca9124dea59dc4f516eeb2a7bfe7042dd58a258a3e54b86004ef447760303a',
}


class Calls(TestSources):
    def __init__(self,policy,item):
        import asyncio
        super().__init__(policy,item,TEST,PINS)
        self.startup=self
        self.module=importlib.import_module('unrest_harness.acp_runner')
        self.product_unit=self.unit(PRODUCT,self.module,self.mode(self.module))
        self.plan_type=self.module.LaunchPlan
        function=self.module.spawn_launch
        self.spawn=self.owner(self.product_unit,self.module,function,'spawn_launch',
            (Link(self.module,'spawn_launch',function),))
        self.constructor=asyncio.create_subprocess_exec
        self.constructor_code,self.constructor_globals=self.constructor.__code__,self.constructor.__globals__

    def select(self,case,audit):
        import asyncio
        if type(case) is not str or case not in CASES or case!=self.case_item.nodeid:
            raise Refused('preflight original selected case')
        frames=active_frames()
        try:
            test=self.test_owner.current(frames)
            fixture=_namespace(self.case_item.funcargs).get('tmp_path')
            if type(fixture) is not type(Path('/')) or frame_fields(test).get('tmp_path') is not fixture:
                raise Refused('preflight original fixture identity')
            source=self.spawn.current(frames,line=409)
            values=frame_fields(source)
            plan=values.get('plan')
            if type(plan) is not self.plan_type or _namespace(self.module).get('LaunchPlan') is not self.plan_type:
                raise Refused('preflight original plan class')
            p,environment=plan_fields(plan)
            if (p['cwd']!=str(fixture) or any(type(values.get(name)) is not int or values[name]!=-1 for name in ('stdin','stdout','stderr'))
                    or type(values.get('limit')) is not int or values['limit']!=65536):
                raise Refused('preflight original source options')
            if (asyncio.create_subprocess_exec is not self.constructor or self.constructor.__code__ is not self.constructor_code
                    or self.constructor.__globals__ is not self.constructor_globals):
                raise Refused('preflight original asyncio constructor')
            candidates=[frame for frame in frames if frame.f_code is self.constructor_code and frame.f_globals is self.constructor_globals]
            if len(candidates)!=1:
                raise Refused('preflight original constructor frame')
            constructor_options(frame_fields(candidates[0]),p,65536,session=False)
            executable,vector,cwd,observed_environment=audit
            if (type(executable) is not str or executable!=p['argv'][0] or type(vector) is not list
                    or tuple(vector)!=p['argv'] or cwd!=p['cwd'] or observed_environment is not p['environment']):
                raise Refused('preflight audited immutable plan identity')
            result=expected(case,p['cwd'],Path(self.profile['owned']),self.profile['native'],self.profile['native_sha256'])
            value=result.expected
            match((value,),Observation(value.executable,value.executable_sha256,tuple(vector),
                tuple(sorted(environment.items())),cwd,value.payload_kind,value.payload_sha256),value.owner,case)
            return Intent(value,result.vector,409,value.payload_sha256)
        finally:
            del frames

    def signal(self,*args):
        raise Refused('preflight family has no signal authority')

    def listener(self):
        raise Refused('preflight family has no listener authority')
