"""Pinned literal inline entries and their sole read-only repository query."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

from content_manifest import Refused
from controlled_startup import Intent
from git_observer import image
from launch_policy import Rule, render
from source_calls import Sources, TestSources
from source_owner import Link, active_frames, frame_fields

TEST = 'tests/test_repository_contract.py'
PRODUCT = 'src/unrest_harness/repository_contract.py'
REMOVED = ('unrest_harness.baseline', 'unrest_harness.governance', 'unrest_harness.repository_contract')
ARGUMENTS = {'help': ('--help',), 'init': ('init', '--help'), 'list': ('list-projects',), 'check': ('check-repository',)}
CASES = tuple(TEST + '::' + name for name in (
    *(f'test_ordinary_cli_entrypoints_do_not_import_repository_modules[arguments{i}]' for i in range(3)),
    'test_repository_command_is_the_lazy_positive_control', 'test_mcp_help_does_not_import_repository_modules',
    'test_real_entrypoint_import_boundary'))
SEQUENCES = dict(zip(CASES, (('help',), ('init',), ('list',), ('check',), ('mcp',), ('help','init','list','mcp','check')), strict=True))
PINS = {'tests/test_repository_contract.py': '12b3f3d7dd5b52bef6d88d5bd2761469a89d748f33f0ef77640579b2228b9f6c', 'src/unrest_harness/repository_contract.py': '619255f96649e14a931e6e0dbf888c1589f023dde96c3a977cda473f08404b86'}


def script(checkout, operation):
    data = (checkout / TEST).read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[TEST]:
        raise Refused('fixed inline source bytes')
    name = 'test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe'
    functions = [node for node in ast.parse(data).body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(functions) != 1:
        raise Refused('fixed inline literal owner')
    values = [node.value.value for node in functions[0].body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'script'
              and isinstance(node.value, ast.Constant) and type(node.value.value) is str]
    if len(values) != 1:
        raise Refused('fixed inline literal declaration')
    return values[0]


def expected(case, operation, native, pin, checkout, environment, *, query=False):
    if type(case) is not str or case not in CASES or type(operation) is not str or operation not in SEQUENCES[case] or type(query) is not bool:
        raise Refused('fixed inline closed operation')
    if query:
        if operation != 'check':
            raise Refused('fixed inline query scope')
        argv, executable, pin, kind = ('git','-C',str(checkout),'rev-parse','--show-toplevel'), '/usr/bin/git', image(), 'native'
        owner = PRODUCT + ':find_repository_root'
    else:
        body = script(checkout, operation)
        tail = (json.dumps(REMOVED),) if operation == 'mcp' else (json.dumps(() if operation == 'check' else REMOVED), json.dumps(ARGUMENTS[operation]))
        argv, executable, kind = (native,'-c',body,*tail), native, 'python-command'
        owner = TEST + ':' + ('test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe')
    rule = Rule('fixed:' + ('query' if query else operation), owner, (case,), executable, pin, argv,
                tuple(sorted(environment.items())), str(checkout), kind, None)
    return render(rule, case, owner, {}, {})


def run_options(local, argv, *, cwd, check, timeout):
    args, kw = local.get('popenargs'), local.get('kwargs')
    if (type(args) is not tuple or len(args) != 1 or type(args[0]) is not list
            or any(type(v) is not str for v in args[0]) or tuple(args[0]) != argv
            or type(kw) is not dict or any(type(k) is not str for k in kw)
            or set(kw) != ({'stdout','stderr','text','cwd'} if cwd is not None else {'stdout','stderr','text'})
            or kw.get('text') is not True or any(type(kw.get(k)) is not int or kw[k] != -1 for k in ('stdout','stderr'))
            or (cwd is not None and (type(kw['cwd']) is not type(Path('/')) or str(kw['cwd']) != cwd))
            or local.get('capture_output') is not True or type(local.get('check')) is not bool or local['check'] != check
            or type(local.get('timeout')) is not type(timeout) or local['timeout'] != timeout or local.get('input') is not None):
        raise Refused('fixed original run options')


class FixedCalls(TestSources):
    def __init__(self, policy, item):
        super().__init__(policy, item, TEST, PINS)
        self.startup, self.step = self, 0
        self.run_code, self.run_globals = subprocess.run.__code__, subprocess.run.__globals__

    def select(self, case, audit):
        if case != self.case_item.nodeid or self.step >= len(SEQUENCES[case]):
            raise Refused('fixed selected original frontier')
        operation = SEQUENCES[case][self.step]
        frames = active_frames()
        try:
            self.test_owner.current(frames)
            name = 'test_mcp_help_does_not_import_repository_modules' if operation == 'mcp' else '_import_probe'
            function = vars(self.tests)[name]
            owner = self.owner(self.test_unit, self.tests, function, name, (Link(self.tests,name,function),))
            values = frame_fields(owner.current(frames, line=587 if operation == 'mcp' else 540))
            if type(values.get('script')) is not str or values['script'] != script(Path(self.profile['checkout']), operation):
                raise Refused('fixed original script local')
            if operation != 'mcp':
                for key in ('arguments','blocked'):
                    if type(values.get(key)) is not tuple or any(type(v) is not str for v in values[key]):
                        raise Refused('fixed original argument primitives')
                if values['arguments'] != ARGUMENTS[operation] or values['blocked'] != (() if operation == 'check' else REMOVED):
                    raise Refused('fixed original argument declaration')
            executable, vector, cwd, env = audit
            result = expected(case, operation, self.profile['native'], self.profile['native_sha256'], Path(self.profile['checkout']),
                {**self.profile['environment'],'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'})
            calls = [f for f in frames if f.f_code is self.run_code and f.f_globals is self.run_globals]
            if len(calls) != 1 or executable != result.executable or type(vector) is not list or tuple(vector) != result.argv or env is not None or type(cwd) is not type(Path('/')) or str(cwd) != result.cwd:
                raise Refused('fixed original audited call')
            run_options(frame_fields(calls[0]), result.argv, cwd=result.cwd, check=operation != 'mcp', timeout=20)
            self.step += 1
            return Intent(result,(result.argv[0],'-I','-S',*result.argv[1:]),587 if operation == 'mcp' else 540,result.payload_sha256)
        finally:
            del frames

    def signal(self, *args):
        raise Refused('fixed inline has no signal authority')

    def listener(self):
        raise Refused('fixed inline has no listener authority')


class FixedQuery(Sources):
    def __init__(self, policy):
        super().__init__(policy,None)
        if self.pins.get(PRODUCT) != PINS[PRODUCT]:
            raise Refused('fixed query product pin')
        self.startup = self
        self.run_code, self.run_globals = subprocess.run.__code__, subprocess.run.__globals__

    def select(self, case, audit):
        module = sys.modules.get('unrest_harness.repository_contract')
        if type(module) is not types.ModuleType:
            raise Refused('fixed query source module')
        unit = self.unit(PRODUCT,module,self.mode(module))
        function = vars(module)['find_repository_root']
        owner = self.owner(unit,module,function,'find_repository_root',(Link(module,'find_repository_root',function),))
        frames = active_frames()
        try:
            values = frame_fields(owner.current(frames,line=507))
            checkout = Path(self.profile['checkout'])
            if type(values.get('start')) is not type(Path('/')) or values['start'] != checkout:
                raise Refused('fixed query repository argument')
            result = expected(case,'check',self.profile['native'],self.profile['native_sha256'],checkout,self.profile['environment'],query=True)
            executable,vector,cwd,env = audit
            calls = [f for f in frames if f.f_code is self.run_code and f.f_globals is self.run_globals]
            if len(calls) != 1 or executable != 'git' or type(vector) is not list or tuple(vector) != result.argv or cwd is not None or env is not None:
                raise Refused('fixed query original audited call')
            run_options(frame_fields(calls[0]),result.argv,cwd=None,check=False,timeout=None)
            return Intent(result,result.argv,507,result.payload_sha256)
        finally:
            del frames
