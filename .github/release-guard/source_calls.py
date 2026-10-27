"""Measured source units, live original callers and owned cleanup processes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import types
from typing import Any, cast

from content_manifest import Refused
from control_transport import unique
from source_owner import Link, Owner, active_frames, prepare


class Sources:
    cleanup: Any
    process_class: Any
    transport_class: Any
    terminal_type: Any
    def __init__(self, policy, item):
        self.policy, self.profile = policy, policy.profile
        raw = (policy.directory / 'source-manifest.json').read_bytes()
        if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != self.profile['source_sha256']:
            raise Refused('root source manifest reference')
        manifest = json.loads(raw, object_pairs_hook=unique)
        if type(manifest) is dict and manifest.get('schema') == 'unrest.source-inputs.v1':
            git = manifest.get('git')
            if (set(manifest) != {'schema','source','git'} or type(git) is not dict
                    or set(git) != {'schema','file_bound','files'} or git['schema'] != 'unrest.git-inputs.v1'
                    or type(git['file_bound']) is not int or git['file_bound'] != 64 * 1024 * 1024
                    or type(git['files']) is not list or not 0 < len(git['files']) <= 20000):
                raise Refused('root public Git manifest schema')
            manifest = manifest['source']
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
    def owner(unit, module, function, qualified, links, *, default_objects=()):
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
                     keyword_defaults=tuple(sorted((keywords or {}).items())), default_objects=default_objects)

    def acp_cleanup(self, module, unit):
        import asyncio
        import asyncio.unix_events
        self.cleanup = tuple(self.owner(unit, module, vars(module)[name], name,
                             (Link(module, name, vars(module)[name]),))
                             for name in ('_close_subprocess', '_wait_for_process_exit'))
        self.process_class, self.terminal_type = asyncio.subprocess.Process, module.ManagedTerminal
        self.transport_class = vars(asyncio.unix_events)['_UnixSubprocessTransport']

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
            if owner.qualified in ('ACPNodeRunner.run_node.<locals>.finish_mcp', 'ACPNodeRunner._run_terminal_review_lifecycle.<locals>.finish_mcp', 'ACPNodeRunner.run_node'):
                process = frame.f_locals.get('mcp_process')
            if owner.qualified == 'ACPClient._cleanup.<locals>.finish_terminal':
                terminal = frame.f_locals.get('terminal')
                if type(terminal) is not self.terminal_type:
                    raise Refused('root original cleanup terminal type')
                process = vars(terminal).get('process')
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




class TestSources(Sources):
    def __init__(self, policy, item, path, pins):
        super().__init__(policy, item)
        if any(self.pins[name] != pin for name, pin in pins.items()):
            raise Refused('original selected source bytes')
        self.case_item, self.tests = item, item.module
        if type(self.tests) is not types.ModuleType or self.tests.__name__ != path.removesuffix('.py').replace('/', '.'):
            raise Refused('original selected test module')
        self.test_unit = self.unit(path, self.tests, 'pytest')
        self.test_owner = self.owner(self.test_unit, self.tests, item.obj, item.originalname,
                                    (Link(self.tests, item.originalname, item.obj),))
        self.test_owner.verify_binding()


def nested_signal(self, pid, sig, group):
    if group:
        raise Refused('ordinary inherited session has no group authority')
    frames = active_frames()
    base_cleanup = self.cleanup
    try:
        for frame in frames:
            if (frame.f_globals is vars(self.startup.module)
                    and type(frame.f_code.co_qualname) is str
                    and frame.f_code.co_qualname == '_finish_owned_cleanup.<locals>.finish'):
                step = frame.f_locals.get('step')
                from functools import partial
                terminal_step = type(step) is partial and type(step.func) is types.FunctionType and type(step.func.__qualname__) is str and step.func.__qualname__ == 'ACPClient._cleanup.<locals>.finish_terminal'
                if terminal_step:
                    step = cast(partial, step)
                    original = step
                    if len(step.args) != 1 or step.keywords or type(step.args[0]) is not self.terminal_type:
                        raise Refused('root original terminal cleanup operands')
                    step = step.func
                if type(step) is types.FunctionType and type(step.__qualname__) is str and step.__qualname__ in (
                        'ACPClient._cleanup.<locals>.finish_terminal',
                        'ACPNodeRunner.run_node.<locals>.finish_mcp',
                        'ACPNodeRunner.run_node.<locals>.finish_agent',
                        'ACPNodeRunner._run_terminal_review_lifecycle.<locals>.finish_mcp',
                        'ACPNodeRunner._run_terminal_review_lifecycle.<locals>.finish_agent'):
                    owner = self.owner(self.startup.unit, self.startup.module, step, step.__qualname__,
                                       ((Link(frame, 'step', original, 'frame'), Link(original, 'func', step, 'partial-function'))
                                        if terminal_step else (Link(frame, 'step', step, 'frame'),)))
                    self.cleanup = (*self.cleanup, owner)
                    break
        Sources.signal(self, pid, sig, group)
    finally:
        # Keep no coroutine/closure frame alive between privileged calls.
        self.cleanup = base_cleanup
        del frames

