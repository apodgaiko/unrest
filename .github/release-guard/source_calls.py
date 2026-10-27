"""Measured source units, live original callers and owned cleanup processes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import types
from typing import Any

from content_manifest import Refused
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
            if process is None and owner.qualified in ('ACPNodeRunner.run_node.<locals>.finish_mcp', 'ACPNodeRunner.run_terminal_review.<locals>.finish_mcp', 'ACPNodeRunner.run_node'):
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
                if type(step) is types.FunctionType and type(step.__qualname__) is str and step.__qualname__ in (
                        'ACPNodeRunner.run_node.<locals>.finish_mcp',
                        'ACPNodeRunner.run_node.<locals>.finish_agent',
                        'ACPNodeRunner.run_terminal_review.<locals>.finish_mcp',
                        'ACPNodeRunner.run_terminal_review.<locals>.finish_agent'):
                    owner = self.owner(self.startup.unit, self.startup.module, step, step.__qualname__,
                                       (Link(frame, 'step', step, 'frame'),))
                    self.cleanup = (*self.cleanup, owner)
                    break
        Sources.signal(self, pid, sig, group)
    finally:
        # Keep no coroutine/closure frame alive between privileged calls.
        self.cleanup = base_cleanup
        del frames

