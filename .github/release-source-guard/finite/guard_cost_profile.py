"""TEST-only metadata CPU attribution alongside the unchanged profile guard."""
from __future__ import annotations

import sys
import threading
import time

NAMES = frozenset({'select', 'source_code', 'original_function', 'active_frames', 'evaluate', 'bound_code', 'profile', 'selected_port', 'admit', 'checked_source', 'digest', 'sha', 'current_code', 'check',
                   'translate', 'observe', 'identity', 'tree', 'tree_identity',
                   'require_ready', 'shared', 'inputs', 'dependency', 'verify',
                   'site_metadata', 'read', 'matches', 'before_python', 'ordinary_python'})
TOOL = 5
NAME = 'unrest-private-guard-cost'


class CostProfile:
    def __init__(self, prefix):
        self.prefix = prefix.rstrip('/') + '/'
        self.thread = threading.get_ident()
        self.codes = {}
        self.stack = []
        self.rows = {}
        self.truncated = False
        self.active = False
        self.profile = sys.getprofile()
        self.thread_profile = threading.getprofile()

    def entered(self, code, offset):
        if not code.co_filename.startswith(self.prefix) or code.co_name not in NAMES:
            return sys.monitoring.DISABLE
        if threading.get_ident() != self.thread:
            return None
        if id(code) not in self.codes:
            if len(self.codes) >= 1024:
                self.truncated = True
                return sys.monitoring.DISABLE
            self.codes[id(code)] = code
            sys.monitoring.set_local_events(TOOL, code,
                sys.monitoring.events.PY_RETURN)
        if len(self.stack) >= 128:
            self.truncated = True
            return None
        self.stack.append([code, time.thread_time_ns(), 0])

    def returned(self, code, offset, value):
        if (threading.get_ident() != self.thread or not self.stack
                or id(code) not in self.codes):
            return
        if self.stack[-1][0] is not code:
            self.truncated = True
            return
        _, started, children = self.stack.pop()
        elapsed = time.thread_time_ns() - started
        key = (code.co_filename, code.co_qualname)
        row = self.rows.setdefault(key, [0, 0, 0])
        row[0] += 1
        row[1] += elapsed
        row[2] += max(0, elapsed - children)
        if self.stack:
            self.stack[-1][2] += elapsed

    def start(self):
        if sys.monitoring.get_tool(TOOL) is not None:
            return False
        sys.monitoring.use_tool_id(TOOL, NAME)
        self.active = True
        try:
            sys.monitoring.register_callback(TOOL, sys.monitoring.events.PY_START, self.entered)
            sys.monitoring.register_callback(TOOL, sys.monitoring.events.PY_RETURN, self.returned)
            sys.monitoring.register_callback(TOOL, sys.monitoring.events.PY_UNWIND, self.returned)
            sys.monitoring.set_events(TOOL, sys.monitoring.events.PY_START | sys.monitoring.events.PY_UNWIND)
        except BaseException:
            self.stop()
            raise
        return True

    def stop(self):
        owned = self.active and sys.monitoring.get_tool(TOOL) == NAME
        if owned:
            sys.monitoring.set_events(TOOL, 0)
            for code in self.codes.values():
                sys.monitoring.set_local_events(TOOL, code, 0)
            for event in (sys.monitoring.events.PY_START, sys.monitoring.events.PY_RETURN,
                          sys.monitoring.events.PY_UNWIND):
                sys.monitoring.register_callback(TOOL, event, None)
            sys.monitoring.free_tool_id(TOOL)
        self.active = False
        return {'complete': bool(owned and not self.stack and not self.truncated),
                'existing_profile_identity_retained': sys.getprofile() is self.profile,
                'existing_thread_profile_identity_retained': threading.getprofile() is self.thread_profile,
                'instrumented_cpu_only': True, 'truncated': self.truncated,
                'rows': [{'path': key[0], 'function': key[1], 'calls': row[0],
                          'inclusive_cpu_ns': row[1], 'exclusive_cpu_ns': row[2]}
                         for key, row in sorted(self.rows.items(), key=lambda pair: (-pair[1][2], pair[0]))]}
