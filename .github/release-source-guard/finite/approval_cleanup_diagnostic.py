"""Bounded passive cleanup stacks in an already authenticated controlled worker."""
from __future__ import annotations

import asyncio
import sys


def install(guard):
    state = guard._STATE
    previous = state.get('primary_snapshot_observer')
    armed, seen = False, set()
    interesting = {'_cancel', '_finish_owned_cleanup', 'finish', 'settle_prompts',
                   'finish_recovery', 'finish_agent', 'finish_mcp', 'close', '_close',
                   'cleanup', '_read_loop', '_cancel_all_tasks', 'shutdown_default_executor',
                   'shutdown', 'join', '_do_shutdown'}

    def location(frame):
        return [frame.f_code.co_filename, frame.f_code.co_name, frame.f_lineno]

    def observe(frame, event, value):
        nonlocal armed
        if previous is not None:
            previous(frame, event, value)
        path, name = frame.f_code.co_filename, frame.f_code.co_name
        if event != 'call':
            return
        if ((path == '/source/src/unrest_harness/run_worker.py' and name == '_cancel')
                or (path == '/source/src/unrest_harness/acp_runner.py' and name == '_finish_owned_cleanup')):
            armed = True
        marker = (path, name)
        if not armed or name not in interesting or marker in seen or len(seen) >= 16:
            return
        seen.add(marker)
        try:
            threads = []
            for _, current in sorted(sys._current_frames().items())[:16]:
                stack = []
                while current is not None and len(stack) < 24:
                    stack.append(location(current))
                    current = current.f_back
                threads.append(stack)
            tasks = []
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                for task in sorted(asyncio.all_tasks(loop), key=lambda item: item.get_name())[:32]:
                    coroutine, stack, visited = task.get_coro(), [], set()
                    while coroutine is not None and id(coroutine) not in visited and len(stack) < 24:
                        visited.add(id(coroutine))
                        current = getattr(coroutine, 'cr_frame', None) or getattr(coroutine, 'gi_frame', None)
                        if current is not None:
                            stack.append(location(current))
                        coroutine = getattr(coroutine, 'cr_await', None) or getattr(coroutine, 'gi_yieldfrom', None)
                    tasks.append({'done': task.done(), 'cancelling': task.cancelling(), 'stack': stack})
            guard.append({'kind': 'controlled_approval_cleanup_tasks', 'trigger': location(frame),
                          'threads': threads, 'tasks': tasks,
                          'diagnostic_only': True, 'eligible_certificate': False})
        except (OSError, RuntimeError, AttributeError, TypeError, ValueError):
            pass  # Optional observation cannot replace the original result.

    state['primary_snapshot_observer'] = observe
    return observe
