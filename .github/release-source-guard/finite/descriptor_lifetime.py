"""Release an unreturned CPython loop's selector after a guard refusal.

This grants no effect. The original exception and global poison are retained.
Caller-supplied selectors and already constructed loops retain their owner.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import types


def prepare():
    if sys.platform != 'linux' or sys.version_info[:2] != (3, 13):
        raise RuntimeError('descriptor_cleanup_runtime_refused')
    import asyncio.selector_events as selector_events
    import asyncio.unix_events as unix_events
    import selectors

    functions = (
        (selector_events, selector_events.BaseSelectorEventLoop._make_self_pipe),
        (selector_events, selector_events.BaseSelectorEventLoop.__init__),
        (unix_events, unix_events._UnixSelectorEventLoop.__init__),
        (selectors, selectors.EpollSelector.close),
    )
    pins = {}
    for module, function in functions:
        path = Path(module.__file__)
        body = path.read_bytes()
        pins[str(path)] = hashlib.sha256(body).hexdigest()
        code = compile(body, str(path), 'exec', dont_inherit=True)
        def named(parent):
            for value in parent.co_consts:
                if isinstance(value, types.CodeType):
                    if value.co_qualname == function.__code__.co_qualname:
                        return value
                    found = named(value)
                    if found is not None:
                        return found
            return None
        if (function.__globals__ is not vars(module) or function.__code__ != named(code)
                or sys.modules.get(module.__name__) is not module):
            raise RuntimeError('descriptor_cleanup_original_code_refused')
    pipe, constructor, outer, close = [function for _, function in functions]
    codes = [function.__code__ for _, function in functions]
    loop_type = unix_events._UnixSelectorEventLoop
    selector_type = selectors.EpollSelector

    def release(frame):
        # The wrapper calls us while its original caller is still suspended.
        constructor_frame = frame.f_back if frame is not None else None
        outer_frame = constructor_frame.f_back if constructor_frame is not None else None
        if (frame is None or constructor_frame is None or outer_frame is None
                or frame.f_code is not codes[0] or frame.f_globals is not vars(selector_events)
                or constructor_frame.f_code is not codes[1]
                or constructor_frame.f_globals is not vars(selector_events)
                or outer_frame.f_code is not codes[2] or outer_frame.f_globals is not vars(unix_events)
                or any(function.__code__ is not code for function, code in zip(
                    (pipe, constructor, outer, close), codes, strict=True))
                or selector_events.BaseSelectorEventLoop._make_self_pipe is not pipe
                or selector_events.BaseSelectorEventLoop.__init__ is not constructor
                or unix_events._UnixSelectorEventLoop.__init__ is not outer
                or selectors.EpollSelector.close is not close
                or selectors.DefaultSelector is not selector_type
                or unix_events._UnixSelectorEventLoop is not loop_type):
            return False
        loop = frame.f_locals.get('self')
        selector = constructor_frame.f_locals.get('selector')
        if (type(loop) is not loop_type or type(selector) is not selector_type
                or constructor_frame.f_locals.get('self') is not loop
                or outer_frame.f_locals.get('self') is not loop
                or outer_frame.f_locals.get('selector') is not None
                or loop._selector is not selector or loop.is_closed()
                or hasattr(loop, '_ssock') or hasattr(loop, '_csock')
                or loop._internal_fds != 0 or loop._ready or loop._scheduled):
            return False
        # __init__ has not returned and has not installed its self-pipe. The
        # normal close() path dereferences that absent pipe and cannot run.
        # Finish only this abandoned constructor's resources, before rethrow.
        close(selector)
        loop._selector = None
        loop._closed = True
        return True

    return release, pins
