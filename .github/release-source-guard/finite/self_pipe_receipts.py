"""Keep an authenticated self-pipe alive only while its receipt is acquired.

The socket operation runs after the lock is released. Closing an asyncio loop
must never wait for a blocking recv, and this hook grants no socket authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import types
import weakref

CASES = frozenset(
    'tests/test_completion_setup.py::test_real_roles_first_use[' + scenario + '-' + role + '-targets' + targets + ']'
    for scenario in ('invalid-invalid', 'valid-invalid', 'valid-valid', 'distinct')
    for role, targets in (('work', '0'), ('work', '1'), ('validate', '2')))
CLASS = 'source-completion-helper:test_real_roles_first_use'
SOURCE = 'tests/test_completion_setup.py'
SOURCE_PIN = 'fe1a1c98792d1b30d81d975cb23ad9122ae74678295ef4ed8c5e532a7aa00b6a'


def named(code, qualname):
    for child in code.co_consts:
        if isinstance(child, types.CodeType):
            if child.co_qualname == qualname:
                return child
            found = named(child, qualname)
            if found is not None:
                return found
    return None


def bridge(endpoint, pipe, pipe_globals, pair_code, payload_code):
    """Install receipt/close ordering; registration still requires the real RPC."""
    original_request = endpoint.request
    original_close = socket.socket.close
    fileno = socket.socket.fileno
    bindings = weakref.WeakKeyDictionary()
    registry_lock = threading.RLock()

    def identity(stream):
        fd = fileno(stream)
        info = os.fstat(fd)
        return fd, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def bound(stream):
        with registry_lock:
            return bindings.get(stream)

    def request(kind, **values):
        caller = sys._getframe(1)
        if (kind == 'socketpair' and caller.f_code == pair_code
                and caller.f_globals is vars(endpoint)):
            parent = caller.f_back
            if (parent is not None and parent.f_code is pipe.__code__
                    and parent.f_globals is pipe_globals):
                left, right = caller.f_locals['left'], caller.f_locals['right']
                if (type(left) is socket.socket and type(right) is socket.socket
                        and values == {'fds': [fileno(left), fileno(right)]}):
                    answer = original_request(kind, **values)
                    # Still in _make_self_pipe, before either object is exposed
                    # to the loop or another thread. No local receipt substitute.
                    rows = [(stream, identity(stream)) for stream in (left, right)]
                    with registry_lock:
                        for stream, snapshot in rows:
                            bindings[stream] = [threading.RLock(), snapshot, False]
                    return answer
        if (kind == 'payload' and caller.f_code == payload_code
                and caller.f_globals is vars(endpoint)):
            stream = caller.f_locals.get('stream')
            entry = bound(stream) if type(stream) is socket.socket else None
            if entry is not None:
                lock, snapshot, _ = entry
                with lock:
                    fd = fileno(stream)
                    if entry[2] and fd == -1:
                        # Only our successful original close sets this flag.
                        # The unchanged native I/O immediately raises EBADF.
                        return None
                    try:
                        current = identity(stream)
                    except OSError:
                        current = None
                    if current == snapshot and values == {'fd': snapshot[0]}:
                        return original_request(kind, **values)
                    # detach, reinitialization, raw close/reuse and drift retain
                    # the original supervisor's refusal, including global poison.
        return original_request(kind, **values)

    def close(stream):
        entry = bound(stream)
        if entry is None:
            return original_close(stream)
        with entry[0]:
            result = original_close(stream)
            entry[2] = fileno(stream) == -1
            return result

    endpoint.request = request
    socket.socket.close = close


def install(guard, endpoint):
    state = guard._STATE
    if state.get('class') != CLASS or state.get('case') not in CASES:
        return
    path = Path(state['checkout']) / SOURCE
    if (state['product_pins'].get(SOURCE) != SOURCE_PIN
            or hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_PIN):
        guard.refuse('self_pipe_owner_source_drift')
    guard.require_ready(state['token'])
    import asyncio.selector_events as selectors
    pipe = selectors.BaseSelectorEventLoop._make_self_pipe
    code = compile(Path(selectors.__file__).read_bytes(), selectors.__file__, 'exec', dont_inherit=True)
    endpoint_path = Path(endpoint.__file__)
    pin = state['direct_support']['files'][str(endpoint_path)]
    if hashlib.sha256(endpoint_path.read_bytes()).hexdigest() != pin:
        guard.refuse('self_pipe_endpoint_source_drift')
    expected = compile(endpoint_path.read_bytes(), str(endpoint_path), 'exec', dont_inherit=True)
    pair_code = named(expected, 'early.<locals>.socketpair')
    payload_code = named(expected, 'early.<locals>.payload')
    request_code = named(expected, 'request')
    if (pipe.__globals__ is not vars(selectors)
            or pipe.__code__ != named(code, 'BaseSelectorEventLoop._make_self_pipe')
            or socket.socketpair.__code__ != pair_code
            or socket.socketpair.__globals__ is not vars(endpoint)
            or endpoint.request.__code__ != request_code
            or endpoint.request.__globals__ is not vars(endpoint)):
        guard.refuse('self_pipe_original_code_drift')
    bridge(endpoint, pipe, vars(selectors), pair_code, payload_code)
    guard.append({'kind': 'self_pipe_receipt_lifetime', 'scope': CLASS,
                  'authority_changed': False, 'lock_scope': 'receipt acquisition only'})
