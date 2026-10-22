"""Check each already admitted self-pipe effect without per-write control IPC.

The socket operation runs after the lock is released. Closing an asyncio loop
must never wait for a blocking recv, and this hook grants no socket authority.
"""
from __future__ import annotations

import hashlib
import errno
import _socket
import struct
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import types
import weakref



def named(code, qualname):
    for child in code.co_consts:
        if isinstance(child, types.CodeType):
            if child.co_qualname == qualname:
                return child
            found = named(child, qualname)
            if found is not None:
                return found
    return None


def bridge(endpoint, pipe, pipe_globals, pair_code, payload_code, refuse, append, authenticate):
    """Install receipt/close ordering; registration still requires the real RPC."""
    original_request = endpoint.request
    original_close = socket.socket.close
    fileno = _socket.socket.fileno
    getsockopt = _socket.socket.getsockopt
    getpeername = _socket.socket.getpeername
    bindings = weakref.WeakKeyDictionary()
    registry_lock = threading.RLock()
    pipe_code = pipe.__code__

    def identity(stream):
        fd = fileno(stream)
        info = os.fstat(fd)
        if (_socket.socket.family.__get__(stream) != socket.AF_UNIX
                or getsockopt(stream, socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
            raise OSError(errno.EBADF, 'self-pipe socket type changed')
        try:
            peer = getpeername(stream)
        except OSError as error:
            if error.errno != errno.ENOTCONN:
                raise
            peer = None
        if peer not in ('', None):
            raise OSError(errno.EBADF, 'self-pipe peer is no longer anonymous')
        cookie = None
        if sys.platform == 'linux':
            if getsockopt(stream, socket.SOL_SOCKET, 39) != socket.AF_UNIX:
                raise OSError(errno.EBADF, 'self-pipe domain changed')
            cookie = int.from_bytes(getsockopt(stream, socket.SOL_SOCKET, 57, 8), sys.byteorder)
            credentials = struct.unpack('3i', getsockopt(stream, socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if credentials != (os.getpid(), os.getuid(), os.getgid()):
                raise OSError(errno.EBADF, 'self-pipe peer credentials changed')
        return fd, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), cookie, info.st_uid

    def bound(stream):
        if type(stream) is not socket.socket:
            return None
        with registry_lock:
            return bindings.get(stream)

    def request(kind, **values):
        caller = sys._getframe(1)
        if (kind == 'socketpair' and caller.f_code == pair_code
                and caller.f_globals is vars(endpoint)):
            parent = caller.f_back
            if (parent is not None and parent.f_code is pipe_code
                    and pipe.__code__ is pipe_code
                    and parent.f_globals is pipe_globals):
                left, right = caller.f_locals['left'], caller.f_locals['right']
                if (type(left) is socket.socket and type(right) is socket.socket
                        and values == {'fds': [fileno(left), fileno(right)]}):
                    answer = original_request(kind, **values)
                    # Still in _make_self_pipe, before either object is exposed
                    # to the loop or another thread. No local receipt substitute.
                    rows = [(stream, identity(stream)) for stream in (left, right)]
                    admitted = answer.get('pair')
                    if (type(admitted) is not list or len(admitted) != 2
                            or len({row['fd'] for row in admitted}) != 2):
                        refuse('self_pipe_pair_receipt_shape_drift')
                    by_fd = {row['fd']: row for row in admitted}
                    for _, snapshot in rows:
                        fd, _, inode, mode, cookie, uid = snapshot
                        row = by_fd.get(fd, {})
                        other = next(item[1][2] for item in rows if item[1][0] != fd)
                        if (row.get('inode') != inode or row.get('socket_cookie') != cookie
                                or row.get('peer_inode') != other or row.get('socket_uid') != uid
                                or uid != os.getuid()
                                or row.get('type') != socket.SOCK_STREAM or mode != stat.S_IFSOCK):
                            refuse('self_pipe_pair_kernel_identity_drift')
                    authority = authenticate()
                    if authority is None:
                        return answer
                    append({'kind': 'self_pipe_pair_local_binding', **authority,
                            'pair_receipt_id': answer['request']['id'], 'authenticated_pair': admitted})
                    with registry_lock:
                        for stream, snapshot in rows:
                            bindings[stream] = [threading.RLock(), snapshot, False,
                                                answer['request']['id']]
                    return answer
        if (kind == 'payload' and caller.f_code == payload_code
                and caller.f_globals is vars(endpoint)):
            stream = caller.f_locals.get('stream')
            entry = bound(stream) if type(stream) is socket.socket else None
            if entry is not None:
                lock, snapshot, _, receipt_id = entry
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
                        # The kernel-admitted anonymous self-pipe cannot become
                        # a network endpoint without changing this identity.
                        # An atomic local record cannot leave a partial control
                        # frame when the original MCP cleanup kills the child.
                        authority = authenticate()
                        if authority is None:
                            return original_request(kind, **values)
                        append({'kind': 'self_pipe_payload_identity', **authority, 'pair_receipt_id': receipt_id,
                                'fd': current[0], 'device': current[1], 'inode': current[2],
                                'socket_cookie': current[4], 'socket_uid': current[5], 'before_effect': True})
                        return None
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

    def audit(event, args):
        if event == 'socket.connect' and bound(args[0]) is not None:
            # Anonymous stream pairs cannot acquire a different peer through a
            # later connect. Keep that constraint ahead of every native effect.
            refuse('self_pipe_reconnect_refused')

    sys.addaudithook(audit)
    endpoint.request = request
    socket.socket.close = close


def install(guard, endpoint):
    state = guard._STATE
    if state.get('setup_mode') != 'source':
        return
    authority_path = Path(__file__).with_name('self_pipe_authority.py')
    authority_pin = state['direct_support']['files'][str(authority_path)]
    authenticate = guard.checked_source(authority_path, authority_pin)['prepare'](guard, endpoint)
    import asyncio.selector_events as selectors
    pipe = selectors.BaseSelectorEventLoop._make_self_pipe
    code = compile(Path(selectors.__file__).read_bytes(), selectors.__file__, 'exec', dont_inherit=True)
    endpoint_path = Path(endpoint.__file__)
    pin = state['direct_support']['files'][str(endpoint_path)]
    if hashlib.sha256(endpoint_path.read_bytes()).hexdigest() != pin:
        guard.refuse('self_pipe_endpoint_source_drift')
    expected = compile(endpoint_path.read_bytes(), str(endpoint_path), 'exec', dont_inherit=True)
    socket_code = compile(Path(socket.__file__).read_bytes(), socket.__file__, 'exec', dont_inherit=True)
    pair_code = named(expected, 'early.<locals>.socketpair')
    payload_code = named(expected, 'early.<locals>.payload')
    request_code = named(expected, 'request')
    if (pipe.__globals__ is not vars(selectors)
            or pipe.__code__ != named(code, 'BaseSelectorEventLoop._make_self_pipe')
            or socket.socketpair.__code__ != pair_code
            or socket.socketpair.__globals__ is not vars(endpoint)
            or endpoint.request.__code__ != request_code
            or endpoint.request.__globals__ is not vars(endpoint)
            or endpoint._CONTROL_GETSOCKOPT is not _socket.socket.getsockopt
            or endpoint._CONTROL_RECV is not _socket.socket.recv
            or socket.socket.close is not endpoint._CONTROL_CLOSE
            or endpoint._CONTROL_CLOSE.__globals__ is not vars(socket)
            or endpoint._CONTROL_CLOSE.__code__ != named(socket_code, 'socket.close')):
        guard.refuse('self_pipe_original_code_drift')
    bridge(endpoint, pipe, vars(selectors), pair_code, payload_code, guard.refuse, guard.append, authenticate)
    guard.append({'kind': 'self_pipe_receipt_lifetime', 'scope': 'existing SOURCE READY authority',
                  'authority_changed': False, 'lock_scope': 'local identity record only'})
