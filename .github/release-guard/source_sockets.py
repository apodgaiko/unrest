"""Mediation for the declared loopback listeners/connections and self-pipes."""
from __future__ import annotations

import asyncio.selector_events
import asyncio.unix_events
import os
import socket
import sys
import types

from bootstrap_cases import declaration
from content_manifest import Refused

TYPE = type


class Hooks:
    def __init__(self, policy):
        self.policy, self.local = policy, policy.local
        self.socket_type, self.base_type = socket.socket, socket.SocketType
        self.fd = socket.socket.fileno
        names = ('bind', 'listen', 'connect', 'connect_ex', 'accept', 'send', 'sendall',
                 'recv', 'recv_into', 'recvfrom', 'recvfrom_into')
        self.original = {name: getattr(socket.socket, name) for name in names}
        self.pair = socket.socketpair
        self.pipe = vars(asyncio.selector_events.BaseSelectorEventLoop)['_make_self_pipe']
        self.pipe_code, self.pipe_globals = self.pipe.__code__, self.pipe.__globals__
        self.loop_type = asyncio.unix_events._UnixSelectorEventLoop
        self.getaddrinfo = socket.getaddrinfo
        self.read, self.write = os.read, os.write

    def descriptor(self, stream):
        if type(stream) is not self.socket_type:
            raise Refused('source exact socket type')
        descriptor = self.fd(stream)
        if type(descriptor) is not int or descriptor < 0:
            raise Refused('source live socket descriptor')
        return descriptor

    def rpc(self, kind, payload):
        try:
            return self.policy.client.request(kind, payload)
        except BaseException:
            self.policy.poison = True
            raise

    def audit(self, event, args):
        if event == 'socket.__new__':
            if (len(args) != 4 or type(args[0]) not in (self.socket_type, self.base_type)
                    or any(type(value) is not int for value in args[1:])
                    or args[1] not in (socket.AF_INET, socket.AF_UNIX)
                    or args[2] & ~(socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) != socket.SOCK_STREAM
                    or args[3] not in (0, socket.IPPROTO_TCP)):
                raise Refused('source unknown socket constructor')
            if args[1] == socket.AF_UNIX:
                if args[3] != 0 or not (self.policy.private_call() or getattr(self.local, 'pair', None) is not None):
                    raise Refused('source Unix creation outside sealed self-pair')
            elif (self.policy.profile['role'] not in ('root', 'acp')
                    and not declaration(self.policy.profile['case']).broker_http):
                raise Refused('source backend network creation')
            return True
        pending = getattr(self.local, 'socket', None)
        if (event not in ('socket.bind', 'socket.connect') or len(args) != 2
                or pending is None or pending[0] != event or pending[1] is not args[0] or pending[2] != args[1]):
            raise Refused('source socket effect without admission')
        self.local.socket = None
        return True

    def call(self, name, stream, *args, **kwargs):
        descriptor = self.descriptor(stream)
        role = self.policy.profile['role']
        if name == 'bind':
            if role != 'root' or self.policy.calls is None or kwargs or args != (('127.0.0.1', 0),):
                self.policy.refuse('source unknown bind')
            source = self.policy.calls.listener()
            self.rpc('bind', {'fd': descriptor, **source})
            self.local.socket = 'socket.bind', stream, args[0]
        elif name in ('connect', 'connect_ex'):
            if (role != 'acp' and not declaration(self.policy.profile['case']).broker_http or kwargs or len(args) != 1 or type(args[0]) is not tuple
                    or len(args[0]) != 2 or type(args[0][0]) is not str or args[0][0] != '127.0.0.1'
                    or type(args[0][1]) is not int or not 0 < args[0][1] <= 65535):
                self.policy.refuse('source unknown connection')
            answer = self.rpc('connect', {'fd': descriptor, 'address': list(args[0])})
            self.local.socket = 'socket.connect', stream, args[0]
            try:
                result = self.original[name](stream, *args)
            except BlockingIOError:
                self.rpc('connected', {'fd': descriptor, 'ticket': answer['ticket']})
                raise
            finally:
                self.local.socket = None
            self.rpc('connected', {'fd': descriptor, 'ticket': answer['ticket']})
            return result
        elif name in ('send', 'sendall', 'recv', 'recv_into', 'recvfrom', 'recvfrom_into', 'accept'):
            count = 0
            if name in ('send', 'sendall'):
                if not args or type(args[0]) not in (bytes, bytearray, memoryview):
                    self.policy.refuse('source payload buffer type')
                count = args[0].nbytes if type(args[0]) is memoryview else len(args[0])
            answer = self.rpc('payload', {'fd': descriptor, 'operation': name, 'bytes': count})
            if answer.get('eof_only') is True:
                if (kwargs or name not in ('recv', 'recv_into') or not args
                        or name == 'recv' and (len(args) != 1 or type(args[0]) is not int or args[0] < 0)
                        or name == 'recv_into' and (len(args) > 2
                            or type(args[0]) not in (bytearray, memoryview)
                            or len(args) == 2 and (type(args[1]) is not int or args[1] < 0))):
                    self.policy.refuse('source EOF-only read flags or buffer')
        elif name == 'listen':
            if role != 'root' or kwargs or len(args) > 1 or args and (type(args[0]) is not int or not 0 <= args[0] <= 2048):
                self.policy.refuse('source listener operation')
            self.rpc('listen', {'fd': descriptor, 'stage': 'before'})
        else:
            self.policy.refuse('source unknown socket operation')
        try:
            result = self.original[name](stream, *args, **kwargs)
        finally:
            self.local.socket = None
        if name == 'listen':
            self.rpc('listen', {'fd': descriptor, 'stage': 'after'})
        elif name == 'accept':
            accepted, _ = result
            self.rpc('accepted', {'listener': descriptor, 'fd': self.descriptor(accepted)})
        return result

    def self_pair(self, family=socket.AF_UNIX, type=socket.SOCK_STREAM, proto=0):
        # No caller-controlled subclasses or flags turn this into another socket domain.
        if (TYPE(family) not in (int, socket.AddressFamily) or TYPE(type) not in (int, socket.SocketKind)
                or TYPE(proto) is not int or int.__int__(family) != socket.AF_UNIX
                or int.__int__(type) != socket.SOCK_STREAM or proto != 0):
            self.policy.refuse('source unknown self-pair domain')
        if (self.pipe.__code__ is not self.pipe_code
                or vars(asyncio.selector_events.BaseSelectorEventLoop)['_make_self_pipe'] is not self.pipe):
            self.policy.refuse('source changed loop self-pipe owner')
        frame: types.FrameType | None = sys._getframe(1)
        found = False
        for _ in range(64):
            if frame is None:
                break
            if (frame.f_code is self.pipe_code and frame.f_globals is self.pipe_globals
                    and TYPE(frame.f_locals.get('self')) is self.loop_type):
                found = True
                break
            frame = frame.f_back
            if frame is None:
                break
        if not found:
            self.policy.refuse('source original self-pipe callsite absent')
        ticket = self.rpc('pair-intent', {'site': 'asyncio-self-pipe'})['ticket']
        self.local.pair = ticket
        try:
            pair = self.pair(family, type, proto)
        finally:
            self.local.pair = None
        self.rpc('pair-seal', {'ticket': ticket, 'fds': [self.descriptor(stream) for stream in pair]})
        return pair

    def fd_io(self, function, descriptor, *args):
        if type(descriptor) is not int or descriptor < 0:
            self.policy.refuse('source file descriptor type')
        try:
            target = os.readlink('/proc/self/fd/' + str(descriptor))
        except FileNotFoundError:
            return function(descriptor, *args)  # Preserve the real EBADF, never claim a close/reap.
        if target.startswith('socket:['):
            count = 0
            if function is self.write:
                if not args or type(args[0]) not in (bytes, bytearray, memoryview):
                    self.policy.refuse('source file payload buffer type')
                count = args[0].nbytes if type(args[0]) is memoryview else len(args[0])
            answer = self.rpc('payload', {'fd': descriptor, 'operation': 'fd-read' if function is self.read else 'fd-write', 'bytes': count})
            if answer.get('eof_only') is True and (function is not self.read or len(args) != 1
                    or type(args[0]) is not int or args[0] < 0):
                self.policy.refuse('source EOF-only file read')
        return function(descriptor, *args)

    def literal_address(self, host, port, family=0, type=0, proto=0, flags=0):
        # This computes a literal tuple; it never calls a DNS resolver. The
        # subsequent connect still needs the observer's exact live route.
        if (TYPE(host) is not str or host != '127.0.0.1' or TYPE(port) is not int or not 0 < port <= 65535
                or TYPE(family) not in (int, socket.AddressFamily) or family not in (0, socket.AF_INET)
                or TYPE(type) not in (int, socket.SocketKind) or type not in (0, socket.SOCK_STREAM)
                or TYPE(proto) is not int or proto not in (0, socket.IPPROTO_TCP)
                or TYPE(flags) is not int or flags != 0):
            self.policy.refuse('source nonliteral address query')
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (host, port))]

    def install(self):
        hooks = self
        def wrap(name):
            def operation(stream, *args, **kwargs):
                return hooks.call(name, stream, *args, **kwargs)
            return operation
        for name in self.original:
            setattr(self.socket_type, name, wrap(name))
        socket.socketpair = self.self_pair
        socket.getaddrinfo = self.literal_address
        def read(descriptor, count):
            return hooks.fd_io(hooks.read, descriptor, count)
        def write(descriptor, data):
            return hooks.fd_io(hooks.write, descriptor, data)
        os.read, os.write = read, write
