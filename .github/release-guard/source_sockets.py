"""Mediation for the declared loopback listeners/connections and self-pipes."""
from __future__ import annotations

import errno
import os
import socket
import stat

from bootstrap_cases import declaration
from controlled_cases import CASES as CONTROLLED, ROOT_HTTP
from controlled_pairs import limits as controlled_limits
from content_manifest import Refused
from http_cases import CASES as HTTP_CASES, TRANSPORT as MCP_CASES
from cleanup_inline import STARTUP
from fixed_inline import NETWORK, NETWORK_CASES, METHOD_CASES

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
        self.getaddrinfo = socket.getaddrinfo
        self.read, self.write = os.read, os.write
        self.unbound_created = False

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
            adoption=getattr(self.local,'adoption',None)
            if (len(args)==4 and adoption is not None and TYPE(args[0]) is self.socket_type and args[0] is adoption[0]
                    and all(TYPE(value) is int and value==-1 for value in args[1:])):
                info=os.fstat(adoption[1])
                if (info.st_dev,info.st_ino,info.st_mode,info.st_uid)!=adoption[2]:
                    raise Refused('source socket adoption generation')
                self.local.adoption=None
                return True
            isolated = self.policy.profile['role']=='fixed-inline' and self.policy.profile['case'] in NETWORK_CASES
            if (len(args) != 4 or type(args[0]) not in (self.socket_type, self.base_type)
                    or any(type(value) is not int for value in args[1:])
                    or args[1] not in ((socket.AF_INET, socket.AF_INET6, socket.AF_UNIX) if isolated else (socket.AF_INET, socket.AF_UNIX))
                    or args[2] & ~(socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) != socket.SOCK_STREAM
                    or args[3] not in (0, socket.IPPROTO_TCP)):
                raise Refused('source unknown socket constructor')
            if args[1] == socket.AF_UNIX:
                if args[3] != 0 or not (self.policy.private_call() or getattr(self.local, 'pair', None) is not None):
                    raise Refused('source Unix creation outside sealed self-pair')
            elif isolated:
                family = NETWORK.get(self.policy.profile['case'],(socket.AF_INET,False))[0]
                if args[1]!=family or self.unbound_created:
                    raise Refused('source isolated one unbound socket family')
                self.unbound_created=True
            elif (self.policy.profile['role'] not in ('root', 'acp', 'mcp', 'cleanup-acp')
                    and not (controlled_limits(self.policy.profile['case'])[1] > 0 if self.policy.profile['case'] in CONTROLLED else declaration(self.policy.profile['case']).broker_http)):
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
            if role == 'mcp':
                if kwargs or args != (('127.0.0.1', int(self.policy.profile['argv'][12])),):
                    self.policy.refuse('source unknown module listener')
                source = {'tag': 'mcp', 'nonce': None}
            else:
                if role != 'root' or self.policy.calls is None or kwargs or args != (('127.0.0.1', 0),):
                    self.policy.refuse('source unknown bind')
                source = self.policy.calls.listener()
            self.rpc('bind', {'fd': descriptor, **source})
            self.local.socket = 'socket.bind', stream, args[0]
        elif name in ('connect', 'connect_ex'):
            cleanup = self.policy.case in (*MCP_CASES, *STARTUP) or self.policy.profile['case'] in (*MCP_CASES, *STARTUP)
            if ((role not in ('root', 'cleanup-acp') if cleanup else role != 'acp' and not (role == 'root' and self.policy.case in ROOT_HTTP) and not (controlled_limits(self.policy.profile['case'])[1] > 0 if self.policy.profile['case'] in CONTROLLED else declaration(self.policy.profile['case']).broker_http)) or kwargs or len(args) != 1 or type(args[0]) is not tuple
                    or len(args[0]) != 2 or type(args[0][0]) is not str or args[0][0] != '127.0.0.1'
                    or type(args[0][1]) is not int or not 0 < args[0][1] <= 65535):
                self.policy.refuse('source unknown connection')
            context = self.policy.calls.connection(args[0][1]) if role == 'root' and self.policy.case in ROOT_HTTP else None
            answer = self.rpc('connect', {'fd': descriptor, 'address': list(args[0]),
                **({'context':context} if context is not None else {})})
            probe = answer.get('probe') is True
            if probe and (role != 'root' or self.policy.case not in STARTUP):
                self.policy.refuse('source negative probe context')
            self.local.socket = 'socket.connect', stream, args[0]
            try:
                result = self.original[name](stream, *args)
            except BlockingIOError:
                if not probe:
                    self.rpc('connected', {'fd': descriptor, 'ticket': answer['ticket']})
                raise
            finally:
                self.local.socket = None
            if probe:
                if type(result) is not int or result not in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.ECONNREFUSED):
                    self.policy.refuse('source negative probe unexpectedly connected')
                return result
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
            if role not in ('root', 'mcp') or kwargs or len(args) > 1 or args and (type(args[0]) is not int or not 0 <= args[0] <= 2048):
                self.policy.refuse('source listener operation')
            self.rpc('listen', {'fd': descriptor, 'stage': 'before'})
        else:
            self.policy.refuse('source unknown socket operation')
        try:
            result = self.original[name](stream, *args, **kwargs)
        finally:
            self.local.socket = None
        if name == 'bind' and role == 'root' and self.policy.case in (*STARTUP,*HTTP_CASES):
            self.rpc('bound', {'fd': descriptor})
        elif name == 'listen':
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
        ticket = self.rpc('pair-intent', {'site':'local-stream-pair'})['ticket']
        self.local.pair = ticket
        try:
            pair = self.pair(family, type, proto)
        finally:
            self.local.pair = None
        self.rpc('pair-seal', {'ticket': ticket, 'fds': [self.descriptor(stream) for stream in pair]})
        return pair

    def fd_io(self, function, descriptor, *args, writing=None):
        if type(descriptor) is not int:
            self.policy.refuse('source file descriptor type')
        if descriptor < 0:
            return function(descriptor, *args)  # Preserve the kernel's EBADF; no live FD is reachable.
        try:
            target = os.readlink('/proc/self/fd/' + str(descriptor))
        except FileNotFoundError:
            return function(descriptor, *args)  # Preserve the real EBADF, never claim a close/reap.
        if target.startswith('socket:['):
            is_write=(function is self.write) if writing is None else writing
            count = 0
            if is_write:
                if not args or type(args[0]) not in (bytes, bytearray, memoryview):
                    self.policy.refuse('source file payload buffer type')
                count = args[0].nbytes if type(args[0]) is memoryview else len(args[0])
            answer = self.rpc('payload', {'fd': descriptor, 'operation':'fd-write' if is_write else 'fd-read', 'bytes': count})
            if answer.get('eof_only') is True and (function is not self.read or len(args) != 1
                    or type(args[0]) is not int or args[0] < 0):
                self.policy.refuse('source EOF-only file read')
        return function(descriptor, *args)

    def literal_address(self, host, port, family=0, type=0, proto=0, flags=0):
        # This computes a literal tuple; it never calls a DNS resolver. The
        # subsequent connect still needs the observer's exact live route.
        http = self.policy.case in MCP_CASES or self.policy.profile['case'] in MCP_CASES
        if http and TYPE(host) is bytes and host==b'127.0.0.1':
            host='127.0.0.1'
        if http and TYPE(port) is str and port.isascii() and port.isdigit() and 0<len(port)<=5:
            port=int(port)
        if (TYPE(host) is not str or host != '127.0.0.1' or TYPE(port) is not int or not 0 < port <= 65535
                or TYPE(family) not in (int, socket.AddressFamily) or family not in (0, socket.AF_INET)
                or TYPE(type) not in (int, socket.SocketKind) or type not in (0, socket.SOCK_STREAM)
                or TYPE(proto) is not int or proto not in (0, socket.IPPROTO_TCP)
                or TYPE(flags) not in (int,socket.AddressInfo) or int.__int__(flags) not in ((0,socket.AI_PASSIVE,socket.AI_PASSIVE|socket.AI_ADDRCONFIG) if http else (0,))):
            def number(value):
                if TYPE(value) not in (int,socket.AddressFamily,socket.SocketKind,socket.AddressInfo):
                    return 'other'
                value=int.__int__(value)
                return str(value) if 0<=value<=65535 else 'outside'
            label={'127.0.0.1':'ipv4','0.0.0.0':'any4','::1':'ipv6','localhost':'localhost'}.get(host,'other') if TYPE(host) is str else 'nontext'
            self.policy.refuse('source nonliteral address query '+label+' '+' '.join(number(value) for value in (port,family,type,proto,flags)))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (host, port))]

    def guarded(self, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Refused as error:
            if not self.policy.poison:
                self.policy.refuse(str(error))
            raise

    def install(self):
        hooks = self
        original_init=hooks.socket_type.__init__
        def initialize(stream,family=-1,type=-1,proto=-1,fileno=None):
            adoption=None
            if (fileno is not None and family==type==proto==-1
                    and hooks.policy.profile['role']=='fixed-inline'
                    and hooks.policy.profile['case'] in (*METHOD_CASES,*NETWORK_CASES)):
                if (TYPE(stream) is not hooks.socket_type or any(TYPE(value) is not int for value in (family,type,proto))
                        or TYPE(fileno) is not int or fileno<0 or getattr(hooks.local,'adoption',None) is not None):
                    hooks.policy.refuse('source socket adoption operand')
                info=os.fstat(fileno)
                if not stat.S_ISSOCK(info.st_mode):
                    raise OSError(errno.ENOTSOCK,'not a socket')
                adoption=(stream,fileno,(info.st_dev,info.st_ino,info.st_mode,info.st_uid))
                hooks.local.adoption=adoption
            try:
                original_init(stream,family,type,proto,fileno)
                if adoption is not None:
                    info=os.fstat(fileno)
                    if hooks.local.adoption is not None or hooks.fd(stream)!=fileno or (info.st_dev,info.st_ino,info.st_mode,info.st_uid)!=adoption[2]:
                        hooks.policy.refuse('source socket adoption completion')
            finally:
                if adoption is not None:
                    hooks.local.adoption=None
        hooks.socket_type.__init__=initialize
        def wrap(name):
            def operation(stream, *args, **kwargs):
                return hooks.guarded(hooks.call, name, stream, *args, **kwargs)
            return operation
        for name in self.original:
            setattr(self.socket_type, name, wrap(name))
        def pair(*args, **kwargs):
            return hooks.guarded(hooks.self_pair, *args, **kwargs)
        socket.socketpair = pair
        socket.getaddrinfo = self.literal_address
        def read(descriptor, count):
            return hooks.fd_io(hooks.read, descriptor, count)
        def write(descriptor, data):
            return hooks.fd_io(hooks.write, descriptor, data)
        os.read, os.write = read, write

        return read,write,self.fd_io
