"""Literal isolated loopback and anonymous Unix stream pairs."""
from __future__ import annotations

import errno
import os
import socket
import stat

from content_manifest import Refused
from http_cases import TRANSPORT as MCP_CASES
from fixed_inline import NETWORK_CASES, METHOD_CASES
from speed_inline import CASES as SPEED_CASES, CLI_CASE
from nested_pytest import CASE as NESTED_CASE

from readiness_launch import READY

TYPE = type


class Hooks:
    def __init__(self, policy):
        self.policy, self.local = policy, policy.local
        self.socket_type, self.base_type = socket.socket, socket.SocketType
        self.fd = socket.socket.fileno
        self.original={name:getattr(socket.socket,name) for name in ('bind','connect','connect_ex')}
        self.pair = socket.socketpair
        self.getaddrinfo = socket.getaddrinfo

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
            isolated = self.policy.profile['role']=='fixed-inline' and self.policy.profile['case'] in (*NETWORK_CASES,READY)
            if (len(args) != 4 or type(args[0]) not in (self.socket_type, self.base_type)
                    or any(type(value) is not int for value in args[1:])
                    or args[1] not in ((socket.AF_INET, socket.AF_INET6, socket.AF_UNIX) if isolated else (socket.AF_INET, socket.AF_UNIX))
                    or args[2] & ~(socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) != socket.SOCK_STREAM
                    or args[3] not in (0, socket.IPPROTO_TCP)):
                raise Refused('source unknown socket constructor')
            if args[1] == socket.AF_UNIX:
                if args[3] != 0 or not (self.policy.private_call() or getattr(self.local, 'pair', None) is not None):
                    raise Refused('source Unix creation outside sealed self-pair')
            return True
        if (event not in ('socket.bind','socket.connect') or len(args)!=2
                or TYPE(args[0]) not in (self.socket_type,self.base_type)
                or args[0].family!=socket.AF_INET):
            raise Refused('source unsupported socket effect')
        from network_scope import address
        address(args[1],bind=event=='socket.bind')
        return True

    def call(self,name,stream,*args,**kwargs):
        # CPython resolves addresses before its audit event. Validate first.
        if (TYPE(stream) not in (self.socket_type,self.base_type) or stream.family!=socket.AF_INET
                or kwargs or len(args)!=1):
            raise Refused('source unsupported socket effect')
        from network_scope import address
        address(args[0],bind=name=='bind')
        return self.original[name](stream,*args)

    def self_pair(self, family=socket.AF_UNIX, type=socket.SOCK_STREAM, proto=0):
        # No caller-controlled subclasses or flags turn this into another socket domain.
        if (TYPE(family) not in (int, socket.AddressFamily) or TYPE(type) not in (int, socket.SocketKind)
                or TYPE(proto) is not int or int.__int__(family) != socket.AF_UNIX
                or int.__int__(type) != socket.SOCK_STREAM or proto != 0):
            self.policy.refuse('source unknown self-pair domain')
        self.local.pair = True
        try:
            pair = self.pair(family, type, proto)
        finally:
            self.local.pair = None
        return pair

    def literal_address(self, host, port, family=0, type=0, proto=0, flags=0):
        if (self.policy.profile['role']=='fixed-inline' and self.policy.profile['case']==SPEED_CASES[0]
                and (host,port,family,type,proto,flags)==('alias-guard.invalid',443,0,0,0,0)):
            return self.getaddrinfo(host,port,family,type,proto,flags)
        # This computes a literal tuple; it never calls a DNS resolver. The
        # subsequent connect is confined to the run's private loopback stack.
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
                    and hooks.policy.profile['role'] in ('fixed-inline','pytest-regression')
                    and hooks.policy.profile['case'] in (*METHOD_CASES,*NETWORK_CASES,*SPEED_CASES,CLI_CASE,NESTED_CASE)):
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
            def operation(stream,*args,**kwargs):
                return hooks.guarded(hooks.call,name,stream,*args,**kwargs)
            operation.__name__=name
            return operation
        for name in self.original:
            setattr(self.socket_type,name,wrap(name))
        def pair(*args, **kwargs):
            return hooks.guarded(hooks.self_pair, *args, **kwargs)
        socket.socketpair = pair
        socket.getaddrinfo = self.literal_address
