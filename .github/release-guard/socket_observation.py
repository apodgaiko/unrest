"""Actual unnamed Unix stream descriptions, not inferred peer lineage."""
import ctypes
import fcntl
import os
import socket
import stat
import struct
import sys

from content_manifest import Refused
from linux_observation import pidfd_open,process_identity
from process_ledger import Birth


def descriptor(fd,uid):
    before=os.fstat(fd)
    flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid!=uid
            or flags&~os.O_CLOEXEC!=os.O_RDWR):
        raise Refused('inherited Unix stream file custody')
    copied=os.dup(fd)
    stream=None
    try:
        stream=socket.socket(fileno=copied)
        if (stream.getsockopt(socket.SOL_SOCKET,39)!=socket.AF_UNIX
                or stream.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM
                or stream.getsockname() not in ('',b'') or stream.getpeername() not in ('',b'')
                or struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1:]!=(uid,uid)):
            raise Refused('inherited unnamed Unix stream domain')
        cookie=struct.unpack('=Q',stream.getsockopt(socket.SOL_SOCKET,57,8))[0]
    finally:
        if stream is None:
            os.close(copied)
        else:
            stream.close()
    after=os.fstat(fd)
    if (before.st_dev,before.st_ino,before.st_uid)!=(after.st_dev,after.st_ino,after.st_uid) or not 0<cookie<(1<<64)-1:
        raise Refused('inherited Unix stream generation')
    return [before.st_dev,before.st_ino,os.O_RDWR,cookie]


def pipe_info(info,flags,uid):
    if (type(info) is not os.stat_result or type(flags) is not int or type(uid) is not int
            or flags & ~os.O_CLOEXEC or not stat.S_ISFIFO(info.st_mode) or info.st_uid!=uid):
        raise Refused('inherited descriptor must be a blocking read pipe')
    return [info.st_dev,info.st_ino]


def pipe_descriptor(fd,uid):
    return pipe_info(os.fstat(fd),fcntl.fcntl(fd,fcntl.F_GETFL),uid)


def acquire(birth,fd,inspect=descriptor):
    if (sys.platform!='linux' or os.uname().machine!='x86_64'
            or type(birth) is not Birth or type(fd) is not int or not 3<=fd<=1024):
        raise Refused('inherited Unix stream acquisition operands')
    if Birth.read(process_identity(birth.pid))!=birth:
        raise Refused('inherited Unix stream birth changed')
    process=pidfd_open(birth.pid)
    try:
        libc=ctypes.CDLL(None,use_errno=True)
        copied=libc.syscall(438,process,fd,0)  # Linux/x86-64 pidfd_getfd.
        if copied<0:
            raise OSError(ctypes.get_errno(),'inherited Unix stream acquisition refused')
        try:
            value=inspect(copied,birth.uid)
            current=os.stat('/proc/'+str(birth.pid)+'/fd/'+str(fd))
            if [current.st_dev,current.st_ino]!=value[:2]:
                raise Refused('inherited Unix stream descriptor replaced')
        finally:
            os.close(copied)
    finally:
        os.close(process)
    if Birth.read(process_identity(birth.pid))!=birth:
        raise Refused('inherited Unix stream birth changed')
    return [fd,*value]
