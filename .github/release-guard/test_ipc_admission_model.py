"""Admission containment retains ownership; payload certification is retired."""
from types import SimpleNamespace
import os
import socket
import threading


from source_sockets import Hooks
from source_profile import METHODS


def test_installed_hooks_leave_kernel_stream_and_file_io_operations_ordinary(monkeypatch):
    from multiprocessing.connection import Connection
    payload={name:getattr(socket.socket,name) for name in ('send','sendall','recv','recv_into','accept')}
    files=os.read,os.write
    connection=getattr(Connection,'_send'),getattr(Connection,'_recv')
    for name in ('bind','listen','connect','connect_ex','__init__'):
        monkeypatch.setattr(socket.socket,name,getattr(socket.socket,name))
    for name in ('socketpair','getaddrinfo'):
        monkeypatch.setattr(socket,name,getattr(socket,name))
    hooks=Hooks(SimpleNamespace(local=threading.local()))
    hooks.install()
    assert payload=={name:getattr(socket.socket,name) for name in payload}
    assert (os.read,os.write)==files
    assert (getattr(Connection,'_send'),getattr(Connection,'_recv'))==connection
    assert not {'payload','connected','accepted'} & METHODS
