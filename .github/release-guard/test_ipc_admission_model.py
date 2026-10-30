"""Admission containment retains ownership; payload certification is retired."""
import os
import socket


from source_profile import METHODS


def test_bootstrap_leaves_kernel_stream_and_file_io_operations_ordinary():
    from multiprocessing.connection import Connection
    payload={name:getattr(socket.socket,name) for name in ('send','sendall','recv','recv_into','accept')}
    files=os.read,os.write
    connection=getattr(Connection,'_send'),getattr(Connection,'_recv')
    __import__('source_entry')
    assert payload=={name:getattr(socket.socket,name) for name in payload}
    assert (os.read,os.write)==files
    assert (getattr(Connection,'_send'),getattr(Connection,'_recv'))==connection
    assert not {'payload','connected','accepted'} & METHODS
