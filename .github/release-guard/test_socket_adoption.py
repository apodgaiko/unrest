"""Ordinary socket adoption retains actual descriptors and normal IO errors."""
import os
import socket


def test_wrapping_preserves_the_original_descriptor():
    left,right=socket.socketpair()
    with left,right:
        fd=os.dup(left.fileno())
        before=os.fstat(fd)
        with socket.socket(fileno=fd) as adopted:
            assert adopted.fileno()==fd and os.fstat(fd)==before
            adopted.sendall(b'private')
            assert right.recv(7)==b'private'


def test_ordinary_io_error_is_not_converted_to_guard_refusal():
    import pytest
    stream=socket.socket()
    stream.close()
    with pytest.raises(OSError) as caught:
        stream.bind(('127.0.0.1',0))
    assert caught.value.errno==9
