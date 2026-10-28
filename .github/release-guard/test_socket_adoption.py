"""Descriptor inspection permits no new endpoint or negative-default escape."""

import errno
import os
import socket
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import METHOD_CASES, NETWORK, NETWORK_CASES
from source_sockets import Hooks
import source_sockets


@pytest.fixture
def adoption(monkeypatch):
    calls = []

    class Socket:
        def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
            calls.append((family, type, proto, fileno))
            hooks.audit("socket.__new__", (self, family, type, proto))
            self.fd = fileno

        def fileno(self):
            return self.fd

    policy = SimpleNamespace(
        profile={"role": "fixed-inline", "case": METHOD_CASES[0]},
        local=SimpleNamespace(),
        private_call=lambda: False,
    )

    def refuse(code):
        raise Refused(code)

    policy.refuse = refuse
    hooks = object.__new__(Hooks)
    hooks.policy, hooks.local = policy, policy.local
    hooks.socket_type = hooks.base_type = Socket
    hooks.fd = Socket.fileno
    hooks.original = {}
    hooks.read, hooks.write = os.read, os.write
    monkeypatch.setattr(
        source_sockets,
        "socket",
        SimpleNamespace(
            socket=Socket,
            AF_INET=2,
            AF_INET6=10,
            AF_UNIX=1,
            SOCK_STREAM=socket.SOCK_STREAM,
            SOCK_NONBLOCK=getattr(socket, "SOCK_NONBLOCK", 2048),
            SOCK_CLOEXEC=getattr(socket, "SOCK_CLOEXEC", 0),
            IPPROTO_TCP=socket.IPPROTO_TCP,
        ),
    )
    monkeypatch.setattr(
        source_sockets, "os", SimpleNamespace(read=os.read, write=os.write, fstat=os.fstat)
    )
    hooks.install()
    return hooks, Socket, calls


def test_adoption_uses_same_socket_fd_and_consumes_single_use_ticket(adoption):
    hooks, Socket, calls = adoption
    left, right = socket.socketpair()
    try:
        fd = os.dup(left.fileno())
        try:
            before = os.fstat(fd)
            value = Socket(fileno=fd)
            assert value.fileno() == fd
            assert calls == [(-1, -1, -1, fd)]
            assert os.fstat(fd) == before and hooks.local.adoption is None
            with pytest.raises(Refused):
                hooks.audit("socket.__new__", (value, -1, -1, -1))
        finally:
            os.close(fd)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("fd", (-1, True, False))
def test_invalid_descriptor_adoption_refuses_before_initializer(adoption, fd):
    hooks, Socket, calls = adoption
    with pytest.raises(Refused):
        Socket(fileno=fd)
    assert not calls and getattr(hooks.local, "adoption", None) is None


def test_pipe_scan_preserves_enotsock_without_calling_socket_initializer(adoption):
    hooks, Socket, calls = adoption
    read, write = os.pipe()
    try:
        with pytest.raises(OSError) as error:
            Socket(fileno=read)
        assert error.value.errno == errno.ENOTSOCK and not calls
    finally:
        os.close(read)
        os.close(write)


def test_negative_defaults_without_adoption_are_not_a_new_socket_permission(adoption):
    hooks, Socket, _ = adoption
    with pytest.raises(Refused):
        Socket()
    with pytest.raises(Refused):
        hooks.audit("socket.__new__", (Socket.__new__(Socket), -1, -1, -1))


def test_adoption_does_not_allow_network_effects(adoption):
    hooks, Socket, _ = adoption
    value = Socket.__new__(Socket)
    for event in ("socket.bind", "socket.connect", "socket.sendto"):
        with pytest.raises(Refused):
            hooks.audit(event, (value, ("127.0.0.1", 1234)))


@pytest.mark.parametrize("mutation", ("identity", "object", "pending"))
def test_stale_foreign_and_reused_adoptions_refuse(adoption, mutation):
    hooks, Socket, calls = adoption
    left, right = socket.socketpair()
    try:
        fd = left.fileno()
        info = os.fstat(fd)
        value = Socket.__new__(Socket)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid)
        hooks.local.adoption = (value, fd, identity if mutation != "identity" else (0, 0, 0, 0))
        with pytest.raises(Refused):
            if mutation == "pending":
                Socket(fileno=fd)
            else:
                hooks.audit(
                    "socket.__new__",
                    (Socket.__new__(Socket) if mutation == "object" else value, -1, -1, -1),
                )
        assert not calls
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("case", NETWORK_CASES)
def test_only_one_exact_unbound_family_is_permitted(adoption, case):
    hooks, Socket, _ = adoption
    hooks.policy.profile["case"] = case
    hooks.unbound_created = False
    family = NETWORK.get(case, (2, False))[0]
    value = Socket.__new__(Socket)
    with pytest.raises(Refused):
        hooks.audit("socket.__new__", (value, 10 if family == 2 else 2, 1, 0))
    assert not hooks.unbound_created
    assert hooks.audit("socket.__new__", (value, family, 1, 0)) is True
    assert hooks.unbound_created
    with pytest.raises(Refused):
        hooks.audit("socket.__new__", (value, family, 1, 0))


def test_unbound_ipv6_is_not_granted_to_an_alias_case(adoption):
    hooks, Socket, _ = adoption
    with pytest.raises(Refused):
        hooks.audit("socket.__new__", (Socket.__new__(Socket), 10, 1, 0))
