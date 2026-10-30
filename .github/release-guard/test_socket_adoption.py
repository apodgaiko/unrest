"""Descriptor inspection permits no new endpoint or negative-default escape."""

import os
import socket
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import METHOD_CASES, NETWORK_CASES
from source_sockets import Hooks
import source_sockets


@pytest.fixture
def adoption(monkeypatch):
    calls = []

    class Socket:
        family=1
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
    hooks.original = {}
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
    hooks.install()
    return hooks, Socket, calls


def test_wrapping_preserves_the_original_initializer_and_fd(adoption):
    hooks, Socket, calls = adoption
    left, right = socket.socketpair()
    try:
        fd = os.dup(left.fileno())
        try:
            before = os.fstat(fd)
            value = Socket(fileno=fd)
            assert value.fileno() == fd
            assert calls == [(-1, -1, -1, fd)]
            assert os.fstat(fd) == before
            assert hooks.audit("socket.__new__", (value, -1, -1, -1)) is True
        finally:
            os.close(fd)
    finally:
        left.close()
        right.close()


def test_default_construction_uses_the_original_initializer(adoption):
    hooks,Socket,calls=adoption
    value=Socket()
    assert calls==[(-1,-1,-1,None)] and value.fileno() is None
    assert hooks.audit('socket.__new__',(value,-1,-1,-1)) is True


def test_adoption_does_not_allow_network_effects(adoption):
    hooks, Socket, _ = adoption
    value = Socket.__new__(Socket)
    for event in ("socket.bind", "socket.connect", "socket.sendto"):
        with pytest.raises(Refused):
            hooks.audit(event, (value, ("127.0.0.1", 1234)))


@pytest.mark.parametrize("case", NETWORK_CASES)
def test_isolated_preflight_stream_families_do_not_have_tcp_quotas(adoption,case):
    hooks,Socket,_=adoption
    hooks.policy.profile['case']=case
    value=Socket.__new__(Socket)
    with pytest.raises(Refused):
        hooks.audit('socket.__new__',(value,17,1,0))
    for family in (2,10):
        assert hooks.audit('socket.__new__',(value,family,1,0)) is True
        assert hooks.audit('socket.__new__',(value,family,1,0)) is True


def test_unbound_ipv6_is_not_granted_to_an_alias_case(adoption):
    hooks, Socket, _ = adoption
    with pytest.raises(Refused):
        hooks.audit("socket.__new__", (Socket.__new__(Socket), 10, 1, 0))
