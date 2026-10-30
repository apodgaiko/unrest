"""Installed socket wrappers poison local refusals, preserving ordinary IO errors."""
from types import SimpleNamespace
import pytest

from content_manifest import Refused
from source_entry import Policy
from source_sockets import Hooks
import source_sockets


@pytest.fixture
def installed(monkeypatch):
    class Socket:
        family=2
        def __init__(self,family=-1,type=-1,proto=-1,fileno=None):
            pass
        def bind(self,*args,**kwargs):
            return None
    policy=object.__new__(Policy)
    policy.poison=False
    records=[]
    policy.client=SimpleNamespace(request=lambda kind,payload:records.append((kind,payload)))
    hooks=object.__new__(Hooks)
    hooks.policy=policy
    hooks.socket_type=hooks.base_type=Socket
    hooks.fd=lambda stream:1
    hooks.original={'bind':Socket.bind}
    hooks.self_pair=lambda *args:None
    hooks.literal_address=lambda *args:None
    hooks.read=lambda *args:None
    hooks.write=lambda *args:None
    monkeypatch.setattr(source_sockets,'socket',SimpleNamespace(socket=Socket))
    hooks.install()
    return hooks,policy,records,Socket


def test_caught_literal_network_audit_refusal_is_sticky(installed):
    hooks,policy,records,Socket=installed
    hooks.base_type=Socket
    policy.sockets=hooks
    with pytest.raises(Refused,match='unsupported socket effect'):
        policy.audit('socket.bind',(object(),('127.0.0.1',0)))
    assert policy.poison
    assert [kind for kind,_ in records]==['guard-refusal']


def test_ordinary_io_error_is_not_converted_to_guard_refusal(installed,monkeypatch):
    hooks,policy,records,Socket=installed
    def failed(*args,**kwargs):
        raise OSError(9,'closed descriptor')
    monkeypatch.setattr(Socket,'bind',failed)
    with pytest.raises(OSError) as caught:
        Socket().bind(('127.0.0.1',0))
    assert caught.value.errno==9
    assert not policy.poison and not records


def test_caught_pair_descriptor_refusal_is_sticky(installed):
    hooks,policy,records,_=installed
    hooks.self_pair=lambda *args,**kwargs:(_ for _ in ()).throw(Refused('unknown self-pair domain'))
    with pytest.raises(Refused,match='unknown self-pair domain'):
        source_sockets.socket.socketpair()
    assert policy.poison
    assert [kind for kind,_ in records]==['guard-refusal']


def test_existing_guard_poison_is_not_reported_twice(installed):
    hooks,policy,records,Socket=installed
    policy.poison=True
    hooks.self_pair=lambda *args,**kwargs:(_ for _ in ()).throw(Refused('unknown self-pair domain'))
    with pytest.raises(Refused):
        source_sockets.socket.socketpair()
    assert policy.poison and not records


def test_wrapper_preserves_bound_method_name_and_receiver(installed):
    _,_,_,Socket=installed
    value=Socket()
    assert value.bind.__name__=='bind' and value.bind.__self__ is value
