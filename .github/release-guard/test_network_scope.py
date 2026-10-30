"""Retained literal-address and namespace boundaries; TCP topology is retired."""
from pathlib import Path

import pytest

from content_manifest import Refused
from network_scope import address,isolated,port_argument


@pytest.mark.parametrize('value',('localhost',('localhost',80),('::1',80),('0.0.0.0',80),
    ('127.0.0.1',True),('127.0.0.1',-1),('127.0.0.1',65536),['127.0.0.1',80],object()))
def test_nonliteral_tcp_effects_are_refused(value):
    with pytest.raises(Refused):
        address(value,bind=True)


def test_literal_loopback_is_ordinary_within_the_isolated_run():
    assert address(('127.0.0.1',0),bind=True)==('127.0.0.1',0)
    assert address(('127.0.0.1',65535))==('127.0.0.1',65535)
    with pytest.raises(Refused):
        address(('127.0.0.1',0))


@pytest.mark.parametrize('value',('',0,'0','65536','service','١٢','+1',' 1','1\x00'))
def test_dynamic_application_ports_remain_bounded_literals(value):
    with pytest.raises(Refused):
        port_argument(value)
    assert port_argument('12345')==12345


@pytest.mark.parametrize('mutation',(None,'same','interface','gateway4','interface4','route6','gateway6'))
def test_network_generation_has_only_loopback_and_no_external_routes(monkeypatch,mutation):
    from types import SimpleNamespace
    import network_scope
    namespace='net:[123]'
    dev='header\nheader\nlo: counters\n'+('eth0: counters\n' if mutation=='interface' else '')
    ipv4='header\n'
    if mutation in ('gateway4','interface4'):
        ipv4+=('eth0' if mutation=='interface4' else 'lo')+' 00000000 '+('0100007F' if mutation=='gateway4' else '00000000')+' 0001 0 0 0 00000000 0 0 0\n'
    ipv6=('0'*32 if mutation=='route6' else '0'*31+'1')+' 80 '+'0'*32+' 00 '+('0'*31+'1' if mutation=='gateway6' else '0'*32)+' 00000000 00000000 00000000 00000001 lo\n'
    bodies={'/proc/self/net/dev':dev,'/proc/net/route':ipv4,'/proc/net/ipv6_route':ipv6}
    monkeypatch.setattr(network_scope,'os',SimpleNamespace(readlink=lambda path:namespace))
    monkeypatch.setattr(Path,'read_text',lambda path:bodies[str(path)])
    if mutation is None:
        assert isolated('net:[122]')==namespace
    else:
        with pytest.raises(Refused):
            isolated(namespace if mutation=='same' else 'net:[122]')


@pytest.mark.parametrize('method',('bind','connect','connect_ex'))
@pytest.mark.parametrize('host',('localhost','alias-guard.invalid','::1','0.0.0.0'))
def test_pre_resolution_wrapper_refuses_before_any_original_socket_call(method,host):
    from source_sockets import Hooks
    calls=[]
    class Socket:
        family=2
    hooks=object.__new__(Hooks)
    hooks.socket_type=hooks.base_type=Socket
    hooks.original={method:lambda *args:calls.append(args)}
    with pytest.raises(Refused):
        hooks.call(method,Socket(),(host,12345))
    assert not calls
    hooks.call(method,Socket(),('127.0.0.1',12345))
    assert len(calls)==1


@pytest.mark.parametrize('branch',('plan','full','ordinary'))
def test_every_exec_branch_rejects_foreign_network_namespace_before_delegation(monkeypatch,branch):
    from types import SimpleNamespace
    import source_observer
    from plan_launch import CASES
    from source_observer import Observer
    host=SimpleNamespace(meta={'network_namespace':'net:[123]'},case=CASES[0] if branch=='plan' else 'ordinary',
                         full=branch=='full',full_started=False)
    monkeypatch.setattr(source_observer,'os',SimpleNamespace(readlink=lambda path:'mnt:[123]'))
    monkeypatch.setattr(source_observer,'process_identity',lambda pid:{'namespaces':{'mnt':'mnt:[123]','net':'net:[foreign]'}})
    assert Observer.resolve(host,None,123,'/native',[],{},'/') is False


@pytest.mark.parametrize('triple',[(-1,-1,-1),(True,-1,-1),(-1,True,-1),(-1,-1,True),(-1,-1,0)])
def test_default_socket_adoption_does_not_select_a_case_or_grant_effects(triple):
    import socket
    import threading
    from types import SimpleNamespace
    from source_sockets import Hooks
    policy=SimpleNamespace(local=threading.local(),profile={'role':'root','case':'ordinary'},
        private_call=lambda:False)
    hooks=Hooks(policy)
    with socket.socket() as stream:
        if triple==(-1,-1,-1):
            assert hooks.audit('socket.__new__',(stream,*triple)) is True
        else:
            with pytest.raises(Refused):
                hooks.audit('socket.__new__',(stream,*triple))
        for target in (('localhost',12345),('0.0.0.0',12345),('::1',12345)):
            with pytest.raises(Refused):
                hooks.audit('socket.connect',(stream,target))
    left,right=socket.socketpair()
    with left,right:
        with pytest.raises(Refused):
            hooks.audit('socket.connect',(left,'/host/service.sock'))


def test_socket_adoption_uses_normal_os_errors_and_preserves_private_pairs(tmp_path):
    import errno
    import os
    import socket
    left,right=socket.socketpair()
    try:
        fd=os.dup(left.fileno())
        with socket.socket(fileno=fd) as adopted:
            adopted.sendall(b'private')
            assert right.recv(7)==b'private'
        with (tmp_path/'ordinary-file').open('wb') as stream:
            fd=os.dup(stream.fileno())
            try:
                with pytest.raises(OSError) as error:
                    socket.socket(fileno=fd)
                assert error.value.errno==errno.ENOTSOCK
            finally:
                os.close(fd)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize('unix',[False,True])
def test_adoption_does_not_clear_sticky_forbidden_connect(unix):
    import socket
    from types import SimpleNamespace
    from source_entry import Policy
    from source_sockets import Hooks
    requests=[]
    client=SimpleNamespace(request=lambda kind,payload:requests.append(kind))
    policy=Policy(None,{'role':'root','case':'ordinary'},None,client)
    policy.sockets=Hooks(policy)
    with socket.socket(socket.AF_UNIX if unix else socket.AF_INET) as stream:
        assert policy.audit('socket.__new__',(stream,-1,-1,-1)) is True
        with pytest.raises(Refused):
            policy.audit('socket.connect',(stream,'/host/service.sock' if unix else ('localhost',12345)))
    assert policy.poison is True and requests==['guard-refusal']
