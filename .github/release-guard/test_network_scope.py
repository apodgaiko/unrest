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
