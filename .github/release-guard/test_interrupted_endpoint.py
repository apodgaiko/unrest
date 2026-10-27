"""EOF-only cleanup policy controls; synthetic rows do not certify kernel facts."""
from dataclasses import replace
from types import SimpleNamespace
import socket
import threading

import pytest

from bootstrap_cases import BOOTSTRAP
from content_manifest import Refused
from endpoint_policy import Endpoints, Owner, Route, Socket, Ticket
from process_ledger import Birth
from source_observer import Observer
from source_sockets import Hooks
import source_observer
from test_endpoint_policy import ready
from test_process_ledger import setup, terminal, wait4, receipt


def interrupted(monkeypatch):
    root = Birth(100, 100, 99, 1000, 'boot', 20000)
    child = Birth(101, 101, 100, 1010, 'boot', 20000)
    case = BOOTSTRAP[1]
    route = Route('lifetime', case, Owner(root, 'root', 1), Owner(child, 'child', 1), 12345)
    listener = Socket(root, 7, 1000, 2000, 10, 20000, ('127.0.0.1', 12345), None)
    client = Socket(child, 6, 1001, 2001, 7, 20000, ('0.0.0.0', 0), None)
    server = Socket(root, 9, 1002, 2002, 8, 20000, ('127.0.0.1', 12345), ('127.0.0.1', 23456))
    ticket = Ticket(1, route, listener, client)
    observer = object.__new__(Observer)
    process = SimpleNamespace(terminal=(10, 15, -15))
    observer.ledger = SimpleNamespace(process=lambda birth: process)
    observer.actors = {child.pid: {'birth': child, 'case': case, 'signals': {15}}}
    observer.case = case
    observer.eof_drains, observer.eof_fds, observer.interrupted_records = {}, {}, []
    def acquire(birth, fd, **kwargs):
        assert birth == root
        return listener if fd == listener.fd else server
    monkeypatch.setattr(source_observer, 'acquire_tcp', acquire)
    return observer, {'birth': root, 'token': 'root'}, process, ticket, server


def test_interrupted_accept_grants_only_eof_not_peer_or_connection(monkeypatch):
    observer, actor, _, ticket, server = interrupted(monkeypatch)
    assert observer.interrupted_accept(actor, [ticket], server) == {'ok': True, 'eof_only': True}
    assert observer.eof_drains[ticket.serial]['ticket'] is ticket
    assert observer.interrupted_records[0]['accepted_peer_proven'] is False
    assert observer.socket_payload(actor, {'fd': server.fd, 'operation': 'recv', 'bytes': 0}) == {'ok': True, 'eof_only': True}
    with pytest.raises(Refused, match='EOF reads only'):
        observer.socket_payload(actor, {'fd': server.fd, 'operation': 'send', 'bytes': 1})


@pytest.mark.parametrize('mutation', ['case', 'live', 'status', 'signal', 'multiple', 'listener', 'descriptor', 'buffered'])
def test_interrupted_accept_rejects_unproven_or_application_channels(monkeypatch, mutation):
    observer, actor, process, ticket, server = interrupted(monkeypatch)
    matches = [ticket]
    if mutation == 'case':
        observer.case = BOOTSTRAP[0]
    elif mutation == 'live':
        process.terminal = None
    elif mutation == 'status':
        process.terminal = (10, 0, 0)
    elif mutation == 'signal':
        observer.actors[ticket.route.client.birth.pid]['signals'].clear()
    elif mutation == 'multiple':
        matches *= 2
    elif mutation == 'listener':
        matches = [replace(ticket, listener=replace(ticket.listener, cookie=9999))]
    elif mutation == 'descriptor':
        server = replace(server, cookie=9999)
    else:
        def buffered(*args, **kwargs):
            if kwargs.get('eof_only'):
                raise RuntimeError('not empty CLOSE_WAIT EOF')
            return ticket.listener
        monkeypatch.setattr(source_observer, 'acquire_tcp', buffered)
    if mutation == 'live':
        assert observer.interrupted_accept(actor, matches, server) is None
    else:
        with pytest.raises((Refused, RuntimeError)):
            observer.interrupted_accept(actor, matches, server)
    assert not observer.eof_drains and not observer.interrupted_records


@pytest.mark.parametrize('stage', ['none', 'terminal', 'kernel-wait', 'complete'])
def test_aborted_ticket_retirement_requires_complete_original_parent_join(stage):
    ledger, root, child = setup()
    server, client = ready(ledger, root), ready(ledger, child)
    endpoints = Endpoints(ledger)
    route = Route('lifetime', 'case[one]', server, client, 12345)
    endpoints.declare(route)
    listener = Socket(root, 7, 1000, 2000, 10, 20000, ('127.0.0.1', 12345), None)
    endpoints.listen(route.name, listener)
    ticket = endpoints.connect(route.name, listener, Socket(child, 6, 1001, 2001, 7, 20000, ('0.0.0.0', 0), None))
    if stage != 'none':
        terminal(ledger, child, 15)
    if stage in ('kernel-wait', 'complete'):
        wait4(ledger, root, child, 15)
    if stage == 'complete':
        ledger.control(root, 'root-token', 0, 2, 'parent-wait', receipt(ledger, root, child, 15))
        endpoints.abort_reaped(ticket)
        assert not endpoints.tickets and not endpoints.connections
    else:
        with pytest.raises(Refused, match='actual parent reap'):
            endpoints.abort_reaped(ticket)
        assert endpoints.tickets[ticket.serial] is ticket


@pytest.mark.parametrize('operation,args', [('recv', (1, socket.MSG_PEEK)),
    ('recv_into', (bytearray(1), 1, socket.MSG_PEEK)), ('send', (b'x',))])
def test_eof_only_source_permission_rejects_flags_and_writes(operation, args):
    def refuse(code):
        raise Refused(code)
    policy = SimpleNamespace(profile={'role': 'root'}, local=threading.local(), refuse=refuse)
    hooks = Hooks(policy)
    hooks.rpc = lambda *args: {'ok': True, 'eof_only': True}
    def forbidden(*args, **kwargs):
        pytest.fail('EOF-only wrapper invoked a forbidden real socket operation')
    hooks.original[operation] = forbidden
    with socket.socket() as stream, pytest.raises(Refused, match='EOF-only'):
        hooks.call(operation, stream, *args)
