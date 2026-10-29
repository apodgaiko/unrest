"""Endpoint mutation controls; fabricated rows never count as kernel proof."""
from dataclasses import replace

import pytest

from content_manifest import Refused
from endpoint_policy import Endpoints, Owner, Route, Socket
from test_process_ledger import PINS, SEAL, emit, identity, setup, terminal, wait4
from process_ledger import Birth


def ready(ledger, birth, *, body=True):
    process = ledger.process(birth)
    ledger.control(birth, process.token, process.generation, 0, 'core-ready', {'pins': PINS})
    if body:
        ledger.control(birth, process.token, process.generation, 1, 'body-ready', {'seal': SEAL})
    return Owner(birth, process.token, process.generation)


def prepared(*, body=True, same_owner=False):
    ledger, root, child = setup()
    client = ready(ledger, root, body=body)
    server = ready(ledger, child, body=body)
    if same_owner:
        client = server
    endpoints = Endpoints(ledger)
    route = Route('route', 'case[one]', server, client, 12345)
    endpoints.declare(route)
    listener = Socket(server.birth, 7, 1000, 2000, 10, 20000, ('127.0.0.1', 12345), None)
    endpoints.listen('route', listener)
    return endpoints, route, listener


def idle_client(route):
    return Socket(route.client.birth, 8, 1001, 2001, 7, 20000, ('0.0.0.0', 0), None)


def connected(*, same_owner=False):
    endpoints, route, listener = prepared(same_owner=same_owner)
    client = Socket(route.client.birth, 8, 1001, 2001, 1, 20000,
                    ('127.0.0.1', 23456), ('127.0.0.1', 12345))
    ticket = endpoints.connect('route', listener, replace(client, state=7, local=('0.0.0.0', 0), remote=None))
    server = Socket(route.server.birth, 9, 1002, 2002, 1, 20000,
                    ('127.0.0.1', 12345), ('127.0.0.1', 23456))
    return endpoints, ticket, client, server


@pytest.mark.parametrize('field,value', [('fd', 20), ('inode', 3000), ('cookie', 4000),
                                        ('state', 1), ('local', ('127.0.0.1', 12346))])
def test_listener_must_be_reacquired_exactly(field, value):
    endpoints, _, listener = prepared()
    with pytest.raises(Refused):
        endpoints.connect('route', replace(listener, **{field: value}), idle_client(endpoints.routes['route']))
    assert endpoints.poison


@pytest.mark.parametrize('phase', ['core', 'exit', 'exec', 'poison'])
def test_no_connect_before_body_ready_or_after_epoch_loss(phase):
    endpoints, route, listener = prepared(body=phase != 'core')
    ledger = endpoints.ledger
    if phase == 'exit':
        emit(ledger, 'kernel_exit', pid=route.server.birth.pid, raw=0)
    elif phase == 'exec':
        ledger.process(route.server.birth).generation += 1
    elif phase == 'poison':
        ledger.poison.append('original-refusal')
    with pytest.raises(Refused):
        endpoints.connect('route', listener, idle_client(route))
    assert endpoints.poison


@pytest.mark.parametrize('parent_wait', [False, True])
def test_retirement_keeps_original_parent_wait_requirement(parent_wait):
    endpoints, route, _ = prepared()
    ledger = endpoints.ledger
    root, child = route.client.birth, route.server.birth
    new_identity = identity(102, 100)
    emit(ledger, 'kernel_child', parent=100, child=102, event=1, identity=new_identity)
    replacement = Birth.read(new_identity)
    ledger.register(replacement, 'next-token', PINS, SEAL, case=route.case, command_class='child')
    next_owner = ready(ledger, replacement)
    next_route = replace(route, name='next-route',server=next_owner)
    terminal(ledger, child, 0)
    # A tracer reap without the actual kernel parent wait is insufficient.
    if parent_wait:
        wait4(ledger, root, child, 0)
        endpoints.retire_owner(route.server,route.case)
        assert endpoints.routes['route'] is route and endpoints.listeners['route']
        assert 'route' in endpoints.retired_names
        endpoints.declare(next_route)
        assert endpoints.route('next-route') is next_route
        with pytest.raises(Refused,match='unknown route'):
            endpoints.route('route')
    else:
        with pytest.raises(Refused):
            endpoints.retire_owner(route.server,route.case)
        assert endpoints.listeners and endpoints.poison


@pytest.mark.parametrize('field,value', [('fd', True), ('inode', 0), ('cookie', (1 << 64) - 1),
    ('state', True), ('uid', True), ('local', ('localhost', 12345)),
    ('local', ('127.0.0.1', True)), ('remote', ('8.8.8.8', 443))])
def test_socket_observations_have_strict_finite_fields(field, value):
    _, _, listener = prepared()
    with pytest.raises(Refused):
        replace(listener, **{field: value})


def test_issued_admission_cannot_be_duplicated_through_an_fd_alias():
    endpoints, ticket, _, _ = connected()
    with pytest.raises(Refused):
        endpoints.connect('route', ticket.listener, replace(ticket.client, fd=20))
    assert endpoints.poison


def test_issued_shared_description_cannot_reserve_through_another_owned_birth():
    endpoints, ticket, _, _ = connected()
    next_route = replace(ticket.route, name='other-route', port=12346, client=ticket.route.server)
    endpoints.declare(next_route)
    listener = replace(ticket.listener, local=('127.0.0.1', 12346), inode=8000, cookie=8001)
    endpoints.listen(next_route.name, listener)
    inherited = replace(ticket.client, owner=next_route.client.birth, fd=20)
    with pytest.raises(Refused):
        endpoints.connect(next_route.name, listener, inherited)
    assert endpoints.poison


def test_shared_listener_retains_different_client_births_and_admissions():
    endpoints, route, listener = prepared()
    ledger = endpoints.ledger
    actual = identity(102, 100)
    third = Birth.read(actual)
    emit(ledger, 'kernel_child', parent=100, child=102, event=1, identity=actual)
    ledger.register(third, 'other-client', PINS, SEAL, case=route.case, command_class='client')
    other = ready(ledger, third)
    second = replace(route, name='other-client-route', client=other)
    endpoints.declare(second, shared_listener=listener)
    endpoints.listen(second.name, listener)
    first_ticket = endpoints.connect(route.name, listener, idle_client(route))
    next_ticket = endpoints.connect(second.name, listener, replace(idle_client(second), inode=3000, cookie=4000))
    assert first_ticket.serial != next_ticket.serial
    assert first_ticket.route.client.birth != next_ticket.route.client.birth
    assert first_ticket.listener == next_ticket.listener


@pytest.mark.parametrize('mutation', ('case', 'server', 'cookie', 'fd', 'inode', 'missing', 'implicit'))
def test_shared_listener_never_transfers_foreign_server_or_binding(mutation):
    endpoints, route, listener = prepared()
    next_route = replace(route, name='second')
    shared = listener
    if mutation == 'case':
        next_route = replace(next_route, case='case[two]')
    elif mutation == 'server':
        next_route = replace(next_route, server=route.client)
    elif mutation in ('cookie', 'fd', 'inode'):
        shared = replace(listener, **{mutation: getattr(listener, mutation) + 1})
    elif mutation == 'missing':
        del endpoints.listeners[route.name]
    else:
        shared = None
    with pytest.raises(Refused):
        endpoints.declare(next_route, shared_listener=shared)
    assert endpoints.poison and len(endpoints.routes) == 1


def test_retired_case_keeps_observations_but_cannot_reuse_capabilities():
    endpoints, route, listener = prepared()
    endpoints.retire_case(route.case)
    assert endpoints.listeners[route.name] is listener and endpoints.routes[route.name] is route
    with pytest.raises(Refused, match='unknown route'):
        endpoints.route(route.name)
    with pytest.raises(Refused, match='poisoned or unknown owner'):
        endpoints.owner(route.client, route.case, body=True)
    # The coordinator's next sealed case has its own route and fresh listener.
    for owner in (route.client, route.server):
        endpoints.ledger.process(owner.birth).case = 'case[two]'
    next_route = replace(route, name='next-case', case='case[two]')
    endpoints.declare(next_route)
    fresh = replace(listener, inode=3000, cookie=4000)
    endpoints.listen(next_route.name, fresh)
    assert endpoints.listeners[next_route.name] is fresh
    assert endpoints.listeners[route.name] is listener


def test_retained_route_ceiling_does_not_replace_the_active_route_ceiling(monkeypatch):
    import endpoint_policy
    monkeypatch.setattr(endpoint_policy,'MAX_ACTIVE_ROUTES',1)
    endpoints,route,_=prepared()
    with pytest.raises(Refused,match='declaration bound'):
        endpoints.declare(replace(route,name='second',port=route.port+1))
    endpoints,route,_=prepared()
    monkeypatch.setattr(endpoint_policy,'MAX_RETAINED_ROUTES',1)
    endpoints.retire_case(route.case)
    with pytest.raises(Refused,match='declaration bound'):
        endpoints.declare(replace(route,name='second',port=route.port+1))
    assert len(endpoints.routes)==1
