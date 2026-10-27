"""Endpoint mutation controls; fabricated rows never count as kernel proof."""
from dataclasses import replace

import pytest

from content_manifest import Refused
from endpoint_policy import Endpoints, Owner, Route, Socket
from test_process_ledger import PINS, SEAL, emit, identity, receipt, setup, terminal, wait4
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


@pytest.mark.parametrize('same_owner', [False, True])
def test_queued_initial_send_is_not_an_accepted_connection(same_owner):
    endpoints, ticket, client, server = connected(same_owner=same_owner)
    endpoints.queued_send(ticket, ticket.listener, client, 128)
    assert endpoints.tickets[ticket.serial] is ticket
    assert endpoints.queued == {ticket.serial: (1, 128)}
    assert not endpoints.connections
    connection = endpoints.accepted(ticket, client, server)
    assert not endpoints.queued and not endpoints.tickets
    endpoints.retained(connection, ticket.route.client, client)


@pytest.mark.parametrize('mutation', ['syn', 'listener-cookie', 'listener-missing', 'client-cookie',
    'client-missing', 'foreign-port', 'missing-admission', 'quota'])
def test_queued_initial_send_requires_fresh_exact_admission(mutation):
    endpoints, ticket, client, _ = connected()
    listener = ticket.listener
    if mutation == 'syn':
        client = replace(client, state=2)
    elif mutation == 'listener-cookie':
        listener = replace(listener, cookie=listener.cookie + 1)
    elif mutation == 'listener-missing':
        listener = None
    elif mutation == 'client-cookie':
        client = replace(client, cookie=client.cookie + 1)
    elif mutation == 'client-missing':
        client = None
    elif mutation == 'foreign-port':
        client = replace(client, remote=('127.0.0.1', 23457))
    elif mutation == 'missing-admission':
        del endpoints.tickets[ticket.serial]
    else:
        endpoints.queued_send(ticket, listener, client, 1048576)
    with pytest.raises(Refused):
        endpoints.queued_send(ticket, listener, client, 1)
    assert endpoints.poison and not endpoints.connections


@pytest.mark.parametrize('same_owner', [False, True])
def test_accepted_peer_survives_listener_close_but_never_allows_reconnect(same_owner):
    endpoints, ticket, client, server = connected(same_owner=same_owner)
    connection = endpoints.accepted(ticket, client, server)
    del endpoints.listeners['route']  # actual adapter must establish close separately
    endpoints.retained(connection, ticket.route.client, client)
    endpoints.retained(connection, ticket.route.server, server)
    endpoints.retained(connection, ticket.route.server, replace(server, state=8))
    endpoints.retained(connection, ticket.route.server, replace(server, state=7, remote=None))
    with pytest.raises(Refused):
        endpoints.connect('route', ticket.listener, replace(client, fd=10, state=7, remote=None))
    assert endpoints.poison


@pytest.mark.parametrize('field,value', [('fd', 20), ('inode', 3000), ('cookie', 4000),
                                        ('state', 1), ('local', ('127.0.0.1', 12346))])
def test_listener_must_be_reacquired_exactly(field, value):
    endpoints, _, listener = prepared()
    with pytest.raises(Refused):
        endpoints.connect('route', replace(listener, **{field: value}), idle_client(endpoints.routes['route']))
    assert endpoints.poison


@pytest.mark.parametrize('side,field,value', [
    ('client', 'fd', 10), ('client', 'state', 10), ('server', 'state', 10),
    ('client', 'remote', ('127.0.0.1', 12346)), ('server', 'remote', ('127.0.0.1', 23457)),
    ('client', 'local', ('127.0.0.1', 23457)), ('server', 'local', ('127.0.0.1', 12346)),
])
def test_reciprocal_kernel_peer_required(side, field, value):
    endpoints, ticket, client, server = connected()
    if side == 'client':
        client = replace(client, **{field: value})
    else:
        server = replace(server, **{field: value})
    with pytest.raises(Refused):
        endpoints.accepted(ticket, client, server)
    assert endpoints.poison


@pytest.mark.parametrize('field,value', [('fd', 11), ('inode', 3000), ('cookie', 4000),
                                        ('local', ('127.0.0.1', 23457)), ('remote', None), ('state', 10)])
def test_retained_connection_cannot_launder_fd_reuse_or_reconnect(field, value):
    endpoints, ticket, client, server = connected()
    connection = endpoints.accepted(ticket, client, server)
    with pytest.raises(Refused):
        endpoints.retained(connection, ticket.route.client, replace(client, **{field: value}))
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


def test_tickets_are_one_use_and_structural_clone_is_not_issued_ticket():
    endpoints, ticket, client, server = connected()
    with pytest.raises(Refused):
        endpoints.accepted(replace(ticket), client, server)
    endpoints, ticket, client, server = connected()
    endpoints.accepted(ticket, client, server)
    with pytest.raises(Refused):
        endpoints.accepted(ticket, client, server)


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
    next_route = replace(route, server=next_owner)
    terminal(ledger, child, 0)
    # A tracer reap and source receipt without the actual kernel parent wait is insufficient.
    ledger.control(root, 'root-token', 0, 2, 'parent-wait', receipt(ledger, root, child, 0))
    if parent_wait:
        wait4(ledger, root, child, 0)
        endpoints.retire('route', next_route)
        assert endpoints.routes['route'] == next_route and not endpoints.listeners
    else:
        with pytest.raises(Refused):
            endpoints.retire('route', next_route)
        assert endpoints.listeners and endpoints.poison



@pytest.mark.parametrize('field,value', [('fd', True), ('inode', 0), ('cookie', (1 << 64) - 1),
    ('state', True), ('uid', True), ('local', ('localhost', 12345)),
    ('local', ('127.0.0.1', True)), ('remote', ('8.8.8.8', 443))])
def test_socket_observations_have_strict_finite_fields(field, value):
    _, _, listener = prepared()
    with pytest.raises(Refused):
        replace(listener, **{field: value})


@pytest.mark.parametrize('field,value', [('fd', 10), ('inode', 9000), ('cookie', 9001)])
def test_preconnect_file_description_cannot_be_replaced(field, value):
    endpoints, ticket, client, server = connected()
    with pytest.raises(Refused):
        endpoints.accepted(ticket, replace(client, **{field: value}), server)
    assert endpoints.poison


def test_existing_connection_cannot_obtain_another_connect_ticket():
    endpoints, ticket, client, server = connected()
    endpoints.accepted(ticket, client, server)
    with pytest.raises(Refused):
        endpoints.connect('route', ticket.listener, replace(client, state=7, remote=None))
    assert endpoints.poison


def test_old_ticket_cannot_bind_replacement_route():
    endpoints, ticket, client, server = connected()
    endpoints.routes['route'] = replace(ticket.route)  # even equal-valued route is a different declaration
    with pytest.raises(Refused, match='stale route'):
        endpoints.accepted(ticket, client, server)
    assert endpoints.poison



def test_numeric_fd_reuse_with_a_new_file_description_is_allowed():
    endpoints, ticket, client, server = connected()
    endpoints.accepted(ticket, client, server)
    new_client = replace(client, inode=9000, cookie=9001, local=('127.0.0.1', 23457))
    next_ticket = endpoints.connect('route', ticket.listener,
        replace(new_client, state=7, local=('0.0.0.0', 0), remote=None))
    next_server = replace(server, fd=10, inode=9002, cookie=9003, remote=new_client.local)
    connection = endpoints.accepted(next_ticket, new_client, next_server)
    endpoints.retained(connection, next_ticket.route.client, new_client)
    assert not endpoints.poison and len(endpoints.connections) == 2



def test_pending_ticket_cannot_be_duplicated_through_an_fd_alias():
    endpoints, ticket, _, _ = connected()
    with pytest.raises(Refused):
        endpoints.connect('route', ticket.listener, replace(ticket.client, fd=20))
    assert endpoints.poison


@pytest.mark.parametrize('side', ['client', 'server'])
def test_accepted_description_cannot_reconnect_via_alias_or_role_switch(side):
    endpoints, ticket, client, server = connected(same_owner=True)
    endpoints.accepted(ticket, client, server)
    saved = client if side == 'client' else server
    alias = replace(saved, fd=20, state=7, remote=None)
    with pytest.raises(Refused):
        endpoints.connect('route', ticket.listener, alias)
    assert endpoints.poison



def test_pending_shared_description_cannot_reserve_through_another_owned_birth():
    endpoints, ticket, _, _ = connected()
    next_route = replace(ticket.route, name='other-route', port=12346, client=ticket.route.server)
    endpoints.declare(next_route)
    listener = replace(ticket.listener, local=('127.0.0.1', 12346), inode=8000, cookie=8001)
    endpoints.listen(next_route.name, listener)
    inherited = replace(ticket.client, owner=next_route.client.birth, fd=20)
    with pytest.raises(Refused):
        endpoints.connect(next_route.name, listener, inherited)
    assert endpoints.poison
