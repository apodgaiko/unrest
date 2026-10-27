"""TCP endpoint state joined to authenticated process epochs and kernel sockets.

Only the trusted supervisor calls this reducer, with independently declared
routes and freshly acquired observations. It does not authenticate RPC frames
or perform socket operations. A returned ticket permits exactly one connect;
an accepted connection never authorizes a replacement listener or reconnect.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from content_manifest import Refused
from process_ledger import Birth, Ledger, fail_closed, integer, text


@dataclass(frozen=True)
class Owner:
    birth: Birth
    token: str
    generation: int


@dataclass(frozen=True)
class Socket:
    owner: Birth
    fd: int
    inode: int
    cookie: int
    state: int
    uid: int
    local: tuple[str, int]
    remote: tuple[str, int] | None

    def __post_init__(self) -> None:
        if type(self.owner) is not Birth or self.uid != self.owner.uid:
            raise Refused('endpoint socket owner')
        integer(self.fd)
        integer(self.inode, 1)
        integer(self.cookie, 1, (1 << 64) - 2)
        integer(self.state, 1, 12)
        integer(self.uid)
        if type(self.local) is not tuple or len(self.local) != 2:
            raise Refused('endpoint local address')
        if not (self.state == 7 and self.remote is None and self.local == ('0.0.0.0', 0)
                and type(self.local[1]) is int):
            address(*self.local)
        if self.remote is not None:
            if type(self.remote) is not tuple or len(self.remote) != 2:
                raise Refused('endpoint remote address')
            address(*self.remote)

    @classmethod
    def read(cls, owner: Birth, row: dict[str, Any]) -> Socket:
        if type(owner) is not Birth or type(row) is not dict or row.get('pid') != owner.pid:
            raise Refused('endpoint socket owner')
        uid = integer(row.get('socket_uid'))
        if uid != owner.uid:
            raise Refused('endpoint socket uid')
        local_host, local_port = row.get('local_host'), row.get('local_port')
        if type(local_host) is not str or type(local_port) is not int:
            raise Refused('endpoint local address')
        local = (local_host, local_port)
        host, port = row.get('remote_host'), row.get('remote_port')
        remote = None if host == '0.0.0.0' and type(port) is int and port == 0 else address(host, port)
        return cls(owner, integer(row.get('fd')), integer(row.get('inode'), 1),
                   integer(row.get('socket_cookie'), 1, (1 << 64) - 2),
                   integer(row.get('state'), 1, 12), uid, local, remote)

    def description(self) -> tuple:
        # Cookies identify file descriptions within this observer's private
        # network namespace, including aliases inherited by another owned PID.
        return self.inode, self.cookie, self.uid

    def binding(self) -> tuple:
        return self.owner, self.fd, self.inode, self.cookie, self.uid


def address(host: Any, port: Any) -> tuple[str, int]:
    if type(host) is not str or host != '127.0.0.1':
        raise Refused('endpoint address')
    return host, integer(port, 1, 65535)


@dataclass(frozen=True)
class Route:
    name: str
    case: str
    server: Owner
    client: Owner
    port: int


@dataclass(frozen=True)
class Ticket:
    serial: int
    route: Route
    listener: Socket
    client: Socket


@dataclass(frozen=True)
class Connection:
    ticket: Ticket
    client: Socket
    server: Socket


class Endpoints:
    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.routes: dict[str, Route] = {}
        self.listeners: dict[str, Socket] = {}
        self.tickets: dict[int, Ticket] = {}
        self.connections: dict[int, Connection] = {}
        self.queued: dict[int, tuple[int, int]] = {}
        self.poison: list[str] = []
        self.serial = 0

    def owner(self, owner: Owner, case: str, *, body: bool) -> None:
        if self.poison or self.ledger.poison or type(owner) is not Owner:
            raise Refused('endpoint poisoned or unknown owner')
        process = self.ledger.process(owner.birth)
        if (type(owner.token) is not str or type(owner.generation) is not int
                or owner.token != process.token or owner.generation != process.generation
                or process.registered_generation != process.generation or process.case != case
                or process.exit is not None or process.terminal is not None
                or process.stage not in (('body-ready',) if body else ('core-ready', 'body-ready'))):
            raise Refused('endpoint owner epoch or readiness')

    @fail_closed
    def declare(self, route: Route) -> None:
        if type(route) is not Route or len(self.routes) >= 256:
            raise Refused('endpoint declaration bound')
        text(route.name)
        text(route.case)
        integer(route.port, 1, 65535)
        if route.name in self.routes or any(item.port == route.port for item in self.routes.values()):
            raise Refused('endpoint duplicate declaration')
        self.owner(route.server, route.case, body=False)
        self.owner(route.client, route.case, body=False)
        self.routes[route.name] = route

    def route(self, name: str) -> Route:
        if type(name) is not str or name not in self.routes or self.poison or self.ledger.poison:
            raise Refused('endpoint unknown route')
        return self.routes[name]

    @fail_closed
    def listen(self, name: str, observed: Socket) -> None:
        route = self.route(name)
        self.owner(route.server, route.case, body=False)
        if (type(observed) is not Socket or observed.owner != route.server.birth
                or observed.uid != route.server.birth.uid or observed.state != 10
                or observed.local != ('127.0.0.1', route.port) or observed.remote is not None
                or name in self.listeners):
            raise Refused('endpoint listener binding')
        self.listeners[name] = observed

    @fail_closed
    def connect(self, name: str, fresh_listener: Socket, client: Socket) -> Ticket:
        route = self.route(name)
        self.owner(route.client, route.case, body=True)
        self.owner(route.server, route.case, body=True)
        if (type(client) is not Socket or client.owner != route.client.birth
                or client.uid != route.client.birth.uid or client.state != 7 or client.remote is not None
                or any(client.description() == saved.description() for item in self.connections.values()
                       for saved in (item.client, item.server))):
            raise Refused('endpoint preconnect descriptor')
        if name not in self.listeners or fresh_listener != self.listeners[name]:
            raise Refused('endpoint listener reacquisition')
        if (len(self.tickets) + len(self.connections) >= 4096
                or any(item.client.description() == client.description()
                       for item in self.tickets.values())):
            raise Refused('endpoint connection bound')
        self.serial += 1
        ticket = Ticket(self.serial, route, fresh_listener, client)
        self.tickets[ticket.serial] = ticket
        return ticket

    @fail_closed
    def queued_send(self, ticket: Ticket, listener: Socket, client: Socket, count: int) -> None:
        """Initial client bytes may precede application accept, never its proof.

        Waiting for a same-loop server to accept here deadlocks that loop. The
        unconsumed ticket remains mandatory until the actual accepted-FD join.
        """
        if type(ticket) is not Ticket or self.tickets.get(ticket.serial) is not ticket:
            raise Refused('endpoint queued admission missing')
        route = self.route(ticket.route.name)
        self.owner(route.client, route.case, body=True)
        self.owner(route.server, route.case, body=True)
        if (route is not ticket.route or type(listener) is not Socket or listener != ticket.listener
                or self.listeners.get(route.name) != listener or listener.state != 10
                or type(client) is not Socket or client.binding() != ticket.client.binding()
                or client.state != 1 or client.remote != listener.local
                or client.local[0] != '127.0.0.1' or client.local[1] == 0):
            raise Refused('endpoint queued live socket binding')
        integer(count, 0, 1048576)
        calls, size = self.queued.get(ticket.serial, (0, 0))
        if calls >= 16 or size + count > 1048576:
            raise Refused('endpoint queued initial send bound')
        self.queued[ticket.serial] = calls + 1, size + count

    @fail_closed
    def accepted(self, ticket: Ticket, client: Socket, server: Socket) -> Connection:
        if type(ticket) is not Ticket or self.tickets.get(ticket.serial) is not ticket:
            raise Refused('endpoint unknown or consumed ticket')
        route = self.route(ticket.route.name)
        if route is not ticket.route:
            raise Refused('endpoint stale route ticket')
        self.owner(route.client, route.case, body=True)
        self.owner(route.server, route.case, body=True)
        if (type(client) is not Socket or type(server) is not Socket
                or client.owner != route.client.birth or server.owner != route.server.birth
                or client.uid != route.client.birth.uid or server.uid != route.server.birth.uid
                or client.binding() != ticket.client.binding() or client.state not in (1, 8) or server.state not in (1, 8)
                or client.remote != server.local or server.remote != client.local
                or server.local != ('127.0.0.1', route.port)
                or server.binding() == ticket.listener.binding()
                or client.binding() == server.binding()):
            raise Refused('endpoint reciprocal peer')
        connection = Connection(ticket, client, server)
        del self.tickets[ticket.serial]
        self.queued.pop(ticket.serial, None)
        self.connections[ticket.serial] = connection
        return connection

    @fail_closed
    def retained(self, connection: Connection, owner: Owner, observed: Socket) -> None:
        if (type(connection) is not Connection
                or self.connections.get(connection.ticket.serial) is not connection):
            raise Refused('endpoint unknown connection')
        route = self.route(connection.ticket.route.name)
        self.owner(owner, route.case, body=True)
        candidates = [saved for expected, saved in ((route.client, connection.client), (route.server, connection.server))
                      if owner == expected and type(observed) is Socket and observed.binding() == saved.binding()]
        if len(candidates) != 1:
            raise Refused('endpoint connection owner or descriptor')
        saved = candidates[0]
        if (type(observed) is not Socket or observed.binding() != saved.binding()
                or observed.local != saved.local
                or not (observed.state in (1, 8) and observed.remote == saved.remote
                        or observed.state == 7 and observed.remote is None)):
            raise Refused('endpoint retained descriptor')

    @fail_closed
    def abort_reaped(self, ticket: Ticket) -> None:
        """Retire an unfinished client, without asserting accepted peer identity."""
        if type(ticket) is not Ticket or self.tickets.get(ticket.serial) is not ticket:
            raise Refused('endpoint unknown aborted ticket')
        route = self.route(ticket.route.name)
        if route is not ticket.route or not self.ledger.reaped(route.client.birth, route.client.token):
            raise Refused('endpoint aborted client requires actual parent reap')
        self.owner(route.server, route.case, body=True)
        del self.tickets[ticket.serial]
        self.queued.pop(ticket.serial, None)

    @fail_closed
    def retire(self, name: str, replacement: Route) -> None:
        route = self.route(name)
        saved = self.listeners.get(name)
        process = self.ledger.process(route.server.birth)
        if (saved is None or type(replacement) is not Route or replacement.name != name
                or replacement.port != route.port or replacement.case != route.case
                or replacement.server.token == route.server.token
                or process.life_token is None
                or not self.ledger.reaped(route.server.birth, process.life_token)):
            raise Refused('endpoint retirement needs actual parent join')
        self.owner(replacement.server, replacement.case, body=False)
        self.owner(replacement.client, replacement.case, body=False)
        del self.listeners[name]
        for serial in [serial for serial, ticket in self.tickets.items() if ticket.route is route]:
            del self.tickets[serial]
            self.queued.pop(serial, None)
        self.routes[name] = replacement
