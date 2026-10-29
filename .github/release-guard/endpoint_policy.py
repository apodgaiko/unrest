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


MAX_ACTIVE_ROUTES=256
MAX_RETAINED_ROUTES=20_000
MAX_ACTIVE_CONNECTIONS=4096
MAX_RETAINED_ADMISSIONS=65_536


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
        self.retired: set[str] = set()
        self.retired_names: set[str] = set()
        self.descriptions: set[tuple] = set()
        self.connection_counts: dict[str,int] = {}

    def owner(self, owner: Owner, case: str, *, body: bool) -> None:
        if self.poison or self.ledger.poison or type(owner) is not Owner or case in self.retired:
            raise Refused('endpoint poisoned or unknown owner')
        process = self.ledger.process(owner.birth)
        if (type(owner.token) is not str or type(owner.generation) is not int
                or owner.token != process.token or owner.generation != process.generation
                or process.registered_generation != process.generation or process.case != case
                or process.exit is not None or process.terminal is not None
                or process.stage not in (('body-ready',) if body else ('core-ready', 'body-ready'))):
            raise Refused('endpoint owner epoch or readiness')

    def route_active(self,route: Route) -> bool:
        return route.case not in self.retired and route.name not in self.retired_names

    @fail_closed
    def declare(self, route: Route, *, shared_listener: Socket | None = None) -> None:
        if (type(route) is not Route or len(self.routes)>=MAX_RETAINED_ROUTES
                or sum(self.route_active(value) for value in self.routes.values())>=MAX_ACTIVE_ROUTES):
            raise Refused('endpoint declaration bound')
        text(route.name)
        text(route.case)
        integer(route.port, 1, 65535)
        self.owner(route.server, route.case, body=False)
        self.owner(route.client, route.case, body=False)
        duplicates = [item for item in self.routes.values() if item.port == route.port and self.route_active(item)]
        if route.name in self.routes:
            raise Refused('endpoint duplicate declaration')
        if duplicates:
            if (type(shared_listener) is not Socket
                    or any(item.case != route.case or item.server != route.server
                           or self.listeners.get(item.name) != shared_listener for item in duplicates)):
                raise Refused('endpoint duplicate declaration')
            for item in duplicates:
                self.owner(item.server, item.case, body=False)
        elif shared_listener is not None:
            raise Refused('endpoint shared listener without original route')
        self.routes[route.name] = route

    @fail_closed
    def retire_case(self, case: str) -> None:
        text(case)
        if case in self.retired or any(ticket.route.case == case for ticket in self.tickets.values()):
            raise Refused('endpoint retirement has outstanding admission')
        # Revoke capabilities, preserving observations; this does not assert FD close.
        self.retired.add(case)

    def route(self, name: str) -> Route:
        if type(name) is not str or name not in self.routes or self.poison or self.ledger.poison or not self.route_active(self.routes[name]):
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
                or client.description() in self.descriptions):
            raise Refused('endpoint preconnect descriptor')
        if name not in self.listeners or fresh_listener != self.listeners[name]:
            raise Refused('endpoint listener reacquisition')
        active=len(self.tickets)+sum(self.connection_counts.get(name,0)
            for name,route in self.routes.items() if self.route_active(route))
        if (active>=MAX_ACTIVE_CONNECTIONS or self.serial>=MAX_RETAINED_ADMISSIONS
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
        self.descriptions.update((client.description(),server.description()))
        self.connection_counts[route.name]=self.connection_counts.get(route.name,0)+1
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
    def retire_owner(self, owner: Owner, case: str) -> None:
        if type(owner) is not Owner:
            raise Refused('endpoint retirement owner primitive')
        process=self.ledger.process(owner.birth)
        if (process.case!=case or process.token!=owner.token or process.generation!=owner.generation
                or process.registered_generation!=owner.generation
                or not self.ledger.reaped(owner.birth,process.life_token)):
            raise Refused('endpoint retirement needs actual parent join')
        names={name for name,route in self.routes.items() if route.case==case and route.server==owner}
        if (any(ticket.route.name in names for ticket in self.tickets.values())
                or any(serial not in self.tickets for serial in self.queued)):
            raise Refused('endpoint retirement has outstanding admission')
        self.retired_names.update(names)
