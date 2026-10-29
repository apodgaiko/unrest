"""Finite owned-listener admission; application payload and accept are not certified."""
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
class Admission:
    serial: int
    route: Route
    listener: Socket
    client: Socket


def root_http_route(host,actor,port):
    """Root HTTP reaches only this case's actual owned broker listener."""
    from controlled_cases import ROOT_HTTP,INITIALIZED_HTTP
    from socket_observation import acquire_tcp
    host.root_only(actor)
    if host.case not in ROOT_HTTP:
        raise Refused('root HTTP finite case')
    slots=[slot for slot in host.listeners.values() if slot['case']==host.case and slot['tag']=='broker'
           and slot['socket'].owner==actor['birth'] and slot['socket'].local==('127.0.0.1',port)]
    if len(slots)!=1:
        raise Refused('root HTTP exact owned broker listener')
    listener=slots[0]['socket']
    if acquire_tcp(actor['birth'],listener.fd)!=listener:
        raise Refused('root HTTP broker listener generation')
    name=actor['token']+':root-http:'+host.case+':'+str(port)
    if name not in host.endpoints.routes:
        owner=host.owner(actor)
        sharing=listener if any(route.port==port and host.endpoints.route_active(route) for route in host.endpoints.routes.values()) else None
        host.endpoints.declare(Route(name,host.case,owner,owner,port),shared_listener=sharing)
        host.endpoints.listen(name,listener)
    return name,4 if host.case==INITIALIZED_HTTP else 3


class Endpoints:
    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.routes: dict[str, Route] = {}
        self.listeners: dict[str, Socket] = {}
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
        if case in self.retired:
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
    def connect(self, name: str, fresh_listener: Socket, client: Socket) -> Admission:
        route = self.route(name)
        self.owner(route.client, route.case, body=True)
        self.owner(route.server, route.case, body=True)
        if (type(client) is not Socket or client.owner != route.client.birth
                or client.uid != route.client.birth.uid or client.state != 7 or client.remote is not None
                or client.local != ('0.0.0.0',0)
                or client.description() in self.descriptions):
            raise Refused('endpoint preconnect descriptor')
        if name not in self.listeners or fresh_listener != self.listeners[name]:
            raise Refused('endpoint listener reacquisition')
        active=sum(self.connection_counts.get(name,0)
            for name,route in self.routes.items() if self.route_active(route))
        if active>=MAX_ACTIVE_CONNECTIONS or self.serial>=MAX_RETAINED_ADMISSIONS:
            raise Refused('endpoint connection bound')
        self.serial += 1
        admission = Admission(self.serial, route, fresh_listener, client)
        self.descriptions.add(client.description())
        self.connection_counts[name]=self.connection_counts.get(name,0)+1
        return admission

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
        self.retired_names.update(names)
