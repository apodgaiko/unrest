"""Owned asyncio self-pairs; no Unix pathname/connect or process authority.

Fresh observer observations and independently authenticated owner/case selection
are required. A retained member may outlive its peer, but cannot authorize a
replacement file description, another FD alias, or reconnect.
"""
from __future__ import annotations

from dataclasses import dataclass

from content_manifest import Refused
from endpoint_policy import Endpoints, Owner
from process_ledger import Birth, fail_closed, integer


@dataclass(frozen=True)
class Member:
    owner: Birth
    fd: int
    inode: int
    cookie: int
    uid: int
    peer: int
    state: int

    def __post_init__(self):
        if type(self.owner) is not Birth or self.uid != self.owner.uid:
            raise Refused('unix member owner')
        for value in (self.fd, self.uid, self.peer):
            integer(value)
        integer(self.inode, 1)
        integer(self.cookie, 1, (1 << 64) - 2)
        if type(self.state) is not int or self.state not in (1, 7):
            raise Refused('unix member state')

    @classmethod
    def read(cls, owner: Birth, row: dict) -> Member:
        required = {'fd', 'inode', 'socket_cookie', 'socket_uid', 'state', 'type'}
        if (type(row) is not dict or set(row) not in (required, required | {'peer_inode'})
                or type(row['type']) is not int or row['type'] != 1):
            raise Refused('unix stream observation')
        return cls(owner, row['fd'], row['inode'], row['socket_cookie'], row['socket_uid'],
                   row.get('peer_inode', 0), row['state'])

    def description(self) -> tuple:
        return self.inode, self.cookie, self.uid

    def binding(self) -> tuple:
        return self.owner, self.fd, *self.description()


@dataclass(frozen=True)
class Pair:
    serial: int
    owner: Owner
    case: str
    members: tuple[Member, Member]


class UnixPairs:
    def __init__(self, endpoints: Endpoints):
        if type(endpoints) is not Endpoints:
            raise Refused('unix endpoint authority')
        self.endpoints = endpoints
        self.poison = endpoints.poison
        self.pairs: dict[int, Pair] = {}
        self.descriptions: set[tuple] = set()

    @fail_closed
    def admit(self, owner: Owner, case: str, members: tuple[Member, Member]) -> Pair:
        self.endpoints.owner(owner, case, body=True)
        if (type(members) is not tuple or len(members) != 2
                or any(type(member) is not Member or member.owner != owner.birth for member in members)
                or len(self.pairs) >= 4096):
            raise Refused('unix pair owner or bound')
        left, right = members
        if (left.fd == right.fd or left.inode == right.inode or left.cookie == right.cookie
                or left.peer != right.inode or right.peer != left.inode
                or left.state != 1 or right.state != 1
                or any(member.description() in self.descriptions for member in members)):
            raise Refused('unix pair reciprocal generation')
        pair = Pair(len(self.pairs) + 1, owner, case, members)
        self.pairs[pair.serial] = pair
        self.descriptions.update(member.description() for member in members)
        return pair

    @fail_closed
    def retained(self, pair: Pair, owner: Owner, observed: Member) -> None:
        if type(pair) is not Pair or self.pairs.get(pair.serial) is not pair or owner != pair.owner:
            raise Refused('unix unknown pair or owner')
        self.endpoints.owner(owner, pair.case, body=True)
        saved = [member for member in pair.members
                 if type(observed) is Member and observed.binding() == member.binding()]
        if len(saved) != 1 or observed.peer not in (0, saved[0].peer):
            raise Refused('unix retained member replacement')
