"""One bounded nonblocking frame per control connection, without policy effects.

The supervisor authenticates both kernel peer and ledger epoch before dispatch.
The source independently checks the observer kernel peer and exact reply echo.
Empty EOF is not cancellation proof; only the ledger's actual-parent reap join
can discharge the narrow controlled-ACP SIGTERM case.
"""
from __future__ import annotations

import json
import socket
import struct
import time
from typing import Any

from content_manifest import Refused, refuse_if
from process_ledger import Birth, Ledger, integer

REQUEST_LIMIT = 8192
RESPONSE_LIMIT = 16384
# Control framing uses captured I/O so source payload mediation cannot recurse
# into the private, independently peer-authenticated observer channel.
_SEND, _RECV, _CLOSE = socket.socket.send, socket.socket.recv, socket.socket.close


def unique(pairs):
    value = {}
    for key, item in pairs:
        refuse_if(key in value, 'control duplicate field')
        value[key] = item
    return value


def finite(value: Any) -> None:
    pending = [(value, 0)]
    nodes = characters = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 16 or nodes > 4096:
            raise Refused('control work bound')
        if value is None or type(value) in (bool, int, str):
            if type(value) is int and not -(1 << 63) <= value < 1 << 64:
                raise Refused('control integer')
            if type(value) is str:
                characters += len(value)
            refuse_if(characters > RESPONSE_LIMIT, 'control text bound')
        elif type(value) is list and len(value) <= 1024:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is dict and len(value) <= 128 and all(type(key) is str for key in value):
            pending.extend((item, depth + 1) for item in value.values())
            pending.extend((key, depth + 1) for key in value)
        else:
            raise Refused('control JSON type')


def encode(value: dict, limit: int) -> bytes:
    refuse_if(type(value) is not dict, 'control object')
    finite(value)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    if not 0 < len(payload) <= limit:
        raise Refused('control frame size')
    return struct.pack('!I', len(payload)) + payload


class Frame:
    def __init__(self, stream: socket.socket, limit: int, *, seconds: int = 4):
        self.seconds = seconds
        self.owner = None
        self.stream, self.limit = stream, limit
        self.started = time.monotonic()
        self.buffer = bytearray()
        self.received: dict | None = None
        self.output: bytes | None = None
        self.eof = False
        self.binding: tuple[Birth, str, int, str, int] | None = None
        stream.setblocking(False)

    def capture(self, ledger: Ledger, birth: Birth, token: str, gid: int) -> None:
        self.check()
        if (self.owner is not None or self.buffer or self.received is not None
                or self.eof or self.binding is not None):
            self.refuse('control late peer capture')
        peer(self.stream, ledger.peer_birth(birth), gid)
        process = ledger.process(birth)
        if (type(token) is not str or process.token != token
                or process.registered_generation != process.generation
                or process.exit is not None or process.terminal is not None):
            self.refuse('control captured registration')
        self.owner = ledger
        self.binding = birth, token, process.generation, process.command_class, gid

    def check(self) -> None:
        if time.monotonic() - self.started > self.seconds:
            self.refuse('control channel deadline')

    def refuse(self, reason: str):
        _CLOSE(self.stream)
        raise Refused(reason)

    def read(self) -> dict | None:
        """At most one recv per scheduler tick, even for a partial frame."""
        self.check()
        if self.received is not None or self.eof:
            return None
        try:
            block = _RECV(self.stream, self.limit + 5 - len(self.buffer))
        except BlockingIOError:
            return None
        if not block:
            self.eof = True
            if self.buffer:
                self.refuse('control partial EOF')
            return None
        self.buffer.extend(block)
        if len(self.buffer) < 4:
            return None
        size = struct.unpack('!I', self.buffer[:4])[0]
        if not 0 < size <= self.limit or len(self.buffer) > size + 4:
            self.refuse('control frame size')
        if len(self.buffer) < size + 4:
            return None
        try:
            value = json.loads(self.buffer[4:], object_pairs_hook=unique)
            refuse_if(type(value) is not dict, 'control object')
            finite(value)
        except (ValueError, RecursionError):
            self.refuse('control JSON')
        self.received = value
        return value

    def answer(self, value: dict) -> None:
        self.check()
        if self.output is not None:
            self.refuse('control duplicate answer')
        try:
            self.output = encode(value, RESPONSE_LIMIT if self.limit == REQUEST_LIMIT else REQUEST_LIMIT)
        except Refused:
            self.refuse('control output')

    def send(self) -> bool:
        """At most one send per tick; partial writes never redispatch policy."""
        self.check()
        if self.output is None:
            self.refuse('control missing answer')
        if not self.output:
            return True
        try:
            sent = _SEND(self.stream, self.output)
        except BlockingIOError:
            return False
        if sent <= 0:
            self.refuse('control write')
        self.output = self.output[sent:]
        return not self.output


def peer(stream: socket.socket, birth: Birth, gid: int) -> None:
    from linux_observation import credential_identity

    integer(gid)
    if type(birth) is not Birth or stream.family != socket.AF_UNIX:
        raise Refused('control peer')
    actual = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    current = credential_identity(birth.pid)
    if (actual != (birth.pid, birth.uid, gid) or Birth.read(current) != birth
            or current['gids'] != [gid] * 4):
        raise Refused('control kernel peer')


class Admission:
    def __init__(self, ledger: Ledger, methods: frozenset[str]):
        self.ledger, self.methods = ledger, methods
        self.seen: set[str] = set()

    def admit(self, frame: Frame) -> dict:
        refuse_if(type(frame) is not Frame or frame.owner is not self.ledger or frame.binding is None, 'control uncaptured channel')
        frame.check()
        birth, token, generation, command_class, gid = frame.binding
        request = frame.received
        refuse_if(type(request) is not dict or set(request) != {'pid', 'nonce', 'token', 'generation', 'id', 'kind', 'payload'}, 'control request schema')
        peer(frame.stream, self.ledger.peer_birth(birth), gid)
        process = self.ledger.process(birth)
        identifier = request['id']
        if (type(identifier) is not str or len(identifier) != 32
                or any(char not in '0123456789abcdef' for char in identifier)
                or identifier in self.seen or len(self.seen) >= 100000
                or type(request['pid']) is not int or request['pid'] != birth.pid
                or type(request['generation']) is not int or request['generation'] != process.generation
                or process.registered_generation != process.generation
                or (process.token, process.generation, process.command_class) != (token, generation, command_class)
                or type(process.token) is not str or request['token'] != process.token
                or request['nonce'] != self.ledger.nonce
                or type(request['kind']) is not str or request['kind'] not in self.methods
                or type(request['payload']) is not dict
                or process.exit is not None or process.terminal is not None):
            raise Refused('control request authority')
        self.seen.add(identifier)
        return request


def cancelled_empty(frame: Frame, ledger: Ledger, birth: Birth, token: str) -> bool:
    frame.check()
    process = ledger.process(birth)
    return (frame.owner is ledger and frame.binding is not None
            and frame.binding[:4] == (birth, token, process.generation, 'controlled-acp')
            and process.token == token and process.registered_generation == process.generation and frame.eof and not frame.buffer and frame.received is None
            and frame.output is None and process.command_class == 'controlled-acp'
            and process.exit is not None and process.exit[1] == 15
            and ledger.reaped(birth, token))


def reply(request: dict, answer: dict) -> dict:
    """The caller validates the operation's closed result schema before encoding."""
    return {'request': request, 'answer': answer}


def verify_reply(response: dict, request: dict) -> dict:
    if (type(response) is not dict or set(response) != {'request', 'answer'}
            or type(response['request']) is not dict or type(response['answer']) is not dict
            or encode(response['request'], REQUEST_LIMIT) != encode(request, REQUEST_LIMIT)):
        raise Refused('control reply echo')
    return response['answer']
