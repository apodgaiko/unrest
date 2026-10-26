"""One bounded nonblocking frame per control connection, without policy effects.

The supervisor authenticates both kernel peer and ledger epoch before dispatch.
The source independently checks the observer kernel peer and exact reply echo.
Empty EOF is not cancellation proof; only the ledger's actual-parent reap join
can discharge the narrow controlled-ACP SIGTERM case.
"""
from __future__ import annotations

import json
from functools import wraps
import socket
import struct
import time
from typing import Any

from content_manifest import Refused
from process_ledger import Birth, Ledger, integer, text

REQUEST_LIMIT = 8192
RESPONSE_LIMIT = 16384
CHANNEL_SECONDS = 4
DRAIN = frozenset({'custody_close', 'custody_signal', 'drain_inventory', 'drain_child', 'drain_complete'})


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused('control duplicate field')
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
            if characters > RESPONSE_LIMIT:
                raise Refused('control text bound')
        elif type(value) is list and len(value) <= 1024:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is dict and len(value) <= 128 and all(type(key) is str for key in value):
            pending.extend((item, depth + 1) for item in value.values())
            pending.extend((key, depth + 1) for key in value)
        else:
            raise Refused('control JSON type')


def encode(value: dict, limit: int) -> bytes:
    if type(value) is not dict:
        raise Refused('control object')
    finite(value)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    if not 0 < len(payload) <= limit:
        raise Refused('control frame size')
    return struct.pack('!I', len(payload)) + payload


def fail_channel(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except BaseException:
            self.poison.append('control transport refused')
            self.shared_poison.append('control transport refused')
            try:
                self.stream.close()
            except OSError:
                pass
            raise
    return guarded


class Frame:
    def __init__(self, stream: socket.socket, limit: int, shared_poison: list[str]):
        if type(limit) is not int or limit not in (REQUEST_LIMIT, RESPONSE_LIMIT):
            raise Refused('control frame limit')
        if stream.family != socket.AF_UNIX or stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise Refused('control Unix stream required')
        if type(shared_poison) is not list:
            raise Refused('control shared poison sink')
        self.shared_poison = shared_poison
        self.stream, self.limit = stream, limit
        self.started = time.monotonic()
        self.buffer = bytearray()
        self.received: dict | None = None
        self.output: bytes | None = None
        self.eof = False
        self.binding: tuple[Birth, str, int, str, int] | None = None
        self.poison: list[str] = []
        stream.setblocking(False)

    @fail_channel
    def capture(self, ledger: Ledger, birth: Birth, token: str, gid: int) -> None:
        self.check()
        if (self.shared_poison is not ledger.poison or self.buffer or self.received is not None
                or self.eof or self.binding is not None):
            self.refuse('control late peer capture')
        peer(self.stream, birth, gid)
        process = ledger.process(birth)
        if (type(token) is not str or process.token != token
                or process.registered_generation != process.generation
                or process.exit is not None or process.terminal is not None):
            self.refuse('control captured registration')
        self.binding = birth, token, process.generation, process.command_class, gid

    def check(self) -> None:
        if self.poison or time.monotonic() - self.started > CHANNEL_SECONDS:
            self.refuse('control channel deadline or poison')

    def refuse(self, reason: str):
        self.poison.append(reason)
        self.shared_poison.append(reason)
        self.stream.close()
        raise Refused(reason)

    @fail_channel
    def read(self) -> dict | None:
        """At most one recv per scheduler tick, even for a partial frame."""
        self.check()
        if self.received is not None or self.eof:
            return None
        try:
            block = self.stream.recv(self.limit + 5 - len(self.buffer))
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
            if type(value) is not dict:
                raise Refused('control object')
            finite(value)
        except (ValueError, RecursionError):
            self.refuse('control JSON')
        self.received = value
        return value

    @fail_channel
    def answer(self, value: dict) -> None:
        self.check()
        if self.output is not None:
            self.refuse('control duplicate answer')
        try:
            self.output = encode(value, RESPONSE_LIMIT if self.limit == REQUEST_LIMIT else REQUEST_LIMIT)
        except Refused:
            self.refuse('control output')

    @fail_channel
    def send(self) -> bool:
        """At most one send per tick; partial writes never redispatch policy."""
        self.check()
        if self.output is None:
            self.refuse('control missing answer')
        if not self.output:
            return True
        try:
            sent = self.stream.send(self.output)
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
        if type(methods) is not frozenset or not methods or len(methods) > 64:
            raise Refused('control methods')
        for method in methods:
            text(method)
        self.ledger, self.methods = ledger, methods
        self.seen: set[str] = set()
        self.poison = ledger.poison

    def admit(self, frame: Frame) -> dict:
        try:
            if type(frame) is not Frame or frame.shared_poison is not self.ledger.poison or frame.binding is None:
                raise Refused('control uncaptured channel')
            frame.check()
            birth, token, generation, command_class, gid = frame.binding
            request = frame.received
            finite(request)
            if type(request) is not dict or set(request) != {'pid', 'nonce', 'token', 'generation', 'id', 'kind', 'payload'}:
                raise Refused('control request schema')
            peer(frame.stream, birth, gid)
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
                    or process.exit is not None or process.terminal is not None
                    or (self.poison or self.ledger.poison) and request['kind'] not in DRAIN):
                raise Refused('control request authority')
            finite(request)
            self.seen.add(identifier)
            return request
        except BaseException:
            self.poison.append('control admission refused')
            raise


def cancelled_empty(frame: Frame, ledger: Ledger, birth: Birth, token: str) -> bool:
    frame.check()
    process = ledger.process(birth)
    return (not frame.poison and frame.shared_poison is ledger.poison and frame.binding is not None
            and frame.binding[:4] == (birth, token, process.generation, 'controlled-acp')
            and process.token == token and process.registered_generation == process.generation and frame.eof and not frame.buffer and frame.received is None
            and frame.output is None and process.command_class == 'controlled-acp'
            and process.exit is not None and process.exit[1] == 15
            and ledger.reaped(birth, token))


def reply(request: dict, answer: dict) -> dict:
    """The caller validates the operation's closed result schema before encoding."""
    if type(request) is not dict or type(answer) is not dict:
        raise Refused('control reply object')
    return {'request': request, 'answer': answer}


def verify_reply(response: dict, request: dict) -> dict:
    finite(response)
    finite(request)
    if (type(response) is not dict or set(response) != {'request', 'answer'}
            or type(response['request']) is not dict or type(response['answer']) is not dict
            or encode(response['request'], REQUEST_LIMIT) != encode(request, REQUEST_LIMIT)):
        raise Refused('control reply echo')
    return response['answer']
