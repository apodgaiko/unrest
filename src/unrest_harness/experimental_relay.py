"""Fixed synthetic byte relay; no provider, spawning, reconnect or protocol parsing."""
from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
import hmac
import json
import os
import secrets
import select
import socket
import sys
import time
from typing import Awaitable, Callable

BUFFER = 65536
AUTH_BYTES = 65
AUTH_SECONDS = 1.0
WRITE_SECONDS = 2.0
lifetime: socket.socket


@dataclass
class ConnectionCleanup:
    """Retain accepted sockets and their sole waiters across caller cancellation."""

    writers: dict[asyncio.StreamWriter, asyncio.Task[None] | None] = field(default_factory=dict)
    owner: asyncio.Task[None] | None = None
    closing: bool = False

    def register(self, writer: asyncio.StreamWriter) -> None:
        self.writers.setdefault(writer, None)
        if self.closing:
            writer.close()
            writer.transport.abort()
            self._waiter(writer)

    def _waiter(self, writer: asyncio.StreamWriter) -> asyncio.Task[None]:
        waiter = self.writers[writer]
        if waiter is None:
            waiter = asyncio.create_task(writer.wait_closed())
            # Observe late errors even when a bounded cleanup has already refused.
            waiter.add_done_callback(lambda task: None if task.cancelled() else task.exception())
            self.writers[writer] = waiter
        return waiter

    async def close(self, server: asyncio.Server | None,
                    tasks: set[asyncio.Task[None]]) -> None:
        if self.owner is None:
            self.closing = True
            if server is not None:
                server.close()
            self.owner = asyncio.create_task(self._close(server, tasks))
        cancelled = False
        while not self.owner.done():
            try:
                await asyncio.shield(self.owner)
            except asyncio.CancelledError:
                cancelled = True
        self.owner.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _close(self, server: asyncio.Server | None,
                     tasks: set[asyncio.Task[None]]) -> None:
        deadline = asyncio.get_running_loop().time() + WRITE_SECONDS
        drained: set[asyncio.StreamWriter] = set()
        uncertain = False
        # Listener close can leave already queued connection callbacks. Give them
        # a turn, then drain to a fixed point before the final server barrier.
        while True:
            await asyncio.sleep(0)
            batch = set(self.writers) - drained
            for writer in batch:
                writer.close()
                writer.transport.abort()
            for task in tasks:
                if not task.done():
                    task.cancel()
            writer_waits = {self._waiter(writer) for writer in batch}
            waits = writer_waits | set(tasks)
            if waits:
                done, pending = await asyncio.wait(
                    waits, timeout=max(0, deadline - asyncio.get_running_loop().time()))
                uncertain |= bool(pending)
                for task in done:
                    if (not task.cancelled() and task.exception() is not None
                            and (task not in writer_waits
                                 or not isinstance(task.exception(), OSError))):
                        uncertain = True
            drained.update(batch)
            await asyncio.sleep(0)
            if set(self.writers) == drained:
                break
            if asyncio.get_running_loop().time() >= deadline:
                uncertain = True
                break
        if server is not None:
            try:
                async with asyncio.timeout(WRITE_SECONDS):
                    await server.wait_closed()
            except (OSError, TimeoutError):
                uncertain = True
        # No timeout may cancel StreamWriter's shared protocol close future.
        if set(self.writers) != drained or uncertain:
            raise TimeoutError('synthetic_connection_cleanup_uncertain')


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               eof: Callable[[], None], observe: Callable[[bytes], None] | None = None,
               restrict: Callable[[bytes], bytes] | None = None,
               shutting_down: Callable[[], bool] = lambda: False) -> None:
    """Bound memory and stalled writes; preserve half-close and every payload byte."""
    writer.transport.set_write_buffer_limits(high=BUFFER, low=BUFFER // 2)
    while True:
        try:
            data = await reader.read(BUFFER)
        except (BrokenPipeError, ConnectionResetError):
            if shutting_down():
                return
            raise
        if not data:
            break
        # Policy and observation callbacks remain failures even during shutdown.
        if restrict is not None:
            data = restrict(data)
        if observe is not None:
            observe(data)
        try:
            writer.write(data)
            async with asyncio.timeout(WRITE_SECONDS):
                await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            if shutting_down():
                return
            raise
    eof()
    if writer.can_write_eof():
        try:
            writer.write_eof()
        except (BrokenPipeError, ConnectionResetError):
            if not shutting_down():
                raise
    else:
        try:
            writer.close()
        except (BrokenPipeError, ConnectionResetError):
            if not shutting_down():
                raise


@dataclass
class Bridge:
    backend_reader: asyncio.StreamReader
    backend_writer: asyncio.StreamWriter
    lost: Callable[[], None]
    admit: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]] | None = None
    observe_adapter: Callable[[bytes], None] | None = None
    observe_backend: Callable[[bytes], None] | None = None
    restrict_adapter: Callable[[bytes], bytes] | None = None
    restrict_backend: Callable[[bytes], bytes] | None = None
    diagnostic_phase: Callable[[str], None] | None = None
    diagnostic_failure: Callable[[BaseException], None] | None = None
    nonce: str = field(default_factory=lambda: secrets.token_hex(32))
    connected: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: set[asyncio.Task[None]] = field(default_factory=set)
    server: asyncio.Server | None = None
    writer: asyncio.StreamWriter | None = None
    claimed: bool = False
    closing: bool = False
    cleanup: ConnectionCleanup = field(default_factory=ConnectionCleanup)

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    observe: Callable[[bytes], None] | None,
                    restrict: Callable[[bytes], bytes] | None) -> None:
        try:
            await pump(reader, writer, self.lost, observe, restrict, lambda: self.closing)
        except BaseException as error:
            if not self.closing:
                # Revoke in this task, before completion can wake a queued sender.
                # Auxiliary callbacks must neither skip loss nor replace the cause.
                with suppress(BaseException):
                    try:
                        if self.diagnostic_failure is not None:
                            self.diagnostic_failure(error)
                    finally:
                        self.lost()
            raise

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.accept, '127.0.0.1', 0,
                                                 limit=BUFFER, backlog=1)
        return int(self.server.sockets[0].getsockname()[1])

    def accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.cleanup.register(writer)
        # The first TCP connection consumes admission, even if authentication fails.
        if self.claimed or self.closing:
            writer.close()
            return
        self.claimed = True
        self.writer = writer
        assert self.server is not None
        self.server.close()
        task = asyncio.create_task(self.attach(reader, writer))
        self.tasks.add(task)

    async def attach(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.cleanup.register(writer)
        self.writer = writer
        from .experimental_diagnostics import startup_timeout

        pumps: list[asyncio.Task[None]] = []
        try:
            if self.diagnostic_phase is not None:
                self.diagnostic_phase('bridge_auth')
            async with startup_timeout(AUTH_SECONDS, 'bridge_auth'):
                greeting = await reader.readexactly(AUTH_BYTES)
            if not hmac.compare_digest(greeting, (self.nonce + '\n').encode()):
                if self.diagnostic_failure is not None:
                    self.diagnostic_failure(PermissionError())
                return
            if self.admit is not None:
                if self.diagnostic_phase is not None:
                    self.diagnostic_phase('bridge_admission')
                await self.admit(reader, writer)
            # readexactly leaves a coalesced first payload in the StreamReader.
            self.connected.set()
            if self.diagnostic_phase is not None:
                self.diagnostic_phase('bridge_forward')
            pumps = [asyncio.create_task(self._pump(reader, self.backend_writer,
                                                   self.observe_adapter, self.restrict_adapter)),
                     asyncio.create_task(self._pump(self.backend_reader, writer,
                                                   self.observe_backend, self.restrict_backend))]
            self.tasks.update(pumps)
            await asyncio.gather(*pumps)
        except (OSError, TimeoutError, asyncio.IncompleteReadError) as error:
            if not pumps and self.diagnostic_failure is not None:
                self.diagnostic_failure(error)
        except BaseException as error:
            if not self.closing and self.diagnostic_failure is not None:
                if not pumps:
                    self.diagnostic_failure(error)
                elif isinstance(error, asyncio.CancelledError):
                    # gather can cancel pumps before their first instruction.
                    with suppress(BaseException):
                        self.diagnostic_failure(error)
            raise
        finally:
            if not self.closing:
                self.lost()
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            writer.close()
            # Only the retained bridge close owner awaits the shared close future.

    def begin_shutdown(self) -> None:
        """Classify subsequent native I/O failures before intentional peer teardown."""
        self.closing = True

    async def close(self) -> None:
        self.begin_shutdown()
        await self.cleanup.close(self.server, self.tasks)


def forward(connection: socket.socket) -> None:
    """Non-forking relay with at most 64 KiB pending in each direction."""
    connection.setblocking(False)
    os.set_blocking(0, False)
    os.set_blocking(1, False)
    pending = {connection.fileno(): bytearray(), 1: bytearray()}
    inputs = {0: connection.fileno(), connection.fileno(): 1}
    stalled: dict[int, float] = {}
    write_closed = False
    output_closed = False
    while inputs or any(pending.values()):
        readable = [fd for fd, target in inputs.items() if len(pending[target]) < BUFFER]
        writable = [fd for fd, data in pending.items() if data]
        ready, writes, _ = select.select(readable, writable, [], .1)
        for fd in ready:
            target = inputs[fd]
            try:
                data = os.read(fd, BUFFER - len(pending[target]))
            except BlockingIOError:
                continue
            if data:
                if not pending[target]:
                    stalled[target] = time.monotonic()
                pending[target].extend(data)
            else:
                del inputs[fd]
        for fd in writes:
            try:
                written = os.write(fd, pending[fd])
            except BlockingIOError:
                continue
            del pending[fd][:written]
            stalled[fd] = time.monotonic()
        if not write_closed and 0 not in inputs and not pending[connection.fileno()]:
            connection.shutdown(socket.SHUT_WR)
            # Shutdown only once, while continuing the opposite stream.
            write_closed = True
        if not output_closed and connection.fileno() not in inputs and not pending[1]:
            os.close(1)
            output_closed = True
        if any(data and time.monotonic() - stalled[fd] > WRITE_SECONDS
               for fd, data in pending.items()):
            raise TimeoutError('stalled')


def main() -> None:
    # Validate before any connection. No argument can select a backend/destination.
    if sys.argv[1:] != ['app-server']:
        raise ValueError('argv')
    port, nonce, lifetime_port, lifetime_nonce = json.loads(os.environ['SYNTHETIC_RELAY'])
    if (type(port) is not int or type(lifetime_port) is not int
            or not 0 < port < 65536 or not 0 < lifetime_port < 65536
            or type(nonce) is not str or len(nonce) != 64
            or type(lifetime_nonce) is not str or len(lifetime_nonce) != 64):
        raise ValueError('launch')
    # Sole global reference; never duplicated/closed by this pinned non-forking
    # program. EOF observes interpreter lifetime, not bridge closure or wait/reap.
    global lifetime
    lifetime = socket.create_connection(('127.0.0.1', lifetime_port), timeout=AUTH_SECONDS)
    lifetime.sendall((lifetime_nonce + '\n').encode())
    with socket.create_connection(('127.0.0.1', port), timeout=AUTH_SECONDS) as connection:
        connection.sendall((nonce + '\n').encode())
        forward(connection)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Fixed structural diagnostic only, never exception text or protocol bytes.
        os.write(2, b'synthetic_relay_failed\n')
        sys.exit(1)
