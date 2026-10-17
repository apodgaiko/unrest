"""Per-attempt byte relay of the original Codex backend behind unmodified ACP.

This process has no public listener or arbitrary-RPC control. The launch owner
selects the original executable before starting the adapter. Raw events remain
in memory and stderr is drained without capture.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import hashlib
import json
import os
import stat
from pathlib import Path
import sys
from typing import Any

from .approval_native import ApprovalUnavailable, NativeBinding, native_event, serialized

FRAME_BYTES = 8 * 1024 * 1024
CONTROL_BYTES = 32 * 1024
IO_SECONDS = 5.0


async def read_frame(reader: asyncio.StreamReader, limit: int = FRAME_BYTES) -> dict[str, Any]:
    try:
        raw = await reader.readline()
        if not raw or len(raw) > limit:
            raise ApprovalUnavailable()

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ApprovalUnavailable()
                result[key] = value
            return result

        value = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ApprovalUnavailable()),
        )
        if not isinstance(value, dict):
            raise ApprovalUnavailable()
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ApprovalUnavailable() from None


async def write_frame(
    writer: asyncio.StreamWriter, frame: dict[str, Any], limit: int = FRAME_BYTES
) -> None:
    raw = serialized(frame) + b"\n"
    if len(raw) > limit:
        raise ApprovalUnavailable()
    writer.write(raw)
    await asyncio.wait_for(writer.drain(), IO_SECONDS)


class Routing:
    """IDs are remapped for every adapter request; native IDs cannot collide."""

    def __init__(self) -> None:
        self.sequence = 0
        self.adapter: dict[str, object] = {}
        self.native: dict[str, asyncio.Future[Any]] = {}
        self.server_ids: set[bytes] = set()

    def allocate(self, original: object | None = None, *, native: bool = False) -> str:
        if len(self.adapter) + len(self.native) >= 128:
            raise ApprovalUnavailable()
        self.sequence += 1
        key = f"unrest-{'native' if native else 'adapter'}:{self.sequence}"
        if native:
            self.native[key] = asyncio.get_running_loop().create_future()
        else:
            if type(original) not in (int, str):
                raise ApprovalUnavailable()
            if any(
                type(old) is type(original) and old == original for old in self.adapter.values()
            ):
                raise ApprovalUnavailable()
            self.adapter[key] = original
        return key

    def reply(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        key = frame.get("id")
        if not isinstance(key, str) or ("result" in frame) == ("error" in frame):
            raise ApprovalUnavailable()
        if key in self.native:
            future = self.native.pop(key)
            if not future.done():
                if "error" in frame or frame.get("result") != {}:
                    future.set_exception(ApprovalUnavailable())
                else:
                    future.set_result({})
            return None
        if key not in self.adapter:
            raise ApprovalUnavailable()
        return dict(frame, id=self.adapter.pop(key))


async def run(
    socket_path: str, token: str, backend_path: str, backend_digest: str, argv: list[str]
) -> None:
    process: asyncio.subprocess.Process | None = None
    tasks: list[asyncio.Task[Any]] = []
    writer: asyncio.StreamWriter | None = None
    output: asyncio.StreamWriter | None = None
    input_transport: asyncio.BaseTransport | None = None
    binding = NativeBinding()
    routes = Routing()
    used = False
    continued = False
    armed = False
    frozen = False
    try:
        with Path(backend_path).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != backend_digest:
                raise ApprovalUnavailable()
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path, limit=CONTROL_BYTES), IO_SECONDS
        )
        assert writer is not None
        await write_frame(writer, {"hello": token}, CONTROL_BYTES)
        environment = dict(os.environ)
        environment["CODEX_PATH"] = backend_path
        process = await asyncio.create_subprocess_exec(
            backend_path,
            *argv,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=FRAME_BYTES,
        )
        assert process.stdin is not None and process.stdout is not None
        await write_frame(
            writer,
            {"event": "ready", "relay_pid": os.getpid(), "backend_pid": process.pid},
            CONTROL_BYTES,
        )
        loop = asyncio.get_running_loop()
        output_transport, output_protocol = await loop.connect_write_pipe(
            lambda: asyncio.streams.FlowControlMixin(loop=loop), sys.stdout.buffer
        )
        output = asyncio.StreamWriter(output_transport, output_protocol, None, loop)
        control_lock = asyncio.Lock()
        backend_lock = asyncio.Lock()

        async def control_write(frame: dict[str, Any]) -> None:
            assert writer is not None
            async with control_lock:
                await write_frame(writer, frame, CONTROL_BYTES)

        async def backend_write(frame: dict[str, Any]) -> None:
            assert process is not None and process.stdin is not None
            async with backend_lock:
                await write_frame(process.stdin, frame)

        async def backend_reader() -> None:
            nonlocal frozen
            assert process is not None and process.stdout is not None
            while True:
                frame = await read_frame(process.stdout)
                previous = binding.event
                binding.consume(frame)
                if binding.invalid:
                    await control_write({"event": "invalid"})
                    raise ApprovalUnavailable()
                if binding.event is not None and previous is None:
                    frozen = True
                    await control_write({"event": "denied", "body": binding.event})
                if frame.get("method") == "turn/completed":
                    await control_write(
                        {
                            "event": "settled",
                            "thread_id": binding.thread_id,
                            "turn_id": binding.turn_id,
                        }
                    )
                if "method" not in frame:
                    forwarded = routes.reply(frame)
                    if forwarded is None:
                        continue
                    frame = forwarded
                elif "id" in frame:
                    if len(routes.server_ids) >= 128:
                        raise ApprovalUnavailable()
                    key = serialized(frame["id"])
                    if key in routes.server_ids:
                        raise ApprovalUnavailable()
                    routes.server_ids.add(key)
                # stdout carries ordinary adapter traffic only. Native responses
                # and private action/control data never enter that stream.
                assert output is not None
                await write_frame(output, frame)

        async def adapter_reader() -> None:
            nonlocal armed, continued, input_transport
            adapter_in = asyncio.StreamReader(limit=FRAME_BYTES)
            input_transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(adapter_in), sys.stdin.buffer
            )
            while True:
                frame = await read_frame(adapter_in)
                method = frame.get("method")
                if method == "thread/approveGuardianDeniedAction":
                    raise ApprovalUnavailable()
                if frozen and method in (
                    "thread/start",
                    "thread/resume",
                    "thread/fork",
                    "turn/steer",
                ):
                    raise ApprovalUnavailable()
                if frozen and method == "turn/start":
                    if (
                        not armed
                        or continued
                        or not binding.settled
                        or frame.get("params", {}).get("threadId") != binding.thread_id
                    ):
                        raise ApprovalUnavailable()
                    armed = False
                    continued = True
                if "method" in frame and "id" in frame:
                    frame = dict(frame, id=routes.allocate(frame["id"]))
                elif "method" not in frame:
                    key = serialized(frame.get("id"))
                    if key not in routes.server_ids:
                        raise ApprovalUnavailable()
                    routes.server_ids.remove(key)
                await backend_write(frame)

        async def control_reader() -> None:
            nonlocal used, armed
            while True:
                message = await read_frame(reader, CONTROL_BYTES)
                if set(message) != {"command", "id"} or type(message["id"]) is not int:
                    raise ApprovalUnavailable()
                command = message["command"]
                if (
                    command != "submit"
                    or used
                    or binding.invalid
                    or not binding.settled
                    or routes.adapter
                    or routes.server_ids
                ):
                    raise ApprovalUnavailable()
                event = binding.event
                if event is None:
                    raise ApprovalUnavailable()
                used = True  # consume BEFORE any transport write; ambiguity cannot retry
                key = routes.allocate(native=True)
                future = routes.native[key]
                await backend_write(
                    {
                        "id": key,
                        "method": "thread/approveGuardianDeniedAction",
                        "params": {"threadId": binding.thread_id, "event": native_event(event)},
                    }
                )
                await asyncio.wait_for(future, IO_SECONDS)
                if binding.invalid or not binding.settled:
                    raise ApprovalUnavailable()
                armed = True
                binding.erase()
                await control_write({"id": message["id"], "result": "queued"})

        async def discard_stderr() -> None:
            assert process is not None and process.stderr is not None
            while await process.stderr.read(65536):
                pass

        tasks = [
            asyncio.create_task(fn())
            for fn in (backend_reader, adapter_reader, control_reader, discard_stderr)
        ]
        done, _ = await asyncio.wait(tasks[:3], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        binding.erase()
        if input_transport is not None:
            input_transport.close()
        for future in routes.native.values():
            if not future.done():
                future.cancel()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if process is not None:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
            try:
                await asyncio.wait_for(process.wait(), IO_SECONDS)
            except TimeoutError:
                with suppress(ProcessLookupError):
                    process.kill()
                await asyncio.wait_for(process.wait(), 2)
        if output is not None:
            output.close()
        if writer is not None:
            writer.close()
            with suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 2)
        # Parent loss closes this private connection too. Remove only the two
        # fixed owned carriers; never recursively delete an unexpected child.
        root = Path(socket_path).parent
        with suppress(FileNotFoundError):
            metadata = root.lstat()
            if (
                root.resolve(strict=True) == root
                and root.name.startswith("unrest-approval-")
                and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o700
                and metadata.st_uid == os.getuid()
            ):
                (root / "backend").unlink(missing_ok=True)
                (root / "control").unlink(missing_ok=True)
                root.rmdir()


def main(socket_path: str, token: str, backend: str, digest: str) -> None:
    try:
        asyncio.run(run(socket_path, token, backend, digest, sys.argv[1:]))
    except BaseException:
        # Never expose backend bytes or an exception including private payloads.
        raise SystemExit(1) from None
