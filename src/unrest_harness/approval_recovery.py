"""Memory-only asynchronous approval ownership and request-associated host review."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import signal
import stat
import sys
import tempfile
import time
from typing import TYPE_CHECKING, Any, AsyncIterator, Awaitable, Callable, cast

# The owned MCP server supplies Context; ownership does not load the SDK for typing.
from pydantic import BaseModel, ConfigDict, StrictBool

from .approval_native import ApprovalUnavailable, human_display, serialized
from .approval_relay import CONTROL_BYTES, IO_SECONDS, read_frame, write_frame
from .config import HarnessConfig
from .storage import (
    ProjectStore,
    atomic_write_json,
    completion_lock,
    validate_atomic_write_destination,
)

RETENTION_SECONDS = 300.0
BACKEND_PINS = frozenset(
    {
        "cc0a05e34876414280a79726153d0fe8d55c93f704ef6c292ec409bfe36d5b06",
        "09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be",
        "0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28",
    }
)


ADAPTER_SHA256 = "878d6a3d825725d0a579305a3e206c7bbb5724a95751b4e3e86af8030cdee758"


def verify_adapter(argv: tuple[str, ...], cwd: str, environment: dict[str, str]) -> None:
    if len(argv) == 1:
        command = argv[0]
        selected = (
            shutil.which(command, path=environment.get("PATH")) if "/" not in command else command
        )
    elif len(argv) == 2 and Path(argv[0]).name == "node":
        selected = argv[1]
    else:
        raise ApprovalUnavailable()
    if selected is None:
        raise ApprovalUnavailable()
    path = Path(selected)
    if not path.is_absolute():
        path = Path(cwd) / path
    with path.resolve(strict=True).open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != ADAPTER_SHA256:
            raise ApprovalUnavailable()


def safe_socket(path: str) -> None:
    target = Path(path)
    if not target.is_absolute() or target.name != "control":
        raise ApprovalUnavailable()
    directory = target.parent
    if directory.resolve(strict=True) != directory:
        raise ApprovalUnavailable()
    parent = directory.lstat()
    carrier = target.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_IMODE(parent.st_mode) != 0o700
        or parent.st_uid != os.getuid()
        or not stat.S_ISSOCK(carrier.st_mode)
        or stat.S_IMODE(carrier.st_mode) != 0o600
        or carrier.st_uid != os.getuid()
    ):
        raise ApprovalUnavailable()


class Confirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm_one_submission: StrictBool


@dataclass(frozen=True)
class RunApprovalContext:
    run_id: str
    is_running: Callable[[], bool]


def cursor_path(config: HarnessConfig, run_id: str, denial_id: str) -> Path:
    digest = hashlib.sha256(serialized([run_id, denial_id])).hexdigest()
    return config.harness_home / ".unrest-runtime" / "approval-recovery" / f"{digest}.json"


@asynccontextmanager
async def completion_fence(path: Path, deadline: float) -> AsyncIterator[None]:
    while True:
        guard = completion_lock(path, blocking=False)
        try:
            guard.__enter__()
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise ApprovalUnavailable() from None
            await asyncio.sleep(min(0.01, max(0, deadline - time.monotonic())))
    try:
        yield
    finally:
        guard.__exit__(None, None, None)


def pending_reference(
    store: ProjectStore, project: str, mission: str, attempt: str, node: str, denial_id: str
) -> str | None:
    _, cursor = store.provider_review_paths(project, mission, attempt, node)
    path = cursor.with_suffix(".selection.json")
    try:
        validate_atomic_write_destination(path, trusted_root=store.bucket_root(project))
        with path.open("rb") as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            return None
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "run_id", "denial_id"}
            or value["schema"] != "unrest.approval-selection.v1"
            or value["denial_id"] != denial_id
            or not isinstance(value["run_id"], str)
            or re.fullmatch(r"run:[0-9a-f]{64}", value["run_id"]) is None
        ):
            return None
        return (
            f"review_approval: run_id={value['run_id']} denial_id={denial_id}. "
            "Availability is rechecked by the original owner and host form; "
            "inspection, continue, retry and steering provide no approval."
        )
    except (OSError, ValueError, TypeError):
        return None


class ApprovalOwner:
    """One originating attempt, one selection, one native submission.

    The private relay handshake is distinct from the host control capability.
    Only the relay reader can populate the event. Neither MCP arguments nor ACP
    Guardian-looking tool content can select an event for execution.
    """

    def __init__(
        self,
        config: HarnessConfig,
        context: RunApprovalContext,
        store: ProjectStore,
        project_id: str,
        mission_id: str,
        attempt_id: str,
        node_id: str,
        handoff: Path,
        credentials: tuple[str, ...],
        *,
        deadline: float | None = None,
    ) -> None:
        self.config = config
        self.context = context
        self.store = store
        self.binding = (project_id, mission_id, attempt_id, node_id)
        self.handoff = handoff
        self.credentials = credentials
        self.deadline = deadline
        self.expiry: float | None = None
        self.phase = "active"
        self.event: dict[str, Any] | None = None
        self.origin: dict[str, Any] | None = None
        self.review_replied = asyncio.Event()
        self.denied = asyncio.Event()
        self.settled = asyncio.Event()
        self.decision = asyncio.Event()
        self.connected = asyncio.Event()
        self.relay_token = secrets.token_hex(32)
        self.host_token = secrets.token_hex(32)
        self.relay_writer: asyncio.StreamWriter | None = None
        self.owned_pids: tuple[int, int] | None = None
        self.adapter_pid: int | None = None
        self.pending: asyncio.Future[Any] | None = None
        self.root: Path | None = None
        self.server: asyncio.Server | None = None
        self.cursor: Path | None = None
        self.reference: Path | None = None
        self.tasks: set[asyncio.Task[Any]] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.submit_requested = False
        self.continuation_requested = False
        self._cleanup: asyncio.Task[None] | None = None

    async def launch_environment(self, environment: dict[str, str]) -> dict[str, str]:
        backend = Path(environment.get("CODEX_PATH", "")).resolve(strict=True)
        with backend.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest not in BACKEND_PINS:
            raise ApprovalUnavailable()
        self.root = Path(tempfile.mkdtemp(prefix="unrest-approval-")).resolve()
        os.chmod(self.root, 0o700)
        socket = self.root / "control"
        self.server = await asyncio.start_unix_server(
            self._accept, str(socket), limit=CONTROL_BYTES
        )
        os.chmod(socket, 0o600)
        launcher = self.root / "backend"
        # The file carries transport identity only, never configuration, an
        # event, prompt or credential. No global launcher/adapter is modified.
        launcher.write_text(
            f"#!{sys.executable}\nimport sys\nsys.path.insert(0, "
            f"{str(Path(__file__).resolve().parent.parent)!r})\n"
            "from unrest_harness.approval_relay import main\n"
            f"main({str(socket)!r}, {self.relay_token!r}, {str(backend)!r}, {digest!r})\n"
        )
        launcher.chmod(0o700)
        return dict(environment, CODEX_PATH=str(launcher))

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writers.add(writer)
        task = asyncio.create_task(self._connection(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(lambda done: None if done.cancelled() else done.exception())

    def bind_adapter(self, pid: int) -> None:
        self.adapter_pid = pid

    def transport_bound(self) -> bool:
        if self.owned_pids is None or self.adapter_pid is None:
            return False
        try:
            group = os.getpgid(self.adapter_pid)
            return all(
                pid != self.adapter_pid and os.getpgid(pid) == group for pid in self.owned_pids
            )
        except ProcessLookupError:
            return False

    def available(self) -> bool:
        return (
            self.expiry is not None
            and time.monotonic() < self.expiry
            and self.context.is_running()
            and not os.path.lexists(self.handoff)
            and self.phase in ("pending", "reviewing")
            and self.relay_writer is not None
            and not self.relay_writer.is_closing()
        )

    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = False
        claimed = False
        relay = False
        try:
            hello = await asyncio.wait_for(read_frame(reader, CONTROL_BYTES), IO_SECONDS)
            if set(hello) == {"hello"} and hmac.compare_digest(
                str(hello["hello"]), self.relay_token
            ):
                if self.relay_writer is not None or self.phase != "active":
                    raise ApprovalUnavailable()
                relay = True
                self.relay_writer = writer
                self.connected.set()
                while True:
                    message = await read_frame(reader, CONTROL_BYTES)
                    if message.get("event") == "ready" and set(message) == {
                        "event",
                        "relay_pid",
                        "backend_pid",
                    }:
                        pids = (message["relay_pid"], message["backend_pid"])
                        if (
                            self.owned_pids is not None
                            or any(
                                type(pid) is not int or pid <= 1 or pid == os.getpid()
                                for pid in pids
                            )
                            or pids[0] == pids[1]
                        ):
                            raise ApprovalUnavailable()
                        self.owned_pids = pids
                        if not self.transport_bound():
                            self.owned_pids = None
                            raise ApprovalUnavailable()
                    elif message.get("event") == "denied" and set(message) == {"event", "body"}:
                        if (
                            self.event is not None
                            or self.submit_requested
                            or self.phase != "active"
                        ):
                            raise ApprovalUnavailable()
                        event = message["body"]
                        if not isinstance(event, dict):
                            raise ApprovalUnavailable()
                        human_display(event, self.credentials)
                        self.event = event
                        self.origin = {
                            key: event[key] for key in ("threadId", "turnId", "reviewId")
                        }
                        now = time.monotonic()
                        self.expiry = min(now + RETENTION_SECONDS, self.deadline or float("inf"))
                        self.denied.set()
                        watchdog = asyncio.create_task(self._expire())
                        self.tasks.add(watchdog)
                        watchdog.add_done_callback(self.tasks.discard)
                    elif message.get("event") == "settled" and set(message) == {
                        "event",
                        "thread_id",
                        "turn_id",
                    }:
                        if self.event is not None and (
                            message["thread_id"],
                            message["turn_id"],
                        ) == (self.event["threadId"], self.event["turnId"]):
                            self.settled.set()
                    elif message == {"id": 1, "result": "queued"} and self.pending is not None:
                        if self.pending.done():
                            raise ApprovalUnavailable()
                        self.pending.set_result(None)
                    else:
                        raise ApprovalUnavailable()
            elif set(hello) == {"host", "run_id", "denial_id"} and hmac.compare_digest(
                str(hello["host"]), self.host_token
            ):
                host = True
                if (
                    not self.available()
                    or self.phase != "pending"
                    or self.event is None
                    or hello["run_id"] != self.context.run_id
                    or hello["denial_id"] != self.event["reviewId"]
                ):
                    raise ApprovalUnavailable()
                claimed = True
                self.phase = "reviewing"  # synchronous claim before any await
                claim = secrets.token_hex(32)
                await write_frame(
                    writer,
                    {
                        "display": human_display(self.event, self.credentials),
                        "claim": claim,
                        "remaining": self.remaining(),
                    },
                    CONTROL_BYTES,
                )
                decision = await asyncio.wait_for(
                    read_frame(reader, CONTROL_BYTES), self.remaining()
                )
                if decision != {"claim": claim, "decision": "confirm"} or not self.available():
                    raise ApprovalUnavailable()
                self.submit_requested = True
                self.decision.set()
                # The runner owns the completion fence and the native operation.
                while self.phase == "reviewing":
                    if self.remaining() <= 0:
                        raise ApprovalUnavailable()
                    await asyncio.sleep(min(0.02, self.remaining()))
                await write_frame(writer, {"disposition": self.phase}, CONTROL_BYTES)
                self.review_replied.set()
            else:
                raise ApprovalUnavailable()
        except (Exception, asyncio.CancelledError):
            if relay or (host and claimed and self.phase == "reviewing"):
                self.phase = "uncertain" if self.submit_requested else "unavailable"
                self.denied.set()
                self.decision.set()
                if self.pending is not None and not self.pending.done():
                    self.pending.set_exception(ApprovalUnavailable())
        finally:
            writer.close()
            with suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 2)
            self.writers.discard(writer)

    async def _expire(self) -> None:
        await asyncio.sleep(self.remaining())
        self.event = None
        if self.phase in ("active", "pending", "reviewing", "submitting", "continued"):
            self.phase = "uncertain" if self.submit_requested else "expired"
            self.decision.set()
            if self.relay_writer is not None:
                self.relay_writer.close()

    def remaining(self) -> float:
        return max(0.0, (self.expiry or time.monotonic()) - time.monotonic())

    async def wait_for_review(self) -> bool:
        if self.event is None or self.phase != "active" or not self.settled.is_set():
            return False
        self.phase = "pending"
        self.cursor = cursor_path(self.config, self.context.run_id, self.event["reviewId"])
        assert self.root is not None
        atomic_write_json(
            self.cursor,
            {
                "run_id": self.context.run_id,
                "denial_id": self.event["reviewId"],
                "owner_pid": os.getpid(),
                "socket": str(self.root / "control"),
                "token": self.host_token,
            },
            trusted_root=self.config.harness_home,
            inventory={},
            mode=0o600,
        )
        _, runtime_cursor = self.store.provider_review_paths(*self.binding)
        self.reference = runtime_cursor.with_suffix(".selection.json")
        atomic_write_json(
            self.reference,
            {
                "schema": "unrest.approval-selection.v1",
                "run_id": self.context.run_id,
                "denial_id": self.event["reviewId"],
            },
            trusted_root=self.store.bucket_root(self.binding[0]),
            inventory={},
            mode=0o600,
        )
        try:
            await asyncio.wait_for(self.decision.wait(), self.remaining())
            return self.submit_requested and self.available()
        except TimeoutError:
            self.phase = "expired"
            return False

    async def submit(self) -> bool:
        if not self.submit_requested or not self.available() or self.event is None:
            return False
        # Hold the same stable inode as end_node, preventing completion from
        # committing between the final check and the native submission.
        async with completion_fence(self.handoff, time.monotonic() + min(5, self.remaining())):
            if not self.available() or not self.transport_bound():
                return False
            self.phase = "submitting"
            self.record("submitting")  # consumed before write, never revived on restart
            self.pending = asyncio.get_running_loop().create_future()
            assert self.relay_writer is not None
            try:
                await write_frame(self.relay_writer, {"command": "submit", "id": 1}, CONTROL_BYTES)
                await asyncio.wait_for(self.pending, min(IO_SECONDS, self.remaining()))
                if not self.context.is_running() or self.remaining() <= 0:
                    raise ApprovalUnavailable()
                self.phase = "continued"
                self.record("queued")
                await asyncio.wait_for(
                    self.review_replied.wait(), min(IO_SECONDS, self.remaining())
                )
                return True
            except BaseException:
                self.phase = "uncertain"
                self.record("uncertain")
                raise
            finally:
                self.event = None

    def record(self, disposition: str) -> None:
        project, mission, attempt, node = self.binding
        durable, _ = self.store.provider_review_paths(project, mission, attempt, node)
        atomic_write_json(
            durable.with_suffix(".appeal.json"),
            {
                "schema": "unrest.provider-review-appeal.v1",
                "run_id": self.context.run_id,
                "project_id": project,
                "mission_id": mission,
                "attempt_id": attempt,
                "node_id": node,
                "disposition": disposition,
                "origin": self.origin,
            },
            trusted_root=self.store.bucket_root(project),
            inventory={},
            mode=0o600,
        )

    async def close(self) -> None:
        if self._cleanup is None:
            self._cleanup = asyncio.create_task(self._close())
        cancelled = False
        while not self._cleanup.done():
            try:
                await asyncio.shield(self._cleanup)
            except asyncio.CancelledError:
                cancelled = True
        self._cleanup.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _close(self) -> None:
        self.event = None
        self.phase = "closed"
        first: BaseException | None = None
        if self.server is not None:
            try:
                self.server.close()
            except BaseException as exc:
                first = first or exc
        for writer in list(self.writers):
            try:
                writer.close()
                writer.transport.abort()
            except BaseException as exc:
                first = first or exc
        tasks = list(self.tasks)
        for task in tasks:
            try:
                task.cancel()
            except BaseException as exc:
                first = first or exc
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except BaseException as exc:
                first = first or exc
        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), 2)
            except BaseException as exc:
                first = first or exc
        try:
            await self._stop_owned_processes()
        except BaseException as exc:
            first = first or exc
        for path, root in (
            (self.cursor, self.config.harness_home),
            (self.reference, self.store.bucket_root(self.binding[0])),
        ):
            if path is not None:
                try:
                    validate_atomic_write_destination(path, trusted_root=root)
                    path.unlink(missing_ok=True)
                except BaseException as exc:
                    first = first or exc
        if self.root is not None:
            try:
                shutil.rmtree(self.root)
            except FileNotFoundError:
                pass  # The relay also removes fixed carriers on parent loss.
            except BaseException as exc:
                first = first or exc
        if first is not None:
            raise first

    async def _stop_owned_processes(self) -> None:
        # Keep the adapter alive to reap its relay while the relay reaps the
        # original backend. Endpoint closure alone is not a process barrier.
        if self.owned_pids is not None:

            def live(pid: int) -> bool:
                try:
                    os.kill(pid, 0)
                    return True
                except ProcessLookupError:
                    return False

            cutoff = time.monotonic() + 8
            while any(live(pid) for pid in self.owned_pids) and time.monotonic() < cutoff:
                await asyncio.sleep(0.01)
            remaining = [pid for pid in self.owned_pids if live(pid)]
            for pid in remaining:
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            if remaining:
                cutoff = time.monotonic() + 2
                while any(live(pid) for pid in remaining) and time.monotonic() < cutoff:
                    await asyncio.sleep(0.01)
                if any(live(pid) for pid in remaining):
                    raise ApprovalUnavailable()


async def review_approval(
    config: HarnessConfig, runs: Any, run_id: str, denial_id: str, ctx: Context
) -> dict[str, Any]:
    """Host-only private request. No public acceptance/actor/action parameter."""
    unavailable = {"run_id": run_id, "denial_id": denial_id, "disposition": "unavailable"}
    writer: asyncio.StreamWriter | None = None
    try:
        if not config.approval_recovery or runs.inspect_run(run_id).state != "running":
            return unavailable
        # Check capabilities BEFORE acquiring a one-use host selection.
        request = ctx.request_context
        if request is None or ctx.is_background_task:
            return unavailable
        client_params = ctx.session.client_params
        if client_params is None:
            return unavailable
        capabilities = client_params.capabilities
        if capabilities.elicitation is None or capabilities.elicitation.form is None:
            return unavailable
        path = cursor_path(config, run_id, denial_id)
        validate_atomic_write_destination(path, trusted_root=config.harness_home)
        with path.open("rb") as stream:
            raw = stream.read(2049)
        if len(raw) > 2048:
            return unavailable
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"run_id", "denial_id", "owner_pid", "socket", "token"}
            or value["run_id"] != run_id
            or value["denial_id"] != denial_id
        ):
            return unavailable
        if type(value["owner_pid"]) is not int or value["owner_pid"] <= 1:
            return unavailable
        os.kill(value["owner_pid"], 0)
        safe_socket(value["socket"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(value["socket"], limit=CONTROL_BYTES), IO_SECONDS
        )
        assert writer is not None
        await write_frame(
            writer,
            {"host": value["token"], "run_id": run_id, "denial_id": denial_id},
            CONTROL_BYTES,
        )
        selection = await asyncio.wait_for(read_frame(reader, CONTROL_BYTES), IO_SECONDS)
        if (
            set(selection) != {"display", "claim", "remaining"}
            or not isinstance(selection["display"], str)
            or len(selection["display"].encode()) > 9000
            or not isinstance(selection["remaining"], int | float)
            or not 0 < selection["remaining"] <= RETENTION_SECONDS
        ):
            return unavailable
        elicit = cast(Callable[[str, type[Confirmation]], Awaitable[Any]], ctx.elicit)
        response = await asyncio.wait_for(
            elicit(selection["display"], Confirmation), selection["remaining"]
        )
        if (
            response.action != "accept"
            or not isinstance(response.data, Confirmation)
            or response.data.confirm_one_submission is not True
            or runs.inspect_run(run_id).state != "running"
        ):
            return unavailable
        await write_frame(
            writer, {"claim": selection["claim"], "decision": "confirm"}, CONTROL_BYTES
        )
        result = await asyncio.wait_for(read_frame(reader, CONTROL_BYTES), IO_SECONDS + 1)
        if result == {"disposition": "continued"}:
            return dict(unavailable, disposition="queued")
        return dict(unavailable, disposition="uncertain")
    except asyncio.CancelledError:
        raise
    except Exception:
        return unavailable
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 2)


def run_owned_mcp(parent_pid: int) -> None:
    """Keep the opt-in worker HTTP server inside its actual parent's lifetime."""
    import runpy
    import threading

    if type(parent_pid) is not int or parent_pid <= 1 or os.getppid() != parent_pid:
        raise SystemExit(1)

    def watch_parent() -> None:
        while os.getppid() == parent_pid:
            time.sleep(0.1)
        # The parent was lost without a Python finalizer. This process has only
        # the MCP listener; exiting closes it even if the event loop is stuck.
        os._exit(1)

    threading.Thread(target=watch_parent, daemon=True).start()
    sys.argv[0] = "unrest_harness"
    runpy.run_module("unrest_harness", run_name="__main__")


if TYPE_CHECKING:
    from fastmcp import Context
