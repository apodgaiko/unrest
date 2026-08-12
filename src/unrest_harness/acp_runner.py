from __future__ import annotations

import asyncio
import codecs
import inspect
import json
import logging
import os
import shutil
import shlex
import socket
import subprocess
import sys
import threading
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, ClassVar, Coroutine, Literal

from . import __version__
from .assets import AssetLoader
from .capability_policy import (
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_PROFILE,
    CapabilityAccessError,
    CapabilityPolicyError,
    ResolvedRoleCapability,
    RoleName,
    StreamingCredentialRedactor,
    build_role_environment,
    enforce_environment_credential_provenance,
    enforce_persisted_environment_credential_provenance,
    finite_credential_values,
    profile_environment,
    redact_credential_values,
    redact_sensitive_value,
    resolve_role_capability,
    serialize_sensitive_value_inventory,
    validate_role_environment,
)
from .config import HarnessConfig
from .dispatcher import DispatchRequest, NodeHandoff
from .models import (
    Task,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from .storage import (
    ProjectStore,
    atomic_write_json,
    trusted_persistence_root,
    validate_atomic_write_destination,
)

logger = logging.getLogger(__name__)
ProgressCallback = Callable[[str], Awaitable[None] | None]
SUBPROCESS_STREAM_LIMIT = int(
    os.environ.get(
        "UNREST_SUBPROCESS_STREAM_LIMIT_BYTES",
        str(8 * 1024 * 1024),
    )
)
MCP_STREAM_CAPTURE_LIMIT = 64 * 1024
MCP_DRAIN_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class _NodeRuntime:
    role: Literal["validator", "worker"]
    role_config: HarnessConfig
    policy: ResolvedRoleCapability
    command: str
    workspace_path: Path
    workspace_dir: str
    project_bucket: str
    handoff_path: Path
    runtime_environment: dict[str, str]
    agent_environment: dict[str, str]
    terminal_environment: dict[str, str]
    credentials: dict[str, str]


def _write_pipe_payload(
    fd: int,
    sensitive_inventory: dict[str, str],
) -> None:
    payload = serialize_sensitive_value_inventory(sensitive_inventory)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Helpers (carried over from stable_version)
# ---------------------------------------------------------------------------


def _run_cmd(command: list[str], cwd: str | None = None, *, timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (result.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _normalize_progress_text(text: str) -> str:
    return " ".join(text.split())


def _extract_text_fragments(payload: Any) -> list[str]:
    if payload is None:
        return []
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, list):
        out: list[str] = []
        for item in payload:
            out.extend(_extract_text_fragments(item))
        return out
    if isinstance(payload, dict):
        if payload.get("type") == "text" and isinstance(payload.get("text"), str):
            return [payload["text"]]
        if "content" in payload:
            return _extract_text_fragments(payload["content"])
    return []


def _truncate_text(text: str, *, limit: int = 280) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _redact_json_value(value: Any, credentials: dict[str, str]) -> Any:
    return redact_sensitive_value(value, credentials)


def _redact_terminal_bytes(
    output: bytes,
    credentials: dict[str, str],
    *,
    incomplete: bool,
) -> str:
    """Redact a terminal snapshot while retaining undecidable stream suffixes."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    text = decoder.decode(output, final=not incomplete)
    redactor = StreamingCredentialRedactor(credentials)
    return redactor.feed(text, final=not incomplete)


def _load_redacted_json(path: Path, credentials: dict[str, str]) -> Any:
    data = json.loads(path.read_text(encoding="utf-8"))
    redacted = _redact_json_value(data, credentials)
    if redacted != data:
        atomic_write_json(path, redacted, trusted_root=path.parent)
    return redacted


_DROP_CREDENTIAL_ALIAS = object()


def _structured_value_is_sensitive(
    value: str,
    credentials: dict[str, str],
) -> bool:
    return not enforce_persisted_environment_credential_provenance(
        {"value": value},
        credentials,
    )


def _drop_structured_credential_aliases(
    value: Any,
    credentials: dict[str, str],
) -> Any:
    """Remove structured scalar values or keys containing credential tokens."""
    if isinstance(value, str):
        if _structured_value_is_sensitive(value, credentials):
            return _DROP_CREDENTIAL_ALIAS
        return value
    if isinstance(value, list):
        items = (
            _drop_structured_credential_aliases(item, credentials)
            for item in value
        )
        return [item for item in items if item is not _DROP_CREDENTIAL_ALIAS]
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, item in sorted(value.items(), key=lambda entry: str(entry[0])):
            if (
                isinstance(key, str)
                and _structured_value_is_sensitive(key, credentials)
            ):
                continue
            projected = _drop_structured_credential_aliases(item, credentials)
            if projected is not _DROP_CREDENTIAL_ALIAS:
                sanitized[key] = projected
        return sanitized
    return value


class ACPError(Exception):
    pass


def _augment_acp_command(command: str, provider, reasoning_effort: str | None = None) -> str:
    """Return the ACP adapter command unchanged.

    ``codex-acp`` does not parse Codex CLI ``-c`` options. Its supported
    integration surface is the environment prepared by
    :func:`_acp_subprocess_env`. The unused compatibility parameters remain in
    this helper so older callers do not need to change atomically.
    """
    return command


def _acp_subprocess_env(
    provider,
    *,
    policy: ResolvedRoleCapability,
    reasoning_effort: str | None = None,
    model: str | None = None,
    internal: dict[str, str] | None = None,
    host_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the least-privilege environment handed to an ACP agent."""
    host = dict(os.environ if host_environment is None else host_environment)
    credentials = finite_credential_values(host)
    env = build_role_environment(
        policy,
        host,
        internal=internal,
        include_credentials=True,
    )
    name = getattr(provider, "name", None)
    if name == "codex":
        codex_path = host.get("CODEX_PATH")
        if not codex_path:
            codex_path = shutil.which("codex", path=host.get("PATH"))
        if codex_path:
            env["CODEX_PATH"] = codex_path

        config: dict[str, Any] = {}
        raw_config = host.get("CODEX_CONFIG")
        if raw_config:
            try:
                parsed = json.loads(raw_config)
            except json.JSONDecodeError as exc:
                raise ValueError("CODEX_CONFIG must be a valid JSON object") from exc
            if not isinstance(parsed, dict):
                raise ValueError("CODEX_CONFIG must be a valid JSON object")
            sanitized = _drop_structured_credential_aliases(parsed, credentials)
            if not isinstance(sanitized, dict):
                raise AssertionError("sanitized CODEX_CONFIG must remain an object")
            config.update(sanitized)
        if policy.profile == UNSAFE_DEVELOPMENT_PROFILE:
            config.update(
                {
                    "sandbox_mode": "danger-full-access",
                    "approval_policy": "never",
                    "model_reasoning_effort": reasoning_effort or "medium",
                }
            )
            env["INITIAL_AGENT_MODE"] = "agent-full-access"
            env["CODEX_SANDBOX"] = "danger-full-access"
            env["CODEX_DISABLE_SANDBOX"] = "1"
        else:
            config.update(
                {
                    "sandbox_mode": "workspace-write",
                    "approval_policy": "on-request",
                    "model_reasoning_effort": reasoning_effort or "medium",
                }
            )
            env["INITIAL_AGENT_MODE"] = "agent"
            env.pop("CODEX_SANDBOX", None)
            env.pop("CODEX_DISABLE_SANDBOX", None)
        if model:
            config["model"] = model
        sanitized_config = _drop_structured_credential_aliases(config, credentials)
        if not isinstance(sanitized_config, dict):
            raise AssertionError("sanitized CODEX_CONFIG must remain an object")
        config = sanitized_config
        env["CODEX_CONFIG"] = json.dumps(config, separators=(",", ":"), sort_keys=True)
    else:
        for key in (
            "CODEX_CONFIG",
            "CODEX_PATH",
            "CODEX_SANDBOX",
            "CODEX_DISABLE_SANDBOX",
            "INITIAL_AGENT_MODE",
        ):
            env.pop(key, None)
        if policy.profile == SAFE_PROFILE:
            for key in (
                "CLAUDE_CODE_BYPASS_PERMISSIONS",
                "CLAUDE_CODE_DISABLE_PERMISSIONS",
                "CLAUDE_CODE_PERMISSION_MODE",
            ):
                env.pop(key, None)
    final_environment = enforce_environment_credential_provenance(
        env,
        credentials,
        inherit_all=policy.environment.inherit_all,
    )
    validate_role_environment(policy, final_environment)
    return final_environment


_NOT_FOUND = object()


async def _close_subprocess(process: asyncio.subprocess.Process, *, timeout: float = 5) -> None:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except Exception:  # noqa: BLE001
            pass
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except OSError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            pass
    transport: object = getattr(process, "_transport", None)
    if transport is not None:
        try:
            getattr(transport, "close", lambda: None)()
        except Exception:  # noqa: BLE001
            pass


async def _wait_for_process_exit(
    process: asyncio.subprocess.Process, *, timeout: float = 5
) -> None:
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except OSError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            pass


async def _drain_stream_chunks(
    stream: asyncio.StreamReader | None,
    *,
    capture_limit: int = MCP_STREAM_CAPTURE_LIMIT,
) -> str:
    if stream is None:
        return ""
    captured = bytearray()
    try:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            if len(captured) < capture_limit:
                remaining = capture_limit - len(captured)
                captured.extend(chunk[:remaining])
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        return captured.decode("utf-8", errors="replace")
    return captured.decode("utf-8", errors="replace")


@dataclass
class ManagedTerminal:
    terminal_id: str
    process: asyncio.subprocess.Process
    output: bytearray = field(default_factory=bytearray)
    output_limit: int = 1024 * 1024
    exit_waiters: list[asyncio.Future] = field(default_factory=list)
    truncated: bool = False


@dataclass
class ACPProgressTracker:
    callback: ProgressCallback | None = None
    redactor: Callable[[str], str] = lambda text: text
    stream_redactor: StreamingCredentialRedactor | None = None
    agent_message_id: str | None = None
    agent_buffer: str = ""
    last_emitted: str = ""
    diagnostic_buffer: str = ""

    async def handle_session_update(self, params: dict[str, Any]) -> None:
        update = params.get("update")
        if not isinstance(update, dict):
            return
        if update.get("sessionUpdate") == "agent_message_chunk":
            text = "".join(_extract_text_fragments(update.get("content")))
            if not text:
                return
            mid = update.get("messageId")
            if mid and mid != self.agent_message_id:
                await self._flush()
                self.agent_message_id = str(mid)
            safe_text = (
                self.stream_redactor.feed(text)
                if self.stream_redactor is not None
                else text
            )
            self.agent_buffer += safe_text
            normalized = _normalize_progress_text(self.agent_buffer)
            if (
                "\n" in text
                or self.agent_buffer.rstrip().endswith((".", "!", "?", ":", ";"))
                or len(normalized) >= 160
            ):
                await self._flush()

    async def flush(self) -> None:
        if self.stream_redactor is not None:
            self.agent_buffer += self.stream_redactor.finish()
        await self._flush()

    async def _flush(self) -> None:
        safe_buffer = (
            self.agent_buffer
            if self.stream_redactor is not None
            else self.redactor(self.agent_buffer)
        )
        msg = _normalize_progress_text(safe_buffer)
        self.agent_buffer = ""
        self.diagnostic_buffer = (self.diagnostic_buffer + safe_buffer)[-4000:]
        if not msg or self.callback is None or msg == self.last_emitted:
            return
        self.last_emitted = msg
        out = self.callback(f"Agent: {msg}")
        if inspect.isawaitable(out):
            await out


# ---------------------------------------------------------------------------
# ACP JSON-RPC client (unchanged from stable)
# ---------------------------------------------------------------------------


class ACPClient:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        working_dir: str,
        policy: ResolvedRoleCapability,
        terminal_environment: dict[str, str],
        session_update_handler: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    ):
        self._process = process
        self._working_dir = working_dir
        self._policy = policy
        self._terminal_environment = terminal_environment
        self._credentials: dict[str, str] = finite_credential_values(
            terminal_environment
        )
        self._session_update_handler = session_update_handler
        self._request_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._terminals: dict[str, ManagedTerminal] = {}
        self._terminal_count = 0
        self._request_tasks: set[asyncio.Task] = set()
        self._closing = False

    def set_credential_inventory(self, credentials: dict[str, str]) -> None:
        self._credentials = credentials.copy()

    async def start(self) -> None:
        self._reader_task = asyncio.create_task(self._read_loop())

    async def send_request(self, method: str, params: dict[str, Any]) -> Any:
        if self._closing:
            raise ACPError("ACP client is shutting down")
        self._request_id += 1
        rid = self._request_id
        msg = {
            "jsonrpc": "2.0",
            "method": method,
            "params": _redact_json_value(params, self._credentials),
            "id": rid,
        }
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[rid] = future
        try:
            await self._write(msg)
        except Exception:
            self._pending.pop(rid, None)
            raise
        return await future

    async def _write(self, msg: dict[str, Any]) -> None:
        assert self._process.stdin is not None
        safe_msg = _redact_json_value(msg, self._credentials)
        data = json.dumps(safe_msg).encode("utf-8") + b"\n"
        self._process.stdin.write(data)
        await self._process.stdin.drain()

    async def _read_loop(self) -> None:
        assert self._process.stdout is not None
        try:
            while line := await self._process.stdout.readline():
                txt = line.decode("utf-8", errors="replace").strip()
                if not txt:
                    continue
                try:
                    data = json.loads(txt)
                except json.JSONDecodeError:
                    continue
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    if "result" in entry or "error" in entry:
                        self._handle_response(entry)
                    elif "method" in entry:
                        task = asyncio.create_task(self._handle_request(entry))
                        self._request_tasks.add(task)
                        task.add_done_callback(self._request_tasks.discard)
        except (BrokenPipeError, ConnectionResetError, OSError, asyncio.CancelledError):
            pass
        finally:
            for t in list(self._request_tasks):
                t.cancel()
            err = "ACP client shutting down" if self._closing else "ACP process exited"
            for rid, fut in self._pending.items():
                if not fut.done():
                    fut.set_exception(ACPError(err))
            self._pending.clear()

    def _handle_response(self, data: dict[str, Any]) -> None:
        rid = data.get("id")
        if rid is not None and rid in self._pending:
            fut = self._pending.pop(rid)
            if "error" in data:
                error = _redact_json_value(data["error"], self._credentials)
                fut.set_exception(ACPError(str(error)))
            else:
                result = _redact_json_value(data.get("result"), self._credentials)
                fut.set_result(result)

    async def _handle_request(self, data: dict[str, Any]) -> None:
        method = data["method"]
        params = data.get("params", {})
        rid = data.get("id")
        try:
            result = await self._dispatch(method, params)
        except Exception as e:  # noqa: BLE001
            if rid is not None:
                await self._write(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "error": {
                            "code": -32603,
                            "message": redact_credential_values(
                                str(e),
                                self._credentials,
                            ),
                        },
                    }
                )
            return
        if rid is not None:
            if result is _NOT_FOUND:
                await self._write(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                )
            else:
                if method != "terminal/output":
                    result = _redact_json_value(result, self._credentials)
                await self._write(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "result": result if result is not None else {},
                    }
                )

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if method == "session/update":
            if self._session_update_handler is not None:
                try:
                    out = self._session_update_handler(params)
                    if inspect.isawaitable(out):
                        await out
                except Exception:  # noqa: BLE001
                    pass
            return None
        if method == "session/request_permission":
            return self._handle_permission_request(params)
        if method == "fs/read_text_file":
            return self._handle_fs_read(params)
        if method == "fs/write_text_file":
            return self._handle_fs_write(params)
        if method == "terminal/create":
            return await self._handle_terminal_create(params)
        if method == "terminal/output":
            return self._handle_terminal_output(params)
        if method == "terminal/wait_for_exit":
            return await self._handle_terminal_wait(params)
        if method in ("terminal/release", "terminal/kill"):
            return self._handle_terminal_release(params)
        return _NOT_FOUND

    def _handle_fs_read(self, params: dict[str, Any]) -> dict[str, str]:
        path = self._policy.authorize_path(
            params.get("path", ""),
            access="read",
            working_dir=Path(self._working_dir),
        )
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            line = params.get("line")
            limit = params.get("limit")
            if line is not None:
                line = max(0, int(line) - 1)
                lines = text.splitlines()
                if limit is not None:
                    text = "\n".join(lines[line : line + int(limit)])
                else:
                    text = "\n".join(lines[line:])
        except OSError:
            text = ""
        return {"content": text}

    def _handle_fs_write(self, params: dict[str, Any]) -> dict[str, Any]:
        path = self._policy.authorize_path(
            params["path"],
            access="write",
            working_dir=Path(self._working_dir),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        content = _redact_json_value(params["content"], self._credentials)
        if not isinstance(content, str):
            raise CapabilityAccessError(
                "filesystem:write",
                "content must be text",
            )
        path.write_text(content, encoding="utf-8")
        return {}

    async def _handle_terminal_create(self, params: dict[str, Any]) -> dict[str, str]:
        command = params.get("command", "")
        if not isinstance(command, str) or not command:
            raise ValueError("terminal command must be a non-empty string")
        raw_args = params.get("args")
        args = [] if raw_args is None else raw_args
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError("terminal args must be a list of strings")
        self._policy.authorize_command(command)
        cwd = self._policy.authorize_path(
            params.get("cwd") or self._working_dir,
            access="cwd",
            working_dir=Path(self._working_dir),
        )
        raw_env = params.get("env")
        env_list = [] if raw_env is None else raw_env
        if not isinstance(env_list, list):
            raise ValueError("terminal env must be a list")
        requested_environment: dict[str, str] = {}
        for variable in env_list:
            if (
                not isinstance(variable, dict)
                or not isinstance(variable.get("name"), str)
                or not isinstance(variable.get("value"), str)
            ):
                raise ValueError("terminal env entries require string name/value")
            name = variable["name"]
            if name in requested_environment:
                raise ValueError(f"duplicate terminal environment name: {name}")
            requested_environment[name] = variable["value"]
        self._policy.authorize_terminal_environment(tuple(requested_environment))
        for name in self._credentials:
            requested_environment.pop(name, None)

        raw_output_limit = params.get("outputByteLimit")
        output_limit = 1024 * 1024 if raw_output_limit is None else raw_output_limit
        if (
            not isinstance(output_limit, int)
            or isinstance(output_limit, bool)
            or output_limit <= 0
        ):
            raise ValueError("outputByteLimit must be a positive integer")
        env = enforce_environment_credential_provenance(
            {**self._terminal_environment, **requested_environment},
            self._credentials,
            inherit_all=False,
        )
        self._terminal_count += 1
        terminal_id = f"terminal-{self._terminal_count}"
        process = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(cwd),
            env=env,
            limit=SUBPROCESS_STREAM_LIMIT,
        )
        terminal = ManagedTerminal(
            terminal_id=terminal_id, process=process, output_limit=output_limit
        )
        self._terminals[terminal_id] = terminal
        asyncio.create_task(self._read_terminal_output(terminal))
        return {"terminalId": terminal_id}

    def _handle_permission_request(self, params: dict[str, Any]) -> dict[str, Any]:
        options = params.get("options")
        tool_call = params.get("toolCall")
        if not isinstance(options, list) or not isinstance(tool_call, dict):
            return {"outcome": {"outcome": "cancelled"}}
        kind = tool_call.get("kind")
        if not isinstance(kind, str) or not kind:
            return {"outcome": {"outcome": "cancelled"}}
        valid_kinds = {
            "allow_always",
            "allow_once",
            "reject_always",
            "reject_once",
        }
        option_ids: set[str] = set()
        for option in options:
            if not isinstance(option, dict):
                return {"outcome": {"outcome": "cancelled"}}
            option_id = option.get("optionId")
            name = option.get("name")
            option_kind = option.get("kind")
            if (
                not isinstance(option_id, str)
                or not option_id.strip()
                or not isinstance(name, str)
                or not name.strip()
                or not isinstance(option_kind, str)
                or option_kind not in valid_kinds
                or option_id in option_ids
            ):
                return {"outcome": {"outcome": "cancelled"}}
            option_ids.add(option_id)

        allowed = (
            self._policy.approvals.behavior == "allow_once"
            and kind in self._policy.approvals.tool_kinds
        )
        desired_kind = "allow_once" if allowed else "reject_once"
        matching = [
            option for option in options if option["kind"] == desired_kind
        ]
        if len(matching) != 1:
            return {"outcome": {"outcome": "cancelled"}}
        return {
            "outcome": {
                "optionId": matching[0]["optionId"],
                "outcome": "selected",
            }
        }

    async def _read_terminal_output(self, terminal: ManagedTerminal) -> None:
        assert terminal.process.stdout is not None
        try:
            while chunk := await terminal.process.stdout.read(4096):
                if terminal.truncated:
                    continue
                if len(terminal.output) + len(chunk) > terminal.output_limit:
                    terminal.truncated = True
                    remaining = terminal.output_limit - len(terminal.output)
                    terminal.output.extend(chunk[:remaining])
                    continue
                terminal.output.extend(chunk)
        except Exception:  # noqa: BLE001
            pass
        await terminal.process.wait()
        for w in terminal.exit_waiters:
            if not w.done():
                w.set_result((terminal.process.returncode, None))

    def _handle_terminal_output(self, params: dict[str, Any]) -> dict[str, Any]:
        tid = params.get("terminalId", "")
        t = self._terminals.get(tid)
        if t is None:
            return {"output": "", "truncated": False}
        out: dict[str, Any] = {
            "output": _redact_terminal_bytes(
                bytes(t.output),
                self._credentials,
                incomplete=t.process.returncode is None or t.truncated,
            ),
            "truncated": t.truncated,
        }
        if t.process.returncode is not None:
            out["exitStatus"] = {"exitCode": t.process.returncode}
        return out

    async def _handle_terminal_wait(self, params: dict[str, Any]) -> dict[str, Any]:
        tid = params.get("terminalId", "")
        t = self._terminals.get(tid)
        if t is None:
            return {"exitCode": -1, "signal": None}
        if t.process.returncode is not None:
            return {"exitCode": t.process.returncode, "signal": None}
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        t.exit_waiters.append(fut)
        code, sig = await fut
        return {"exitCode": code, "signal": sig}

    def _handle_terminal_release(self, params: dict[str, Any]) -> dict[str, Any]:
        tid = params.get("terminalId", "")
        t = self._terminals.pop(tid, None)
        if t and t.process.returncode is None:
            try:
                t.process.terminate()
            except OSError:
                pass
        return {}

    async def cleanup(self, *, close_main_process: bool = True) -> None:
        self._closing = True
        for t in self._terminals.values():
            if t.process.returncode is None:
                try:
                    t.process.terminate()
                except OSError:
                    pass
            await _close_subprocess(t.process, timeout=5)
        self._terminals.clear()
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if close_main_process:
            await _close_subprocess(self._process, timeout=5)


# ---------------------------------------------------------------------------
# ACPNodeRunner — the v5 equivalent of the stable ACPWorkerRunner
# ---------------------------------------------------------------------------


@dataclass
class ACPNodeRunner:
    """Runs ONE node end-to-end via ACP + worker MCP server subprocess."""

    supports_progress_updates: ClassVar[bool] = True
    config: HarnessConfig
    loader: AssetLoader
    _mcp_drains: dict[
        int, tuple[asyncio.Task[str], asyncio.Task[str]]
    ] = field(default_factory=dict, init=False, repr=False)
    _mcp_start_locks: weakref.WeakKeyDictionary[
        asyncio.AbstractEventLoop, asyncio.Lock
    ] = field(
        default_factory=weakref.WeakKeyDictionary,
        init=False,
        repr=False,
    )
    _mcp_start_locks_guard: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def _mcp_start_lock(self) -> asyncio.Lock:
        """Return the startup serializer owned by the current event loop."""
        loop = asyncio.get_running_loop()
        with self._mcp_start_locks_guard:
            lock = self._mcp_start_locks.get(loop)
            if lock is None:
                lock = asyncio.Lock()
                self._mcp_start_locks[loop] = lock
            return lock

    def _start_mcp_drains(self, process: asyncio.subprocess.Process) -> None:
        if id(process) in self._mcp_drains:
            raise RuntimeError("MCP child streams already have drain owners")
        self._mcp_drains[id(process)] = (
            asyncio.create_task(
                _drain_stream_chunks(process.stdout),
                name=f"unrest-mcp-stdout-{process.pid}",
            ),
            asyncio.create_task(
                _drain_stream_chunks(process.stderr),
                name=f"unrest-mcp-stderr-{process.pid}",
            ),
        )

    async def _close_mcp_process(
        self,
        process: asyncio.subprocess.Process,
        credentials: dict[str, str],
    ) -> str:
        drains = self._mcp_drains.pop(id(process), ())
        drained: list[str | BaseException] = []
        try:
            await _close_subprocess(process, timeout=5)
        finally:
            if drains:
                try:
                    drained = list(
                        await asyncio.wait_for(
                            asyncio.gather(*drains, return_exceptions=True),
                            timeout=MCP_DRAIN_TIMEOUT_SECONDS,
                        )
                    )
                except asyncio.TimeoutError:
                    for task in drains:
                        task.cancel()
                    drained = list(
                        await asyncio.gather(*drains, return_exceptions=True)
                    )
        output = redact_credential_values(
            "\n".join(item for item in drained if isinstance(item, str)),
            credentials,
        )
        output_bytes = output.encode("utf-8")[: 2 * MCP_STREAM_CAPTURE_LIMIT]
        output = output_bytes.decode("utf-8", errors="ignore")
        if process.returncode not in (None, 0) and output:
            logger.warning(
                "MCP child exited with code %s: %s",
                process.returncode,
                _truncate_text(output, limit=2000),
            )
        return output

    @staticmethod
    def _find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _node_runtime(
        self,
        project_id: str,
        mission_id: str,
        task: Task,
        spawn_ts: str,
        store: ProjectStore,
        cwd: str | Path | None,
    ) -> _NodeRuntime:
        role: Literal["validator", "worker"] = (
            "validator" if task.type == "validate" else "worker"
        )
        role_config = self.config.for_role(role)
        project_record = store.load_project(project_id)
        workspace_path = (
            Path(cwd).expanduser().resolve(strict=True)
            if cwd
            else store.workspace_dir(project_id).resolve(strict=True)
        )
        project_record_path = store.unrest_dir(project_id).resolve(strict=True)
        policy = resolve_role_capability(
            role_config.worker_provider,
            role=role,
            policy=role_config.capability_policy,
            profile=role_config.capability_profile,
            workspace=workspace_path,
            project_record=project_record_path,
        )
        command = (
            role_config.worker_acp_command
            or role_config.resolved_worker_acp_command
        )
        if not command:
            raise RuntimeError(
                f"No ACP command for role={role}. "
                f"Set UNREST_{role.upper()}_ACP_COMMAND."
            )
        command = _augment_acp_command(
            command,
            role_config.worker_provider,
            role_config.worker_reasoning_effort,
        )
        handoff_path = store.attempt_path(
            project_id, mission_id, spawn_ts, task.id
        )
        runtime_environment = {
            **profile_environment(role_config.capability_profile),
            "UNREST_HANDOFF_PATH": str(handoff_path),
            "UNREST_HOME": str(self.config.harness_home),
            "UNREST_MISSION_ID": mission_id,
            "UNREST_NODE_ID": task.id,
            "UNREST_NODE_TYPE": task.type,
            "UNREST_PROJECT_ID": project_id,
        }
        credentials = finite_credential_values(os.environ)
        return _NodeRuntime(
            role=role,
            role_config=role_config,
            policy=policy,
            command=command,
            workspace_path=workspace_path,
            workspace_dir=str(workspace_path),
            project_bucket=str(project_record_path),
            handoff_path=handoff_path,
            runtime_environment=runtime_environment,
            agent_environment=_acp_subprocess_env(
                role_config.worker_provider,
                policy=policy,
                reasoning_effort=(
                    project_record.worker_reasoning_effort
                    if role == "worker" and project_record.worker_reasoning_effort
                    else role_config.worker_reasoning_effort
                ),
                model=(
                    project_record.worker_model
                    or os.environ.get("UNREST_WORKER_MODEL")
                    if role == "worker"
                    else None
                ),
                internal=runtime_environment,
            ),
            terminal_environment=build_role_environment(
                policy,
                os.environ,
                include_credentials=False,
            ),
            credentials=credentials,
        )

    async def run_node(
        self,
        project_id: str,
        mission_id: str,
        task: Task,
        spawn_ts: str,
        store: ProjectStore,
        *,
        cwd: str | Path | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> NodeHandoff:
        """Spawn the worker MCP server + ACP agent; poll the attempt file; return the handoff."""
        runtime = self._node_runtime(
            project_id, mission_id, task, spawn_ts, store, cwd
        )
        role_config = runtime.role_config
        resolved_policy = runtime.policy
        workspace_path = runtime.workspace_path
        workspace_dir = runtime.workspace_dir
        project_bucket = runtime.project_bucket
        handoff_path = runtime.handoff_path
        runtime_environment = runtime.runtime_environment
        agent_env = runtime.agent_environment
        terminal_environment = runtime.terminal_environment
        secrets = runtime.credentials

        def redact(text: str) -> str:
            return redact_credential_values(text, secrets)

        handoff_path.parent.mkdir(parents=True, exist_ok=True)

        _ensure_claude_settings(
            workspace_path,
            role_config.worker_provider,
            role_config.capability_profile,
            role=runtime.role,
            allowed_ancestor=workspace_path,
        )

        # A free-port probe is only advisory after its socket closes. Keep the
        # probe, child spawn, and readiness confirmation atomic within this
        # runner so concurrent nodes cannot select and connect to one sibling's
        # MCP endpoint.
        async with self._mcp_start_lock():
            mcp_port = self._find_free_port()
            mcp_process = await self._start_worker_mcp_server(
                task=task,
                project_id=project_id,
                mission_id=mission_id,
                handoff_path=str(handoff_path),
                workspace_dir=workspace_dir,
                mcp_port=mcp_port,
                sensitive_inventory=secrets,
                environment=build_role_environment(
                    resolved_policy,
                    os.environ,
                    internal=runtime_environment,
                    include_credentials=False,
                ),
            )
            try:
                await self._wait_for_server_ready("127.0.0.1", mcp_port)
            except TimeoutError:
                if mcp_process.returncode is None:
                    mcp_process.terminate()
                await self._close_mcp_process(mcp_process, secrets)
                return self._synthesize_missing_handoff(
                    task, summary="Worker MCP server failed to start"
                )
            except BaseException:
                if mcp_process.returncode is None:
                    mcp_process.terminate()
                await self._close_mcp_process(mcp_process, secrets)
                raise

        worker_mcp_cfg = {
            "type": "http",
            "name": "unrest-worker",
            "url": f"http://127.0.0.1:{mcp_port}/mcp",
            "headers": [],
            "env": [],
        }

        # 2) Render the prompt (system + template merged into one first message).
        try:
            first_message = self._render_prompts(
                task=task,
                mission_id=mission_id,
                project_bucket=project_bucket,
                workspace_dir=workspace_dir,
                store=store,
                project_id=project_id,
            )

            # 3) Spawn the ACP agent.
            command_parts = shlex.split(runtime.command)
            if not command_parts:
                raise ValueError("ACP command cannot be empty")
            process = await asyncio.create_subprocess_exec(
                *command_parts,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_dir,
                env=agent_env,
                limit=SUBPROCESS_STREAM_LIMIT,
            )
        except BaseException:
            if mcp_process.returncode is None:
                mcp_process.terminate()
            await self._close_mcp_process(mcp_process, secrets)
            raise
        progress_tracker = ACPProgressTracker(
            callback=progress_callback,
            redactor=redact,
            stream_redactor=StreamingCredentialRedactor(secrets),
        )
        client = ACPClient(
            process,
            workspace_dir,
            policy=resolved_policy,
            terminal_environment=terminal_environment,
            session_update_handler=progress_tracker.handle_session_update,
        )
        set_credential_inventory = getattr(
            client,
            "set_credential_inventory",
            None,
        )
        if set_credential_inventory is not None:
            set_credential_inventory(secrets)
        prompt_stop_reason: str | None = None
        session_error: str | None = None
        worker_exit_code: int | None = None
        worker_stderr: str = ""
        stderr_task = asyncio.create_task(_drain_stream_chunks(process.stderr))

        try:
            await client.start()
            await client.send_request(
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {
                            "readTextFile": any(root.read for root in resolved_policy.roots),
                            "writeTextFile": any(root.write for root in resolved_policy.roots),
                        },
                        "terminal": resolved_policy.process.enabled,
                    },
                    "clientInfo": {"name": "unrest", "version": __version__},
                },
            )
            session_params: dict[str, Any] = {
                "cwd": workspace_dir,
                "mcpServers": [worker_mcp_cfg],
            }
            provider = role_config.worker_provider
            session_resp = await client.send_request("session/new", session_params)
            session_id = session_resp["sessionId"]
            await self._maybe_set_mode(
                client,
                session_id,
                provider,
                role_config.capability_profile,
            )

            prompt_result = await client.send_request(
                "session/prompt",
                {"prompt": [{"type": "text", "text": first_message}], "sessionId": session_id},
            )
            if isinstance(prompt_result, dict):
                sr = prompt_result.get("stopReason")
                if isinstance(sr, str):
                    prompt_stop_reason = sr

            # 4) Give the worker MCP server a short grace period to flush.
            await self._poll_attempt_file(handoff_path, timeout=2.0)
        except Exception as exc:  # noqa: BLE001
            session_error = redact(str(exc))
            logger.error("ACP session failed for node %s: %s", task.id, session_error)
        finally:
            await progress_tracker.flush()
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    try:
                        process.terminate()
                    except OSError:
                        pass
            await _wait_for_process_exit(process, timeout=5)
            worker_exit_code = process.returncode
            try:
                worker_stderr = _truncate_text(
                    redact(await asyncio.wait_for(stderr_task, timeout=0.5)),
                    limit=2000,
                )
            except (asyncio.TimeoutError, Exception):
                worker_stderr = ""
            await client.cleanup(close_main_process=False)
            await _close_subprocess(process, timeout=0)
            if mcp_process.returncode is None:
                try:
                    mcp_process.terminate()
                except OSError:
                    pass
            await self._close_mcp_process(mcp_process, secrets)

        # 5) Parse and return.
        if handoff_path.exists():
            return self._parse_handoff_file(
                handoff_path,
                task,
                credentials=secrets,
            )
        return self._synthesize_and_persist_missing_handoff(
            handoff_path=handoff_path,
            task=task,
            stop_reason=prompt_stop_reason,
            exit_code=worker_exit_code,
            stderr=worker_stderr,
            session_error=session_error,
            agent_output=progress_tracker.diagnostic_buffer,
            credentials=secrets,
        )

    async def run_terminal_review(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        store: ProjectStore,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> TerminalReviewHandoff:
        """Run and bound the complete fresh-context terminal-review lifecycle."""
        timeout = self.config.terminal_review_timeout_seconds
        try:
            return await asyncio.wait_for(
                self._run_terminal_review_lifecycle(
                    project_id,
                    mission_id,
                    spawn_ts,
                    store,
                    progress_callback=progress_callback,
                ),
                timeout=timeout,
            )
        except TimeoutError:
            return TerminalReviewHandoff(
                done=False,
                report=(
                    "Terminal review timed out after "
                    f"{timeout} seconds. The ACP reviewer and its MCP server were "
                    "stopped; mission artifacts were preserved and closure was not sealed. "
                    "Resolve the reviewer failure or increase "
                    "UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS, then retry closure."
                ),
            )

    async def _run_terminal_review_lifecycle(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        store: ProjectStore,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> TerminalReviewHandoff:
        """Adversarial review body; cancellation always tears down both children."""
        role_config = self.config.for_role("terminal_reviewer")
        workspace_path = store.workspace_dir(project_id).resolve(strict=True)
        project_record_path = store.unrest_dir(project_id).resolve(strict=True)
        review_config = store.load_terminal_review_config(project_id, mission_id)
        resolved_policy = resolve_role_capability(
            role_config.worker_provider,
            role="terminal_reviewer",
            policy=role_config.capability_policy,
            profile=role_config.capability_profile,
            workspace=workspace_path,
            project_record=project_record_path,
            deliverable_roots=tuple(Path(root) for root in review_config.deliverable_roots),
        )
        acp_command = role_config.worker_acp_command
        if not acp_command:
            raise RuntimeError(
                "No ACP command for terminal reviewer. Set UNREST_TERMINAL_REVIEWER_ACP_COMMAND."
            )
        acp_command = _augment_acp_command(
            acp_command,
            role_config.worker_provider,
            role_config.worker_reasoning_effort,
        )
        workspace_dir = str(workspace_path)
        project_bucket = str(project_record_path)
        report_path = store.terminal_review_path(project_id, mission_id, spawn_ts)
        runtime_environment = {
            **profile_environment(role_config.capability_profile),
            "UNREST_HOME": str(self.config.harness_home),
            "UNREST_MISSION_ID": mission_id,
            "UNREST_PROJECT_ID": project_id,
            "UNREST_TERMINAL_REVIEW_PATH": str(report_path),
        }
        agent_env = _acp_subprocess_env(
            role_config.worker_provider,
            policy=resolved_policy,
            reasoning_effort=role_config.worker_reasoning_effort,
            internal=runtime_environment,
        )
        terminal_environment = build_role_environment(
            resolved_policy,
            os.environ,
            include_credentials=False,
        )
        secrets = finite_credential_values(os.environ)

        def redact(text: str) -> str:
            return redact_credential_values(text, secrets)

        report_path.parent.mkdir(parents=True, exist_ok=True)

        _ensure_claude_settings(
            workspace_path,
            role_config.worker_provider,
            role_config.capability_profile,
            role="terminal_reviewer",
            allowed_ancestor=workspace_path,
        )

        mcp_port = self._find_free_port()
        mcp_process = await self._start_terminal_reviewer_mcp(
            project_id=project_id,
            mission_id=mission_id,
            report_path=str(report_path),
            workspace_dir=workspace_dir,
            mcp_port=mcp_port,
            sensitive_inventory=secrets,
            environment=build_role_environment(
                resolved_policy,
                os.environ,
                internal=runtime_environment,
                include_credentials=False,
            ),
        )
        process: asyncio.subprocess.Process | None = None
        client: ACPClient | None = None
        stderr_task: asyncio.Task[str] | None = None
        tracker = ACPProgressTracker(
            callback=progress_callback,
            redactor=redact,
            stream_redactor=StreamingCredentialRedactor(secrets),
        )
        try:
            try:
                await self._wait_for_server_ready("127.0.0.1", mcp_port)
            except TimeoutError as exc:
                raise RuntimeError(
                    "Terminal reviewer MCP server failed to start; cannot run terminal review"
                ) from exc

            worker_mcp_cfg = {
                "type": "http",
                "name": "unrest-terminal-reviewer",
                "url": f"http://127.0.0.1:{mcp_port}/mcp",
                "headers": [],
                "env": [],
            }
            first_message = self._render_terminal_reviewer_prompts(
                project_bucket=project_bucket,
                workspace_dir=workspace_dir,
                deliverable_roots=review_config.deliverable_roots,
            )
            command_parts = shlex.split(acp_command)
            if not command_parts:
                raise ValueError("ACP command cannot be empty")
            process = await asyncio.create_subprocess_exec(
                *command_parts,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_dir,
                env=agent_env,
                limit=SUBPROCESS_STREAM_LIMIT,
            )
            client = ACPClient(
                process,
                workspace_dir,
                policy=resolved_policy,
                terminal_environment=terminal_environment,
                session_update_handler=tracker.handle_session_update,
            )
            set_credential_inventory = getattr(
                client,
                "set_credential_inventory",
                None,
            )
            if set_credential_inventory is not None:
                set_credential_inventory(secrets)
            await client.start()
            # Continuous draining prevents a chatty reviewer from filling the
            # stderr pipe and stalling its ACP/stdout channel.
            stderr_task = asyncio.create_task(_drain_stream_chunks(process.stderr))
            await client.send_request(
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {
                            "readTextFile": any(root.read for root in resolved_policy.roots),
                            "writeTextFile": any(root.write for root in resolved_policy.roots),
                        },
                        "terminal": resolved_policy.process.enabled,
                    },
                    "clientInfo": {"name": "unrest", "version": __version__},
                },
            )
            session_params: dict[str, Any] = {
                "cwd": workspace_dir,
                "mcpServers": [worker_mcp_cfg],
            }
            provider = role_config.worker_provider
            session_resp = await client.send_request("session/new", session_params)
            session_id = session_resp["sessionId"]
            await self._maybe_set_mode(
                client,
                session_id,
                provider,
                role_config.capability_profile,
            )
            await client.send_request(
                "session/prompt",
                {
                    "prompt": [{"type": "text", "text": first_message}],
                    "sessionId": session_id,
                },
            )
            await self._poll_attempt_file(report_path, timeout=2.0)
        finally:
            try:
                await tracker.flush()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Terminal-review progress callback failed: %s",
                    redact(str(exc)),
                )
            if process is not None and process.returncode is None:
                try:
                    process.terminate()
                except OSError:
                    pass
            if process is not None:
                await _wait_for_process_exit(process, timeout=5)
            if stderr_task is not None:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
            if client is not None:
                await client.cleanup(close_main_process=False)
            if process is not None:
                await _close_subprocess(process, timeout=0)
            if mcp_process.returncode is None:
                try:
                    mcp_process.terminate()
                except OSError:
                    pass
            await self._close_mcp_process(mcp_process, secrets)

        if report_path.exists():
            return TerminalReviewHandoff.model_validate(
                _load_redacted_json(report_path, secrets)
            )
        raise RuntimeError(
            "Terminal reviewer exited without calling submit_terminal_review; "
            "no terminal review was written. The mission cannot be sealed as done "
            "without an explicit reviewer verdict."
        )

    # ------------------------------------------------------------------
    # Subprocess plumbing
    # ------------------------------------------------------------------

    async def _start_worker_mcp_server(
        self,
        *,
        task: Task,
        project_id: str,
        mission_id: str,
        handoff_path: str,
        workspace_dir: str,
        mcp_port: int,
        sensitive_inventory: dict[str, str],
        environment: dict[str, str],
    ) -> asyncio.subprocess.Process:
        read_fd, write_fd = os.pipe()
        cmd = [
            sys.executable,
            "-m",
            "unrest_harness",
            "--mode",
            "validator" if task.type == "validate" else "worker",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(mcp_port),
            "--sensitive-inventory-fd",
            str(read_fd),
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_dir,
                env=environment,
                limit=SUBPROCESS_STREAM_LIMIT,
                pass_fds=(read_fd,),
            )
            self._start_mcp_drains(process)
        except BaseException:
            os.close(write_fd)
            raise
        finally:
            os.close(read_fd)
        try:
            await asyncio.to_thread(
                _write_pipe_payload,
                write_fd,
                sensitive_inventory,
            )
        except BaseException:
            if process.returncode is None:
                process.terminate()
            await self._close_mcp_process(process, sensitive_inventory)
            raise
        return process

    async def _start_terminal_reviewer_mcp(
        self,
        *,
        project_id: str,
        mission_id: str,
        report_path: str,
        workspace_dir: str,
        mcp_port: int,
        sensitive_inventory: dict[str, str],
        environment: dict[str, str],
    ) -> asyncio.subprocess.Process:
        read_fd, write_fd = os.pipe()
        cmd = [
            sys.executable,
            "-m",
            "unrest_harness",
            "--mode",
            "terminal-reviewer",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(mcp_port),
            "--sensitive-inventory-fd",
            str(read_fd),
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_dir,
                env=environment,
                limit=SUBPROCESS_STREAM_LIMIT,
                pass_fds=(read_fd,),
            )
            self._start_mcp_drains(process)
        except BaseException:
            os.close(write_fd)
            raise
        finally:
            os.close(read_fd)
        try:
            await asyncio.to_thread(
                _write_pipe_payload,
                write_fd,
                sensitive_inventory,
            )
        except BaseException:
            if process.returncode is None:
                process.terminate()
            await self._close_mcp_process(process, sensitive_inventory)
            raise
        return process

    async def _wait_for_server_ready(self, host: str, port: int, *, timeout: float = 15) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                _, writer = await asyncio.open_connection(host, port)
                writer.close()
                await writer.wait_closed()
                return
            except (ConnectionRefusedError, OSError):
                await asyncio.sleep(0.3)
        raise TimeoutError(f"MCP server on {host}:{port} not ready within {timeout}s")

    async def _poll_attempt_file(self, path: Path, *, timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if path.exists():
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.1)

    async def _maybe_set_mode(
        self,
        client: ACPClient,
        session_id: str,
        provider,
        profile: str,
    ) -> None:
        mode = (
            "bypassPermissions"
            if provider.name == "claude" and profile == UNSAFE_DEVELOPMENT_PROFILE
            else None
        )
        if not mode:
            return
        try:
            await client.send_request("session/set_mode", {"sessionId": session_id, "modeId": mode})
        except ACPError as exc:
            raise ACPError(
                f"Failed to set ACP runtime mode {mode!r} for {provider.name}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def _render_prompts(
        self,
        *,
        task: Task,
        mission_id: str,
        project_bucket: str,
        workspace_dir: str,
        store: ProjectStore,
        project_id: str,
    ) -> str:
        session_type = "validator" if task.type == "validate" else "worker"
        system_prompt = self.loader.load_prompt_file(session_type, "system_prompt.md")
        template_vars = self._build_template_vars(
            task=task,
            mission_id=mission_id,
            project_bucket=project_bucket,
            workspace_dir=workspace_dir,
            store=store,
            project_id=project_id,
        )
        template = self.loader.render_prompt_template(session_type, "template.md", template_vars)
        if system_prompt:
            return system_prompt + "\n\n---\n\n" + template
        return template

    def _render_terminal_reviewer_prompts(
        self,
        *,
        project_bucket: str,
        workspace_dir: str,
        deliverable_roots: list[str],
    ) -> str:
        brief_path = Path(project_bucket) / "brief.md"
        brief_text = brief_path.read_text() if brief_path.exists() else ""
        return self.loader.render_prompt_template(
            "terminal-reviewer",
            "system_prompt.md",
            {
                "user_request": brief_text,
                "workspace": workspace_dir,
                "deliverable_roots": (
                    "\n".join(f"- {json.dumps(root)}" for root in deliverable_roots)
                    if deliverable_roots
                    else "- (none; inspect the normal workspace only)"
                ),
            },
        )

    def _build_template_vars(
        self,
        *,
        task: Task,
        mission_id: str,
        project_bucket: str,
        workspace_dir: str,
        store: ProjectStore,
        project_id: str,
    ) -> dict[str, str]:
        assertions: list[str] = []
        target_rows: list[str] = []
        for aid in task.targets:
            contract_p = store.contract_assertion_path(project_id, mission_id, aid)
            target_rows.append(f"- **{aid}**: `{contract_p}`")
            body = store.load_contract_assertion(project_id, mission_id, aid)
            if body is None:
                assertions.append(f"[Missing contract assertion {aid} at {contract_p}]\n")
                continue
            assertions.append(body.rstrip() + "\n")
        target_paths = "\n".join(target_rows) if target_rows else ""
        mission_dir = store.mission_dir(project_id, mission_id)
        project_bucket_path = Path(project_bucket)
        agents_path = Path(workspace_dir) / "AGENTS.md"
        return {
            "assignment_body": task.body,
            "contract_target_paths": target_paths,
            "memory_path": str(project_bucket_path / "MEMORY.md"),
            "mission_scope_path": str(mission_dir / "SCOPE.md"),
            "agents_path": str(agents_path),
            "attempts_dir": str(store.attempts_dir(project_id, mission_id)),
            # Legacy names are retained for validator templates and provider
            # prompts that have not yet been migrated from node vocabulary.
            "node_id": task.id,
            "node_type": task.type,
            "node_body": task.body,
            "node_targets": ", ".join(task.targets),
            "skill_name": task.skill or "",
            "workspace": workspace_dir,
            "project_bucket": project_bucket,
            "mission_id": mission_id,
            "contract_assertions": "\n\n---\n\n".join(assertions),
            "target_paths": target_paths,
            "regressions_dir": str(store.regressions_dir(project_id, mission_id)),
            "evidence_dir": str(mission_dir / "evidence"),
        }

    # ------------------------------------------------------------------
    # Handoff parsing + synthesis
    # ------------------------------------------------------------------

    def _parse_handoff_file(
        self,
        path: Path,
        task: Task,
        *,
        credentials: dict[str, str] | None = None,
    ) -> NodeHandoff:
        data = _load_redacted_json(path, credentials or {})
        if task.type == "validate":
            handoff: NodeHandoff = ValidateHandoff.model_validate(data)
        else:
            handoff = WorkHandoff.model_validate(data)
        attempt_id = path.stem.split("__", 1)[0]
        if handoff.node_id != task.id:
            raise ValueError("attempt node_id does not match dispatched task")
        if handoff.attempt_id != attempt_id:
            raise ValueError("attempt_id does not match dispatched generation")
        return handoff

    def _synthesize_missing_handoff(self, task: Task, *, summary: str = "") -> NodeHandoff:
        report = summary or "Agent session ended without calling end_node."
        if task.type == "validate":
            return ValidateHandoff(
                node_id=task.id, done=False, report=report, items=[], passed=False
            )
        return WorkHandoff(
            node_id=task.id,
            done=False,
            report=report,
            request_attention=False,
        )

    def _synthesize_and_persist_missing_handoff(
        self,
        *,
        handoff_path: Path,
        task: Task,
        stop_reason: str | None,
        exit_code: int | None,
        stderr: str,
        session_error: str | None,
        agent_output: str = "",
        credentials: dict[str, str] | None = None,
    ) -> NodeHandoff:
        parts: list[str] = ["Agent session ended without calling end_node."]
        if session_error:
            parts.append(f"acp_error={session_error}")
        if stop_reason:
            parts.append(f"stop_reason={stop_reason}")
        if exit_code is not None:
            parts.append(f"exit_code={exit_code}")
        if stderr:
            parts.append(f"stderr={stderr}")
        if agent_output:
            parts.append(f"agent_output={_truncate_text(agent_output[-4000:], limit=2000)}")
        summary = redact_credential_values(" ".join(parts), credentials or {})
        handoff = self._synthesize_missing_handoff(task, summary=summary)
        atomic_write_json(
            handoff_path,
            handoff.model_dump(mode="json"),
            trusted_root=trusted_persistence_root(handoff_path),
        )
        return handoff


# ---------------------------------------------------------------------------
# Production NodeDispatcher / TerminalReviewer wrappers
# ---------------------------------------------------------------------------


def _run_coro_blocking(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async coroutine to completion from sync code.

    Uses `asyncio.run` when no event loop is active. When the caller is
    already inside a running loop (e.g. an MCP tool handler that forgot
    to wrap with `asyncio.to_thread`), execute the coroutine in a fresh
    loop on a worker thread instead of crashing.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Inside a running loop: hop to a worker thread with its own loop.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class ACPNodeDispatcher:
    """Implements `NodeDispatcher` by calling `ACPNodeRunner.run_node`."""

    def __init__(self, config: HarnessConfig, store: ProjectStore | None = None):
        self.config = config
        self.store = store or ProjectStore(config)
        self.loader = AssetLoader(config)
        self.runner = ACPNodeRunner(config=config, loader=self.loader)

    def dispatch(self, request: DispatchRequest) -> NodeHandoff:
        self.store.refresh_inventory(os.environ)
        return _run_coro_blocking(
            self.runner.run_node(
                project_id=request.project_id,
                mission_id=request.mission_id,
                task=request.task,
                spawn_ts=request.spawn_ts,
                store=self.store,
                cwd=request.cwd,
            )
        )

    def dispatch_batch(self, requests: list[DispatchRequest]) -> list[NodeHandoff]:
        self.store.refresh_inventory(os.environ)

        async def _run_all() -> list[NodeHandoff]:
            results = await asyncio.gather(
                *(
                    self.runner.run_node(
                        project_id=request.project_id,
                        mission_id=request.mission_id,
                        task=request.task,
                        spawn_ts=request.spawn_ts,
                        store=self.store,
                        cwd=request.cwd,
                    )
                    for request in requests
                ),
                return_exceptions=True,
            )
            handoffs: list[NodeHandoff] = []
            for request, result in zip(requests, results, strict=True):
                if isinstance(result, BaseException):
                    summary = _truncate_text(
                        "Dispatcher crashed before a handoff: "
                        + redact_credential_values(
                            f"{type(result).__name__}: {result}", self.store.inventory
                        ),
                        limit=2000,
                    )
                    handoff = self.runner._synthesize_missing_handoff(
                        request.task,
                        summary=summary,
                    )
                    self.store.save_attempt(
                        request.project_id,
                        request.mission_id,
                        request.spawn_ts,
                        request.task.id,
                        handoff,
                    )
                    handoffs.append(handoff)
                else:
                    handoffs.append(result)
            return handoffs

        return _run_coro_blocking(_run_all())


class ACPTerminalReviewer:
    """Implements `TerminalReviewer` by calling `ACPNodeRunner.run_terminal_review`."""

    def __init__(self, config: HarnessConfig, store: ProjectStore | None = None):
        self.config = config
        self.store = store or ProjectStore(config)
        self.loader = AssetLoader(config)
        self.runner = ACPNodeRunner(config=config, loader=self.loader)

    def review(self, project_id: str, mission_id: str, spawn_ts: str) -> TerminalReviewHandoff:
        return _run_coro_blocking(
            self.runner.run_terminal_review(
                project_id=project_id,
                mission_id=mission_id,
                spawn_ts=spawn_ts,
                store=self.store,
                progress_callback=self._report_progress,
            )
        )

    @staticmethod
    def _report_progress(message: str) -> None:
        print(f"[unrest terminal-review] {message}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# claude-agent-acp settings workaround
# ---------------------------------------------------------------------------


def _ensure_claude_settings(
    workspace: Path,
    provider,
    profile: str,
    *,
    role: RoleName = "orchestrator",
    settings_dir: Path | None = None,
    allowed_ancestor: Path | None = None,
) -> None:
    """Install or migrate only Unrest-owned Claude permission defaults."""
    if provider.name != "claude":
        return
    claude_dir = settings_dir or workspace / ".claude"
    settings_path = claude_dir / "settings.json"
    marker_path = claude_dir / ".unrest-managed-settings.json"
    creation_boundary = allowed_ancestor or workspace
    try:
        for target in (settings_path, marker_path):
            validate_atomic_write_destination(
                target,
                trusted_root=claude_dir,
                allowed_ancestor=creation_boundary,
            )
    except OSError as exc:
        raise CapabilityPolicyError(
            provider="claude",
            role=role,
            version=1,
            capability="host-settings",
            reason="Claude settings path is not a safe regular workspace path",
        ) from exc
    existing: dict[str, Any]
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityPolicyError(
                provider="claude",
                role=role,
                version=1,
                capability="host-settings",
                reason="Claude settings must be a valid JSON object",
            ) from exc
        if not isinstance(loaded, dict):
            raise CapabilityPolicyError(
                provider="claude",
                role=role,
                version=1,
                capability="host-settings",
                reason="Claude settings root must be an object",
            )
        existing = loaded
    else:
        existing = {}

    marker_managed = False
    if marker_path.exists():
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityPolicyError(
                provider="claude",
                role=role,
                version=1,
                capability="host-settings-marker",
                reason="managed settings marker is malformed",
            ) from exc
        marker_managed = marker == {
            "managed_fields": ["permissions.defaultMode"],
            "schema_version": 1,
        }
        if not marker_managed:
            raise CapabilityPolicyError(
                provider="claude",
                role=role,
                version=1,
                capability="host-settings-marker",
                reason="managed settings marker is unsupported",
            )

    permissions = existing.get("permissions")
    if permissions is None:
        permissions = {}
        existing["permissions"] = permissions
    if not isinstance(permissions, dict):
        raise CapabilityPolicyError(
            provider="claude",
            role=role,
            version=1,
            capability="host-settings:permissions",
            reason="permissions must be an object",
        )

    legacy_managed = existing == {
        "permissions": {"defaultMode": "bypassPermissions"}
    }
    current_mode = permissions.get("defaultMode")
    desired_mode = (
        "bypassPermissions"
        if profile == UNSAFE_DEVELOPMENT_PROFILE
        else "default"
    )
    if (
        profile == SAFE_PROFILE
        and current_mode not in (None, "default")
        and not marker_managed
        and not legacy_managed
    ):
        raise CapabilityPolicyError(
            provider="claude",
            role=role,
            version=1,
            capability="host-settings:permissions.defaultMode",
            reason="unmanaged ambient permission mode is not safe",
        )
    if (
        profile == UNSAFE_DEVELOPMENT_PROFILE
        and settings_path.exists()
        and not marker_managed
        and not legacy_managed
    ):
        raise CapabilityPolicyError(
            provider="claude",
            role=role,
            version=1,
            capability="host-settings:permissions.defaultMode",
            reason="unmanaged Claude settings cannot be changed for unrestricted mode",
        )

    should_manage = (
        not settings_path.exists()
        or marker_managed
        or legacy_managed
    )
    if not should_manage:
        return
    permissions["defaultMode"] = desired_mode
    atomic_write_json(
        settings_path,
        existing,
        trusted_root=settings_path.parent,
        allowed_ancestor=creation_boundary,
    )
    atomic_write_json(
        marker_path,
        {
            "managed_fields": ["permissions.defaultMode"],
            "schema_version": 1,
        },
        trusted_root=marker_path.parent,
        allowed_ancestor=creation_boundary,
    )


__all__ = [
    "ACPClient",
    "ACPError",
    "ACPNodeRunner",
    "ACPNodeDispatcher",
    "ACPTerminalReviewer",
    "ACPProgressTracker",
    "SUBPROCESS_STREAM_LIMIT",
]
