"""Bounded, private-by-default structured ACP provider sessions."""
from __future__ import annotations

import asyncio
import json
import os
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from . import __version__
from .acp_runner import (
    MCP_STREAM_CAPTURE_LIMIT,
    SUBPROCESS_STREAM_LIMIT,
    ACPClient,
    LaunchError,
    LaunchPlan,
    _acp_subprocess_env,
    _augment_acp_command,
    _close_subprocess,
    _drain_stream_chunks,
    _extract_text_fragments,
    build_launch_plan,
    preflight_launch,
)
from .capability_policy import (
    RoleName,
    StreamingCredentialRedactor,
    build_role_environment,
    finite_credential_values,
    redact_credential_values,
    resolve_role_capability,
)
from .config import HarnessConfig, VALID_REASONING_EFFORTS
from .storage import atomic_write_text, validate_atomic_write_destination

ProviderSessionRole = Literal[
    "inquiry_branch",
    "inquiry_synthesis",
    "candidate_author",
    "independent_evaluator",
    "independent_reviewer",
]
ProviderSessionStatus = Literal["completed", "failed", "timed_out", "cancelled"]
ProviderSessionErrorCode = Literal[
    "adapter_not_configured",
    "adapter_start_failed",
    "cancelled",
    "invalid_structured_output",
    "output_limit_exceeded",
    "protocol_error",
    "timed_out",
]

DEFAULT_SESSION_TIMEOUT_SECONDS = 300.0
DEFAULT_PROMPT_LIMIT_BYTES = 256 * 1024
DEFAULT_RESPONSE_LIMIT_BYTES = 65_536
_SAFE_STOP_REASONS = frozenset(
    {"cancelled", "end_turn", "max_tokens", "refusal", "stop_sequence", "unknown"}
)


class ProviderSessionError(RuntimeError):
    """Stable value-free failure at the provider-session persistence boundary."""


async def _spawn_provider_launch(
    plan: LaunchPlan,
    *,
    limit: int,
) -> asyncio.subprocess.Process:
    """Spawn one checked provider plan while retaining process-group cleanup."""
    try:
        return await asyncio.create_subprocess_exec(
            *plan.argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=plan.cwd,
            env=plan.environment,
            limit=limit,
            start_new_session=True,
        )
    except OSError:
        raise LaunchError("startup_failed") from None


@dataclass(frozen=True)
class ProviderSessionRequest:
    role: ProviderSessionRole
    prompt: str
    workspace_path: Path
    project_record_path: Path
    private_artifact_path: Path
    private_artifact_root: Path
    deliverable_roots: tuple[Path, ...] = ()
    timeout_seconds: float = DEFAULT_SESSION_TIMEOUT_SECONDS
    max_prompt_bytes: int = DEFAULT_PROMPT_LIMIT_BYTES
    max_response_bytes: int = DEFAULT_RESPONSE_LIMIT_BYTES
    model: str | None = None
    reasoning_effort: str | None = None

    def __post_init__(self) -> None:
        if not self.prompt:
            raise ValueError("provider session prompt must not be empty")
        if len(self.prompt.encode("utf-8")) > self.max_prompt_bytes:
            raise ValueError("provider session prompt exceeds its byte limit")
        if self.timeout_seconds <= 0:
            raise ValueError("provider session timeout must be positive")
        if self.max_prompt_bytes <= 0 or self.max_response_bytes <= 0:
            raise ValueError("provider session byte limits must be positive")
        if self.max_response_bytes > DEFAULT_RESPONSE_LIMIT_BYTES:
            raise ValueError("provider session response byte limit exceeds the safe ceiling")
        if (
            self.reasoning_effort is not None
            and self.reasoning_effort not in VALID_REASONING_EFFORTS
        ):
            raise ValueError("provider session reasoning effort is unsupported")


@dataclass(frozen=True)
class ProviderSessionResult:
    """Allowlisted public metadata; raw content and artifact location are absent."""

    role: ProviderSessionRole
    provider: Literal["claude", "codex"]
    status: ProviderSessionStatus
    stop_reason: str | None
    response_bytes: int
    response_truncated: bool
    structured_output: bool
    adapter_exit_code: int | None
    error_code: ProviderSessionErrorCode | None

    def public_metadata(self) -> dict[str, object]:
        return {
            "adapter_exit_code": self.adapter_exit_code,
            "error_code": self.error_code,
            "provider": self.provider,
            "response_bytes": self.response_bytes,
            "response_truncated": self.response_truncated,
            "role": self.role,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "structured_output": self.structured_output,
        }


@dataclass
class _ResponseCapture:
    limit: int
    credentials: dict[str, str]
    observed_bytes: int = 0
    truncated: bool = False
    _buffer: bytearray = field(default_factory=bytearray, init=False)
    _redactor: StreamingCredentialRedactor = field(init=False)
    _last_message_id: str | None = field(default=None, init=False)
    _last_message_chunks: list[str] = field(default_factory=list, init=False)
    _message_ids_complete: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        self._redactor = StreamingCredentialRedactor(self.credentials)

    async def handle_update(self, params: dict[str, Any]) -> None:
        update = params.get("update")
        if not isinstance(update, dict):
            return
        if update.get("sessionUpdate") != "agent_message_chunk":
            return
        for text in _extract_text_fragments(update.get("content")):
            self.observed_bytes += len(text.encode("utf-8"))
            self._append(self._redactor.feed(text).encode("utf-8"))
            message_id = update.get("messageId")
            if not isinstance(message_id, str) or not message_id:
                self._message_ids_complete = False
                continue
            if message_id != self._last_message_id:
                self._last_message_id = message_id
                self._last_message_chunks.clear()
            if self.observed_bytes <= self.limit:
                self._last_message_chunks.append(text)

    def finish(self) -> str:
        self._append(self._redactor.finish().encode("utf-8"))
        return self._buffer.decode("utf-8", errors="replace")

    def final_message(self, full_response: str) -> str:
        """ACP message IDs delimit the final answer from earlier commentary."""
        if not self._message_ids_complete or self._last_message_id is None:
            return full_response
        return redact_credential_values("".join(self._last_message_chunks), self.credentials)

    def _append(self, payload: bytes) -> None:
        remaining = self.limit - len(self._buffer)
        if remaining <= 0:
            if payload:
                self.truncated = True
            return
        self._buffer.extend(payload[:remaining])
        if len(payload) > remaining:
            self.truncated = True


class ProviderSessionRunner:
    """Run one provider turn without granting Mission or workspace mutation."""

    def __init__(self, config: HarnessConfig) -> None:
        self.config = config

    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult:
        workspace = request.workspace_path.expanduser().resolve(strict=True)
        project_record = request.project_record_path.expanduser().resolve(strict=True)
        private_root = request.private_artifact_root.expanduser().resolve(strict=True)
        artifact_path = request.private_artifact_path.expanduser().absolute()
        validate_atomic_write_destination(
            artifact_path,
            trusted_root=private_root,
        )

        role: RoleName = request.role
        role_config = self.config.for_role(role)
        provider = role_config.worker_provider
        policy = resolve_role_capability(
            provider,
            role=role,
            policy=role_config.capability_policy,
            profile=role_config.capability_profile,
            workspace=workspace,
            project_record=project_record,
            deliverable_roots=request.deliverable_roots,
        )
        if policy.process.enabled or any(root.write for root in policy.roots):
            raise ProviderSessionError(
                "PROVIDER-SESSION-001 role policy is not structurally read-only"
            )

        command = self._configured_command(request.role)
        credentials = finite_credential_values(os.environ)
        prompt = self._render_prompt(request.role, request.prompt)
        capture = _ResponseCapture(request.max_response_bytes, credentials)
        status: ProviderSessionStatus = "failed"
        error_code: ProviderSessionErrorCode | None = None
        stop_reason: str | None = None
        structured: dict[str, Any] | None = None
        stderr_text = ""
        process: asyncio.subprocess.Process | None = None
        client: ACPClient | None = None
        protocol_task: asyncio.Task[dict[str, Any]] | None = None
        cancel_task: asyncio.Task[bool] | None = None
        stderr_task: asyncio.Task[str] | None = None
        adapter_exit_code: int | None = None

        if command is None:
            error_code = "adapter_not_configured"
        else:
            try:
                environment = _acp_subprocess_env(
                    provider,
                    policy=policy,
                    reasoning_effort=(
                        request.reasoning_effort
                        or role_config.worker_reasoning_effort
                    ),
                    model=request.model,
                )
                launch_plan = build_launch_plan(
                    _augment_acp_command(
                        command,
                        provider,
                        request.reasoning_effort
                        or role_config.worker_reasoning_effort,
                    ),
                    cwd=workspace,
                    environment=environment,
                )
                preflight_launch(launch_plan)
                process = await _spawn_provider_launch(
                    launch_plan,
                    limit=min(
                        SUBPROCESS_STREAM_LIMIT,
                        max(64 * 1024, request.max_response_bytes * 2 + 64 * 1024),
                    ),
                )
                client = ACPClient(
                    process,
                    str(workspace),
                    policy=policy,
                    terminal_environment=build_role_environment(
                        policy,
                        os.environ,
                        include_credentials=False,
                    ),
                    session_update_handler=capture.handle_update,
                )
                client.set_credential_inventory(credentials)
                stderr_task = asyncio.create_task(
                    _drain_stream_chunks(
                        process.stderr,
                        capture_limit=MCP_STREAM_CAPTURE_LIMIT,
                    )
                )
                protocol_task = asyncio.create_task(
                    self._run_protocol(client, provider, workspace, prompt)
                )
                waiters: set[asyncio.Task[Any]] = {protocol_task}
                if cancel_event is not None:
                    cancel_task = asyncio.create_task(cancel_event.wait())
                    waiters.add(cancel_task)
                done, _ = await asyncio.wait(
                    waiters,
                    timeout=request.timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if protocol_task in done:
                    prompt_result = protocol_task.result()
                    stop_reason = self._safe_stop_reason(
                        prompt_result.get("stopReason")
                    )
                    status = "completed"
                elif cancel_task is not None and cancel_task in done:
                    status = "cancelled"
                    error_code = "cancelled"
                else:
                    status = "timed_out"
                    error_code = "timed_out"
                if protocol_task not in done:
                    protocol_task.cancel()
                adapter_exit_code = process.returncode
            except asyncio.CancelledError:
                if protocol_task is not None:
                    protocol_task.cancel()
                raise
            except LaunchError as exc:
                stderr_text = str(exc)
                error_code = "adapter_start_failed" if process is None else "protocol_error"
            except (OSError, ValueError):
                error_code = "adapter_start_failed" if process is None else "protocol_error"
            except Exception:  # noqa: BLE001
                error_code = "protocol_error"
            finally:
                if cancel_task is not None:
                    cancel_task.cancel()
                if protocol_task is not None and not protocol_task.done():
                    protocol_task.cancel()
                pending_tasks = tuple(
                    task
                    for task in (protocol_task, cancel_task)
                    if task is not None and not task.done()
                )
                if pending_tasks:
                    await asyncio.gather(*pending_tasks, return_exceptions=True)
                if client is not None:
                    await client.cleanup(close_main_process=False)
                if process is not None:
                    await self._stop_process_group(process)
                    if status != "completed" and adapter_exit_code is None:
                        adapter_exit_code = process.returncode
                if stderr_task is not None:
                    stderr_text = await self._finish_stderr(stderr_task)

        response_text = capture.finish()
        if status == "completed":
            if capture.truncated:
                status = "failed"
                error_code = "output_limit_exceeded"
            else:
                structured = self._parse_structured_response(
                    capture.final_message(response_text)
                )
                if structured is None:
                    status = "failed"
                    error_code = "invalid_structured_output"
        safe_stderr = redact_credential_values(stderr_text, credentials)
        artifact = {
            "adapter_exit_code": adapter_exit_code,
            "error_code": error_code,
            "input": {"prompt": redact_credential_values(prompt, credentials)},
            "output": {
                "parsed": structured,
                "response_bytes": capture.observed_bytes,
                "response_text": response_text,
                "response_truncated": capture.truncated,
                "stderr": safe_stderr,
            },
            "privacy": "private-provider-session",
            "provider": provider.name,
            "role": request.role,
            "schema_version": 1,
            "status": status,
            "stop_reason": stop_reason,
        }
        try:
            atomic_write_text(
                artifact_path,
                json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                trusted_root=private_root,
                mode=0o600,
                inventory=credentials,
            )
        except OSError as exc:
            raise ProviderSessionError(
                "PROVIDER-SESSION-002 private artifact could not be persisted"
            ) from exc

        return ProviderSessionResult(
            role=request.role,
            provider=provider.name,
            status=status,
            stop_reason=stop_reason,
            response_bytes=capture.observed_bytes,
            response_truncated=capture.truncated,
            structured_output=structured is not None,
            adapter_exit_code=adapter_exit_code,
            error_code=error_code,
        )

    def _configured_command(self, role: ProviderSessionRole) -> str | None:
        """Resolve role fallbacks while preserving an explicitly configured empty value."""
        if role in {"inquiry_branch", "candidate_author"}:
            configured = self.config.worker_acp_command
            return configured if configured is not None else self.config.resolved_worker_acp_command
        if role in {"inquiry_synthesis", "independent_evaluator"}:
            configured = self.config.validator_acp_command
            if configured is not None:
                return configured
            worker = self.config.worker_acp_command
            return worker if worker is not None else self.config.resolved_validator_acp_command
        configured = self.config.terminal_reviewer_acp_command
        if configured is not None:
            return configured
        validator = self.config.validator_acp_command
        if validator is not None:
            return validator
        worker = self.config.worker_acp_command
        return worker if worker is not None else self.config.resolved_terminal_reviewer_acp_command

    async def _run_protocol(
        self,
        client: ACPClient,
        provider: Any,
        workspace: Path,
        prompt: str,
    ) -> dict[str, Any]:
        await client.start()
        await client.send_request(
            "initialize",
            {
                "protocolVersion": 1,
                "clientCapabilities": {
                    "fs": {"readTextFile": True, "writeTextFile": False},
                    "terminal": False,
                },
                "clientInfo": {"name": "unrest", "version": __version__},
            },
        )
        session = await client.send_request(
            "session/new",
            {"cwd": str(workspace), "mcpServers": []},
        )
        if not isinstance(session, dict) or not isinstance(session.get("sessionId"), str):
            raise ProviderSessionError("PROVIDER-SESSION-003 invalid ACP session identity")
        result = await client.send_request(
            "session/prompt",
            {
                "prompt": [{"type": "text", "text": prompt}],
                "sessionId": session["sessionId"],
            },
        )
        if not isinstance(result, dict):
            raise ProviderSessionError("PROVIDER-SESSION-004 invalid ACP prompt result")
        return result

    def _render_prompt(self, role: ProviderSessionRole, prompt: str) -> str:
        path = self.config.bundled_dir / "prompts" / role / "system_prompt.md"
        try:
            system_prompt = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProviderSessionError(
                "PROVIDER-SESSION-005 role prompt is unavailable"
            ) from exc
        return f"{system_prompt.rstrip()}\n\n## Assignment\n\n{prompt}"

    @staticmethod
    def _safe_stop_reason(value: Any) -> str:
        if isinstance(value, str) and value in _SAFE_STOP_REASONS:
            return value
        return "unknown"

    @staticmethod
    def _parse_structured_response(text: str) -> dict[str, Any] | None:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    async def _finish_stderr(task: asyncio.Task[str]) -> str:
        if task.done():
            try:
                return task.result()
            except Exception:  # noqa: BLE001
                return ""
        task.cancel()
        try:
            return await task
        except (asyncio.CancelledError, Exception):
            return ""

    @staticmethod
    async def _stop_process_group(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            await _close_subprocess(process, timeout=0)
            return
        if hasattr(os, "killpg"):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        else:
            try:
                process.terminate()
            except OSError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            else:
                try:
                    process.kill()
                except OSError:
                    pass
        await _close_subprocess(process, timeout=2)


__all__ = [
    "ProviderSessionError",
    "ProviderSessionRequest",
    "ProviderSessionResult",
    "ProviderSessionRole",
    "ProviderSessionRunner",
]
