"""Durable, private-by-default read-only Inquiry orchestration.

Inquiry is an evidence-producing surface adjacent to Mission.  It can read a
workspace through capability-limited provider sessions, but this module has no
Mission coordinator, workspace integration, or evolution campaign dependency.
Raw questions and provider bodies remain in the private Inquiry subtree; public
records contain only canonical identities, outcomes, and allowlisted metadata.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator, Literal, Protocol, cast

from .canonical_identity import (
    IdentityRecord,
    canonical_json_bytes,
    construct_identity,
    verify_canonical_json_bytes,
)
from .config import HarnessConfig
from .foundation_store import FoundationStore
from .provider_sessions import (
    ProviderSessionRequest,
    ProviderSessionResult,
    ProviderSessionRunner,
)
from .storage import atomic_write_text


InquiryState = Literal[
    "open",
    "exploring",
    "synthesizing",
    "paused",
    "answered",
    "failed",
    "cancelled",
    "budget_exhausted",
]
BranchOutcome = Literal[
    "pending",
    "running",
    "paused",
    "answered",
    "failed",
    "cancelled",
    "budget_exhausted",
]

BRANCH_ROLES = ("direct", "evidence", "critic", "analogy")
_INQUIRY_ID = re.compile(r"^inquiry:[a-z0-9-]+$")
_CONSUMER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class InquiryError(RuntimeError):
    """Stable, value-free Inquiry failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class InquiryBudget:
    max_steps: int
    timeout_seconds: int
    max_branches: int = 4

    def __post_init__(self) -> None:
        for value in (self.max_steps, self.timeout_seconds, self.max_branches):
            if isinstance(value, bool) or not isinstance(value, int):
                raise InquiryError("invalid_argument", "Inquiry budget is invalid")
        if self.max_steps < 1 or self.timeout_seconds < 1:
            raise InquiryError("invalid_argument", "Inquiry budget is invalid")
        if not 1 <= self.max_branches <= len(BRANCH_ROLES):
            raise InquiryError("invalid_argument", "Inquiry budget is invalid")

    def public_record(self) -> dict[str, int]:
        return {
            "max_branches": self.max_branches,
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class InquirySummary:
    inquiry_id: str
    state: InquiryState
    branch_outcomes: Mapping[str, BranchOutcome]
    receipt_id: str | None

    def public_record(self) -> dict[str, object]:
        return {
            "branch_outcomes": dict(sorted(self.branch_outcomes.items())),
            "inquiry_id": self.inquiry_id,
            "receipt_id": self.receipt_id,
            "state": self.state,
        }


@dataclass(frozen=True)
class HandoffSummary:
    handoff_id: str
    inquiry_id: str
    consumer_id: str
    receipt_id: str

    def public_record(self) -> dict[str, str]:
        return {
            "consumer_id": self.consumer_id,
            "handoff_id": self.handoff_id,
            "inquiry_id": self.inquiry_id,
            "receipt_id": self.receipt_id,
        }


class InquiryProviderRunner(Protocol):
    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_record(value: Mapping[str, Any] | Sequence[Any]) -> str:
    return _sha(canonical_json_bytes(value))


def _token(digest: str, length: int = 24) -> str:
    if _DIGEST.fullmatch(digest) is None:
        raise InquiryError("integrity_error", "Inquiry identity is invalid")
    return digest[-length:]


def _without_none(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, (list, tuple)):
        return [_without_none(item) for item in value]
    return value


def _validate_text(value: str, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise InquiryError("invalid_argument", "Inquiry request is invalid")
    try:
        value.encode("utf-8", errors="strict")
        canonical_json_bytes({"value": value})
    except (UnicodeError, ValueError) as exc:
        raise InquiryError("invalid_argument", "Inquiry request is invalid") from exc


class _InquiryStore:
    """Append-only event authority with a replaceable derived state cursor."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve(strict=True)
        if not self.project_root.is_dir():
            raise InquiryError("invalid_argument", "Inquiry project root is invalid")
        self.root = self.project_root / ".unrest" / "inquiries"
        self.runtime_root = self.project_root / ".unrest-runtime" / "inquiries"
        self._ensure_directory(self.root)
        self._ensure_directory(self.runtime_root)
        self._ensure_directory(self.root / "open-index")
        self.lock_path = self.runtime_root / "store.lock"

    def _ensure_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.project_root)
        except ValueError as exc:
            raise InquiryError("integrity_error", "Inquiry storage is invalid") from exc
        current = self.project_root
        for part in relative.parts:
            current /= part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            current_stat = current.lstat()
            if not stat.S_ISDIR(current_stat.st_mode):
                raise InquiryError("integrity_error", "Inquiry storage is invalid")

    @contextmanager
    def locked(self) -> Iterator[None]:
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def operation_guard(self, inquiry_id: str) -> Iterator[None]:
        path = self.runtime_root / f"operation-{_token(_sha(inquiry_id.encode('utf-8')), 32)}.lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InquiryError("busy", "Inquiry already has an active operation") from exc
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def inquiry_root(self, inquiry_id: str) -> Path:
        if _INQUIRY_ID.fullmatch(inquiry_id) is None:
            raise InquiryError("invalid_argument", "Inquiry identity is invalid")
        return self.root / inquiry_id.removeprefix("inquiry:")

    def private_root(self, inquiry_id: str) -> Path:
        return self.inquiry_root(inquiry_id) / "private"

    def initialize(self, inquiry_id: str) -> None:
        root = self.inquiry_root(inquiry_id)
        for path in (
            root,
            root / "events",
            root / "evidence-receipts",
            self.private_root(inquiry_id),
            self.private_root(inquiry_id) / "branches",
            self.private_root(inquiry_id) / "synthesis",
            self.private_root(inquiry_id) / "handoffs",
            self.private_root(inquiry_id) / "handoff-index",
        ):
            self._ensure_directory(path)

    def append_evidence_receipt(
        self,
        inquiry_id: str,
        document: Mapping[str, Any],
    ) -> None:
        receipt_id = str(document["receipt_id"])
        path = (
            self.inquiry_root(inquiry_id)
            / "evidence-receipts"
            / f"{receipt_id.rsplit(':', 1)[-1]}.json"
        )
        payload = canonical_json_bytes(document)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise InquiryError("conflict", "Inquiry evidence receipt conflicts") from None
            return
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written == 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append_public_record(self, path: Path, document: Mapping[str, Any]) -> None:
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise InquiryError("integrity_error", "Inquiry public path is invalid") from exc
        try:
            parent_stat = path.parent.lstat()
        except OSError as exc:
            raise InquiryError("integrity_error", "Inquiry public path is invalid") from exc
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise InquiryError("integrity_error", "Inquiry public path is invalid")
        payload = canonical_json_bytes(document)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise InquiryError("conflict", "Inquiry public record conflicts") from None
            return
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written == 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append_event(self, state: Mapping[str, Any]) -> None:
        inquiry_id = str(state["inquiry_id"])
        sequence = state.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise InquiryError("integrity_error", "Inquiry event is invalid")
        document = dict(state)
        document.pop("event_digest", None)
        document.pop("predecessor_event_digest", None)
        if sequence == 1:
            predecessor = {"state": "absent"}
        else:
            predecessor_path = (
                self.inquiry_root(inquiry_id)
                / "events"
                / f"{sequence - 1:08d}.json"
            )
            try:
                predecessor_value = verify_canonical_json_bytes(
                    predecessor_path.read_bytes()
                )
            except (OSError, ValueError) as exc:
                raise InquiryError("integrity_error", "Inquiry event chain is invalid") from exc
            if not isinstance(predecessor_value, Mapping) or not isinstance(
                predecessor_value.get("event_digest"), str
            ):
                raise InquiryError("integrity_error", "Inquiry event chain is invalid")
            predecessor = {
                "state": "present",
                "value": predecessor_value["event_digest"],
            }
        document["predecessor_event_digest"] = predecessor
        document["event_digest"] = _sha(canonical_json_bytes(document))
        payload = canonical_json_bytes(document)
        event_path = self.inquiry_root(inquiry_id) / "events" / f"{sequence:08d}.json"
        try:
            descriptor = os.open(
                event_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            if event_path.read_bytes() != payload:
                raise InquiryError("conflict", "Inquiry event conflicts") from None
        else:
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written == 0:
                        raise OSError("short write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        atomic_write_text(
            self.inquiry_root(inquiry_id) / "state.json",
            payload.decode("utf-8"),
            trusted_root=self.inquiry_root(inquiry_id),
            mode=0o600,
        )

    def load(self, inquiry_id: str) -> dict[str, Any]:
        events = self.inquiry_root(inquiry_id) / "events"
        try:
            paths = sorted(events.glob("*.json"))
        except OSError as exc:
            raise InquiryError("integrity_error", "Inquiry record is invalid") from exc
        if not paths:
            raise InquiryError("not_found", "Inquiry was not found")
        predecessor_digest: str | None = None
        latest: dict[str, Any] | None = None
        for sequence, path in enumerate(paths, start=1):
            try:
                value = verify_canonical_json_bytes(path.read_bytes())
            except (OSError, ValueError) as exc:
                raise InquiryError("integrity_error", "Inquiry record is invalid") from exc
            if (
                not isinstance(value, dict)
                or value.get("inquiry_id") != inquiry_id
                or value.get("sequence") != sequence
            ):
                raise InquiryError("integrity_error", "Inquiry event chain is invalid")
            event_digest = value.get("event_digest")
            predecessor = value.get("predecessor_event_digest")
            material = dict(value)
            material.pop("event_digest", None)
            if event_digest != _sha(canonical_json_bytes(material)):
                raise InquiryError("integrity_error", "Inquiry event chain is invalid")
            expected_predecessor: Mapping[str, Any] = (
                {"state": "absent"}
                if predecessor_digest is None
                else {"state": "present", "value": predecessor_digest}
            )
            if predecessor != expected_predecessor:
                raise InquiryError("integrity_error", "Inquiry event chain is invalid")
            predecessor_digest = str(event_digest)
            latest = value
        assert latest is not None
        return latest

    def write_private(self, path: Path, value: Mapping[str, Any]) -> None:
        root = path.parents[0]
        while root.parent != self.root and root.name != "private":
            root = root.parent
        if root.name != "private":
            raise InquiryError("integrity_error", "Inquiry private path is invalid")
        atomic_write_text(
            path,
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            trusted_root=root,
            mode=0o600,
        )

    def write_immutable_private(self, path: Path, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if path.read_text(encoding="utf-8") != payload:
                raise InquiryError("conflict", "Inquiry private record conflicts") from None
            return
        try:
            encoded = payload.encode("utf-8")
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def open_index(self, idempotency_digest: str) -> Path:
        return self.root / "open-index" / f"{_token(idempotency_digest, 64)}.json"


class InquiryManager:
    """Coordinate finite read-only Inquiry fan-out and evidence handoff."""

    def __init__(
        self,
        project_root: str | Path,
        config: HarnessConfig,
        *,
        custody_root_id: str = "unrest-inquiry-local-v1",
        provider_runner: InquiryProviderRunner | None = None,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.project_root = Path(project_root).resolve(strict=True)
        self.config = config
        self.store = _InquiryStore(self.project_root)
        self.foundation = FoundationStore(
            self.project_root,
            custody_root_id=custody_root_id,
        )
        self.provider_runner = provider_runner or ProviderSessionRunner(config)
        self._now = now
        self._local_cancel: dict[str, asyncio.Event] = {}

    def open_inquiry(
        self,
        *,
        question: str,
        budget: InquiryBudget,
        idempotency_key: str,
        project_id: str | None = None,
    ) -> InquirySummary:
        _validate_text(question)
        _validate_text(idempotency_key)
        if project_id is not None:
            _validate_text(project_id)
        question_digest = _sha(question.encode("utf-8"))
        policy_digest = self._capability_policy_digest()
        request_digest = _hash_record(
            _without_none(
                {
                    "budget": budget.public_record(),
                    "project_id": project_id,
                    "question_digest": question_digest,
                }
            )
        )
        idempotency_digest = _sha(idempotency_key.encode("utf-8"))
        inquiry_id = "inquiry:" + _token(
            _hash_record(
                {
                    "idempotency_key_digest": idempotency_digest,
                    "request_digest": request_digest,
                }
            )
        )
        with self.store.locked():
            index_path = self.store.open_index(idempotency_digest)
            if index_path.exists():
                try:
                    indexed = verify_canonical_json_bytes(index_path.read_bytes())
                except (OSError, ValueError) as exc:
                    raise InquiryError("integrity_error", "Inquiry index is invalid") from exc
                if not isinstance(indexed, Mapping) or indexed.get("request_digest") != request_digest:
                    raise InquiryError("conflict", "Idempotency key conflicts")
                return self._summary(self._load(str(indexed["inquiry_id"])))

            events = self.store.inquiry_root(inquiry_id) / "events"
            if events.is_dir() and any(events.glob("*.json")):
                existing = self._load(inquiry_id)
                if existing.get("open_request_digest") != request_digest:
                    raise InquiryError("conflict", "Inquiry open request conflicts")
                self.store.append_public_record(
                    index_path,
                    {
                        "inquiry_id": inquiry_id,
                        "request_digest": request_digest,
                        "schema_version": 1,
                    },
                )
                return self._summary(existing)

            self.store.initialize(inquiry_id)
            inquiry_identity = self._append_identity(
                "inquiry",
                {
                    "budget_envelope": {"amount": budget.max_steps, "unit": "steps"},
                    "capability_policy_digest": policy_digest,
                    "public_id": inquiry_id,
                    "question_digest": question_digest,
                    "schema_version": 1,
                },
            )
            branches: dict[str, dict[str, Any]] = {}
            for role in BRANCH_ROLES[: budget.max_branches]:
                provider_digest, route_digest = self._provider_route_digests(
                    "inquiry_branch", role
                )
                branch_id = "branch:" + role
                branch_identity = self._append_identity(
                    "inquiry_branch",
                    {
                        "branch_id": branch_id,
                        "branch_role": role,
                        "budget_envelope": {
                            "amount": budget.max_steps,
                            "unit": "steps",
                        },
                        "inquiry_digest": inquiry_identity.digest,
                        "provider_configuration_digest": provider_digest,
                        "public_id": f"inquiry_branch:{_token(inquiry_identity.digest, 12)}:{role}",
                        "route_profile_digest": route_digest,
                        "schema_version": 1,
                    },
                )
                branches[role] = {
                    "attempts": 0,
                    "branch_id": branch_id,
                    "identity_digest": branch_identity.digest,
                    "outcome": "pending",
                    "steps_used": 0,
                }
            state: dict[str, Any] = {
                "active_operation": {"state": "absent"},
                "branches": branches,
                "budget": budget.public_record(),
                "capability_policy_digest": policy_digest,
                "created_at": _format_time(self._now()),
                "handoffs": [],
                "idempotency": {},
                "inquiry_id": inquiry_id,
                "inquiry_identity_digest": inquiry_identity.digest,
                "open_request_digest": request_digest,
                "project_binding": (
                    {"state": "present", "value": project_id}
                    if project_id is not None
                    else {"state": "absent"}
                ),
                "question_digest": question_digest,
                "receipt_id": {"state": "absent"},
                "schema_version": 1,
                "sequence": 1,
                "state": "open",
                "synthesis": {"state": "absent"},
                "updated_at": _format_time(self._now()),
            }
            self.store.write_immutable_private(
                self.store.private_root(inquiry_id) / "question.json",
                {"question": question, "question_digest": question_digest, "schema_version": 1},
            )
            self.store.write_immutable_private(
                self.store.private_root(inquiry_id) / "provider-project-record.json",
                {
                    "inquiry_id": inquiry_id,
                    "inquiry_identity_digest": inquiry_identity.digest,
                    "privacy": "private-inquiry-adjacent-record",
                    "schema_version": 1,
                },
            )
            self.store.append_event(state)
            index_value = {
                "inquiry_id": inquiry_id,
                "request_digest": request_digest,
                "schema_version": 1,
            }
            self.store.append_public_record(index_path, index_value)
            return self._summary(state)

    def inspect_inquiry(self, inquiry_id: str) -> InquirySummary:
        with self.store.locked():
            return self._summary(self._load(inquiry_id))

    async def advance_inquiry(
        self,
        inquiry_id: str,
        *,
        idempotency_key: str,
    ) -> InquirySummary:
        with self.store.operation_guard(inquiry_id):
            return await self._advance_owned(
                inquiry_id,
                idempotency_key=idempotency_key,
            )

    async def _advance_owned(
        self,
        inquiry_id: str,
        *,
        idempotency_key: str,
    ) -> InquirySummary:
        _validate_text(idempotency_key)
        key_digest = _sha(idempotency_key.encode("utf-8"))
        request_digest = _hash_record(
            {"inquiry_id": inquiry_id, "operation": "advance_inquiry"}
        )
        with self.store.locked():
            state = self._load(inquiry_id)
            replay = self._idempotent_replay(state, key_digest, "advance_inquiry", request_digest)
            if replay is not None:
                return replay
            active = state["active_operation"]
            if active["state"] == "present":
                value = active["value"]
                if value["key_digest"] != key_digest:
                    raise InquiryError("busy", "Inquiry already has an active operation")
            elif state["state"] not in {"open", "exploring", "synthesizing"}:
                raise InquiryError("invalid_transition", "Inquiry cannot be advanced")

            pending = [
                role
                for role, branch in sorted(state["branches"].items())
                if branch["outcome"] in {"pending", "running"}
            ]
            phase = "branches" if pending else "synthesis"
            state["state"] = "exploring" if pending else "synthesizing"
            for role in pending:
                state["branches"][role]["outcome"] = "running"
            state["active_operation"] = {
                "state": "present",
                "value": {
                    "key_digest": key_digest,
                    "operation": "advance_inquiry",
                    "phase": phase,
                    "request_digest": request_digest,
                },
            }
            self._transition(state)

        cancel_event = asyncio.Event()
        self._local_cancel[inquiry_id] = cancel_event
        watcher = asyncio.create_task(self._watch_cancellation(inquiry_id, cancel_event))
        try:
            if pending:
                results = await self._run_branches(state, pending, cancel_event)
                with self.store.locked():
                    current = self._load(inquiry_id)
                    self._apply_branch_results(current, results)
                    if current["state"] in {"paused", "cancelled"}:
                        self._complete_operation(
                            current,
                            key_digest,
                            request_digest,
                            "advance_inquiry",
                        )
                        self._transition(current)
                        return self._summary(current)
                    current["state"] = "synthesizing"
                    current["active_operation"]["value"]["phase"] = "synthesis"
                    self._transition(current)
                    state = current

            synthesis_result = await self._run_synthesis(state, cancel_event)
            with self.store.locked():
                current = self._load(inquiry_id)
                if current["state"] in {"paused", "cancelled"}:
                    self._complete_operation(
                        current,
                        key_digest,
                        request_digest,
                        "advance_inquiry",
                    )
                    self._transition(current)
                    return self._summary(current)
                self._apply_synthesis_result(current, synthesis_result)
                self._complete_operation(
                    current,
                    key_digest,
                    request_digest,
                    "advance_inquiry",
                )
                self._transition(current)
                return self._summary(current)
        finally:
            cancel_event.set()
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            self._local_cancel.pop(inquiry_id, None)

    def pause_inquiry(
        self,
        inquiry_id: str,
        *,
        reason: str,
        idempotency_key: str,
    ) -> InquirySummary:
        return self._interrupt(
            inquiry_id,
            reason=reason,
            idempotency_key=idempotency_key,
            operation="pause_inquiry",
            terminal_state="paused",
        )

    def cancel_inquiry(
        self,
        inquiry_id: str,
        *,
        reason: str,
        idempotency_key: str,
    ) -> InquirySummary:
        return self._interrupt(
            inquiry_id,
            reason=reason,
            idempotency_key=idempotency_key,
            operation="cancel_inquiry",
            terminal_state="cancelled",
        )

    def resume_inquiry(
        self,
        inquiry_id: str,
        *,
        idempotency_key: str,
    ) -> InquirySummary:
        _validate_text(idempotency_key)
        key_digest = _sha(idempotency_key.encode("utf-8"))
        request_digest = _hash_record(
            {"inquiry_id": inquiry_id, "operation": "resume_inquiry"}
        )
        with self.store.locked():
            state = self._load(inquiry_id)
            replay = self._idempotent_replay(state, key_digest, "resume_inquiry", request_digest)
            if replay is not None:
                return replay
            if state["state"] != "paused":
                raise InquiryError("invalid_transition", "Inquiry cannot be resumed")
            if state["active_operation"]["state"] == "present":
                raise InquiryError("busy", "Inquiry operation is still draining")
            for branch in state["branches"].values():
                if branch["outcome"] == "paused":
                    branch["outcome"] = "pending"
            state["state"] = "open"
            state["active_operation"] = {"state": "absent"}
            self._record_idempotency(state, key_digest, "resume_inquiry", request_digest)
            self._transition(state)
            return self._summary(state)

    def handoff_inquiry(
        self,
        inquiry_id: str,
        *,
        consumer_id: str,
        idempotency_key: str,
    ) -> HandoffSummary:
        _validate_text(idempotency_key)
        if not isinstance(consumer_id, str) or _CONSUMER_ID.fullmatch(consumer_id) is None:
            raise InquiryError("invalid_argument", "Inquiry consumer is invalid")
        key_digest = _sha(idempotency_key.encode("utf-8"))
        with self.store.locked():
            state = self._load(inquiry_id)
            if state["state"] != "answered" or state["synthesis"]["state"] != "present":
                raise InquiryError("invalid_transition", "Inquiry cannot be handed off")
            synthesis = state["synthesis"]["value"]
            branch_denominator = [
                {
                    "identity_digest": branch["identity_digest"],
                    "outcome": branch["outcome"],
                    "role": role,
                }
                for role, branch in sorted(state["branches"].items())
            ]
            handoff_material = {
                "branch_denominator": branch_denominator,
                "consumer_id": consumer_id,
                "inquiry_digest": state["inquiry_identity_digest"],
                "question_digest": state["question_digest"],
                "retention": "project_lifetime_private_evidence",
                "synthesis_digest": synthesis["synthesis_digest"],
            }
            handoff_digest = _hash_record(handoff_material)
            request_digest = _hash_record(
                {
                    "consumer_id": consumer_id,
                    "handoff_digest": handoff_digest,
                    "inquiry_id": inquiry_id,
                }
            )
            index_path = self.store.private_root(inquiry_id) / "handoff-index" / f"{_token(key_digest, 64)}.json"
            if index_path.exists():
                indexed = json.loads(index_path.read_text(encoding="utf-8"))
                if indexed.get("request_digest") != request_digest:
                    raise InquiryError("conflict", "Idempotency key conflicts")
                return HandoffSummary(
                    handoff_id=str(indexed["handoff_id"]),
                    inquiry_id=inquiry_id,
                    consumer_id=consumer_id,
                    receipt_id=str(indexed["receipt_id"]),
                )
            identity = self._append_identity(
                "inquiry_handoff",
                {
                    "consumer_id": consumer_id,
                    "handoff_digest": handoff_digest,
                    "inquiry_digest": state["inquiry_identity_digest"],
                    "public_id": f"inquiry_handoff:{_token(handoff_digest)}",
                    "schema_version": 1,
                    "synthesis_digest": synthesis["synthesis_digest"],
                },
            )
            handoff_id = "handoff:" + _token(identity.digest)
            receipt_id = self._issue_evidence_receipt(
                inquiry_id,
                subject_kind="inquiry_handoff",
                subject_digest=identity.digest,
                outcome="handoff_issued",
                consumer_id=consumer_id,
                dependencies=(
                    state["inquiry_identity_digest"],
                    synthesis["identity_digest"],
                    *(
                        branch["identity_digest"]
                        for branch in state["branches"].values()
                    ),
                ),
            )
            private_question = self._load_private_question(inquiry_id)
            private_synthesis = self._load_provider_artifact(
                self._private_path(inquiry_id, str(synthesis["artifact_relative_path"]))
            )
            artifact = {
                "branch_denominator": branch_denominator,
                "consumer_id": consumer_id,
                "handoff_digest": handoff_digest,
                "handoff_id": handoff_id,
                "handoff_identity_digest": identity.digest,
                "inquiry_id": inquiry_id,
                "privacy": "private-evidence-only-handoff",
                "question": private_question,
                "retention": "project_lifetime_private_evidence",
                "schema_version": 1,
                "synthesis": private_synthesis.get("output", {}).get("parsed"),
            }
            relative = f"handoffs/{_token(identity.digest)}.json"
            self.store.write_immutable_private(
                self.store.private_root(inquiry_id) / relative,
                artifact,
            )
            indexed = {
                "handoff_id": handoff_id,
                "receipt_id": receipt_id,
                "request_digest": request_digest,
                "schema_version": 1,
            }
            self.store.write_immutable_private(index_path, indexed)
            state["handoffs"].append(
                {
                    "consumer_id": consumer_id,
                    "handoff_id": handoff_id,
                    "identity_digest": identity.digest,
                    "receipt_id": receipt_id,
                }
            )
            self._transition(state)
            return HandoffSummary(handoff_id, inquiry_id, consumer_id, receipt_id)

    def _interrupt(
        self,
        inquiry_id: str,
        *,
        reason: str,
        idempotency_key: str,
        operation: str,
        terminal_state: Literal["paused", "cancelled"],
    ) -> InquirySummary:
        _validate_text(reason)
        _validate_text(idempotency_key)
        key_digest = _sha(idempotency_key.encode("utf-8"))
        request_digest = _hash_record(
            {
                "inquiry_id": inquiry_id,
                "operation": operation,
                "reason_digest": _sha(reason.encode("utf-8")),
            }
        )
        with self.store.locked():
            state = self._load(inquiry_id)
            replay = self._idempotent_replay(state, key_digest, operation, request_digest)
            if replay is not None:
                return replay
            allowed = {"open", "exploring", "synthesizing"}
            if state["state"] not in allowed:
                raise InquiryError("invalid_transition", f"Inquiry cannot be {terminal_state}")
            state["state"] = terminal_state
            for branch in state["branches"].values():
                if branch["outcome"] in {"pending", "running"}:
                    branch["outcome"] = terminal_state
            state["interrupt"] = {
                "operation": operation,
                "reason_digest": _sha(reason.encode("utf-8")),
            }
            self._record_idempotency(state, key_digest, operation, request_digest)
            self._transition(state)
        event = self._local_cancel.get(inquiry_id)
        if event is not None:
            event.set()
        return self._summary(state)

    async def _run_branches(
        self,
        state: Mapping[str, Any],
        roles: Sequence[str],
        cancel_event: asyncio.Event,
    ) -> dict[str, tuple[ProviderSessionResult, str, int]]:
        inquiry_id = str(state["inquiry_id"])
        budget = state["budget"]
        semaphore = asyncio.Semaphore(int(budget["max_branches"]))

        async def run_one(role: str) -> tuple[str, ProviderSessionResult, str, int]:
            branch = state["branches"][role]
            attempt = int(branch["attempts"]) + 1
            relative = f"branches/{role}/attempt-{attempt:04d}.json"
            artifact = self.store.private_root(inquiry_id) / relative
            self.store._ensure_directory(artifact.parent)
            prompt = self._branch_prompt(inquiry_id, role, branch, int(budget["max_steps"]))
            request = ProviderSessionRequest(
                role="inquiry_branch",
                prompt=prompt,
                workspace_path=self.project_root,
                project_record_path=self.store.private_root(inquiry_id) / "provider-project-record.json",
                private_artifact_path=artifact,
                private_artifact_root=self.store.private_root(inquiry_id),
                timeout_seconds=int(budget["timeout_seconds"]),
            )
            async with semaphore:
                result = await self.provider_runner.run(request, cancel_event=cancel_event)
            return role, result, relative, attempt

        gathered = await asyncio.gather(
            *(run_one(role) for role in roles),
            return_exceptions=True,
        )
        results: dict[str, tuple[ProviderSessionResult, str, int]] = {}
        for role, item in zip(roles, gathered, strict=True):
            if isinstance(item, BaseException):
                results[role] = (
                    ProviderSessionResult(
                        role="inquiry_branch",
                        provider="claude",
                        status="failed",
                        stop_reason=None,
                        response_bytes=0,
                        response_truncated=False,
                        structured_output=False,
                        adapter_exit_code=None,
                        error_code="protocol_error",
                    ),
                    "",
                    int(state["branches"][role]["attempts"]) + 1,
                )
            else:
                observed_role, result, relative, attempt = item
                results[observed_role] = (result, relative, attempt)
        return results

    def _apply_branch_results(
        self,
        state: dict[str, Any],
        results: Mapping[str, tuple[ProviderSessionResult, str, int]],
    ) -> None:
        interrupted = state["state"] in {"paused", "cancelled"}
        for role, (result, relative, attempt) in sorted(results.items()):
            branch = state["branches"][role]
            branch["attempts"] = attempt
            branch["provider"] = _without_none(result.public_metadata())
            if relative:
                branch["artifact_relative_path"] = relative
                parsed = self._load_provider_artifact(
                    self._private_path(str(state["inquiry_id"]), relative)
                )
                steps_used = self._parsed_steps_used(parsed)
            else:
                steps_used = 0
            branch["steps_used"] = steps_used
            if interrupted:
                branch["outcome"] = state["state"]
            elif steps_used > int(state["budget"]["max_steps"]):
                branch["outcome"] = "budget_exhausted"
            elif result.status == "completed" and result.structured_output:
                branch["outcome"] = "answered"
            elif result.status == "cancelled":
                branch["outcome"] = "cancelled"
            else:
                branch["outcome"] = "failed"

    async def _run_synthesis(
        self,
        state: Mapping[str, Any],
        cancel_event: asyncio.Event,
    ) -> tuple[ProviderSessionResult, str, int]:
        inquiry_id = str(state["inquiry_id"])
        synthesis = state["synthesis"]
        attempt = 1
        if synthesis["state"] == "present":
            attempt = int(synthesis["value"].get("attempt", 0)) + 1
        relative = f"synthesis/attempt-{attempt:04d}.json"
        artifact = self.store.private_root(inquiry_id) / relative
        prompt = self._synthesis_prompt(state)
        request = ProviderSessionRequest(
            role="inquiry_synthesis",
            prompt=prompt,
            workspace_path=self.project_root,
            project_record_path=self.store.private_root(inquiry_id) / "provider-project-record.json",
            private_artifact_path=artifact,
            private_artifact_root=self.store.private_root(inquiry_id),
            timeout_seconds=int(state["budget"]["timeout_seconds"]),
        )
        try:
            result = await self.provider_runner.run(request, cancel_event=cancel_event)
        except Exception:  # noqa: BLE001
            result = ProviderSessionResult(
                role="inquiry_synthesis",
                provider="claude",
                status="failed",
                stop_reason=None,
                response_bytes=0,
                response_truncated=False,
                structured_output=False,
                adapter_exit_code=None,
                error_code="protocol_error",
            )
            relative = ""
        return result, relative, attempt

    def _apply_synthesis_result(
        self,
        state: dict[str, Any],
        result_tuple: tuple[ProviderSessionResult, str, int],
    ) -> None:
        result, relative, attempt = result_tuple
        provider = _without_none(result.public_metadata())
        if result.status != "completed" or not result.structured_output or not relative:
            state["synthesis"] = {
                "state": "present",
                "value": {"attempt": attempt, "provider": provider, "status": "failed"},
            }
            outcomes = {branch["outcome"] for branch in state["branches"].values()}
            state["state"] = (
                "budget_exhausted" if outcomes == {"budget_exhausted"} else "failed"
            )
            state["receipt_id"] = {"state": "absent"}
            return
        path = self._private_path(str(state["inquiry_id"]), relative)
        artifact = self._load_provider_artifact(path)
        parsed = artifact.get("output", {}).get("parsed")
        if not isinstance(parsed, Mapping) or not self._valid_synthesis(parsed, state):
            state["synthesis"] = {
                "state": "present",
                "value": {"attempt": attempt, "provider": provider, "status": "failed"},
            }
            state["state"] = "failed"
            return
        try:
            synthesis_digest = _hash_record(dict(parsed))
        except ValueError:
            state["synthesis"] = {
                "state": "present",
                "value": {"attempt": attempt, "provider": provider, "status": "failed"},
            }
            state["state"] = "failed"
            return
        branch_set_digest = _hash_record(
            [
                {
                    "identity_digest": branch["identity_digest"],
                    "outcome": branch["outcome"],
                    "role": role,
                }
                for role, branch in sorted(state["branches"].items())
            ]
        )
        identity = self._append_identity(
            "inquiry_synthesis",
            {
                "branch_set_digest": branch_set_digest,
                "inquiry_digest": state["inquiry_identity_digest"],
                "public_id": f"inquiry_synthesis:{_token(synthesis_digest)}",
                "schema_version": 1,
                "synthesis_digest": synthesis_digest,
            },
        )
        dissent = parsed.get("minority_dissent")
        limitations = parsed.get("limitations")
        state["synthesis"] = {
            "state": "present",
            "value": {
                "artifact_digest": _sha(path.read_bytes()),
                "artifact_relative_path": relative,
                "attempt": attempt,
                "branch_set_digest": branch_set_digest,
                "citation_count": len(parsed["citations"]),
                "dissent_present": isinstance(dissent, list) and bool(dissent),
                "identity_digest": identity.digest,
                "limitations_count": len(limitations) if isinstance(limitations, list) else 0,
                "provider": provider,
                "status": "answered",
                "synthesis_digest": synthesis_digest,
            },
        }
        state["state"] = "answered"
        receipt_id = self._issue_evidence_receipt(
            str(state["inquiry_id"]),
            subject_kind="inquiry_synthesis",
            subject_digest=identity.digest,
            outcome="answered",
            consumer_id=None,
            dependencies=(
                state["inquiry_identity_digest"],
                *(branch["identity_digest"] for branch in state["branches"].values()),
            ),
        )
        state["receipt_id"] = {
            "state": "present",
            "value": receipt_id,
        }

    def _branch_prompt(
        self,
        inquiry_id: str,
        role: str,
        branch: Mapping[str, Any],
        max_steps: int,
    ) -> str:
        question = self._load_private_question(inquiry_id)
        instructions = {
            "analogy": "Develop useful analogies and lateral alternatives, then name their limits.",
            "critic": "Stress-test premises, failure modes, and missing counterevidence.",
            "direct": "Answer the question directly with a compact explicit argument.",
            "evidence": "Seek and weigh concrete evidence available in the read-only workspace.",
        }
        return (
            f"Inquiry branch identity: {branch['identity_digest']}\n"
            f"Branch role: {role}\n"
            f"Finite step budget: {max_steps}\n"
            f"Role instruction: {instructions[role]}\n\n"
            f"Question:\n{question}\n\n"
            "Return one JSON object. Include answer, evidence, limitations, and "
            "steps_used (an integer no greater than the finite budget)."
        )

    def _synthesis_prompt(self, state: Mapping[str, Any]) -> str:
        inquiry_id = str(state["inquiry_id"])
        denominator: list[dict[str, Any]] = []
        for role, branch in sorted(state["branches"].items()):
            parsed: Any = None
            relative = branch.get("artifact_relative_path")
            if branch["outcome"] == "answered" and isinstance(relative, str):
                artifact = self._load_provider_artifact(
                    self._private_path(inquiry_id, relative)
                )
                parsed = artifact.get("output", {}).get("parsed")
            denominator.append(
                _without_none(
                    {
                        "branch_identity": branch["identity_digest"],
                        "outcome": branch["outcome"],
                        "response": parsed,
                        "role": role,
                    }
                )
            )
        payload = {
            "branches": denominator,
            "question": self._load_private_question(inquiry_id),
        }
        return (
            "Independently synthesize this complete Inquiry denominator. Preserve "
            "minority dissent, identify failed or missing evidence, and cite every "
            "branch identity exactly once or more. Return a JSON object with answer, "
            "citations (objects containing branch_identity and outcome), "
            "minority_dissent (array), and limitations (array).\n\n"
            + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )

    @staticmethod
    def _valid_synthesis(parsed: Mapping[str, Any], state: Mapping[str, Any]) -> bool:
        citations = parsed.get("citations")
        dissent = parsed.get("minority_dissent")
        limitations = parsed.get("limitations")
        if not isinstance(citations, list) or not isinstance(dissent, list) or not isinstance(limitations, list):
            return False
        expected = {
            (branch["identity_digest"], branch["outcome"])
            for branch in state["branches"].values()
        }
        observed: set[tuple[str, str]] = set()
        for citation in citations:
            if not isinstance(citation, Mapping):
                return False
            identity = citation.get("branch_identity")
            outcome = citation.get("outcome")
            if isinstance(identity, str) and isinstance(outcome, str):
                observed.add((identity, outcome))
        return expected == observed

    async def _watch_cancellation(
        self,
        inquiry_id: str,
        cancel_event: asyncio.Event,
    ) -> None:
        while not cancel_event.is_set():
            await asyncio.sleep(0.05)
            try:
                state = self._load(inquiry_id)
            except InquiryError:
                cancel_event.set()
                return
            if state["state"] in {"paused", "cancelled"}:
                cancel_event.set()
                return

    def _load(self, inquiry_id: str) -> dict[str, Any]:
        state = self.store.load(inquiry_id)
        try:
            inquiry = self.foundation.load_identity(
                "inquiry", str(state["inquiry_identity_digest"])
            )
            budget = state["budget"]
            expected_inquiry = {
                "budget_envelope": {
                    "amount": int(budget["max_steps"]),
                    "unit": "steps",
                },
                "capability_policy_digest": state["capability_policy_digest"],
                "public_id": inquiry_id,
                "question_digest": state["question_digest"],
                "schema_version": 1,
            }
            if inquiry.payload != expected_inquiry:
                raise InquiryError("integrity_error", "Inquiry identity is invalid")
            question = self._load_private_question(inquiry_id)
            if _sha(question.encode("utf-8")) != state["question_digest"]:
                raise InquiryError("integrity_error", "Inquiry private evidence is invalid")
            expected_roles = set(BRANCH_ROLES[: int(budget["max_branches"])])
            if set(state["branches"]) != expected_roles:
                raise InquiryError("integrity_error", "Inquiry branch set is invalid")
            for role, branch in state["branches"].items():
                identity = self.foundation.load_identity(
                    "inquiry_branch", str(branch["identity_digest"])
                )
                payload = identity.payload
                if (
                    payload.get("inquiry_digest") != inquiry.digest
                    or payload.get("branch_id") != f"branch:{role}"
                    or payload.get("branch_role") != role
                    or payload.get("budget_envelope")
                    != {"amount": int(budget["max_steps"]), "unit": "steps"}
                ):
                    raise InquiryError("integrity_error", "Inquiry branch identity is invalid")
            synthesis = state["synthesis"]
            if synthesis["state"] == "present" and synthesis["value"].get("status") == "answered":
                value = synthesis["value"]
                path = self._private_path(inquiry_id, str(value["artifact_relative_path"]))
                if _sha(path.read_bytes()) != value["artifact_digest"]:
                    raise InquiryError("integrity_error", "Inquiry synthesis evidence is invalid")
                artifact = self._load_provider_artifact(path)
                parsed = artifact.get("output", {}).get("parsed")
                if not isinstance(parsed, Mapping) or not self._valid_synthesis(parsed, state):
                    raise InquiryError("integrity_error", "Inquiry synthesis evidence is invalid")
                synthesis_digest = _hash_record(dict(parsed))
                branch_set_digest = _hash_record(
                    [
                        {
                            "identity_digest": branch["identity_digest"],
                            "outcome": branch["outcome"],
                            "role": role,
                        }
                        for role, branch in sorted(state["branches"].items())
                    ]
                )
                identity = self.foundation.load_identity(
                    "inquiry_synthesis", str(value["identity_digest"])
                )
                if (
                    synthesis_digest != value["synthesis_digest"]
                    or branch_set_digest != value["branch_set_digest"]
                    or identity.payload.get("inquiry_digest") != inquiry.digest
                    or identity.payload.get("synthesis_digest") != synthesis_digest
                    or identity.payload.get("branch_set_digest") != branch_set_digest
                ):
                    raise InquiryError("integrity_error", "Inquiry synthesis identity is invalid")
                receipt = state["receipt_id"]
                expected_receipt = self._evidence_receipt_document(
                    subject_kind="inquiry_synthesis",
                    subject_digest=identity.digest,
                    outcome="answered",
                    consumer_id=None,
                    dependencies=(
                        inquiry.digest,
                        *(branch["identity_digest"] for branch in state["branches"].values()),
                    ),
                )
                if receipt != {"state": "present", "value": expected_receipt["receipt_id"]}:
                    raise InquiryError("integrity_error", "Inquiry evidence receipt is invalid")
                self._verify_evidence_receipt(inquiry_id, expected_receipt)
            for handoff in state["handoffs"]:
                identity = self.foundation.load_identity(
                    "inquiry_handoff", str(handoff["identity_digest"])
                )
                if (
                    identity.payload.get("inquiry_digest") != inquiry.digest
                    or identity.payload.get("consumer_id") != handoff["consumer_id"]
                    or handoff["handoff_id"] != "handoff:" + _token(identity.digest)
                    or handoff["receipt_id"]
                    != "receipt:inquiry-evidence:" + _token(identity.digest)
                ):
                    raise InquiryError("integrity_error", "Inquiry handoff identity is invalid")
                if synthesis["state"] != "present":
                    raise InquiryError("integrity_error", "Inquiry handoff identity is invalid")
                expected_receipt = self._evidence_receipt_document(
                    subject_kind="inquiry_handoff",
                    subject_digest=identity.digest,
                    outcome="handoff_issued",
                    consumer_id=str(handoff["consumer_id"]),
                    dependencies=(
                        inquiry.digest,
                        synthesis["value"]["identity_digest"],
                        *(branch["identity_digest"] for branch in state["branches"].values()),
                    ),
                )
                self._verify_evidence_receipt(inquiry_id, expected_receipt)
        except InquiryError:
            raise
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise InquiryError("integrity_error", "Inquiry record is invalid") from exc
        return state

    def _private_path(self, inquiry_id: str, relative: str) -> Path:
        path = Path(relative)
        if path.is_absolute() or not path.parts or any(
            part in {"", ".", ".."} for part in path.parts
        ):
            raise InquiryError("integrity_error", "Inquiry private path is invalid")
        root = self.store.private_root(inquiry_id)
        candidate = root.joinpath(*path.parts)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise InquiryError("integrity_error", "Inquiry private path is invalid") from exc
        return candidate

    def _load_private_question(self, inquiry_id: str) -> str:
        try:
            value = json.loads(
                (self.store.private_root(inquiry_id) / "question.json").read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise InquiryError("integrity_error", "Inquiry private evidence is invalid") from exc
        question = value.get("question") if isinstance(value, Mapping) else None
        if not isinstance(question, str) or _sha(question.encode("utf-8")) != value.get("question_digest"):
            raise InquiryError("integrity_error", "Inquiry private evidence is invalid")
        return question

    @staticmethod
    def _load_provider_artifact(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InquiryError("integrity_error", "Inquiry provider evidence is invalid") from exc
        if not isinstance(value, dict):
            raise InquiryError("integrity_error", "Inquiry provider evidence is invalid")
        return value

    @staticmethod
    def _parsed_steps_used(artifact: Mapping[str, Any]) -> int:
        output = artifact.get("output")
        parsed = output.get("parsed") if isinstance(output, Mapping) else None
        steps = parsed.get("steps_used", 1) if isinstance(parsed, Mapping) else 0
        if isinstance(steps, bool) or not isinstance(steps, int) or steps < 0:
            return 9_007_199_254_740_991
        return steps

    def _capability_policy_digest(self) -> str:
        path = self.config.bundled_dir / "policies" / "role-capabilities.v1.json"
        try:
            return _sha(path.read_bytes())
        except OSError as exc:
            raise InquiryError("provider_unavailable", "Inquiry policy is unavailable") from exc

    def _provider_route_digests(self, session_role: str, branch_role: str) -> tuple[str, str]:
        role_config = self.config.for_role("inquiry_branch")
        provider = role_config.worker_provider.name
        command = role_config.worker_acp_command or role_config.resolved_worker_acp_command
        provider_digest = _hash_record(
            {
                "adapter_command_digest": _sha((command or "unconfigured").encode("utf-8")),
                "provider": provider,
                "session_role": session_role,
            }
        )
        route_digest = _hash_record(
            _without_none(
                {
                    "branch_role": branch_role,
                    "provider": provider,
                    "reasoning_effort": role_config.worker_reasoning_effort,
                    "session_role": session_role,
                }
            )
        )
        return provider_digest, route_digest

    def _append_identity(self, kind: str, payload: Mapping[str, Any]) -> IdentityRecord:
        identity = construct_identity(kind, payload)
        self.foundation.append_identity(identity)
        return identity

    def _issue_evidence_receipt(
        self,
        inquiry_id: str,
        *,
        subject_kind: Literal["inquiry_synthesis", "inquiry_handoff"],
        subject_digest: str,
        outcome: Literal["answered", "handoff_issued"],
        consumer_id: str | None,
        dependencies: Sequence[str],
    ) -> str:
        document = self._evidence_receipt_document(
            subject_kind=subject_kind,
            subject_digest=subject_digest,
            outcome=outcome,
            consumer_id=consumer_id,
            dependencies=dependencies,
        )
        self.store.append_evidence_receipt(inquiry_id, document)
        return str(document["receipt_id"])

    @staticmethod
    def _evidence_receipt_document(
        *,
        subject_kind: Literal["inquiry_synthesis", "inquiry_handoff"],
        subject_digest: str,
        outcome: Literal["answered", "handoff_issued"],
        consumer_id: str | None,
        dependencies: Sequence[str],
    ) -> dict[str, Any]:
        return {
            "authority_class": "evidence_only_non_authoritative",
            "authoritative": False,
            "consumer": (
                {"state": "present", "value": consumer_id}
                if consumer_id is not None
                else {"state": "absent"}
            ),
            "dependencies": sorted(set(dependencies)),
            "outcome": outcome,
            "receipt_id": "receipt:inquiry-evidence:" + _token(subject_digest),
            "retention": "project_lifetime",
            "schema_version": 1,
            "subject_digest": subject_digest,
            "subject_kind": subject_kind,
        }

    def _verify_evidence_receipt(
        self,
        inquiry_id: str,
        expected: Mapping[str, Any],
    ) -> None:
        receipt_id = str(expected["receipt_id"])
        path = (
            self.store.inquiry_root(inquiry_id)
            / "evidence-receipts"
            / f"{receipt_id.rsplit(':', 1)[-1]}.json"
        )
        try:
            observed = verify_canonical_json_bytes(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise InquiryError("integrity_error", "Inquiry evidence receipt is invalid") from exc
        if observed != expected:
            raise InquiryError("integrity_error", "Inquiry evidence receipt is invalid")

    def _transition(self, state: dict[str, Any]) -> None:
        state["sequence"] = int(state["sequence"]) + 1
        state["updated_at"] = _format_time(self._now())
        self.store.append_event(state)

    def _idempotent_replay(
        self,
        state: Mapping[str, Any],
        key_digest: str,
        operation: str,
        request_digest: str,
    ) -> InquirySummary | None:
        recorded = state["idempotency"].get(key_digest)
        if recorded is None:
            return None
        if recorded["operation"] != operation or recorded["request_digest"] != request_digest:
            raise InquiryError("conflict", "Idempotency key conflicts")
        return self._summary(state)

    @staticmethod
    def _record_idempotency(
        state: dict[str, Any],
        key_digest: str,
        operation: str,
        request_digest: str,
    ) -> None:
        state["idempotency"][key_digest] = {
            "operation": operation,
            "request_digest": request_digest,
        }

    def _complete_operation(
        self,
        state: dict[str, Any],
        key_digest: str,
        request_digest: str,
        operation: str,
    ) -> None:
        self._record_idempotency(state, key_digest, operation, request_digest)
        state["active_operation"] = {"state": "absent"}

    @staticmethod
    def _summary(state: Mapping[str, Any]) -> InquirySummary:
        receipt = state["receipt_id"]
        receipt_id = str(receipt["value"]) if receipt["state"] == "present" else None
        return InquirySummary(
            inquiry_id=str(state["inquiry_id"]),
            state=str(state["state"]),  # type: ignore[arg-type]
            branch_outcomes={
                role: cast(BranchOutcome, str(branch["outcome"]))
                for role, branch in sorted(state["branches"].items())
            },
            receipt_id=receipt_id,
        )


__all__ = [
    "BRANCH_ROLES",
    "HandoffSummary",
    "InquiryBudget",
    "InquiryError",
    "InquiryManager",
    "InquiryProviderRunner",
    "InquirySummary",
]
