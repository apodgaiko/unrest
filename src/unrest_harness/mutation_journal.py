"""Durable idempotency and externally issued grant custody for v0.3.1.

The journal is deliberately below the public tool facade.  It records the
complete canonical request before dispatch, so a reused key cannot reach a
manager event or a repository effect.  Human grants are separate immutable
records admitted by the host/controller and consumed by exact request
fingerprint; an effect adapter cannot manufacture its own authority.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, BinaryIO, Iterator, NoReturn
import uuid

class MutationJournalError(RuntimeError):
    """Typed failure from durable request/grant custody."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise MutationJournalError(code)


def request_fingerprint(request: Mapping[str, Any]) -> str:
    try:
        encoded = _canonical_bytes(dict(request))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MutationJournalError("invalid_argument") from exc
    return "sha256:" + hashlib.sha256(b"unrest.public-mutation.v1\0" + encoded).hexdigest()


def _token(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(dict(value))).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                dict(value),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MutationJournalError("invalid_argument") from exc


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, value: Mapping[str, Any], *, immutable: bool) -> None:
    content = _canonical_bytes(dict(value))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.parent.lstat().st_mode):
        _fail("integrity_error")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".mutation-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if immutable:
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != content:
                    _fail("conflict")
        else:
            os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read(path: Path) -> Mapping[str, Any]:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            _fail("integrity_error")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(value, Mapping) or _canonical_bytes(value) != raw:
            _fail("integrity_error")
    except (FileNotFoundError, OSError, UnicodeError, ValueError) as exc:
        raise MutationJournalError("integrity_error") from exc
    if not isinstance(value, Mapping):
        _fail("integrity_error")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


@contextmanager
def _lock(path: Path) -> Iterator[BinaryIO]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stream = path.open("a+b")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream
    finally:
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


class DurableMutationJournal:
    """Execute public mutations with crash-distinguishable effect custody."""

    _async_locks: dict[str, asyncio.Lock] = {}
    _active_generations: set[str] = set()

    def __init__(
        self,
        repository: Path,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> None:
        self.durable_root = repository / ".unrest" / "foundation" / "public-mutations"
        self.runtime_root = repository / ".unrest-runtime" / "foundation" / "public-mutations"
        self.durable_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._fault = fault or (lambda _: None)

    def execute(
        self,
        *,
        operation: str,
        resource_key: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        effect: Callable[[str], Mapping[str, Any]],
        reconcile: Callable[[str], Mapping[str, Any] | None],
        stage: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        identity, fingerprint, path = self._identity(
            operation, resource_key, idempotency_key, request
        )
        state = self._admit(identity, fingerprint, path)
        terminal = self._terminal_replay(identity, fingerprint, path, state)
        if terminal is not None:
            return terminal
        if state.get("state") == "applying":
            return self._reconcile(identity, fingerprint, path, reconcile)
        if stage is not None:
            stage(fingerprint)
        self._fault("staged")
        generation = self._claim(identity, fingerprint, path)
        if generation is None:
            return self._reconcile(identity, fingerprint, path, reconcile)
        self._active_generations.add(generation)
        try:
            result = dict(effect(fingerprint))
            self._fault("effect_applied")
            self._effect_complete(identity, fingerprint, path, generation, result)
            self._fault("effect_complete")
            return self._complete(identity, fingerprint, path)
        finally:
            self._active_generations.discard(generation)

    async def execute_async(
        self,
        *,
        operation: str,
        resource_key: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        effect: Callable[[str], Awaitable[Mapping[str, Any]]],
        reconcile: Callable[[str], Mapping[str, Any] | None],
        stage: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        identity, fingerprint, path = self._identity(
            operation, resource_key, idempotency_key, request
        )
        key = str(path)
        local_lock = self._async_locks.setdefault(key, asyncio.Lock())
        async with local_lock:
            state = self._admit(identity, fingerprint, path)
            terminal = self._terminal_replay(identity, fingerprint, path, state)
            if terminal is not None:
                return terminal
            if state.get("state") == "applying":
                return self._reconcile(identity, fingerprint, path, reconcile)
            if stage is not None:
                stage(fingerprint)
            self._fault("staged")
            generation = self._claim(identity, fingerprint, path)
            if generation is None:
                return self._reconcile(identity, fingerprint, path, reconcile)
            self._active_generations.add(generation)
            try:
                result = dict(await effect(fingerprint))
                self._fault("effect_applied")
                self._effect_complete(identity, fingerprint, path, generation, result)
                self._fault("effect_complete")
                return self._complete(identity, fingerprint, path)
            finally:
                self._active_generations.discard(generation)

    def _identity(
        self,
        operation: str,
        resource_key: str,
        idempotency_key: str,
        request: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str, Path]:
        if not operation or not resource_key or not idempotency_key:
            _fail("invalid_argument")
        identity = {
            "idempotency_key_digest": "sha256:"
            + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
            "operation": operation,
            "resource_key": resource_key,
        }
        token = _token({**identity, "idempotency_key": idempotency_key})
        return identity, request_fingerprint(request), self.durable_root / f"{token}.json"

    def _admit(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
    ) -> Mapping[str, Any]:
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            if path.exists():
                record = self._checked(identity, fingerprint, path)
                if record.get("state") == "prepared":
                    staged = {**record, "state": "staged"}
                    _atomic_write(path, staged, immutable=False)
                    return staged
                return record
            prepared = {
                **identity,
                "request_fingerprint": fingerprint,
                "schema_version": 1,
                "state": "prepared",
            }
            _atomic_write(path, prepared, immutable=True)
            self._fault("prepared")
            staged = {**prepared, "state": "staged"}
            _atomic_write(path, staged, immutable=False)
            return staged

    def _claim(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
    ) -> str | None:
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            record = self._checked(identity, fingerprint, path)
            if record.get("state") != "staged":
                return None
            generation = uuid.uuid4().hex
            _atomic_write(
                path,
                {
                    **record,
                    "owner_generation": generation,
                    "owner_pid": os.getpid(),
                    "state": "applying",
                },
                immutable=False,
            )
            return generation

    def _effect_complete(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
        generation: str,
        result: Mapping[str, Any],
    ) -> None:
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            record = self._checked(identity, fingerprint, path)
            if (
                record.get("state") != "applying"
                or record.get("owner_generation") != generation
            ):
                _fail("integrity_error")
            _atomic_write(
                path,
                {**record, "result": dict(result), "state": "effect_complete"},
                immutable=False,
            )

    def _complete(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
    ) -> dict[str, Any]:
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            record = self._checked(identity, fingerprint, path)
            if record.get("state") == "completed":
                result = record.get("result")
                if isinstance(result, Mapping):
                    return dict(result)
                _fail("integrity_error")
            if record.get("state") != "effect_complete" or not isinstance(
                record.get("result"), Mapping
            ):
                _fail("integrity_error")
            completed = {**record, "state": "completed"}
            _atomic_write(path, completed, immutable=False)
            return dict(completed["result"])

    def _reconcile(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
        reconcile: Callable[[str], Mapping[str, Any] | None],
    ) -> dict[str, Any]:
        terminal_record: Mapping[str, Any] | None = None
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            record = self._checked(identity, fingerprint, path)
            if record.get("state") != "applying":
                terminal_record = record
            else:
                generation = record.get("owner_generation")
                if isinstance(generation, str) and generation in self._active_generations:
                    _fail("busy")
                owner_pid = record.get("owner_pid")
                if (
                    isinstance(owner_pid, int)
                    and owner_pid != os.getpid()
                    and _pid_is_alive(owner_pid)
                ):
                    _fail("busy")
        if terminal_record is not None:
            terminal = self._terminal_replay(
                identity, fingerprint, path, terminal_record
            )
            if terminal is not None:
                return terminal
            _fail("integrity_error")
        reconciled = reconcile(fingerprint)
        if reconciled is None:
            _fail("invalid_transition")
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            current = self._checked(identity, fingerprint, path)
            if current.get("state") == "applying":
                _atomic_write(
                    path,
                    {**current, "result": dict(reconciled), "state": "effect_complete"},
                    immutable=False,
                )
        return self._complete(identity, fingerprint, path)

    def _terminal_replay(
        self,
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if record.get("state") == "effect_complete":
            return self._complete(identity, fingerprint, path)
        if record.get("state") == "completed":
            result = record.get("result")
            if not isinstance(result, Mapping):
                _fail("integrity_error")
            return dict(result)
        if record.get("state") not in {"prepared", "staged", "applying"}:
            _fail("integrity_error")
        return None

    @staticmethod
    def _checked(
        identity: Mapping[str, Any],
        fingerprint: str,
        path: Path,
    ) -> Mapping[str, Any]:
        record = _read(path)
        if any(record.get(key) != value for key, value in identity.items()):
            _fail("integrity_error")
        if record.get("request_fingerprint") != fingerprint:
            _fail("conflict")
        return record


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


_CONSUMED_GRANT_GUARD = object()


class _ConsumedGrantProof:
    __slots__ = ("_guard", "authorized_by", "grant_id", "operation", "project_id")

    def __init__(
        self,
        guard: object,
        *,
        authorized_by: str,
        grant_id: str,
        operation: str,
        project_id: str,
    ) -> None:
        if guard is not _CONSUMED_GRANT_GUARD:
            raise TypeError("consumed grant proofs are verifier-owned")
        self._guard = guard
        self.authorized_by = authorized_by
        self.grant_id = grant_id
        self.operation = operation
        self.project_id = project_id


def _require_consumed_grant(
    proof: object,
    *,
    grant_id: str,
    operation: str,
    project_id: str,
) -> None:
    if (
        not isinstance(proof, _ConsumedGrantProof)
        or proof._guard is not _CONSUMED_GRANT_GUARD
        or proof.grant_id != grant_id
        or proof.operation != operation
        or proof.project_id != project_id
    ):
        _fail("unauthorized")


class _ExternalGrantRecords:
    """Immutable host-admitted human grants with single-request consumption."""

    def __init__(self, repository: Path, *, custody_root_id: str) -> None:
        if not custody_root_id:
            _fail("invalid_argument")
        self.custody_root_id = custody_root_id
        self.durable_root = repository / ".unrest" / "foundation" / "human-grants"
        self.runtime_root = repository / ".unrest-runtime" / "foundation" / "human-grants"
        self.durable_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def retain(
        self,
        *,
        grant_id: str,
        authorized_by: str,
        issuer_custody_root_id: str,
        issuer_identity_digest: str,
        operation: str,
        project_id: str,
        scope: Mapping[str, Any],
    ) -> None:
        if (
            not grant_id.startswith("human-grant:")
            or not authorized_by
            or not issuer_custody_root_id
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", issuer_identity_digest)
            or not operation
            or not project_id
        ):
            _fail("invalid_argument")
        record = {
            "authorized_by": authorized_by,
            "grant_id": grant_id,
            "issuer_custody_root_id": issuer_custody_root_id,
            "issuer_identity_digest": issuer_identity_digest,
            "operation": operation,
            "project_id": project_id,
            "schema_version": 1,
            "scope": dict(scope),
        }
        token = hashlib.sha256(grant_id.encode("utf-8")).hexdigest()
        with _lock(self.runtime_root / f"{token}.lock"):
            _atomic_write(self.durable_root / f"{token}.json", record, immutable=True)

    def consume(
        self,
        *,
        grant_id: str,
        operation: str,
        project_id: str,
        scope: Mapping[str, Any],
        request_fingerprint: str,
    ) -> _ConsumedGrantProof:
        token = hashlib.sha256(grant_id.encode("utf-8")).hexdigest()
        with _lock(self.runtime_root / f"{token}.lock"):
            grant_path = self.durable_root / f"{token}.json"
            if not grant_path.is_file():
                _fail("unauthorized")
            grant = _read(grant_path)
            if (
                grant.get("grant_id") != grant_id
                or grant.get("operation") != operation
                or grant.get("project_id") != project_id
                or grant.get("scope") != dict(scope)
                or not isinstance(grant.get("authorized_by"), str)
                or not str(grant["authorized_by"])
                or grant.get("issuer_custody_root_id") != self.custody_root_id
                or not re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    str(grant.get("issuer_identity_digest", "")),
                )
            ):
                _fail("unauthorized")
            consumption = self.durable_root / f"{token}.consumed.json"
            if consumption.exists():
                prior = _read(consumption)
                if prior.get("request_fingerprint") != request_fingerprint:
                    _fail("unauthorized")
                return _ConsumedGrantProof(
                    _CONSUMED_GRANT_GUARD,
                    authorized_by=str(grant["authorized_by"]),
                    grant_id=grant_id,
                    operation=operation,
                    project_id=project_id,
                )
            _atomic_write(
                consumption,
                {
                    "grant_id": grant_id,
                    "request_fingerprint": request_fingerprint,
                    "schema_version": 1,
                },
                immutable=True,
            )
            return _ConsumedGrantProof(
                _CONSUMED_GRANT_GUARD,
                authorized_by=str(grant["authorized_by"]),
                grant_id=grant_id,
                operation=operation,
                project_id=project_id,
            )


class ExternalGrantVerifier:
    """Consume-only grant view held by public effect facades."""

    def __init__(self, repository: Path, *, custody_root_id: str) -> None:
        self._records = _ExternalGrantRecords(
            repository,
            custody_root_id=custody_root_id,
        )

    def consume(
        self,
        *,
        grant_id: str,
        operation: str,
        project_id: str,
        scope: Mapping[str, Any],
        request_fingerprint: str,
    ) -> _ConsumedGrantProof:
        return self._records.consume(
            grant_id=grant_id,
            operation=operation,
            project_id=project_id,
            scope=scope,
            request_fingerprint=request_fingerprint,
        )


def _retain_external_grant(
    repository: Path,
    *,
    custody_root_id: str,
    grant_id: str,
    authorized_by: str,
    issuer_custody_root_id: str,
    issuer_identity_digest: str,
    operation: str,
    project_id: str,
    scope: Mapping[str, Any],
) -> None:
    _ExternalGrantRecords(repository, custody_root_id=custody_root_id).retain(
        grant_id=grant_id,
        authorized_by=authorized_by,
        issuer_custody_root_id=issuer_custody_root_id,
        issuer_identity_digest=issuer_identity_digest,
        operation=operation,
        project_id=project_id,
        scope=scope,
    )


__all__ = [
    "DurableMutationJournal",
    "ExternalGrantVerifier",
    "MutationJournalError",
    "request_fingerprint",
]
