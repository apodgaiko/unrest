"""Durable idempotency and externally issued grant custody for v0.3.1.

The journal is deliberately below the public tool facade.  It records the
complete canonical request before dispatch, so a reused key cannot reach a
manager event or a repository effect.  Human grants are separate immutable
records admitted by the host/controller and consumed by exact request
fingerprint; an effect adapter cannot manufacture its own authority.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, BinaryIO, Iterator, NoReturn

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
    """Execute public mutations once for one canonical request."""

    def __init__(self, repository: Path) -> None:
        self.durable_root = repository / ".unrest" / "foundation" / "public-mutations"
        self.runtime_root = repository / ".unrest-runtime" / "foundation" / "public-mutations"
        self.durable_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def execute(
        self,
        *,
        operation: str,
        resource_key: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        effect: Callable[[str], Mapping[str, Any]],
    ) -> dict[str, Any]:
        identity, fingerprint, path = self._identity(
            operation, resource_key, idempotency_key, request
        )
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            replay = self._prepare(identity, fingerprint, path)
            if replay is not None:
                return replay
            result = dict(effect(fingerprint))
            _atomic_write(
                path,
                {
                    **identity,
                    "request_fingerprint": fingerprint,
                    "result": result,
                    "schema_version": 1,
                    "state": "completed",
                },
                immutable=False,
            )
            return result

    async def execute_async(
        self,
        *,
        operation: str,
        resource_key: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        effect: Callable[[str], Awaitable[Mapping[str, Any]]],
    ) -> dict[str, Any]:
        identity, fingerprint, path = self._identity(
            operation, resource_key, idempotency_key, request
        )
        with _lock(self.runtime_root / f"{path.stem}.lock"):
            replay = self._prepare(identity, fingerprint, path)
            if replay is not None:
                return replay
            result = dict(await effect(fingerprint))
            _atomic_write(
                path,
                {
                    **identity,
                    "request_fingerprint": fingerprint,
                    "result": result,
                    "schema_version": 1,
                    "state": "completed",
                },
                immutable=False,
            )
            return result

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

    @staticmethod
    def _prepare(
        identity: Mapping[str, Any], fingerprint: str, path: Path
    ) -> dict[str, Any] | None:
        if path.exists():
            record = _read(path)
            if any(record.get(key) != value for key, value in identity.items()):
                _fail("integrity_error")
            if record.get("request_fingerprint") != fingerprint:
                _fail("conflict")
            if record.get("state") == "completed" and isinstance(record.get("result"), Mapping):
                return dict(record["result"])
            if record.get("state") != "prepared":
                _fail("integrity_error")
            return None
        _atomic_write(
            path,
            {
                **identity,
                "request_fingerprint": fingerprint,
                "schema_version": 1,
                "state": "prepared",
            },
            immutable=True,
        )
        return None


class ExternalGrantStore:
    """Immutable host-admitted human grants with single-request consumption."""

    def __init__(self, repository: Path) -> None:
        self.durable_root = repository / ".unrest" / "foundation" / "human-grants"
        self.runtime_root = repository / ".unrest-runtime" / "foundation" / "human-grants"
        self.durable_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def retain(
        self,
        *,
        grant_id: str,
        authorized_by: str,
        operation: str,
        project_id: str,
        scope: Mapping[str, Any],
    ) -> None:
        if (
            not grant_id.startswith("human-grant:")
            or not authorized_by.startswith("human:")
            or not operation
            or not project_id
        ):
            _fail("invalid_argument")
        record = {
            "authorized_by": authorized_by,
            "grant_id": grant_id,
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
    ) -> str:
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
                or not str(grant["authorized_by"]).startswith("human:")
            ):
                _fail("unauthorized")
            consumption = self.durable_root / f"{token}.consumed.json"
            if consumption.exists():
                prior = _read(consumption)
                if prior.get("request_fingerprint") != request_fingerprint:
                    _fail("unauthorized")
                return str(grant["authorized_by"])
            _atomic_write(
                consumption,
                {
                    "grant_id": grant_id,
                    "request_fingerprint": request_fingerprint,
                    "schema_version": 1,
                },
                immutable=True,
            )
            return str(grant["authorized_by"])


__all__ = [
    "DurableMutationJournal",
    "ExternalGrantStore",
    "MutationJournalError",
    "request_fingerprint",
]
