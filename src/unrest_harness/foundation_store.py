"""Append-only local custody for canonical identities and receipts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

from .canonical_identity import (
    FoundationValidationError,
    IdentityRecord,
    canonical_json_bytes,
    verify_canonical_json_bytes,
    verify_identity,
)
from .receipts import ReceiptExport, ReceiptRecord, export_receipt, verify_receipt


_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]*$")
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_CUSTODY_PREFIX = b"unrest.local-custody.v1\0"


@dataclass(frozen=True)
class CustodyActor:
    actor_id: str
    authority_class: str
    decision_ref: str


@dataclass(frozen=True)
class CustodyEntry:
    sequence: int
    custody_digest: str
    record_kind: str
    record_digest: str
    canonical_bytes: bytes


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FoundationStore:
    """Store immutable records below one project-local custody root.

    Durable identities, receipts, and custody entries live in ``.unrest``.
    The replaceable derived head cursor lives in ``.unrest-runtime`` and is
    never consulted as authority.
    """

    def __init__(self, project_root: str | Path, *, custody_root_id: str) -> None:
        if not custody_root_id or not custody_root_id.isascii():
            raise FoundationValidationError("invalid_argument", "$.custody_root_id")
        self.project_root = Path(os.path.abspath(os.fspath(project_root)))
        self.custody_root_id = custody_root_id
        self.durable_root = self.project_root / ".unrest" / "foundation"
        self.runtime_root = self.project_root / ".unrest-runtime" / "foundation"
        self.identity_root = self.durable_root / "identities"
        self.receipt_root = self.durable_root / "receipts"
        self.custody_root = self.durable_root / "custody"
        self._initialize()

    def _initialize(self) -> None:
        try:
            root_stat = self.project_root.lstat()
        except FileNotFoundError as exc:
            raise FoundationValidationError("not_found", "$.project_root") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise FoundationValidationError("invalid_argument", "$.project_root")
        for directory in (
            self.durable_root,
            self.runtime_root,
            self.identity_root,
            self.receipt_root,
            self.custody_root,
        ):
            self._ensure_directory(directory)
        root_record = {
            "custody_root_id": self.custody_root_id,
            "schema_version": 1,
        }
        try:
            self._append_exact(
                self.durable_root / "custody-root.json", canonical_json_bytes(root_record)
            )
        except FoundationValidationError as exc:
            if exc.code == "immutable_conflict":
                raise FoundationValidationError(
                    "custody_root_mismatch", "$.custody_root_id"
                ) from exc
            raise
        stored = verify_canonical_json_bytes(
            self._read_regular(self.durable_root / "custody-root.json", "$.custody_root")
        )
        if not isinstance(stored, Mapping) or stored != root_record:
            raise FoundationValidationError("custody_root_mismatch", "$.custody_root_id")

    def _ensure_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.project_root)
        except ValueError as exc:
            raise FoundationValidationError("invalid_path") from exc
        current = self.project_root
        for part in relative.parts:
            current /= part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            current_stat = current.lstat()
            if not stat.S_ISDIR(current_stat.st_mode):
                raise FoundationValidationError("invalid_path")

    def _append_exact(self, path: Path, content: bytes) -> None:
        self._ensure_directory(path.parent)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".append-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written == 0:
                    raise OSError("short append-only write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(temporary, path)
            except FileExistsError:
                try:
                    existing_stat = path.lstat()
                    if not stat.S_ISREG(existing_stat.st_mode):
                        raise FoundationValidationError("immutable_conflict")
                    existing = path.read_bytes()
                except OSError as exc:
                    raise FoundationValidationError("immutable_conflict") from exc
                if existing != content:
                    raise FoundationValidationError("immutable_conflict")
            _fsync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _safe_kind(kind: str) -> str:
        if _SAFE_NAME.fullmatch(kind) is None:
            raise FoundationValidationError("invalid_argument", "$.kind")
        return kind

    @staticmethod
    def _digest_hex(digest: str) -> str:
        match = _DIGEST.fullmatch(digest)
        if match is None:
            raise FoundationValidationError("invalid_argument", "$.digest")
        return match.group(1)

    @staticmethod
    def _read_regular(path: Path, public_path: str) -> bytes:
        try:
            path_stat = path.lstat()
            if not stat.S_ISREG(path_stat.st_mode):
                raise FoundationValidationError("integrity_error", public_path)
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise FoundationValidationError("not_found", public_path) from exc

    def append_identity(self, identity: IdentityRecord) -> Path:
        checked = verify_identity(identity.kind, identity.canonical_bytes, identity.digest)
        path = (
            self.identity_root
            / self._safe_kind(checked.kind)
            / f"{self._digest_hex(checked.digest)}.json"
        )
        self._append_exact(path, checked.canonical_bytes)
        return path

    def load_identity(self, kind: str, digest: str) -> IdentityRecord:
        path = self.identity_root / self._safe_kind(kind) / f"{self._digest_hex(digest)}.json"
        content = self._read_regular(path, "$.identity")
        return verify_identity(kind, content, digest)

    def append_receipt(self, receipt: ReceiptRecord, *, custodian: CustodyActor) -> Path:
        checked = verify_receipt(receipt.canonical_bytes, receipt.digest)
        issuer = checked.record["issuer"]
        authority = checked.record["issuer_authority"]
        if (
            custodian.actor_id != issuer["issuer_id"]
            or custodian.authority_class != authority["authority_class"]
            or custodian.decision_ref != authority["decision_ref"]
        ):
            raise FoundationValidationError("unauthorized", "$.custodian")
        path = (
            self.receipt_root
            / self._safe_kind(checked.family)
            / f"{self._digest_hex(checked.digest)}.json"
        )
        self._append_exact(path, checked.canonical_bytes)
        if not self.has_local_custody(checked.digest):
            self._append_custody(checked, custodian)
        return path

    def load_receipt(self, family: str, digest: str) -> ReceiptRecord:
        path = self.receipt_root / self._safe_kind(family) / f"{self._digest_hex(digest)}.json"
        content = self._read_regular(path, "$.receipt")
        record = verify_receipt(content, digest)
        if record.family != family:
            raise FoundationValidationError("digest_mismatch", "$.receipt_kind")
        return record

    @staticmethod
    def _custody_digest(record_without_digest: Mapping[str, Any]) -> str:
        preimage = _CUSTODY_PREFIX + canonical_json_bytes(record_without_digest)
        return "sha256:" + hashlib.sha256(preimage).hexdigest()

    def _append_custody(self, receipt: ReceiptRecord, custodian: CustodyActor) -> CustodyEntry:
        for _ in range(100):
            entries = self.verify_custody_chain()
            sequence = entries[-1].sequence + 1 if entries else 1
            predecessor: Mapping[str, Any]
            if entries:
                predecessor = {"state": "present", "value": entries[-1].custody_digest}
            else:
                predecessor = {"state": "absent"}
            record: dict[str, Any] = {
                "custodian": {
                    "actor_id": custodian.actor_id,
                    "authority_class": custodian.authority_class,
                    "decision_ref": custodian.decision_ref,
                },
                "custody_root_id": self.custody_root_id,
                "previous_custody_digest": predecessor,
                "record_digest": receipt.digest,
                "record_kind": receipt.family,
                "record_type": "receipt",
                "schema_version": 1,
                "sequence": sequence,
            }
            digest = self._custody_digest(record)
            record["custody_digest"] = digest
            encoded = canonical_json_bytes(record)
            # The sequence-only destination is the compare-and-set boundary:
            # two writers cannot both append a different entry at one index.
            path = self.custody_root / f"{sequence:020d}.json"
            try:
                self._append_exact(path, encoded)
            except FoundationValidationError as exc:
                if exc.code == "immutable_conflict":
                    continue
                raise
            self._write_runtime_head(sequence, digest)
            return CustodyEntry(sequence, digest, receipt.family, receipt.digest, encoded)
        raise FoundationValidationError("busy", "$.custody")

    def _write_runtime_head(self, sequence: int, digest: str) -> None:
        content = canonical_json_bytes(
            {"custody_digest": digest, "schema_version": 1, "sequence": sequence}
        )
        descriptor, temporary_name = tempfile.mkstemp(prefix=".head-", dir=self.runtime_root)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written == 0:
                    raise OSError("short runtime cursor write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.runtime_root / "custody-head.json")
        _fsync_directory(self.runtime_root)

    def verify_custody_chain(self) -> tuple[CustodyEntry, ...]:
        entries: list[CustodyEntry] = []
        predecessor: str | None = None
        files = sorted(self.custody_root.glob("*.json"))
        for expected_sequence, path in enumerate(files, start=1):
            custody_bytes = self._read_regular(path, "$.custody")
            parsed = verify_canonical_json_bytes(custody_bytes)
            if not isinstance(parsed, Mapping):
                raise FoundationValidationError("integrity_error", "$.custody")
            required = {
                "custodian", "custody_digest", "custody_root_id", "previous_custody_digest",
                "record_digest", "record_kind", "record_type", "schema_version", "sequence",
            }
            if set(parsed) != required:
                raise FoundationValidationError("integrity_error", "$.custody")
            if (
                parsed["schema_version"] != 1
                or parsed["record_type"] != "receipt"
                or parsed["custody_root_id"] != self.custody_root_id
                or parsed["sequence"] != expected_sequence
            ):
                raise FoundationValidationError("custody_root_mismatch", "$.custody")
            previous = parsed["previous_custody_digest"]
            expected_previous: Mapping[str, Any] = (
                {"state": "absent"}
                if predecessor is None
                else {"state": "present", "value": predecessor}
            )
            if previous != expected_previous:
                raise FoundationValidationError("integrity_error", "$.custody")
            body = dict(parsed)
            supplied_digest = body.pop("custody_digest")
            computed = self._custody_digest(body)
            if supplied_digest != computed:
                raise FoundationValidationError("integrity_error", "$.custody")
            record_kind = str(parsed["record_kind"])
            record_digest = str(parsed["record_digest"])
            receipt_path = self.receipt_root / self._safe_kind(record_kind) / f"{self._digest_hex(record_digest)}.json"
            try:
                receipt = verify_receipt(
                    self._read_regular(receipt_path, "$.custody"), record_digest
                )
            except (OSError, FoundationValidationError) as exc:
                raise FoundationValidationError("integrity_error", "$.custody") from exc
            custodian = parsed["custodian"]
            if not isinstance(custodian, Mapping) or set(custodian) != {
                "actor_id", "authority_class", "decision_ref"
            }:
                raise FoundationValidationError("integrity_error", "$.custody")
            if (
                custodian["actor_id"] != receipt.record["issuer"]["issuer_id"]
                or custodian["authority_class"]
                != receipt.record["issuer_authority"]["authority_class"]
                or custodian["decision_ref"]
                != receipt.record["issuer_authority"]["decision_ref"]
            ):
                raise FoundationValidationError("unauthorized", "$.custody")
            predecessor = computed
            entries.append(
                CustodyEntry(expected_sequence, computed, record_kind, record_digest, custody_bytes)
            )
        return tuple(entries)

    def has_local_custody(self, receipt_digest: str) -> bool:
        self._digest_hex(receipt_digest)
        return any(
            entry.record_digest == receipt_digest
            for entry in self.verify_custody_chain()
        )

    def export_receipt(
        self,
        family: str,
        digest: str,
        *,
        consumer_id: str,
        authoritative: bool,
    ) -> ReceiptExport:
        receipt = self.load_receipt(family, digest)
        return export_receipt(
            receipt,
            consumer_id=consumer_id,
            authoritative=authoritative,
            local_custody_verified=self.has_local_custody(digest),
        )

    def list_identity_digests(self, kind: str) -> tuple[str, ...]:
        directory = self.identity_root / self._safe_kind(kind)
        if not directory.exists():
            return ()
        return tuple(f"sha256:{path.stem}" for path in sorted(directory.glob("*.json")))

    def list_receipt_digests(self, family: str) -> tuple[str, ...]:
        directory = self.receipt_root / self._safe_kind(family)
        if not directory.exists():
            return ()
        return tuple(f"sha256:{path.stem}" for path in sorted(directory.glob("*.json")))


__all__ = ["CustodyActor", "CustodyEntry", "FoundationStore"]
