"""Recoverable whole-generation filesystem transactions for decision patches.

The journal is deliberately mechanical: callers supply already-rendered bytes.
Recovery therefore never needs to parse a decision report or reconstruct an
operation from mutable product state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal, cast


INTEGRITY_ERROR: Final = "patch_transaction_integrity_error"
UNSUPPORTED_BATCH: Final = "patch_transaction_unsupported_batch"
SCHEMA: Final = "unrest.v045.patch-transaction.v1"
PRECONDITIONS_NAME: Final = "preconditions.json"
INSTALL_ORDER: Final = (
    "task_list",
    "task_state",
    "contract_state",
    "supersession_lineage",
    "mission_seal",
    "project_record",
    "decision_record",
    "attention_cursor",
    "project_state",
)
_INSTALL_INDEX = {kind: index for index, kind in enumerate(INSTALL_ORDER)}
Condition = Literal["absent"] | str
FaultInjector = Callable[[str], None]


class PatchTransactionError(RuntimeError):
    """Stable fail-closed transaction refusal."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TransactionTarget:
    """One allowlisted live target and its exact pre/post image."""

    kind: str
    relative_path: str
    precondition: Condition
    postcondition: Condition
    post_bytes: bytes | None

    @classmethod
    def from_images(
        cls,
        kind: str,
        relative_path: str,
        pre_bytes: bytes | None,
        post_bytes: bytes | None,
    ) -> TransactionTarget:
        return cls(
            kind=kind,
            relative_path=relative_path,
            precondition=_condition(pre_bytes),
            postcondition=_condition(post_bytes),
            post_bytes=post_bytes,
        )


def canonical_json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _condition(body: bytes | None) -> Condition:
    if body is None:
        return "absent"
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _event(injector: FaultInjector | None, label: str) -> None:
    if injector is not None:
        injector(label)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _open_exclusive(path: Path, body: bytes, mode: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short transaction write")
            view = view[written:]
        os.fchmod(descriptor, mode)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _probe_rename_support(project_root: Path) -> None:
    """Probe synthetic files under the cooperative mutation lock.

    Creation descriptors establish file ownership; directory handles are borrowed.
    Named observations detect custody loss, not arbitrary same-UID interference
    after the final observation before a pathname syscall. Without runtime state,
    same-directory admission proves only the basic primitive, not crossdir policy.
    Recovery deliberately does not call this probe or collect its residue.
    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors: list[int] = []
    files: list[int] = []
    directories: list[tuple[int | None, str, os.stat_result]] = []
    names: list[tuple[int, str]] = []

    def identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    def authenticate(parent: int | None, name: str, expected: os.stat_result) -> None:
        actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            identity(actual) != identity(expected)
            or actual.st_mode != expected.st_mode
            or actual.st_uid != expected.st_uid
        ):
            raise OSError("rename probe custody lost")

    def borrow(parent: int | None, name: str, info: os.stat_result) -> int:
        descriptor = os.open(name, directory_flags, dir_fd=parent)
        descriptors.append(descriptor)
        actual = os.fstat(descriptor)
        if not stat.S_ISDIR(actual.st_mode) or identity(actual) != identity(info):
            raise OSError("rename probe directory replaced")
        directories.append((parent, name, info))
        authenticate(parent, name, info)
        return descriptor

    def check_directories() -> None:
        for parent, name, info in directories:
            authenticate(parent, name, info)

    def absent(parent: int, name: str) -> None:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise OSError("rename probe name occupied")

    def file(parent: int, name: str, body: bytes) -> tuple[int, os.stat_result]:
        check_directories()
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent,
        )
        descriptors.append(descriptor)
        files.append(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
        ):
            raise OSError("unsafe rename probe file")
        check_directories()
        authenticate(parent, name, info)
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short rename probe write")
            view = view[written:]
        os.fsync(descriptor)
        check_directories()
        authenticate(parent, name, info)
        os.fsync(parent)
        return descriptor, info

    def move(
        source: int, source_name: str, destination: int, destination_name: str,
        created: tuple[int, os.stat_result], prior: os.stat_result | None, body: bytes,
    ) -> None:
        descriptor, expected = created
        check_directories()
        authenticate(source, source_name, expected)
        if prior is None:
            absent(destination, destination_name)
        else:
            authenticate(destination, destination_name, prior)
        os.replace(source_name, destination_name, src_dir_fd=source, dst_dir_fd=destination)
        check_directories()
        authenticate(destination, destination_name, expected)
        absent(source, source_name)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(body) + 1) != body:
            raise OSError("rename probe bytes differ")
        os.fsync(descriptor)
        os.fsync(source)
        os.fsync(destination)
        check_directories()
        authenticate(destination, destination_name, expected)
        absent(source, source_name)

    try:
        root_info = project_root.lstat()
        root = borrow(None, str(project_root), root_info)
        try:
            runtime_info = os.stat(".unrest-runtime", dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            destination = root
        else:
            if not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_dev != root_info.st_dev:
                raise OSError("unsafe rename probe runtime directory")
            destination = borrow(root, ".unrest-runtime", runtime_info)
        token = ".unrest-rename-probe-" + secrets.token_hex(16)
        source_name, destination_name = token + "-source", token + "-destination"
        names = [(root, source_name), (destination, destination_name)]
        first = file(root, source_name, b"rename-probe-first\n")
        move(root, source_name, destination, destination_name, first, None, b"rename-probe-first\n")
        second = file(root, source_name, b"rename-probe-second\n")
        move(root, source_name, destination, destination_name, second, first[1], b"rename-probe-second\n")
    finally:
        cleanup_error: OSError | None = None
        owned: list[os.stat_result] = []
        for descriptor in files:
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid()
                ):
                    raise OSError("rename probe cleanup custody lost")
                owned.append(info)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        for parent, name in names:
            try:
                check_directories()
                try:
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                expected = next((item for item in owned if identity(item) == identity(info)), None)
                if expected is None:
                    raise OSError("rename probe cleanup custody lost")
                authenticate(parent, name, expected)
                os.unlink(name, dir_fd=parent)
                absent(parent, name)
                os.fsync(parent)
                check_directories()
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        for descriptor in reversed(descriptors):
            try:
                # A failing close may already have released the FD; never retry it.
                os.close(descriptor)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise cleanup_error

class PatchTransaction:
    """Prepare, commit, install, and recover one finite target generation."""

    def __init__(
        self,
        project_root: Path,
        mission_id: str,
        transaction_id: str,
        targets: Iterable[TransactionTarget],
        *,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        if os.name != "posix":
            raise PatchTransactionError(UNSUPPORTED_BATCH)
        try:
            self.project_root = project_root.resolve(strict=True)
        except OSError as exc:
            raise PatchTransactionError(UNSUPPORTED_BATCH) from exc
        self.mission_id = mission_id
        self.transaction_id = transaction_id
        self.targets = tuple(targets)
        self.fault_injector = fault_injector
        self.transactions_root = (
            self.project_root
            / ".unrest-runtime"
            / "missions"
            / mission_id
            / "patch-transactions"
        )
        self.transaction_dir = self.transactions_root / transaction_id
        self.post_images_dir = self.transaction_dir / "post-images"
        self._validate_definition()

    def _validate_definition(self) -> None:
        paths = [target.relative_path for target in self.targets]
        kinds = [target.kind for target in self.targets]
        # New-batch duplicates are unsupported even when count or order is invalid.
        # Recovery remaps constructor refusals to persisted-manifest integrity errors.
        if len(paths) != len(set(paths)) or len(kinds) != len(set(kinds)):
            raise PatchTransactionError(UNSUPPORTED_BATCH)
        if not self.targets or len(self.targets) != len(INSTALL_ORDER):
            raise PatchTransactionError(INTEGRITY_ERROR)
        if tuple(target.kind for target in self.targets) != INSTALL_ORDER:
            raise PatchTransactionError(INTEGRITY_ERROR)
        if not self.mission_id or "/" in self.mission_id:
            raise PatchTransactionError(UNSUPPORTED_BATCH)
        if not self.transaction_id or "/" in self.transaction_id:
            raise PatchTransactionError(UNSUPPORTED_BATCH)
        for target in self.targets:
            if not _target_path_allowed(target.kind, target.relative_path, self.mission_id):
                raise PatchTransactionError(INTEGRITY_ERROR)
            self._live_path(target)
            if target.postcondition != _condition(target.post_bytes):
                raise PatchTransactionError(UNSUPPORTED_BATCH)
            if target.precondition != "absent" and not _is_digest(target.precondition):
                raise PatchTransactionError(UNSUPPORTED_BATCH)
        self._validate_same_filesystem()

    def _live_path(self, target: TransactionTarget) -> Path:
        pure = PurePosixPath(target.relative_path)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != target.relative_path
            or not pure.parts
        ):
            raise PatchTransactionError(INTEGRITY_ERROR)
        path = self.project_root.joinpath(*pure.parts)
        try:
            path.relative_to(self.project_root)
        except ValueError as exc:  # pragma: no cover - lexical guard above
            raise PatchTransactionError(INTEGRITY_ERROR) from exc
        cursor = self.project_root
        for part in pure.parts[:-1]:
            cursor /= part
            try:
                info = cursor.lstat()
            except FileNotFoundError:
                break
            except OSError as exc:
                raise PatchTransactionError(UNSUPPORTED_BATCH) from exc
            if not stat.S_ISDIR(info.st_mode):
                raise PatchTransactionError(UNSUPPORTED_BATCH)
        return path

    def _validate_same_filesystem(self) -> None:
        device = self.project_root.stat().st_dev
        for path in (self.transactions_root, *(self._live_path(t).parent for t in self.targets)):
            ancestor = path
            while not ancestor.exists():
                if ancestor == self.project_root:
                    break
                ancestor = ancestor.parent
            try:
                if ancestor.stat().st_dev != device:
                    raise PatchTransactionError(UNSUPPORTED_BATCH)
            except OSError as exc:
                raise PatchTransactionError(UNSUPPORTED_BATCH) from exc

    def manifest_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "mission_id": self.mission_id,
                "schema": SCHEMA,
                "targets": [
                    {
                        "kind": target.kind,
                        "path": target.relative_path,
                        "post": target.postcondition,
                        "pre": target.precondition,
                    }
                    for target in self.targets
                ],
                "transaction_id": self.transaction_id,
            }
        )

    def execute(self) -> None:
        try:
            self._validate_same_filesystem()
            _probe_rename_support(self.project_root)
        except OSError as exc:
            raise PatchTransactionError(UNSUPPORTED_BATCH) from exc
        try:
            self.prepare()
            if any(self._state(target) != target.precondition for target in self.targets):
                raise PatchTransactionError(INTEGRITY_ERROR)
            self.commit()
            self.install()
            self.finish()
        except OSError as exc:
            code = (
                INTEGRITY_ERROR
                if (self.transaction_dir / "COMMIT").exists()
                else UNSUPPORTED_BATCH
            )
            raise PatchTransactionError(code) from exc

    def prepare(self) -> None:
        _mkdir_private(self.transactions_root)
        _mkdir_private(self.transaction_dir)
        _mkdir_private(self.post_images_dir)
        descriptor = _open_exclusive(
            self.transaction_dir / PRECONDITIONS_NAME, self.manifest_bytes(), 0o600
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.transaction_dir)
        for target in self.targets:
            if target.post_bytes is None:
                continue
            _event(self.fault_injector, f"before_post_image_write:{target.kind}")
            image = self.post_images_dir / target.kind
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(image, flags, 0o700)
            try:
                view = memoryview(target.post_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short transaction write")
                    view = view[written:]
                os.fchmod(descriptor, 0o700)
                _event(self.fault_injector, f"after_post_image_write:{target.kind}")
                _event(self.fault_injector, f"before_post_image_fsync:{target.kind}")
                os.fsync(descriptor)
                _event(self.fault_injector, f"after_post_image_fsync:{target.kind}")
            finally:
                os.close(descriptor)
        _event(self.fault_injector, "before_post_images_directory_fsync")
        _fsync_directory(self.post_images_dir)
        _event(self.fault_injector, "after_post_images_directory_fsync")
        _event(self.fault_injector, "before_manifest_write")
        descriptor = _open_exclusive(
            self.transaction_dir / "manifest.json", self.manifest_bytes(), 0o600
        )
        try:
            _event(self.fault_injector, "after_manifest_write")
            _event(self.fault_injector, "before_manifest_fsync")
            os.fsync(descriptor)
            _event(self.fault_injector, "after_manifest_fsync")
        finally:
            os.close(descriptor)
        _event(self.fault_injector, "before_staging_directory_fsync")
        _fsync_directory(self.transaction_dir)
        _event(self.fault_injector, "after_staging_directory_fsync")

    def commit(self) -> None:
        _event(self.fault_injector, "before_commit_create")
        descriptor = _open_exclusive(self.transaction_dir / "COMMIT", b"", 0o600)
        try:
            _event(self.fault_injector, "after_commit_create")
            _event(self.fault_injector, "before_commit_fsync")
            os.fsync(descriptor)
            _event(self.fault_injector, "after_commit_fsync")
        finally:
            os.close(descriptor)
        _event(self.fault_injector, "before_commit_directory_fsync")
        _fsync_directory(self.transaction_dir)
        _event(self.fault_injector, "after_commit_directory_fsync")

    def install(self) -> None:
        self._validate_staging(committed=True)
        for target in self.targets:
            state = self._state(target)
            if state == target.postcondition:
                continue
            if state != target.precondition:
                raise PatchTransactionError(INTEGRITY_ERROR)
            path = self._live_path(target)
            _safe_private_parents(path.parent, self.project_root)
            _event(self.fault_injector, f"before_target_install:{target.kind}")
            if target.post_bytes is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                os.replace(self.post_images_dir / target.kind, path)
                path.chmod(0o700)
            _event(self.fault_injector, f"after_target_install:{target.kind}")
            _event(self.fault_injector, f"before_target_directory_fsync:{target.kind}")
            _fsync_directory(path.parent)
            _event(self.fault_injector, f"after_target_directory_fsync:{target.kind}")

    def finish(self) -> None:
        if any(self._state(target) != target.postcondition for target in self.targets):
            raise PatchTransactionError(INTEGRITY_ERROR)
        done = self.transaction_dir / "DONE"
        if not done.exists():
            _event(self.fault_injector, "before_done_create")
            descriptor = _open_exclusive(done, b"", 0o600)
            try:
                _event(self.fault_injector, "after_done_create")
                _event(self.fault_injector, "before_done_fsync")
                os.fsync(descriptor)
                _event(self.fault_injector, "after_done_fsync")
            finally:
                os.close(descriptor)
            _event(self.fault_injector, "before_done_directory_fsync")
            _fsync_directory(self.transaction_dir)
            _event(self.fault_injector, "after_done_directory_fsync")
        _event(self.fault_injector, "before_transaction_cleanup")
        shutil.rmtree(self.transaction_dir)
        _fsync_directory(self.transactions_root)
        _event(self.fault_injector, "after_transaction_cleanup")

    def recover(self) -> None:
        if not self.transaction_dir.exists():
            return
        commit = self.transaction_dir / "COMMIT"
        if not commit.exists():
            if any(self._state(target) != target.precondition for target in self.targets):
                raise PatchTransactionError(INTEGRITY_ERROR)
            self._validate_staging(committed=False)
            shutil.rmtree(self.transaction_dir)
            _fsync_directory(self.transactions_root)
            return
        self.install()
        self.finish()

    def _state(self, target: TransactionTarget) -> Condition:
        path = self._live_path(target)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return "absent"
        if not stat.S_ISREG(info.st_mode):
            return "third"
        try:
            return _condition(path.read_bytes())
        except OSError as exc:
            raise PatchTransactionError(INTEGRITY_ERROR) from exc

    def _validate_staging(self, *, committed: bool) -> None:
        _require_private_directory(self.transaction_dir)
        _require_private_directory(self.post_images_dir)
        manifest = self.transaction_dir / "manifest.json"
        _require_file(manifest, 0o600)
        if manifest.read_bytes() != self.manifest_bytes():
            raise PatchTransactionError(INTEGRITY_ERROR)
        for marker in ("COMMIT", "DONE"):
            path = self.transaction_dir / marker
            if path.exists():
                _require_file(path, 0o600)
                if path.read_bytes() != b"":
                    raise PatchTransactionError(INTEGRITY_ERROR)
        if (self.transaction_dir / "DONE").exists() and not (
            self.transaction_dir / "COMMIT"
        ).exists():
            raise PatchTransactionError(INTEGRITY_ERROR)
        if committed and not (self.transaction_dir / "COMMIT").exists():
            raise PatchTransactionError(INTEGRITY_ERROR)
        preconditions = self.transaction_dir / PRECONDITIONS_NAME
        if preconditions.exists():
            _require_file(preconditions, 0o600)
            if preconditions.read_bytes() != self.manifest_bytes():
                raise PatchTransactionError(INTEGRITY_ERROR)
        allowed = {
            PRECONDITIONS_NAME,
            "manifest.json",
            "post-images",
            "COMMIT",
            "DONE",
        }
        if {entry.name for entry in self.transaction_dir.iterdir()} - allowed:
            raise PatchTransactionError(INTEGRITY_ERROR)
        image_names = {entry.name for entry in self.post_images_dir.iterdir()}
        expected_image_names = {
            target.kind for target in self.targets if target.post_bytes is not None
        }
        if image_names - expected_image_names:
            raise PatchTransactionError(INTEGRITY_ERROR)
        for target in self.targets:
            image = self.post_images_dir / target.kind
            if target.post_bytes is None or self._state(target) == target.postcondition:
                if image.exists() and target.post_bytes is None:
                    raise PatchTransactionError(INTEGRITY_ERROR)
                continue
            _require_file(image, 0o700)
            if image.read_bytes() != target.post_bytes:
                raise PatchTransactionError(INTEGRITY_ERROR)


def recover_patch_transactions(project_root: Path) -> None:
    """Recover every mission journal before a project is read or mutated."""
    try:
        _recover_patch_transactions(project_root)
    except PatchTransactionError:
        raise
    except OSError as exc:
        raise PatchTransactionError(INTEGRITY_ERROR) from exc


def _recover_patch_transactions(project_root: Path) -> None:
    runtime_missions = project_root / ".unrest-runtime" / "missions"
    if not runtime_missions.exists():
        return
    committed_count = 0
    pending: list[tuple[Path, dict[str, object]]] = []
    for mission_dir in sorted(runtime_missions.iterdir(), key=lambda path: path.name):
        if mission_dir.is_symlink() or not mission_dir.is_dir():
            raise PatchTransactionError(INTEGRITY_ERROR)
        tx_root = mission_dir / "patch-transactions"
        if not tx_root.exists():
            continue
        _require_private_directory(tx_root)
        for tx_dir in sorted(tx_root.iterdir(), key=lambda path: path.name):
            if tx_dir.is_symlink() or not tx_dir.is_dir():
                raise PatchTransactionError(INTEGRITY_ERROR)
            manifest_path = tx_dir / "manifest.json"
            if not manifest_path.exists():
                _discard_incomplete_uncommitted(project_root, tx_dir, tx_root)
                continue
            committed = (tx_dir / "COMMIT").exists()
            payload = _load_manifest(manifest_path)
            if committed:
                committed_count += 1
            pending.append((tx_dir, payload))
    if committed_count > 1:
        raise PatchTransactionError(INTEGRITY_ERROR)
    for tx_dir, payload in pending:
        try:
            transaction = PatchTransaction(
                project_root,
                str(payload["mission_id"]),
                str(payload["transaction_id"]),
                _targets_from_manifest(
                    project_root, tx_dir, cast(list[object], payload["targets"])
                ),
            )
        except PatchTransactionError as exc:
            raise PatchTransactionError(INTEGRITY_ERROR) from exc
        if transaction.transaction_dir != tx_dir:
            raise PatchTransactionError(INTEGRITY_ERROR)
        transaction.recover()


def _load_manifest(path: Path) -> dict[str, object]:
    _require_file(path, 0o600)
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PatchTransactionError(INTEGRITY_ERROR) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "transaction_id", "mission_id", "targets"
    }:
        raise PatchTransactionError(INTEGRITY_ERROR)
    if payload.get("schema") != SCHEMA or canonical_json_bytes(payload) != raw:
        raise PatchTransactionError(INTEGRITY_ERROR)
    if not isinstance(payload.get("targets"), list):
        raise PatchTransactionError(INTEGRITY_ERROR)
    return cast(dict[str, object], payload)


def _targets_from_manifest(
    project_root: Path, tx_dir: Path, rows: list[object]
) -> tuple[TransactionTarget, ...]:
    targets: list[TransactionTarget] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"kind", "path", "pre", "post"}:
            raise PatchTransactionError(INTEGRITY_ERROR)
        kind, relative = row.get("kind"), row.get("path")
        pre, post = row.get("pre"), row.get("post")
        if not all(isinstance(value, str) for value in (kind, relative, pre, post)):
            raise PatchTransactionError(INTEGRITY_ERROR)
        post_bytes: bytes | None
        if post == "absent":
            post_bytes = None
        else:
            image = tx_dir / "post-images" / cast(str, kind)
            live = project_root.joinpath(*PurePosixPath(cast(str, relative)).parts)
            if image.is_file() and not image.is_symlink():
                post_bytes = image.read_bytes()
            elif live.is_file() and not live.is_symlink() and _condition(live.read_bytes()) == post:
                post_bytes = live.read_bytes()
            else:
                raise PatchTransactionError(INTEGRITY_ERROR)
        if _condition(post_bytes) != post:
            raise PatchTransactionError(INTEGRITY_ERROR)
        targets.append(
            TransactionTarget(
                cast(str, kind),
                cast(str, relative),
                cast(str, pre),
                cast(str, post),
                post_bytes,
            )
        )
    if tuple(target.kind for target in targets) != INSTALL_ORDER:
        raise PatchTransactionError(INTEGRITY_ERROR)
    # The caller replaces post_bytes from the transaction's post-images after
    # construction; keep parsing centralized in recover_patch_transactions.
    return tuple(targets)


def _discard_incomplete_uncommitted(
    project_root: Path, tx_dir: Path, tx_root: Path
) -> None:
    if (tx_dir / "COMMIT").exists() or (tx_dir / "DONE").exists():
        raise PatchTransactionError(INTEGRITY_ERROR)
    _require_private_directory(tx_dir)
    preconditions_path = tx_dir / PRECONDITIONS_NAME
    if not preconditions_path.exists():
        raise PatchTransactionError(INTEGRITY_ERROR)
    payload = _load_manifest(preconditions_path)
    if (
        payload["transaction_id"] != tx_dir.name
        or payload["mission_id"] != tx_root.parent.name
    ):
        raise PatchTransactionError(INTEGRITY_ERROR)
    allowed = {PRECONDITIONS_NAME, "post-images"}
    if {entry.name for entry in tx_dir.iterdir()} - allowed:
        raise PatchTransactionError(INTEGRITY_ERROR)
    post_images = tx_dir / "post-images"
    _require_private_directory(post_images)
    rows = cast(list[object], payload["targets"])
    if len(rows) != len(INSTALL_ORDER):
        raise PatchTransactionError(INTEGRITY_ERROR)
    paths: set[str] = set()
    expected_images: set[str] = set()
    for expected_kind, row in zip(INSTALL_ORDER, rows, strict=True):
        if not isinstance(row, dict) or set(row) != {"kind", "path", "pre", "post"}:
            raise PatchTransactionError(INTEGRITY_ERROR)
        kind, relative = row.get("kind"), row.get("path")
        pre, post = row.get("pre"), row.get("post")
        if not all(isinstance(value, str) for value in (kind, relative, pre, post)):
            raise PatchTransactionError(INTEGRITY_ERROR)
        kind = cast(str, kind)
        relative = cast(str, relative)
        pre = cast(str, pre)
        post = cast(str, post)
        if (
            kind != expected_kind
            or relative in paths
            or not _target_path_allowed(kind, relative, cast(str, payload["mission_id"]))
            or (pre != "absent" and not _is_digest(pre))
            or (post != "absent" and not _is_digest(post))
        ):
            raise PatchTransactionError(INTEGRITY_ERROR)
        paths.add(relative)
        if post != "absent":
            expected_images.add(kind)
        if _live_state(project_root, relative) != pre:
            raise PatchTransactionError(INTEGRITY_ERROR)
    for entry in post_images.iterdir():
        if entry.name not in expected_images:
            raise PatchTransactionError(INTEGRITY_ERROR)
        _require_file(entry, 0o700)
        row = cast(dict[str, str], rows[_INSTALL_INDEX[entry.name]])
        if _condition(entry.read_bytes()) != row["post"]:
            raise PatchTransactionError(INTEGRITY_ERROR)
    shutil.rmtree(tx_dir)
    _fsync_directory(tx_root)


def _live_state(project_root: Path, relative_path: str) -> Condition:
    pure = PurePosixPath(relative_path)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != relative_path
        or not pure.parts
    ):
        raise PatchTransactionError(INTEGRITY_ERROR)
    path = project_root.joinpath(*pure.parts)
    cursor = project_root
    for part in pure.parts[:-1]:
        cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            return "absent"
        if not stat.S_ISDIR(info.st_mode):
            raise PatchTransactionError(INTEGRITY_ERROR)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    if not stat.S_ISREG(info.st_mode):
        raise PatchTransactionError(INTEGRITY_ERROR)
    return _condition(path.read_bytes())


def _require_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PatchTransactionError(INTEGRITY_ERROR) from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise PatchTransactionError(INTEGRITY_ERROR)


def _require_file(path: Path, mode: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PatchTransactionError(INTEGRITY_ERROR) from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
        raise PatchTransactionError(INTEGRITY_ERROR)


def _safe_private_parents(parent: Path, root: Path) -> None:
    missing: list[Path] = []
    cursor = parent
    while not cursor.exists() and cursor != root:
        missing.append(cursor)
        cursor = cursor.parent
    try:
        relative = cursor.relative_to(root)
    except ValueError as exc:
        raise PatchTransactionError(INTEGRITY_ERROR) from exc
    checked = root
    for part in relative.parts:
        checked /= part
        info = checked.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise PatchTransactionError(INTEGRITY_ERROR)
    for path in reversed(missing):
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        _fsync_directory(path.parent)


def _is_digest(value: str) -> bool:
    if not value.startswith("sha256:") or len(value) != 71:
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _target_path_allowed(kind: str, relative_path: str, mission_id: str) -> bool:
    exact = {
        "task_list": f".unrest-runtime/missions/{mission_id}/tasks.json",
        "task_state": f".unrest-runtime/missions/{mission_id}/task-state.json",
        "contract_state": (
            f".unrest-runtime/missions/{mission_id}/contract-state.json"
        ),
        "supersession_lineage": (
            f".unrest/missions/{mission_id}/supersession-lineage.json"
        ),
        "mission_seal": f".unrest/missions/{mission_id}/closeout.md",
        "project_record": ".unrest-runtime/project.json",
        "attention_cursor": ".unrest-runtime/attention.json",
        "project_state": ".unrest-runtime/state.json",
    }
    if kind == "decision_record":
        return re.fullmatch(r"\.unrest/decisions/[0-9]+-[a-z0-9-]+\.md", relative_path) is not None
    return exact.get(kind) == relative_path


__all__ = [
    "INSTALL_ORDER",
    "INTEGRITY_ERROR",
    "PatchTransaction",
    "PatchTransactionError",
    "TransactionTarget",
    "UNSUPPORTED_BATCH",
    "canonical_json_bytes",
    "recover_patch_transactions",
]
