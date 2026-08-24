"""T1 Git-worktree leases and parent-authorized patch integration.

This module provides Git separation, not an OS sandbox.  A lease owns one
detached worktree, an exact base revision, and a finite set of repository write
paths.  Durable events and artifacts live below ``.unrest``; replaceable locks
and worktrees live below ``.unrest-runtime``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterator, Literal
import uuid

from .accepted_point_authority import (
    AcceptedPointAuthorityError,
    _AcceptedPointCapability,
    _require_accepted_point_capability,
)
from .canonical_identity import (
    canonical_json_bytes,
    construct_identity,
    verify_canonical_json_bytes,
)
from .foundation_store import CustodyActor, FoundationStore
from .receipts import ReceiptRecord, construct_receipt, load_receipt_catalog


_REVISION = re.compile(r"^[0-9a-f]{40}$")
_LEASE_ID = re.compile(r"^lease:[a-z0-9-]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROTECTED = (".git", ".unrest", ".unrest-runtime")


class WorkspaceError(RuntimeError):
    """Typed public failure that never includes patch or source content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ResourceBudget:
    max_processes: int = 0
    max_patch_bytes: int = 10_000_000


@dataclass(frozen=True)
class FileInventoryEntry:
    path: str
    status: str
    object_kind: Literal["file", "symlink", "deleted"]
    content_digest: str
    size_bytes: int


@dataclass(frozen=True)
class WorkspaceLease:
    lease_id: str
    lease_identity_digest: str
    base_revision: str
    parent_ref: str
    worktree_path: str
    owner_id: str
    declared_write_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    capability_policy_digest: str
    expires_at: str
    isolation_level: Literal["T1_git_worktree_only"]
    resource_budget: ResourceBudget
    state: str
    sequence: int
    workspace_receipt_digest: str
    patch_digest: str | None = None
    patch_receipt_digest: str | None = None
    candidate_identity_digest: str | None = None
    returned_inventory: tuple[FileInventoryEntry, ...] = ()
    cleanup_receipt_digest: str | None = None
    integration_receipt_digest: str | None = None
    integration_grant_id: str | None = None
    integration_request_fingerprint: str | None = None
    terminal_reason: str | None = None


@dataclass(frozen=True)
class WorkspaceReturn:
    lease_id: str
    outcome: str
    patch_digest: str | None
    patch_path: str | None
    inventory: tuple[FileInventoryEntry, ...]
    patch_receipt_digest: str | None


@dataclass(frozen=True)
class HumanIntegrationGrant:
    grant_id: str
    authorized_by: str
    lease_id: str
    patch_digest: str
    expected_parent_revision: str


@dataclass(frozen=True)
class IntegrationResult:
    predecessor: str
    accepted_revision: str
    ordered_patches: tuple[tuple[str, str], ...]
    receipt_digests: tuple[str, ...]


@dataclass(frozen=True)
class CleanupResult:
    lease_id: str
    outcome: Literal["released", "quarantined", "cleanup_failed", "unsettled"]
    receipt_digest: str


@dataclass(frozen=True)
class OwnedProcess:
    pid: int
    process_group_id: int
    start_token_digest: str
    command_digest: str


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise WorkspaceError("invalid_expiry") from exc
    return parsed.astimezone(UTC)


def _normalize_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise WorkspaceError("invalid_write_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WorkspaceError("invalid_write_path")
    normalized = path.as_posix()
    if normalized == ".":
        raise WorkspaceError("invalid_write_path")
    return normalized


def _contains(root: str, path: str) -> bool:
    return path == root or path.startswith(root + "/")


def _overlap(left: str, right: str) -> bool:
    return _contains(left, right) or _contains(right, left)


class WorkspaceManager:
    """Manage one repository's finite T1 workspace leases."""

    def __init__(
        self,
        repository: str | Path,
        *,
        custody_root_id: str = "workspace-manager:local",
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.repository = Path(repository).resolve(strict=True)
        self._now = now
        self._live_processes: dict[int, subprocess.Popen[bytes]] = {}
        self._assert_repository()
        self.store = FoundationStore(self.repository, custody_root_id=custody_root_id)
        self.durable_root = self.repository / ".unrest" / "workspaces"
        self.runtime_root = self.repository / ".unrest-runtime" / "workspaces"
        self.events_root = self.durable_root / "leases"
        self.artifact_root = self.durable_root / "patches"
        self.tree_root = self.runtime_root / "trees"
        self.process_root = self.runtime_root / "processes"
        for directory in (self.events_root, self.artifact_root, self.tree_root, self.process_root):
            directory.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.runtime_root / "manager.lock"

    def _assert_repository(self) -> None:
        if self._git("rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
            raise WorkspaceError("not_git_repository")
        top = Path(self._git("rev-parse", "--show-toplevel").stdout.strip()).resolve()
        if top != self.repository:
            raise WorkspaceError("repository_root_required")

    def _git(
        self,
        *arguments: str,
        cwd: Path | None = None,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", *arguments],
                cwd=cwd or self.repository,
                check=check,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env=dict(env) if env is not None else None,
            )
        except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
            raise WorkspaceError("git_operation_failed") from exc

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _clean_parent(self) -> bool:
        output = self._git("status", "--porcelain=v1", "--untracked-files=all").stdout
        for line in output.splitlines():
            candidate = line[3:] if len(line) >= 4 else line
            if not any(_contains(root, candidate) for root in (".unrest", ".unrest-runtime")):
                return False
        return True

    def _validate_declared_paths(
        self, declared: Sequence[str], protected: Sequence[str]
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        normalized = tuple(sorted(_normalize_path(item) for item in declared))
        if not normalized or len(set(normalized)) != len(normalized):
            raise WorkspaceError("invalid_write_path")
        if any(_overlap(left, right) for index, left in enumerate(normalized) for right in normalized[index + 1 :]):
            raise WorkspaceError("overlapping_write_paths")
        protected_paths = tuple(sorted(set(_PROTECTED + tuple(_normalize_path(item) for item in protected))))
        if any(_overlap(write, blocked) for write in normalized for blocked in protected_paths):
            raise WorkspaceError("protected_write_path")
        return normalized, protected_paths

    def lease_workspace(
        self,
        *,
        base_revision: str,
        owner_id: str,
        declared_write_paths: Sequence[str],
        capability_policy_digest: str,
        duration_seconds: int,
        lease_id: str | None = None,
        protected_paths: Sequence[str] = (),
        resource_budget: ResourceBudget = ResourceBudget(),
    ) -> WorkspaceLease:
        """Allocate one detached worktree from an exact commit."""

        lease_id = lease_id or "lease:" + uuid.uuid4().hex
        if _LEASE_ID.fullmatch(lease_id) is None or not owner_id:
            raise WorkspaceError("invalid_lease")
        if _REVISION.fullmatch(base_revision) is None:
            raise WorkspaceError("exact_base_revision_required")
        if _DIGEST.fullmatch(capability_policy_digest) is None:
            raise WorkspaceError("invalid_policy_digest")
        if (
            isinstance(duration_seconds, bool)
            or duration_seconds <= 0
            or duration_seconds > 31_536_000
            or isinstance(resource_budget.max_processes, bool)
            or resource_budget.max_processes < 0
            or isinstance(resource_budget.max_patch_bytes, bool)
            or resource_budget.max_patch_bytes <= 0
        ):
            raise WorkspaceError("invalid_resource_budget")
        declared, protected = self._validate_declared_paths(declared_write_paths, protected_paths)
        with self._locked():
            if self._event_directory(lease_id).exists():
                raise WorkspaceError("duplicate_lease")
            if not self._clean_parent():
                raise WorkspaceError("dirty_parent")
            resolved = self._git("rev-parse", "--verify", f"{base_revision}^{{commit}}").stdout.strip()
            if resolved != base_revision:
                raise WorkspaceError("base_not_found")
            parent_revision = self._git("rev-parse", "HEAD").stdout.strip()
            if parent_revision != base_revision:
                raise WorkspaceError("stale_base")
            parent_ref = self._git("symbolic-ref", "--quiet", "HEAD").stdout.strip()
            worktree = self.tree_root / lease_id.removeprefix("lease:")
            if worktree.exists():
                raise WorkspaceError("workspace_path_collision")
            try:
                self._git("worktree", "add", "--detach", "--no-checkout", str(worktree), base_revision)
                self._git("checkout", "--detach", base_revision, cwd=worktree)
            except WorkspaceError:
                shutil.rmtree(worktree, ignore_errors=True)
                raise
            expires = self._now() + timedelta(seconds=duration_seconds)
            lease_identity = construct_identity(
                "workspace_lease",
                {
                    "base_revision": base_revision,
                    "capability_policy_digest": capability_policy_digest,
                    "public_id": "workspace_lease:" + lease_id.removeprefix("lease:"),
                    "schema_version": 1,
                    "workspace_lease_id": lease_id,
                },
            )
            self.store.append_identity(lease_identity)
            dependency_digests = self._foundation_identities(base_revision, capability_policy_digest, lease_identity)
            receipt = self._issue_receipt(
                "workspace_receipt.v1",
                subject_id="workspace_lease:" + lease_id.removeprefix("lease:"),
                subject_digest=lease_identity.digest,
                outcome="active",
                terminal="active",
                dependency_digests=dependency_digests,
                sequence=1,
                expires_at=_format_time(expires),
            )
            lease = WorkspaceLease(
                lease_id=lease_id,
                lease_identity_digest=lease_identity.digest,
                base_revision=base_revision,
                parent_ref=parent_ref,
                worktree_path=str(worktree),
                owner_id=owner_id,
                declared_write_paths=declared,
                protected_paths=protected,
                capability_policy_digest=capability_policy_digest,
                expires_at=_format_time(expires),
                isolation_level="T1_git_worktree_only",
                resource_budget=resource_budget,
                state="active",
                sequence=1,
                workspace_receipt_digest=receipt.digest,
            )
            self._append_event(lease)
            return lease

    def inspect_workspace(self, lease_id: str) -> WorkspaceLease:
        lease = self._load_latest(lease_id)
        if lease.state == "active" and self._now() >= _parse_time(lease.expires_at):
            with self._locked():
                lease = self._load_latest(lease_id)
                if lease.state == "active" and self._now() >= _parse_time(lease.expires_at):
                    lease = self._workspace_transition(
                        lease,
                        state="expired",
                        outcome="timed_out",
                        terminal="attention",
                        terminal_reason="lease_expired",
                    )
        return lease

    def return_workspace(self, lease_id: str) -> WorkspaceReturn:
        """Freeze a scope-checked binary patch without changing the parent."""

        with self._locked():
            lease = self._load_latest(lease_id)
            if lease.state != "active":
                raise WorkspaceError("lease_not_active")
            if self._now() >= _parse_time(lease.expires_at):
                self._workspace_transition(
                    lease,
                    state="expired",
                    outcome="timed_out",
                    terminal="attention",
                    terminal_reason="lease_expired",
                )
                raise WorkspaceError("lease_expired")
            worktree = Path(lease.worktree_path)
            if not worktree.is_dir():
                self._workspace_transition(
                    lease,
                    state="orphaned",
                    outcome="orphaned",
                    terminal="attention",
                    terminal_reason="worktree_missing",
                )
                raise WorkspaceError("workspace_orphaned")
            if self._git("rev-parse", "HEAD", cwd=worktree).stdout.strip() != lease.base_revision:
                self._record_failed_return(lease, "child_self_integration", self._inventory(worktree))
                raise WorkspaceError("child_self_integration")
            inventory = self._inventory(worktree)
            if not inventory:
                failed = self._record_failed_return(lease, "empty_patch", ())
                return WorkspaceReturn(lease_id, "empty_patch", None, None, (), failed.patch_receipt_digest)
            try:
                self._validate_inventory_scope(lease, inventory)
            except WorkspaceError as exc:
                self._record_failed_return(lease, exc.code, inventory)
                raise
            self._git("add", "-A", "--", ".", cwd=worktree)
            patch = self._git("diff", "--cached", "--binary", "--no-ext-diff", lease.base_revision, cwd=worktree).stdout.encode("utf-8")
            if not patch:
                raise WorkspaceError("empty_patch")
            if len(patch) > lease.resource_budget.max_patch_bytes:
                raise WorkspaceError("patch_budget_exceeded")
            patch_digest = _sha(patch)
            patch_path = self.artifact_root / (patch_digest.removeprefix("sha256:") + ".patch")
            self._append_exact(patch_path, patch)
            artifact = construct_identity(
                "artifact",
                {"artifact_digest": patch_digest, "public_id": "artifact:" + patch_digest[-24:], "schema_version": 1},
            )
            self.store.append_identity(artifact)
            candidate = self._candidate_identity(lease, patch_digest, artifact.digest)
            self.store.append_identity(candidate)
            dependencies = self._foundation_digest_map(lease)
            dependencies.update({"artifact": artifact.digest, "candidate": candidate.digest, "workspace_receipt.v1": lease.workspace_receipt_digest})
            receipt = self._issue_receipt(
                "patch_receipt.v1",
                subject_id="candidate:" + lease.lease_id.removeprefix("lease:"),
                subject_digest=candidate.digest,
                outcome="patch_returned",
                terminal="returned",
                dependency_digests=dependencies,
                sequence=lease.sequence + 1,
                artifact=(patch_digest, len(patch)),
            )
            workspace_receipt = self._workspace_receipt(
                lease, outcome="returned", terminal="returned"
            )
            updated = self._transition(
                lease,
                state="returned",
                workspace_receipt_digest=workspace_receipt.digest,
                patch_digest=patch_digest,
                patch_receipt_digest=receipt.digest,
                candidate_identity_digest=candidate.digest,
                returned_inventory=inventory,
            )
            return WorkspaceReturn(updated.lease_id, "patch_returned", patch_digest, str(patch_path), inventory, receipt.digest)

    def integrate_workspaces(
        self,
        grants: Sequence[HumanIntegrationGrant],
        *,
        validate: Callable[[Path], bool] | None = None,
        request_fingerprint: str = "",
        _accepted_point_capability: _AcceptedPointCapability | None = None,
    ) -> IntegrationResult:
        """Integrate exact returned patches after explicit human grants."""

        try:
            _require_accepted_point_capability(
                _accepted_point_capability, self.repository
            )
        except AcceptedPointAuthorityError as exc:
            raise WorkspaceError(exc.code) from exc
        if not grants:
            raise WorkspaceError("integration_grant_required")
        if _DIGEST.fullmatch(request_fingerprint) is None:
            raise WorkspaceError("invalid_request_fingerprint")
        with self._locked():
            leases: list[WorkspaceLease] = []
            seen: set[str] = set()
            for grant in grants:
                if not grant.grant_id or not grant.authorized_by or grant.lease_id in seen:
                    raise WorkspaceError("invalid_integration_grant")
                lease = self._load_latest(grant.lease_id)
                if lease.state not in {"returned", "integrated"} or lease.patch_digest is None:
                    raise WorkspaceError("workspace_not_returned")
                if grant.patch_digest != lease.patch_digest:
                    raise WorkspaceError("grant_patch_mismatch")
                if grant.expected_parent_revision != lease.base_revision:
                    raise WorkspaceError("grant_predecessor_mismatch")
                if lease.state == "returned":
                    self._verify_return_unchanged_or_cleaned(lease)
                elif (
                    lease.integration_grant_id != grant.grant_id
                    or lease.integration_request_fingerprint != request_fingerprint
                ):
                    raise WorkspaceError("integration_evidence_mismatch")
                leases.append(lease)
                seen.add(grant.lease_id)
            ordered = sorted(leases, key=lambda item: (item.lease_id, item.patch_digest or ""))
            self._reject_overlap(ordered)
            transaction = self._load_integration_transaction(request_fingerprint)
            grant_pairs = tuple((grant.lease_id, grant.grant_id) for grant in grants)
            if transaction is not None:
                if (
                    transaction.get("grant_pairs") != [list(item) for item in grant_pairs]
                    or transaction.get("request_fingerprint") != request_fingerprint
                ):
                    raise WorkspaceError("integration_transaction_mismatch")
                predecessor = str(transaction["expected_old_revision"])
                commit = str(transaction["expected_new_revision"])
            else:
                predecessor = self._git("rev-parse", "HEAD").stdout.strip()
                if any(item.base_revision != predecessor for item in ordered):
                    raise WorkspaceError("stale_parent")
                if not self._clean_parent():
                    raise WorkspaceError("dirty_parent")
                commit = self._build_integration_commit(ordered, predecessor, validate)
                self._append_integration_transaction(
                    request_fingerprint,
                    {
                        "expected_new_revision": commit,
                        "expected_old_revision": predecessor,
                        "grant_pairs": [list(item) for item in grant_pairs],
                        "request_fingerprint": request_fingerprint,
                        "state": "pre_ref",
                    },
                )
                self._accepted_point_fault("pre_ref")
            head = self._git("rev-parse", "HEAD").stdout.strip()
            if head == predecessor:
                try:
                    self._git("update-ref", ordered[0].parent_ref, commit, predecessor)
                    self._git("reset", "--hard", commit)
                except (OSError, subprocess.CalledProcessError) as exc:
                    raise WorkspaceError("git_operation_failed") from exc
            elif head != commit:
                raise WorkspaceError("integration_transaction_attention")
            self._append_integration_transaction(
                request_fingerprint,
                {
                    "expected_new_revision": commit,
                    "expected_old_revision": predecessor,
                    "grant_pairs": [list(item) for item in grant_pairs],
                    "request_fingerprint": request_fingerprint,
                    "state": "post_ref",
                },
            )
            self._accepted_point_fault("post_ref")
            receipts: list[str] = []
            accepted_digest = _sha((commit + "\0" + predecessor).encode())
            accepted = construct_identity(
                "accepted_working_point",
                {"accepted_working_point_digest": accepted_digest, "base_revision": commit, "public_id": "accepted_working_point:" + commit[:20], "schema_version": 1},
            )
            self.store.append_identity(accepted)
            grants_by_lease = {grant.lease_id: grant for grant in grants}
            for lease in ordered:
                grant = grants_by_lease[lease.lease_id]
                latest = self._load_latest(lease.lease_id)
                if latest.state == "integrated":
                    if (
                        latest.integration_grant_id != grant.grant_id
                        or latest.integration_request_fingerprint != request_fingerprint
                        or latest.integration_receipt_digest is None
                    ):
                        raise WorkspaceError("integration_evidence_mismatch")
                    receipts.append(latest.integration_receipt_digest)
                    continue
                dependencies = self._foundation_digest_map(lease)
                dependencies.update({
                    "accepted_working_point": accepted.digest,
                    "artifact": self._artifact_identity_digest(lease.patch_digest or ""),
                    "candidate": lease.candidate_identity_digest or _sha(b"missing"),
                    "patch_receipt.v1": lease.patch_receipt_digest or _sha(b"missing"),
                })
                receipt = self._issue_receipt(
                    "integration_receipt.v1",
                    subject_id="accepted_working_point:" + commit[:20],
                    subject_digest=accepted.digest,
                    outcome="integrated_and_validated",
                    terminal="integrated",
                    dependency_digests=dependencies,
                    sequence=lease.sequence + 1,
                )
                self._transition(
                    lease,
                    state="integrated",
                    integration_grant_id=grant.grant_id,
                    integration_receipt_digest=receipt.digest,
                    integration_request_fingerprint=request_fingerprint,
                )
                receipts.append(receipt.digest)
            self._accepted_point_fault("post_receipt")
            self._append_integration_transaction(
                request_fingerprint,
                {
                    "expected_new_revision": commit,
                    "expected_old_revision": predecessor,
                    "grant_pairs": [list(item) for item in grant_pairs],
                    "request_fingerprint": request_fingerprint,
                    "state": "completed",
                },
            )
            return IntegrationResult(predecessor, commit, tuple((item.lease_id, item.patch_digest or "") for item in ordered), tuple(receipts))

    def _build_integration_commit(
        self,
        ordered: Sequence[WorkspaceLease],
        predecessor: str,
        validate: Callable[[Path], bool] | None,
    ) -> str:
        integration_tree = Path(
            tempfile.mkdtemp(prefix="integration-", dir=self.runtime_root)
        )
        try:
            self._git("worktree", "add", "--detach", str(integration_tree), predecessor)
            for lease in ordered:
                self._git(
                    "apply",
                    "--index",
                    "--binary",
                    str(self._patch_path(lease.patch_digest or "")),
                    cwd=integration_tree,
                )
            if validate is not None:
                try:
                    valid = validate(integration_tree)
                except Exception as exc:
                    raise WorkspaceError("validation_failed") from exc
                if not valid:
                    raise WorkspaceError("validation_failed")
            tree = self._git("write-tree", cwd=integration_tree).stdout.strip()
            environment = dict(os.environ)
            predecessor_time = self._git(
                "show", "-s", "--format=%aI", predecessor
            ).stdout.strip()
            environment.update(
                {
                    "GIT_AUTHOR_NAME": "Unrest parent integration authority",
                    "GIT_AUTHOR_EMAIL": "unrest@localhost",
                    "GIT_COMMITTER_NAME": "Unrest parent integration authority",
                    "GIT_COMMITTER_EMAIL": "unrest@localhost",
                    "GIT_AUTHOR_DATE": predecessor_time,
                    "GIT_COMMITTER_DATE": predecessor_time,
                }
            )
            message = "Integrate Unrest workspaces\n\n" + "\n".join(
                f"{item.lease_id} {item.patch_digest}" for item in ordered
            ) + "\n"
            return subprocess.run(
                ["git", "commit-tree", tree, "-p", predecessor],
                cwd=integration_tree,
                input=message,
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise WorkspaceError("git_operation_failed") from exc
        finally:
            self._git(
                "worktree", "remove", "--force", str(integration_tree), check=False
            )
            shutil.rmtree(integration_tree, ignore_errors=True)

    def _integration_transaction_directory(self, fingerprint: str) -> Path:
        token = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        return self.repository / ".unrest" / "workspaces" / "transactions" / token

    def _load_integration_transaction(
        self, fingerprint: str
    ) -> Mapping[str, Any] | None:
        directory = self._integration_transaction_directory(fingerprint)
        events = sorted(directory.glob("*.json"))
        if not events:
            return None
        value = verify_canonical_json_bytes(events[-1].read_bytes())
        if not isinstance(value, Mapping):
            raise WorkspaceError("integration_transaction_corrupt")
        return value

    def _append_integration_transaction(
        self,
        fingerprint: str,
        record: Mapping[str, Any],
    ) -> None:
        directory = self._integration_transaction_directory(fingerprint)
        sequence = len(tuple(directory.glob("*.json"))) + 1
        self._append_exact(
            directory / f"{sequence:08d}.json",
            canonical_json_bytes(record),
        )

    def _accepted_point_fault(self, _boundary: str) -> None:
        return None

    def cleanup_workspace(self, lease_id: str) -> CleanupResult:
        """Remove only this lease's owned worktree; evidence remains durable."""

        with self._locked():
            lease = self._load_latest(lease_id)
            if lease.state == "active" and self._now() < _parse_time(lease.expires_at):
                raise WorkspaceError("lease_not_terminal")
            worktree = Path(lease.worktree_path)
            outcome: Literal["released", "quarantined", "cleanup_failed", "unsettled"]
            processes_drained = self._drain_owned_processes(lease)
            if not processes_drained:
                outcome = "unsettled"
            elif worktree.exists() and not self._owned_worktree(lease, worktree):
                outcome = "quarantined"
            elif worktree.exists():
                result = self._git("worktree", "remove", "--force", str(worktree), check=False)
                if result.returncode != 0 or worktree.exists():
                    outcome = "cleanup_failed"
                else:
                    outcome = "released"
            else:
                self._git("worktree", "prune", check=False)
                outcome = "released"
            receipt_outcome = {"released": "released", "cleanup_failed": "cleanup_failed", "quarantined": "resources_unsettled", "unsettled": "resources_unsettled"}[outcome]
            terminal = "released" if outcome == "released" else ("attention" if outcome == "cleanup_failed" else "unsettled")
            dependencies = self._foundation_digest_map(lease)
            dependencies.update({"workspace_receipt.v1": lease.workspace_receipt_digest})
            receipt = self._issue_receipt(
                "cleanup_receipt.v1",
                subject_id="workspace_lease:" + lease.lease_id.removeprefix("lease:"),
                subject_digest=lease.lease_identity_digest,
                outcome=receipt_outcome,
                terminal=terminal,
                dependency_digests=dependencies,
                sequence=lease.sequence + 1,
            )
            self._transition(lease, state=outcome, cleanup_receipt_digest=receipt.digest, terminal_reason=outcome)
            return CleanupResult(lease_id, outcome, receipt.digest)

    def start_owned_process(self, lease_id: str, command: Sequence[str]) -> OwnedProcess:
        """Start a process that cleanup can safely identify and drain.

        This is lifecycle ownership, not process confinement.  The command is
        never persisted; only its digest and an OS-observed start token are.
        """

        if not command or any(not isinstance(item, str) or not item for item in command):
            raise WorkspaceError("invalid_process_command")
        with self._locked():
            lease = self._load_latest(lease_id)
            if lease.state != "active" or self._now() >= _parse_time(lease.expires_at):
                raise WorkspaceError("lease_not_active")
            active = [item for item in self._load_owned_processes(lease_id) if self._process_matches(item)]
            if len(active) >= lease.resource_budget.max_processes:
                raise WorkspaceError("process_budget_exceeded")
            try:
                process = subprocess.Popen(
                    list(command),
                    cwd=lease.worktree_path,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                group_id = os.getpgid(process.pid)
            except OSError as exc:
                raise WorkspaceError("process_start_failed") from exc
            if group_id != process.pid:
                process.terminate()
                raise WorkspaceError("process_ownership_unverifiable")
            owned = OwnedProcess(
                pid=process.pid,
                process_group_id=group_id,
                start_token_digest=_sha(os.urandom(32)),
                command_digest=_sha(canonical_json_bytes(list(command))),
            )
            self._live_processes[process.pid] = process
            self._append_exact(
                self._process_path(lease_id, process.pid), canonical_json_bytes(asdict(owned))
            )
            return owned

    def cancel_workspace(self, lease_id: str) -> WorkspaceLease:
        with self._locked():
            lease = self._load_latest(lease_id)
            if lease.state != "active":
                raise WorkspaceError("lease_not_active")
            return self._workspace_transition(
                lease,
                state="cancelled",
                outcome="cancelled",
                terminal="attention",
                terminal_reason="cancelled_by_authority",
            )

    def discover_orphans(self) -> tuple[WorkspaceLease, ...]:
        discovered: list[WorkspaceLease] = []
        with self._locked():
            for directory in sorted(self.events_root.iterdir()):
                if not directory.is_dir():
                    continue
                lease = self._load_latest("lease:" + directory.name)
                if lease.state == "active" and not self._owned_worktree(lease, Path(lease.worktree_path)):
                    lease = self._workspace_transition(
                        lease,
                        state="orphaned",
                        outcome="orphaned",
                        terminal="attention",
                        terminal_reason="owned_worktree_missing_or_changed",
                    )
                    discovered.append(lease)
        return tuple(discovered)

    def _foundation_identities(self, base_revision: str, policy_digest: str, lease_identity: Any) -> dict[str, str]:
        accepted_digest = _sha(base_revision.encode())
        identities = {
            "base": construct_identity("base", {"base_revision": base_revision, "public_id": "base:" + base_revision[:20], "schema_version": 1}),
            "accepted_working_point": construct_identity("accepted_working_point", {"accepted_working_point_digest": accepted_digest, "base_revision": base_revision, "public_id": "accepted_working_point:" + base_revision[:20], "schema_version": 1}),
            "artifact": construct_identity("artifact", {"artifact_digest": _sha(("lease:" + base_revision).encode()), "public_id": "artifact:lease-" + base_revision[:16], "schema_version": 1}),
            "environment": construct_identity("environment", {"environment_digest": _sha(b"workspace-t1-git-v1"), "public_id": "environment:workspace-t1", "schema_version": 1}),
            "policy": construct_identity("policy", {"capability_policy_digest": policy_digest, "public_id": "policy:workspace-" + policy_digest[-16:], "schema_version": 1}),
            "workspace_lease": lease_identity,
        }
        for identity in identities.values():
            self.store.append_identity(identity)
        return {kind: identity.digest for kind, identity in identities.items()}

    def _foundation_digest_map(self, lease: WorkspaceLease) -> dict[str, str]:
        return self._foundation_identities(
            lease.base_revision,
            lease.capability_policy_digest,
            self.store.load_identity("workspace_lease", lease.lease_identity_digest),
        )

    def _candidate_identity(self, lease: WorkspaceLease, patch_digest: str, artifact_identity_digest: str) -> Any:
        context = _sha(canonical_json_bytes(list(lease.declared_write_paths)))
        return construct_identity(
            "candidate",
            {
                "accepted_working_point_digest": _sha(lease.base_revision.encode()),
                "artifact_digest": artifact_identity_digest,
                "base_revision": lease.base_revision,
                "candidate_digest": patch_digest,
                "capability_policy_digest": lease.capability_policy_digest,
                "context_digest": context,
                "public_id": "candidate:" + patch_digest[-24:],
                "route_profile_digest": _sha(b"workspace-return-v1"),
                "schema_version": 1,
            },
        )

    def _record_failed_return(
        self,
        lease: WorkspaceLease,
        reason: str,
        inventory: Sequence[FileInventoryEntry],
    ) -> WorkspaceLease:
        evidence_digest = _sha(canonical_json_bytes([asdict(item) for item in inventory]))
        artifact = construct_identity(
            "artifact",
            {
                "artifact_digest": evidence_digest,
                "public_id": "artifact:" + evidence_digest[-24:],
                "schema_version": 1,
            },
        )
        self.store.append_identity(artifact)
        candidate = self._candidate_identity(lease, evidence_digest, artifact.digest)
        self.store.append_identity(candidate)
        dependencies = self._foundation_digest_map(lease)
        dependencies.update(
            {
                "artifact": artifact.digest,
                "candidate": candidate.digest,
                "workspace_receipt.v1": lease.workspace_receipt_digest,
            }
        )
        patch_receipt = self._issue_receipt(
            "patch_receipt.v1",
            subject_id="candidate:" + lease.lease_id.removeprefix("lease:"),
            subject_digest=candidate.digest,
            outcome="failed_return",
            terminal="failed",
            dependency_digests=dependencies,
            sequence=lease.sequence + 1,
        )
        workspace_receipt = self._workspace_receipt(
            lease, outcome="returned", terminal="failed"
        )
        return self._transition(
            lease,
            state="returned",
            workspace_receipt_digest=workspace_receipt.digest,
            patch_receipt_digest=patch_receipt.digest,
            candidate_identity_digest=candidate.digest,
            returned_inventory=tuple(inventory),
            terminal_reason=reason,
        )

    def _workspace_receipt(
        self, lease: WorkspaceLease, *, outcome: str, terminal: str
    ) -> ReceiptRecord:
        return self._issue_receipt(
            "workspace_receipt.v1",
            subject_id="workspace_lease:" + lease.lease_id.removeprefix("lease:"),
            subject_digest=lease.lease_identity_digest,
            outcome=outcome,
            terminal=terminal,
            dependency_digests=self._foundation_digest_map(lease),
            sequence=lease.sequence + 1,
            expires_at=lease.expires_at,
        )

    def _workspace_transition(
        self,
        lease: WorkspaceLease,
        *,
        state: str,
        outcome: str,
        terminal: str,
        terminal_reason: str,
    ) -> WorkspaceLease:
        receipt = self._workspace_receipt(lease, outcome=outcome, terminal=terminal)
        return self._transition(
            lease,
            state=state,
            workspace_receipt_digest=receipt.digest,
            terminal_reason=terminal_reason,
        )

    def _artifact_identity_digest(self, patch_digest: str) -> str:
        return construct_identity(
            "artifact",
            {"artifact_digest": patch_digest, "public_id": "artifact:" + patch_digest[-24:], "schema_version": 1},
        ).digest

    def _issue_receipt(
        self,
        family_id: str,
        *,
        subject_id: str,
        subject_digest: str,
        outcome: str,
        terminal: str,
        dependency_digests: Mapping[str, str],
        sequence: int,
        expires_at: str | None = None,
        artifact: tuple[str, int] | None = None,
    ) -> ReceiptRecord:
        family = load_receipt_catalog().families[family_id]
        dependencies = []
        for spec in family.dependencies:
            kind = str(spec["dependency_kind"])
            digest = dependency_digests.get(kind)
            if digest is None:
                raise WorkspaceError("missing_receipt_dependency")
            dependencies.append({
                "dependency_digest": digest,
                "dependency_id": kind + ":" + digest[-16:],
                "dependency_kind": kind,
                "dependency_type": spec["dependency_type"],
                "must_be_fresh": spec["must_be_fresh"],
                "role": spec["role"],
            })
        dependencies.sort(key=lambda item: (item["dependency_type"], item["dependency_kind"], item["dependency_id"], item["role"]))
        authority = family.issuer_authority
        issuer_id = "component:" + authority
        decision_ref = "decision:issue:" + family_id
        artifact_refs: list[dict[str, Any]] = []
        if artifact is not None:
            artifact_refs.append({"artifact_digest": artifact[0], "artifact_id": "patch:" + artifact[0][-24:], "media_type": "text/x-diff", "size_bytes": artifact[1]})
        fields: dict[str, Any] = {
            "append_only_disposition": "immutable",
            "artifact_refs": artifact_refs,
            "chronology_is_authority": False,
            "consumers": list(family.consumers),
            "cost": {"accounting_boundary": "receipt:" + family_id, "completeness": "not_applicable", "quantities": []},
            "dependencies": dependencies,
            "deviations": [],
            "freshness_policy": {
                "dependency_mode": "exact_typed_set",
                "expiry": {"state": "present", "value": {"expires_at": expires_at, "trusted_clock_id": "workspace-manager-clock"}} if expires_at else {"state": "absent"},
                "policy_id": "freshness:" + family_id,
                "revocation_authority": family.revocation_authority,
                "revocation_view": {"state": "present", "value": {"authority_decision_ref": "decision:revocation:" + family_id, "watermark": "workspace-local-v1"}},
                "unavailable_dependency": "unverifiable",
            },
            "integrity": {"canonicalization": "canonical-json-v1", "detached_signature": {"state": "absent"}, "digest_algorithm": "sha256", "domain": "unrest.receipt.v1"},
            "issuer": {"identity_digest": _sha(issuer_id.encode()), "issuer_id": issuer_id, "issuer_kind": "provider_configuration"},
            "issuer_authority": {"authority_class": authority, "decision_ref": decision_ref},
            "observed_at": _format_time(self._now()),
            "outcome": outcome,
            "receipt_id": "receipt:" + family_id + ":" + uuid.uuid4().hex,
            "receipt_kind": family_id,
            "schema_version": 1,
            "sequence": sequence,
            "subject": {"subject_digest": subject_digest, "subject_id": subject_id, "subject_kind": family.subject_kind},
            "terminal_disposition": terminal,
        }
        receipt = construct_receipt(fields)
        self.store.append_receipt(receipt, custodian=CustodyActor(issuer_id, authority, decision_ref))
        return receipt

    def _inventory(self, worktree: Path) -> tuple[FileInventoryEntry, ...]:
        raw = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=worktree,
            check=True,
            capture_output=True,
        ).stdout
        fields = raw.split(b"\0")
        entries: dict[str, str] = {}
        index = 0
        while index < len(fields) and fields[index]:
            field = fields[index].decode("utf-8", "strict")
            status, path = field[:2], field[3:]
            if status[0] in {"R", "C"} or status[1] in {"R", "C"}:
                index += 1
                old_path = fields[index].decode("utf-8", "strict")
                entries[_normalize_path(old_path)] = "D "
            entries[_normalize_path(path)] = status
            index += 1
        result: list[FileInventoryEntry] = []
        for path, status in sorted(entries.items()):
            candidate = worktree / path
            if not candidate.exists() and not candidate.is_symlink():
                result.append(FileInventoryEntry(path, status, "deleted", _sha(b"deleted"), 0))
            elif candidate.is_symlink():
                data = os.readlink(candidate).encode("utf-8")
                result.append(FileInventoryEntry(path, status, "symlink", _sha(data), len(data)))
            elif candidate.is_file():
                data = candidate.read_bytes()
                result.append(FileInventoryEntry(path, status, "file", _sha(data), len(data)))
            else:
                raise WorkspaceError("unsupported_workspace_object")
        return tuple(result)

    def _validate_inventory_scope(self, lease: WorkspaceLease, inventory: Sequence[FileInventoryEntry]) -> None:
        for item in inventory:
            if any(_contains(blocked, item.path) for blocked in lease.protected_paths):
                raise WorkspaceError("protected_path_changed")
            if not any(_contains(allowed, item.path) for allowed in lease.declared_write_paths):
                raise WorkspaceError("write_scope_escape")

    def _verify_return_unchanged_or_cleaned(self, lease: WorkspaceLease) -> None:
        worktree = Path(lease.worktree_path)
        if not worktree.exists():
            return
        current = tuple(
            (item.path, item.object_kind, item.content_digest, item.size_bytes)
            for item in self._inventory(worktree)
        )
        returned = tuple(
            (item.path, item.object_kind, item.content_digest, item.size_bytes)
            for item in lease.returned_inventory
        )
        if current != returned:
            raise WorkspaceError("workspace_mutated_after_return")
        patch = self._patch_path(lease.patch_digest or "").read_bytes()
        if _sha(patch) != lease.patch_digest:
            raise WorkspaceError("patch_artifact_mutated")

    def _reject_overlap(self, leases: Sequence[WorkspaceLease]) -> None:
        claimed: list[tuple[str, str]] = []
        for lease in leases:
            for item in lease.returned_inventory:
                for previous_lease, previous_path in claimed:
                    if _overlap(previous_path, item.path):
                        raise WorkspaceError("overlapping_returns")
                claimed.append((lease.lease_id, item.path))

    def _owned_worktree(self, lease: WorkspaceLease, path: Path) -> bool:
        if path != self.tree_root / lease.lease_id.removeprefix("lease:") or not path.is_dir():
            return False
        result = self._git("rev-parse", "--show-toplevel", cwd=path, check=False)
        return result.returncode == 0 and Path(result.stdout.strip()).resolve() == path.resolve()

    def _process_path(self, lease_id: str, pid: int) -> Path:
        if pid <= 0:
            raise WorkspaceError("invalid_process")
        return self.process_root / self._event_directory(lease_id).name / f"{pid}.json"

    def _load_owned_processes(self, lease_id: str) -> tuple[OwnedProcess, ...]:
        directory = self.process_root / self._event_directory(lease_id).name
        if not directory.exists():
            return ()
        processes: list[OwnedProcess] = []
        for path in sorted(directory.glob("*.json")):
            value = verify_canonical_json_bytes(path.read_bytes())
            if not isinstance(value, Mapping):
                raise WorkspaceError("process_registry_corrupt")
            try:
                processes.append(OwnedProcess(**value))
            except (TypeError, ValueError) as exc:
                raise WorkspaceError("process_registry_corrupt") from exc
        return tuple(processes)

    def _process_matches(self, process: OwnedProcess) -> bool:
        handle = self._live_processes.get(process.pid)
        if handle is None or handle.poll() is not None:
            return False
        try:
            return (
                os.getpgid(process.pid) == process.process_group_id
                and process.process_group_id == process.pid
            )
        except OSError:
            return False

    def _drain_owned_processes(self, lease: WorkspaceLease) -> bool:
        settled = True
        for process in self._load_owned_processes(lease.lease_id):
            registry = self._process_path(lease.lease_id, process.pid)
            if not self._process_matches(process):
                # A missing process is settled.  A reused PID must never be
                # signalled; retain its registry as attention evidence.
                try:
                    os.kill(process.pid, 0)
                except OSError:
                    registry.unlink(missing_ok=True)
                else:
                    settled = False
                continue
            try:
                os.killpg(process.process_group_id, signal.SIGTERM)
            except OSError:
                pass
            for _ in range(20):
                self._reap_process(process.pid)
                if not self._process_matches(process):
                    break
                time.sleep(0.025)
            if self._process_matches(process):
                try:
                    os.killpg(process.process_group_id, signal.SIGKILL)
                except OSError:
                    pass
                for _ in range(20):
                    self._reap_process(process.pid)
                    if not self._process_matches(process):
                        break
                    time.sleep(0.025)
            if self._process_matches(process):
                settled = False
            else:
                registry.unlink(missing_ok=True)
                self._live_processes.pop(process.pid, None)
        return settled

    @staticmethod
    def _reap_process(pid: int) -> None:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass

    def _patch_path(self, digest: str) -> Path:
        if _DIGEST.fullmatch(digest) is None:
            raise WorkspaceError("invalid_patch_digest")
        path = self.artifact_root / (digest.removeprefix("sha256:") + ".patch")
        if not path.is_file():
            raise WorkspaceError("patch_artifact_missing")
        return path

    def _event_directory(self, lease_id: str) -> Path:
        if _LEASE_ID.fullmatch(lease_id) is None:
            raise WorkspaceError("invalid_lease")
        return self.events_root / lease_id.removeprefix("lease:")

    def _append_exact(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".workspace-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written == 0:
                    raise OSError("short workspace artifact write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(temporary, path)
            except FileExistsError:
                try:
                    existing = path.lstat()
                    if not stat.S_ISREG(existing.st_mode) or path.read_bytes() != data:
                        raise WorkspaceError("immutable_artifact_conflict")
                except OSError as exc:
                    raise WorkspaceError("immutable_artifact_conflict") from exc
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def _append_event(self, lease: WorkspaceLease) -> None:
        document = {key: value for key, value in asdict(lease).items() if value is not None}
        event_path = self._event_directory(lease.lease_id) / f"{lease.sequence:08d}.json"
        self._append_exact(event_path, canonical_json_bytes(document))

    def _load_latest(self, lease_id: str) -> WorkspaceLease:
        directory = self._event_directory(lease_id)
        try:
            events = sorted(directory.glob("*.json"))
        except OSError as exc:
            raise WorkspaceError("lease_not_found") from exc
        if not events:
            raise WorkspaceError("lease_not_found")
        value = verify_canonical_json_bytes(events[-1].read_bytes())
        if not isinstance(value, Mapping):
            raise WorkspaceError("lease_integrity_error")
        try:
            inventory = tuple(FileInventoryEntry(**item) for item in value.get("returned_inventory", []))
            budget = ResourceBudget(**value["resource_budget"])
            fields = dict(value)
            for optional in (
                "patch_digest",
                "patch_receipt_digest",
                "candidate_identity_digest",
                "cleanup_receipt_digest",
                "integration_receipt_digest",
                "integration_grant_id",
                "integration_request_fingerprint",
                "terminal_reason",
            ):
                fields.setdefault(optional, None)
            fields["declared_write_paths"] = tuple(fields["declared_write_paths"])
            fields["protected_paths"] = tuple(fields["protected_paths"])
            fields["returned_inventory"] = inventory
            fields["resource_budget"] = budget
            return WorkspaceLease(**fields)
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspaceError("lease_integrity_error") from exc

    def _transition(self, lease: WorkspaceLease, **changes: Any) -> WorkspaceLease:
        fields = asdict(lease)
        fields.update(changes)
        fields["sequence"] = lease.sequence + 1
        fields["resource_budget"] = ResourceBudget(**fields["resource_budget"])
        fields["declared_write_paths"] = tuple(fields["declared_write_paths"])
        fields["protected_paths"] = tuple(fields["protected_paths"])
        fields["returned_inventory"] = tuple(
            item if isinstance(item, FileInventoryEntry) else FileInventoryEntry(**item)
            for item in fields["returned_inventory"]
        )
        updated = WorkspaceLease(**fields)
        self._append_event(updated)
        return updated


__all__ = [
    "CleanupResult",
    "FileInventoryEntry",
    "HumanIntegrationGrant",
    "IntegrationResult",
    "OwnedProcess",
    "ResourceBudget",
    "WorkspaceError",
    "WorkspaceLease",
    "WorkspaceManager",
    "WorkspaceReturn",
]
