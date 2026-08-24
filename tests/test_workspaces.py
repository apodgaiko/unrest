from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import unrest_harness.accepted_point_authority as accepted_authority

from unrest_harness.accepted_point_authority import (
    AcceptedPointAuthorityError,
    WorkspaceIntegrationPlan,
    _apply_accepted_point_plan,
    _mint_mission_grant_proof,
)
from unrest_harness.mutation_journal import request_fingerprint
from unrest_harness.workspaces import (
    HumanIntegrationGrant,
    ResourceBudget,
    WorkspaceError,
    WorkspaceManager,
)


_POLICY = "sha256:" + "a" * 64


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Workspace Test")
    _git(root, "config", "user.email", "workspace@example.test")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", "base")
    return root


def _manager(repository: Path, *, now=None) -> WorkspaceManager:
    arguments = {"custody_root_id": "workspace-test"}
    if now is not None:
        arguments["now"] = now
    return WorkspaceManager(repository, **arguments)  # type: ignore[arg-type]


def _lease(
    manager: WorkspaceManager,
    repository: Path,
    lease_id: str,
    paths: tuple[str, ...],
    *,
    duration: int = 600,
):
    return manager.lease_workspace(
        base_revision=_git(repository, "rev-parse", "HEAD"),
        owner_id="worker:test",
        declared_write_paths=paths,
        capability_policy_digest=_POLICY,
        duration_seconds=duration,
        lease_id=lease_id,
        resource_budget=ResourceBudget(max_processes=0, max_patch_bytes=100_000),
    )


def _grant(lease, patch_digest: str) -> HumanIntegrationGrant:
    return HumanIntegrationGrant(
        grant_id="mission-grant:" + lease.lease_id,
        authorized_by="maintainer:test",
        lease_id=lease.lease_id,
        patch_digest=patch_digest,
        expected_parent_revision=lease.base_revision,
    )


class _AuthorityStore:
    def __init__(self, repository: Path) -> None:
        self.repository = repository

    def workspace_dir(self, _project_id: str) -> Path:
        return self.repository

    def mutation_lock_path(self, _project_id: str) -> Path:
        path = self.repository / ".unrest-runtime" / "test-authority.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def mission_dir(self, _project_id: str, _mission_id: str) -> Path:
        path = self.repository / ".unrest" / "missions" / "mission:test"
        path.mkdir(parents=True, exist_ok=True)
        return path


def _integrate(manager, grants, *, validate=None):
    ordered = tuple(sorted(grants, key=lambda item: item.lease_id))
    fingerprint = request_fingerprint(
        {
            "grant_ids": [item.grant_id for item in ordered],
            "lease_ids": [item.lease_id for item in ordered],
        }
    )
    plan = WorkspaceIntegrationPlan(
        tuple(item.lease_id for item in ordered),
        tuple(item.grant_id for item in ordered),
        fingerprint,
        validation_policy="git_index_check" if validate is not None else "none",
    )
    store = _AuthorityStore(manager.repository)
    proof = _mint_mission_grant_proof(store, "project:test", "mission:test", plan)
    original = accepted_authority._validate_git_index
    if validate is not None:
        accepted_authority._validate_git_index = validate
    try:
        return _apply_accepted_point_plan(store, "project:test", plan, proof)
    finally:
        accepted_authority._validate_git_index = original


def test_exact_clean_base_scope_and_t1_label_survive_restart(repository: Path) -> None:
    manager = _manager(repository)
    base = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(WorkspaceError, match="exact_base_revision_required"):
        manager.lease_workspace(
            base_revision="HEAD",
            owner_id="worker:test",
            declared_write_paths=("src",),
            capability_policy_digest=_POLICY,
            duration_seconds=60,
        )
    with pytest.raises(WorkspaceError, match="protected_write_path"):
        manager.lease_workspace(
            base_revision=base,
            owner_id="worker:test",
            declared_write_paths=(".git/config",),
            capability_policy_digest=_POLICY,
            duration_seconds=60,
        )
    with pytest.raises(WorkspaceError, match="overlapping_write_paths"):
        manager.lease_workspace(
            base_revision=base,
            owner_id="worker:test",
            declared_write_paths=("src", "src/pkg"),
            capability_policy_digest=_POLICY,
            duration_seconds=60,
        )

    lease = _lease(manager, repository, "lease:restart", ("src",))
    restarted = _manager(repository)
    inspected = restarted.inspect_workspace(lease.lease_id)
    assert inspected == lease
    assert inspected.isolation_level == "T1_git_worktree_only"
    assert Path(inspected.worktree_path).is_dir()
    assert _git(Path(inspected.worktree_path), "rev-parse", "HEAD") == base

    (repository / "dirty.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="dirty_parent"):
        restarted.lease_workspace(
            base_revision=base,
            owner_id="worker:test",
            declared_write_paths=("other",),
            capability_policy_digest=_POLICY,
            duration_seconds=60,
        )


def test_two_leases_use_distinct_worktrees_and_scope_escape_fails(repository: Path) -> None:
    manager = _manager(repository)
    first = _lease(manager, repository, "lease:one", ("one",))
    second = _lease(manager, repository, "lease:two", ("two",))
    assert first.worktree_path != second.worktree_path

    first_tree = Path(first.worktree_path)
    (first_tree / "outside.txt").write_text("escape", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="write_scope_escape"):
        manager.return_workspace(first.lease_id)
    assert _git(repository, "rev-parse", "HEAD") == first.base_revision
    failed = manager.inspect_workspace(first.lease_id)
    assert failed.state == "returned"
    assert failed.terminal_reason == "write_scope_escape"
    assert failed.patch_receipt_digest is not None
    assert manager.inspect_workspace(second.lease_id).state == "active"


def test_return_is_identity_bound_append_only_and_parent_is_unchanged(repository: Path) -> None:
    manager = _manager(repository)
    lease = _lease(manager, repository, "lease:return", ("src",))
    parent_tree = _git(repository, "rev-parse", "HEAD^{tree}")
    tree = Path(lease.worktree_path)
    (tree / "src").mkdir()
    (tree / "src" / "binary.dat").write_bytes(b"\x00\xff\x01")

    returned = manager.return_workspace(lease.lease_id)
    assert returned.patch_digest is not None
    assert returned.patch_receipt_digest is not None
    assert Path(returned.patch_path or "").read_bytes()
    assert _git(repository, "rev-parse", "HEAD^{tree}") == parent_tree

    restarted = _manager(repository)
    persisted = restarted.inspect_workspace(lease.lease_id)
    assert persisted.patch_digest == returned.patch_digest
    assert persisted.returned_inventory[0].content_digest.startswith("sha256:")
    assert list((repository / ".unrest" / "workspaces" / "leases" / "return").glob("*.json"))

    with pytest.raises(WorkspaceError, match="parent_authority_required"):
        restarted.integrate_workspaces([_grant(lease, returned.patch_digest)])
    assert _git(repository, "rev-parse", "HEAD^{tree}") == parent_tree

    (tree / "src" / "binary.dat").write_bytes(b"changed")
    with pytest.raises(WorkspaceError, match="workspace_mutated_after_return"):
        _integrate(restarted, [_grant(lease, returned.patch_digest)])
    assert _git(repository, "rev-parse", "HEAD^{tree}") == parent_tree


def test_disjoint_returns_integrate_in_deterministic_order(repository: Path) -> None:
    manager = _manager(repository)
    later = _lease(manager, repository, "lease:zeta", ("zeta.txt",))
    earlier = _lease(manager, repository, "lease:alpha", ("alpha.txt",))
    Path(later.worktree_path, "zeta.txt").write_text("zeta\n", encoding="utf-8")
    Path(earlier.worktree_path, "alpha.txt").write_text("alpha\n", encoding="utf-8")
    later_return = manager.return_workspace(later.lease_id)
    earlier_return = manager.return_workspace(earlier.lease_id)
    assert later_return.patch_digest and earlier_return.patch_digest

    observed_validation: list[tuple[bool, bool]] = []

    def validate(path: Path) -> bool:
        observed_validation.append(((path / "alpha.txt").is_file(), (path / "zeta.txt").is_file()))
        return True

    result = _integrate(
        manager,
        [_grant(later, later_return.patch_digest), _grant(earlier, earlier_return.patch_digest)],
        validate=validate,
    )
    assert result.ordered_patches == (
        ("lease:alpha", earlier_return.patch_digest),
        ("lease:zeta", later_return.patch_digest),
    )
    assert observed_validation == [(True, True)]
    assert (repository / "alpha.txt").read_text(encoding="utf-8") == "alpha\n"
    assert (repository / "zeta.txt").read_text(encoding="utf-8") == "zeta\n"
    assert _git(repository, "rev-parse", "HEAD") == result.accepted_revision


def test_overlap_stale_and_validation_failure_preserve_parent(repository: Path) -> None:
    manager = _manager(repository)
    first = _lease(manager, repository, "lease:overlap-a", ("same.txt",))
    second = _lease(manager, repository, "lease:overlap-b", ("same.txt",))
    Path(first.worktree_path, "same.txt").write_text("a", encoding="utf-8")
    Path(second.worktree_path, "same.txt").write_text("b", encoding="utf-8")
    first_return = manager.return_workspace(first.lease_id)
    second_return = manager.return_workspace(second.lease_id)
    before = _git(repository, "rev-parse", "HEAD^{tree}")
    assert first_return.patch_digest and second_return.patch_digest
    with pytest.raises(WorkspaceError, match="overlapping_returns"):
        _integrate(
            manager,
            [_grant(first, first_return.patch_digest), _grant(second, second_return.patch_digest)]
        )
    assert _git(repository, "rev-parse", "HEAD^{tree}") == before

    separate = _lease(manager, repository, "lease:validation", ("valid.txt",))
    Path(separate.worktree_path, "valid.txt").write_text("candidate", encoding="utf-8")
    separate_return = manager.return_workspace(separate.lease_id)
    assert separate_return.patch_digest
    with pytest.raises(WorkspaceError, match="validation_failed"):
        _integrate(manager, [_grant(separate, separate_return.patch_digest)], validate=lambda _: False)
    assert _git(repository, "rev-parse", "HEAD^{tree}") == before

    (repository / "advance.txt").write_text("advance", encoding="utf-8")
    _git(repository, "add", "advance.txt")
    _git(repository, "commit", "-m", "advance parent")
    with pytest.raises(WorkspaceError, match="stale_parent"):
        _integrate(manager, [_grant(separate, separate_return.patch_digest)])


def test_expiry_orphan_cleanup_and_retry_preserve_evidence(repository: Path) -> None:
    moment = [datetime(2026, 8, 24, tzinfo=UTC)]
    manager = _manager(repository, now=lambda: moment[0])
    expired = _lease(manager, repository, "lease:expired", ("expired.txt",), duration=1)
    moment[0] += timedelta(seconds=2)
    assert manager.inspect_workspace(expired.lease_id).state == "expired"
    cleaned = manager.cleanup_workspace(expired.lease_id)
    assert cleaned.outcome == "released"
    assert not Path(expired.worktree_path).exists()
    retry = manager.cleanup_workspace(expired.lease_id)
    assert retry.outcome == "released"

    current_base = _git(repository, "rev-parse", "HEAD")
    orphan = manager.lease_workspace(
        base_revision=current_base,
        owner_id="worker:test",
        declared_write_paths=("orphan.txt",),
        capability_policy_digest=_POLICY,
        duration_seconds=60,
        lease_id="lease:orphan",
    )
    shutil.rmtree(orphan.worktree_path)
    discovered = manager.discover_orphans()
    assert [item.lease_id for item in discovered] == [orphan.lease_id]
    assert manager.cleanup_workspace(orphan.lease_id).outcome == "released"
    assert (repository / ".unrest" / "workspaces" / "leases" / "orphan").is_dir()


def test_child_commit_is_not_parent_authority(repository: Path) -> None:
    manager = _manager(repository)
    lease = _lease(manager, repository, "lease:self-merge", ("child.txt",))
    child = Path(lease.worktree_path)
    (child / "child.txt").write_text("child", encoding="utf-8")
    _git(child, "add", "child.txt")
    _git(child, "commit", "-m", "child self commit")
    parent = _git(repository, "rev-parse", "HEAD")
    with pytest.raises(WorkspaceError, match="child_self_integration"):
        manager.return_workspace(lease.lease_id)
    assert _git(repository, "rev-parse", "HEAD") == parent


def test_owned_process_budget_and_restart_cleanup(repository: Path) -> None:
    moment = [datetime(2026, 8, 24, tzinfo=UTC)]
    manager = _manager(repository, now=lambda: moment[0])
    lease = manager.lease_workspace(
        base_revision=_git(repository, "rev-parse", "HEAD"),
        owner_id="worker:process",
        declared_write_paths=("process.txt",),
        capability_policy_digest=_POLICY,
        duration_seconds=1,
        lease_id="lease:process",
        resource_budget=ResourceBudget(max_processes=1, max_patch_bytes=1000),
    )
    process = manager.start_owned_process(
        lease.lease_id, [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    assert process.pid > 0
    with pytest.raises(WorkspaceError, match="process_budget_exceeded"):
        manager.start_owned_process(
            lease.lease_id, [sys.executable, "-c", "import time; time.sleep(60)"]
        )
    moment[0] += timedelta(seconds=2)
    restarted = _manager(repository, now=lambda: moment[0])
    assert restarted.inspect_workspace(lease.lease_id).state == "expired"
    # A restarted controller lacks a trustworthy OS start token at T1 and
    # therefore preserves the process rather than risking a reused-PID kill.
    assert restarted.cleanup_workspace(lease.lease_id).outcome == "unsettled"
    assert manager.cleanup_workspace(lease.lease_id).outcome == "released"
    with pytest.raises(OSError):
        __import__("os").kill(process.pid, 0)


def test_mutated_patch_artifact_and_cleanup_failure_are_retained(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _manager(repository)
    lease = _lease(manager, repository, "lease:artifact", ("artifact.txt",))
    Path(lease.worktree_path, "artifact.txt").write_text("artifact", encoding="utf-8")
    returned = manager.return_workspace(lease.lease_id)
    assert returned.patch_digest and returned.patch_path
    patch_path = Path(returned.patch_path)
    original = patch_path.read_bytes()
    patch_path.write_bytes(original + b"corrupt")
    with pytest.raises(WorkspaceError, match="patch_artifact_mutated"):
        _integrate(manager, [_grant(lease, returned.patch_digest)])
    patch_path.write_bytes(original)

    original_git = manager._git

    def fail_remove(*arguments, **kwargs):
        if arguments[:3] == ("worktree", "remove", "--force"):
            return subprocess.CompletedProcess(["git"], 1, "", "locked")
        return original_git(*arguments, **kwargs)

    monkeypatch.setattr(manager, "_git", fail_remove)
    assert manager.cleanup_workspace(lease.lease_id).outcome == "cleanup_failed"
    assert Path(lease.worktree_path).exists()
    monkeypatch.setattr(manager, "_git", original_git)
    assert manager.cleanup_workspace(lease.lease_id).outcome == "released"
    assert patch_path.read_bytes() == original


def test_closed_plan_rejects_nonhuman_and_swapped_mission_proofs(
    repository: Path,
) -> None:
    manager = _manager(repository)
    lease = _lease(manager, repository, "lease:closed", ("closed.txt",))
    Path(lease.worktree_path, "closed.txt").write_text("closed\n")
    returned = manager.return_workspace(lease.lease_id)
    assert returned.patch_digest is not None
    store = _AuthorityStore(repository)
    plan = WorkspaceIntegrationPlan(
        (lease.lease_id,),
        ("mission-grant:closed",),
        request_fingerprint({"value": "closed-a"}),
    )
    proof = _mint_mission_grant_proof(store, "project:test", "mission:test", plan)
    swapped = WorkspaceIntegrationPlan(
        plan.lease_ids,
        plan.grant_ids,
        request_fingerprint({"value": "closed-b"}),
    )
    with pytest.raises(AcceptedPointAuthorityError, match="unauthorized"):
        _apply_accepted_point_plan(store, "project:test", swapped, proof)
    nonhuman = WorkspaceIntegrationPlan(
        plan.lease_ids,
        ("operator:forged",),
        plan.request_fingerprint,
    )
    with pytest.raises(AcceptedPointAuthorityError, match="unauthorized"):
        _apply_accepted_point_plan(store, "project:test", nonhuman, proof)
    assert not hasattr(plan, "manager")
    assert not hasattr(plan, "validate")
    assert _git(repository, "rev-parse", "HEAD") == lease.base_revision


@pytest.mark.parametrize("boundary", ["pre_ref", "post_ref", "post_receipt"])
def test_integration_transaction_recovers_each_git_boundary(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    manager = _manager(repository)
    lease = _lease(manager, repository, "lease:recover", ("recover.txt",))
    Path(lease.worktree_path, "recover.txt").write_text("recovered\n")
    returned = manager.return_workspace(lease.lease_id)
    assert returned.patch_digest is not None
    fired = False

    def fault(_self, observed: str) -> None:
        nonlocal fired
        if observed == boundary and not fired:
            fired = True
            raise RuntimeError("injected accepted-point crash")

    monkeypatch.setattr(WorkspaceManager, "_accepted_point_fault", fault)
    grant = _grant(lease, returned.patch_digest)
    with pytest.raises(RuntimeError, match="injected accepted-point crash"):
        _integrate(manager, [grant])
    result = _integrate(manager, [grant])
    latest = manager.inspect_workspace(lease.lease_id)
    assert result.accepted_revision == _git(repository, "rev-parse", "HEAD")
    assert latest.integration_grant_id == grant.grant_id
    assert latest.integration_request_fingerprint is not None
    assert latest.integration_receipt_digest is not None
