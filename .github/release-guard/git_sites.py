"""Finite operations and original byte pins; no Python caller authentication."""
from measurement_git import COLD as MEASUREMENT_OPERATIONS
from history_git import CASES as HISTORY_CASES
from git_fixtures import SLOTS
from git_commands import OPERATIONS as COMMANDS,SETUP
CASES = (
    'tests/test_workspaces.py::test_exact_clean_base_scope_and_t1_label_survive_restart',
    'tests/test_workspaces.py::test_two_leases_use_distinct_worktrees_and_scope_escape_fails',
    'tests/test_workspaces.py::test_return_is_identity_bound_append_only_and_parent_is_unchanged',
    'tests/test_workspaces.py::test_disjoint_returns_integrate_in_deterministic_order',
    'tests/test_workspaces.py::test_overlap_stale_and_validation_failure_preserve_parent',
    'tests/test_workspaces.py::test_expiry_orphan_cleanup_and_retry_preserve_evidence',
    'tests/test_workspaces.py::test_child_commit_is_not_parent_authority',
    'tests/test_workspaces.py::test_owned_process_budget_and_restart_cleanup',
    'tests/test_workspaces.py::test_mutated_patch_artifact_and_cleanup_failure_are_retained',
    'tests/test_workspaces.py::test_closed_plan_rejects_nonhuman_and_swapped_mission_proofs',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[pre_ref]',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[post_ref]',
    'tests/test_workspaces.py::test_integration_transaction_recovers_each_git_boundary[post_receipt]',
    'tests/test_evolution.py::test_campaign_freeze_is_complete_immutable_and_restartable',
    'tests/test_evolution.py::test_genealogy_retains_failures_retries_and_rejections',
    'tests/test_evolution.py::test_independent_evaluation_review_and_reward_hack_fail_closed',
    'tests/test_evolution.py::test_missing_provider_is_non_improving_and_cannot_promote',
    'tests/test_evolution.py::test_human_promotion_is_exact_atomic_and_idempotent',
    'tests/test_evolution.py::test_post_accept_receipt_failure_reconciles_without_reapply',
    'tests/test_evolution.py::test_exact_human_rollback_and_receipt_recovery',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[pre_ref]',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[post_ref]',
    'tests/test_evolution.py::test_rollback_transaction_recovers_each_git_boundary[post_receipt]',
    'tests/test_evolution.py::test_rollback_validation_failure_preserves_current',
)
WORKSPACE_ONLY=frozenset({'head-tree','stage-advance','commit-advance','stage-child','commit-child'})
SHARED_OPERATIONS=tuple(sorted(set(COMMANDS)-WORKSPACE_ONLY-set(SETUP)))
OPERATIONS={'workspaces':tuple(sorted(COMMANDS)),
    'evolution':tuple(sorted(set(COMMANDS)-WORKSPACE_ONLY)),
    'candidate':('init','candidate-command'),'measurement':('init','measurement-command',*MEASUREMENT_OPERATIONS)}

OWNED_BODY = 'import time; time.sleep(60)'

CASES=(*CASES,*SLOTS,*HISTORY_CASES)
