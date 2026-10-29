"""Finite operations and original byte pins; no Python caller authentication."""
from git_fixtures import SLOTS,GROUPS as FIXTURE_GROUPS
PINS = {
    'tests/test_workspaces.py': '590b0e1d07d73a6a2a770edb41d839ec903f53b8c28ff19be16a0e13dc6abe14',
    'tests/test_evolution.py': '778aeac7d73291bbeaaad3cb2ad2905d6a4e93a723a42378daa080222e7c57db',
    'src/unrest_harness/workspaces.py': '9359e8bb14e68531a487aa8fbeb0eeb91cab444a1e24bbf02c0f03462e205f92',
    'src/unrest_harness/evolution.py': '4f5547d803449eab5ce969688533afbf8dd099a117888d524187dc851d39b79d',
    'src/unrest_harness/accepted_point_authority.py': '4df305ef4be4c176d77e3faddfdb625193599bc9152c9cf470a763f3c58a9c80',
}
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
SHARED_OPERATIONS = (
    'apply',
    'check-index',
    'checkout',
    'clean',
    'commit-tree',
    'date',
    'diff-return',
    'head',
    'inside',
    'integration-add',
    'inventory',
    'lease-add',
    'parent-ref',
    'prune',
    'remove-tree',
    'reset-parent',
    'rollback-add',
    'rollback-reset',
    'rollback-update',
    'stage-return',
    'top',
    'update-parent',
    'verify-base',
    'write-tree',
)
FIXTURE_OPERATIONS = {
    'workspaces': (
        'commit-advance',
        'commit-base',
        'commit-child',
        'config-email',
        'config-name',
        'head',
        'head-tree',
        'init',
        'stage-advance',
        'stage-base',
        'stage-child',
    ),
    'evolution': (
        'commit-base',
        'config-email',
        'config-name',
        'head',
        'init',
        'stage-base',
    ),
}
OPERATIONS = {family: tuple(sorted(set(SHARED_OPERATIONS) | set(operations)))
              for family,operations in FIXTURE_OPERATIONS.items()}

OWNED_BODY = 'import time; time.sleep(60)'

WORKSPACE_CASES=CASES
CASES=(*CASES,*SLOTS)
GROUPS={"workspaces24":WORKSPACE_CASES,**FIXTURE_GROUPS}
