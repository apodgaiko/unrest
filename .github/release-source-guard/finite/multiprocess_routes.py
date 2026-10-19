"""Finite stdlib spawn boundaries for explicit original-parent test owners."""

from __future__ import annotations

import hashlib
import fcntl
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

# The full release collection supplies the closed case set. This is data, not
# a module/descendant permission: every actual call also needs the bound owner,
# original stdlib caller, exact target and current live descriptor custody.
CASES = frozenset(
    [
        ".github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status",
        ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[arguments]",
        ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[caller]",
        ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[case]",
        ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[descriptor]",
        ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[globals]",
        "tests/test_attention.py::test_whole_envelope_bytes_match_in_independent_process_after_restart",
        "tests/test_multiprocess_resource_ownership.py::test_altered_stdlib_stop_is_refused_before_launch",
        "tests/test_multiprocess_resource_ownership.py::test_case_drift_refuses_without_releasing_owned_resources",
        "tests/test_multiprocess_resource_ownership.py::test_joined_spawn_queue_event_and_value_close_before_summary",
        "tests/test_multiprocess_resource_ownership.py::test_live_child_refusal_preserves_original_error_and_does_not_kill",
        "tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved[0]",
        "tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved[17]",
        "tests/test_multiprocess_resource_ownership.py::test_original_failure_or_cancellation_survives_clean_teardown[error0]",
        "tests/test_multiprocess_resource_ownership.py::test_original_failure_or_cancellation_survives_clean_teardown[error1]",
        "tests/test_multiprocess_resource_ownership.py::test_parent_feeder_and_both_pipe_endpoints_are_settled",
        "tests/test_multiprocess_resource_ownership.py::test_preexisting_tracker_is_refused_and_left_owned_by_its_parent",
        "tests/test_multiprocess_resource_ownership.py::test_reused_descriptor_number_has_no_pipe_authority",
        "tests/test_multiprocess_resource_ownership.py::test_unrelated_finalizer_is_not_consumed",
        "tests/test_patch_transaction.py::test_interrupted_probe_coexists_with_committed_recovery",
        "tests/test_patch_transaction.py::test_two_mutators_and_two_inspectors_are_process_linearizable",
        "tests/test_project_lock.py::test_legacy_lock_survives_nine_target_project_record_replacement",
        "tests/test_project_lock.py::test_os_releases_lock_after_abrupt_holder_death",
        "tests/test_project_lock.py::test_spawned_public_mutations_are_exclusive_and_project_scoped",
        "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[terminal_reviewer]",
        "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[validator]",
        "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[worker]",
        "tests/test_supervision_finalization.py::test_finalization_real_snapshot_contention_is_bounded",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-terminal_reviewer]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-validator]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-worker]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-terminal_reviewer]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-validator]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-worker]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-terminal_reviewer]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-validator]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-worker]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-terminal_reviewer]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-validator]",
        "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-worker]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[blocked]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[checkpoint]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[continue]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[nudge]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-checkpoint]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-steer]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-stop]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[recovery]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[stop]",
        "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[timeout]",
        "tests/test_supervision_nested.py::test_supplemental_exact_cutoff_and_recovery_rows_share_context",
        "tests/test_supervision_paths.py::test_competing_first_use_and_restart_share_carrier",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[hardlink-False]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[hardlink-True]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[mode-False]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[mode-True]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[remove-False]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[remove-True]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[replace-False]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[replace-True]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[symlink-False]",
        "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[symlink-True]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-terminal_reviewer]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-validator]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-worker]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-terminal_reviewer]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-validator]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-worker]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-terminal_reviewer]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-validator]",
        "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-worker]",
        "tests/test_supervision_transactions.py::test_contended_owner_release_before_original_cutoff_succeeds",
        "tests/test_supervision_transactions.py::test_distinct_processes_share_tail_and_compete_for_one_action",
        "tests/test_supervision_transactions.py::test_exact_and_after_deadline_do_not_retry_ownership[1.001]",
        "tests/test_supervision_transactions.py::test_exact_and_after_deadline_do_not_retry_ownership[1.0]",
        "tests/test_supervision_transactions.py::test_nonwaiter_contention_is_finite_and_checkpoint_cannot_publish",
        "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_consumed_inbox_fsync-wait-False]",
        "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_pending_inbox_fsync-steer-True]",
        "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_receipt_fsync:nudge_consumed-wait-False]",
        "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[before_consumed_inbox_fsync-wait-True]",
        "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0.06]",
        "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0.15]",
        "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0]",
        "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[held_snapshot]",
        "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[path_fault]",
        "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[storage_fault]",
    ]
)
TARGETS = {
    ("tests.test_attention", "_inspect_in_process"): "tests/test_attention.py",
    (
        "tests.test_multiprocess_resource_ownership",
        "_exit_with_status",
    ): "tests/test_multiprocess_resource_ownership.py",
    (
        "tests.test_multiprocess_resource_ownership",
        "_publish",
    ): "tests/test_multiprocess_resource_ownership.py",
    (
        "tests.test_multiprocess_resource_ownership",
        "_wait",
    ): "tests/test_multiprocess_resource_ownership.py",
    ("tests.test_patch_transaction", "_inspector_process"): "tests/test_patch_transaction.py",
    ("tests.test_patch_transaction", "_interrupt_rename_probe"): "tests/test_patch_transaction.py",
    ("tests.test_patch_transaction", "_mutator_process"): "tests/test_patch_transaction.py",
    ("tests.test_project_lock", "_competitor_process"): "tests/test_project_lock.py",
    ("tests.test_project_lock", "_holder_process"): "tests/test_project_lock.py",
    ("tests.test_project_lock", "_legacy_lock_contender"): "tests/test_project_lock.py",
    ("tests.test_project_lock", "_legacy_replacement_holder"): "tests/test_project_lock.py",
    ("tests.test_project_lock", "_single_call_process"): "tests/test_project_lock.py",
    ("tests.test_supervision", "_process_wait_for_steering"): "tests/test_supervision.py",
    (
        "tests.test_supervision_finalization",
        "_hold_snapshot",
    ): "tests/test_supervision_finalization.py",
    ("tests.test_supervision_finalization", "_publisher"): "tests/test_supervision_finalization.py",
    ("tests.test_supervision_nested", "_hold_snapshot"): "tests/test_supervision_nested.py",
    ("tests.test_supervision_paths", "_first_save"): "tests/test_supervision_paths.py",
    ("tests.test_supervision_transactions", "_child"): "tests/test_supervision_transactions.py",
}


CASE_TARGETS = {
    ".github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status": (
        ("tests.test_multiprocess_resource_ownership", "_exit_with_status"),
    ),
    ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[arguments]": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[caller]": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[case]": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[descriptor]": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    ".github/release-source-guard/multiprocess_guard_methods.py::test_refusal_is_sticky[globals]": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    "tests/test_attention.py::test_whole_envelope_bytes_match_in_independent_process_after_restart": (
        ("tests.test_attention", "_inspect_in_process"),
    ),
    "tests/test_multiprocess_resource_ownership.py::test_altered_stdlib_stop_is_refused_before_launch": (),
    "tests/test_multiprocess_resource_ownership.py::test_case_drift_refuses_without_releasing_owned_resources": (),
    "tests/test_multiprocess_resource_ownership.py::test_joined_spawn_queue_event_and_value_close_before_summary": (
        ("tests.test_multiprocess_resource_ownership", "_publish"),
    ),
    "tests/test_multiprocess_resource_ownership.py::test_live_child_refusal_preserves_original_error_and_does_not_kill": (
        ("tests.test_multiprocess_resource_ownership", "_wait"),
    ),
    "tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved[0]": (
        ("tests.test_multiprocess_resource_ownership", "_exit_with_status"),
    ),
    "tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved[17]": (
        ("tests.test_multiprocess_resource_ownership", "_exit_with_status"),
    ),
    "tests/test_multiprocess_resource_ownership.py::test_original_failure_or_cancellation_survives_clean_teardown[error0]": (),
    "tests/test_multiprocess_resource_ownership.py::test_original_failure_or_cancellation_survives_clean_teardown[error1]": (),
    "tests/test_multiprocess_resource_ownership.py::test_parent_feeder_and_both_pipe_endpoints_are_settled": (),
    "tests/test_multiprocess_resource_ownership.py::test_preexisting_tracker_is_refused_and_left_owned_by_its_parent": (),
    "tests/test_multiprocess_resource_ownership.py::test_reused_descriptor_number_has_no_pipe_authority": (),
    "tests/test_multiprocess_resource_ownership.py::test_unrelated_finalizer_is_not_consumed": (),
    "tests/test_patch_transaction.py::test_interrupted_probe_coexists_with_committed_recovery": (
        ("tests.test_patch_transaction", "_interrupt_rename_probe"),
    ),
    "tests/test_patch_transaction.py::test_two_mutators_and_two_inspectors_are_process_linearizable": (
        ("tests.test_patch_transaction", "_inspector_process"),
        ("tests.test_patch_transaction", "_mutator_process"),
    ),
    "tests/test_project_lock.py::test_legacy_lock_survives_nine_target_project_record_replacement": (
        ("tests.test_project_lock", "_legacy_lock_contender"),
        ("tests.test_project_lock", "_legacy_replacement_holder"),
    ),
    "tests/test_project_lock.py::test_os_releases_lock_after_abrupt_holder_death": (
        ("tests.test_project_lock", "_holder_process"),
        ("tests.test_project_lock", "_single_call_process"),
    ),
    "tests/test_project_lock.py::test_spawned_public_mutations_are_exclusive_and_project_scoped": (
        ("tests.test_project_lock", "_competitor_process"),
        ("tests.test_project_lock", "_holder_process"),
    ),
    "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[terminal_reviewer]": (
        ("tests.test_supervision", "_process_wait_for_steering"),
    ),
    "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[validator]": (
        ("tests.test_supervision", "_process_wait_for_steering"),
    ),
    "tests/test_supervision.py::test_independent_child_process_adapter_observes_bound_action[worker]": (
        ("tests.test_supervision", "_process_wait_for_steering"),
    ),
    "tests/test_supervision_finalization.py::test_finalization_real_snapshot_contention_is_bounded": (
        ("tests.test_supervision_finalization", "_hold_snapshot"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-terminal_reviewer]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-validator]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-finalization_first-worker]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-terminal_reviewer]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-validator]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[False-publication_first-worker]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-terminal_reviewer]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-validator]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-finalization_first-worker]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-terminal_reviewer]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-validator]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_finalization.py::test_process_orderings_preserve_carrier_and_terminal_fence[True-publication_first-worker]": (
        ("tests.test_supervision_finalization", "_publisher"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[blocked]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[checkpoint]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[continue]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[nudge]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-checkpoint]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-steer]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[other-stop]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[recovery]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[stop]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_real_held_snapshot_refuses_and_reconciles[timeout]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_nested.py::test_supplemental_exact_cutoff_and_recovery_rows_share_context": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_competing_first_use_and_restart_share_carrier": (
        ("tests.test_supervision_paths", "_first_save"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[hardlink-False]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[hardlink-True]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[mode-False]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[mode-True]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[remove-False]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[remove-True]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[replace-False]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[replace-True]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[symlink-False]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_paths.py::test_detectable_change_while_real_owner_holds[symlink-True]": (
        ("tests.test_supervision_nested", "_hold_snapshot"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-terminal_reviewer]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-validator]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[cancelled-client-worker]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-terminal_reviewer]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-validator]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-inbox-worker]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-terminal_reviewer]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-validator]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_actual_role_excludes_both_diagnostic_interleavings[held-recovery-worker]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_contended_owner_release_before_original_cutoff_succeeds": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_distinct_processes_share_tail_and_compete_for_one_action": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_exact_and_after_deadline_do_not_retry_ownership[1.001]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_exact_and_after_deadline_do_not_retry_ownership[1.0]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_nonwaiter_contention_is_finite_and_checkpoint_cannot_publish": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_consumed_inbox_fsync-wait-False]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_pending_inbox_fsync-steer-True]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[after_receipt_fsync:nudge_consumed-wait-False]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_process_death_releases_stable_carrier_and_recovery_never_replays[before_consumed_inbox_fsync-wait-True]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0.06]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0.15]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_supervision_transactions.py::test_real_contended_wait_uses_original_deadline_without_false_timeout[0]": (
        ("tests.test_supervision_transactions", "_child"),
    ),
    "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[held_snapshot]": (
        ("tests.test_supervision_finalization", "_hold_snapshot"),
    ),
    "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[path_fault]": (
        ("tests.test_supervision_finalization", "_hold_snapshot"),
    ),
    "tests/test_terminal_review_report_ordering.py::test_crash_report_survives_finalization_refusal[storage_fault]": (
        ("tests.test_supervision_finalization", "_hold_snapshot"),
    ),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_function(function, module):
    if function.__globals__ is not vars(module):
        return False
    path = Path(module.__file__)
    code = compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
    pending = [code]
    while pending:
        candidate = pending.pop()
        if candidate == function.__code__:
            return True
        pending.extend(v for v in candidate.co_consts if inspect.iscode(v))
    return False


def frames_from(frame):
    result = []
    while frame:
        result.append(frame)
        frame = frame.f_back
    return result


def descriptor(fd):
    info = os.fstat(fd)
    return {
        "fd": fd,
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "uid": info.st_uid,
        "access": fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE,
        "inheritable": os.get_inheritable(fd),
    }


def pair(reader, writer):
    left, right = descriptor(reader), descriptor(writer)
    if (
        not stat.S_ISFIFO(left["mode"])
        or not stat.S_ISFIFO(right["mode"])
        or any(left[k] != right[k] for k in ("device", "inode", "mode"))
    ):
        raise RuntimeError("multiprocess FIFO pair custody mismatch")
    return left, right


def match(state, executable, argv, passfds, frame):
    from multiprocessing import popen_spawn_posix, resource_tracker, spawn, util
    import subprocess

    root = Path(state["checkout"])
    case = state.get("case")
    if case not in CASES:
        raise RuntimeError("multiprocess case is outside finite inventory")
    helper = sys.modules.get("tests.multiprocess_lifetime")
    if helper is None or Path(helper.__file__) != root / "tests/multiprocess_lifetime.py":
        raise RuntimeError("multiprocess owner module missing")
    for name in ("tests/multiprocess_lifetime.py", case.split("::")[0]):
        if digest(root / name) != state["product_pins"][name]:
            raise RuntimeError("multiprocess current source drift")
    if (
        os.fsdecode(executable) != sys.executable
        or Path(sys.executable).resolve() != Path(state["runtime"]["realpath"])
        or digest(executable) != state["runtime"]["sha256"]
        or os.getcwd() != str(root)
    ):
        raise RuntimeError("multiprocess runtime or cwd mismatch")
    stack = frames_from(frame)
    source_frames = [f for f in stack if f.f_code is helper.SpawnResources.context.__code__]
    tracker = resource_tracker._resource_tracker
    if not source_function(util._args_from_interpreter_flags, subprocess):
        raise RuntimeError("multiprocess interpreter flag source mismatch")
    if not source_function(spawn.get_command_line, spawn):
        raise RuntimeError("multiprocess command renderer source mismatch")
    prefix = "from multiprocessing.resource_tracker import main;main("
    flags = [
        os.fsdecode(v)
        for v in __import__(
            "multiprocessing.util", fromlist=["_args_from_interpreter_flags"]
        )._args_from_interpreter_flags()
    ]
    if (
        len(argv) == len(flags) + 3
        and argv[: 1 + len(flags)] == [sys.executable, *flags]
        and argv[-2] == "-c"
        and argv[-1].startswith(prefix)
        and argv[-1].endswith(")")
    ):
        caller = resource_tracker.ResourceTracker._launch
        if (
            frame.f_code is not caller.__code__
            or frame.f_globals is not vars(resource_tracker)
            or not source_function(caller, resource_tracker)
            or len(source_frames) != 1
        ):
            raise RuntimeError("multiprocess tracker stdlib or owner caller mismatch")
        owner_frame = source_frames[0]
        owner = owner_frame.f_locals["self"]
        if (
            owner_frame.f_globals is not vars(helper)
            or type(owner) is not helper.SpawnResources
            or not source_function(helper.SpawnResources.context, helper)
            or owner.parent != os.getpid()
            or owner.case != case
            or owner.identity is not None
            or owner.tracker is not tracker
            or tracker._fd is not None
            or tracker._pid is not None
        ):
            raise RuntimeError("multiprocess tracker acquisition identity mismatch")
        read, write = frame.f_locals["r"], frame.f_locals["w"]
        if argv[-1] != prefix + str(read) + ")" or sorted(passfds) != sorted(
            [sys.stderr.fileno(), read]
        ):
            raise RuntimeError("multiprocess tracker exact vector mismatch")
        pipes = pair(read, write)
        kind = "source-multiprocess-tracker"
    else:
        caller = popen_spawn_posix.Popen._launch
        if (
            frame.f_code is not caller.__code__
            or frame.f_globals is not vars(popen_spawn_posix)
            or not source_function(caller, popen_spawn_posix)
        ):
            raise RuntimeError("multiprocess spawn stdlib caller mismatch")
        process = frame.f_locals["process_obj"]
        target = process._target
        target_module = sys.modules.get(target.__module__)
        target_path = TARGETS.get((target.__module__, target.__name__))
        if (
            target_path is None
            or (target.__module__, target.__name__) not in CASE_TARGETS[case]
            or target_module is None
            or target is not getattr(target_module, target.__name__)
            or target.__globals__ is not vars(target_module)
            or Path(target_module.__file__) != root / target_path
            or digest(root / target_path) != state["product_pins"][target_path]
            or process._parent_pid != os.getpid()
        ):
            raise RuntimeError("multiprocess finite child target mismatch")
        code = state["isolated_source_code"](root / target_path)
        expected = state["isolated_named"](code, target.__name__)
        if target.__code__ != expected:
            raise RuntimeError("multiprocess target rewritten code mismatch")
        read, write = frame.f_locals["child_r"], frame.f_locals["parent_w"]
        expected_argv = [
            os.fsdecode(v) for v in spawn.get_command_line(tracker_fd=tracker._fd, pipe_handle=read)
        ]
        if argv != expected_argv or sorted(passfds) != sorted(frame.f_locals["self"]._fds):
            raise RuntimeError("multiprocess spawn vector or descriptors mismatch")
        reference = helper._process_owners.get(process)
        owner = reference() if reference is not None else None
        if (
            owner is None
            or type(owner) is not helper.SpawnResources
            or process not in owner.processes
            or owner.parent != os.getpid()
            or owner.case != case
            or owner.tracker is not tracker
            or owner.fd != tracker._fd
            or owner.pid != tracker._pid
        ):
            raise RuntimeError("multiprocess original process owner missing")
        binding = helper._process_bindings.get(process)
        if (
            binding is None
            or process._target is not binding[0]
            or process._args is not binding[1]
            or process._kwargs is not binding[2]
        ):
            raise RuntimeError("multiprocess acquisition arguments changed")
        tracker_pipe = descriptor(owner.fd)
        custody = descriptor(owner.custody)
        if any(tracker_pipe[k] != custody[k] for k in ("device", "inode", "mode")):
            raise RuntimeError("multiprocess tracker descriptor generation mismatch")
        pipes = pair(read, write)
        pair(frame.f_locals["parent_r"], frame.f_locals["child_w"])
        kind = "source-multiprocess-spawn"
    inherited = [descriptor(fd) for fd in sorted(set(passfds))]
    binding = {
        "path": str(root / "tests/multiprocess_lifetime.py"),
        "sha256": state["product_pins"]["tests/multiprocess_lifetime.py"],
        "function": "context",
        "case": case,
    }
    return {"class": kind, "source_binding": binding, "python": True}, inherited, pipes


def install(state, append, refuse, ready, bootstrap, inherited_environment):
    from multiprocessing import util

    original = util.spawnv_passfds
    if not source_function(original, util):
        refuse("multiprocess_original_spawnv_source_mismatch")

    def spawnv(executable, arguments, passfds):
        ready(state["token"])
        try:
            argv = [os.fsdecode(v) for v in arguments]
            registration, descriptors, pipes = match(
                state, executable, argv, passfds, sys._getframe(1)
            )
        except (OSError, RuntimeError, KeyError, AttributeError, TypeError, ValueError) as error:
            refuse("multiprocess_binding:" + str(error))
        token = uuid.uuid4().hex
        payload = {
            "token": token,
            "class": registration["class"],
            "case": state["case"],
            "mode": "inline",
            "target": argv[argv.index("-c") + 1],
            "isolated": "-I" in argv[1 : argv.index("-c")],
            "sys_argv": ["-c", *argv[argv.index("-c") + 2 :]],
            "orig_argv": argv,
            "path0": "",
            "source_binding": registration["source_binding"],
            "operation_lineage": [],
            "isolated_refusal": None,
        }
        code = bootstrap(
            state["manifest_path"], state["pin"], state["guard"], state["guard_sha256"], payload
        )
        child_argv = [argv[0], *argv[1 : argv.index("-c")], "-c", code]
        append(
            {
                "kind": "actual_launch_binding",
                "token": token,
                "transformed_argv_sha256": hashlib.sha256(
                    json.dumps(child_argv).encode()
                ).hexdigest(),
                "bootstrap_sha256": hashlib.sha256(code.encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(inherited_environment(), sort_keys=True).encode()
                ).hexdigest(),
                "cwd": os.getcwd(),
                "multiprocess_descriptors": descriptors,
                "multiprocess_fifo_pair": pipes,
            }
        )
        append(
            {
                "kind": "admitted",
                "token": token,
                **registration,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            }
        )
        pid = original(executable, child_argv, passfds)
        append(
            {
                "kind": "launch_lifecycle_binding",
                "token": token,
                "start_new_session": False,
                "executable_sha256": digest(executable),
            }
        )
        append({"kind": "registered", "token": token, "pid": pid, **registration})
        deadline = time.monotonic() + 5
        journal = Path(state["events"]) / (str(pid) + ".jsonl")
        while True:
            rows = (
                [json.loads(line) for line in journal.read_text().splitlines()]
                if journal.exists()
                else []
            )
            if any(
                row.get("kind") == "ready"
                and row.get("token") == token
                and row.get("owner_pid") == pid
                and row.get("parent_pid") == os.getpid()
                and row.get("manifest_sha256") == state["pin"]
                and row.get("guard_sha256") == state["guard_sha256"]
                for row in rows
            ):
                break
            if time.monotonic() >= deadline:
                refuse("multiprocess_child_READY_deadline")
            time.sleep(0.001)
        append({"kind": "bounded_multiprocess_READY_handshake", "token": token, "pid": pid})
        return pid

    util.spawnv_passfds = spawnv
