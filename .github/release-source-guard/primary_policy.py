"""Primary script authority, distinct from source-fixture UV registrations."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shlex
from typing import NamedTuple

from ci_commands import bind_generated
from preflight_policy import CASES as PREFLIGHT_CASES

FOCUSED = {'Install dependencies', 'Import package', 'Supported CLI surfaces',
           'Lint (ruff)', 'Type-check (mypy)', 'Repository contract'}
SHELL = '/bin/bash'
SHELL_FLAGS = ['--noprofile', '--norc', '-e', '-o', 'pipefail']
UV = '/opt/source-bootstrap/bin/uv'
PYTHON = '/usr/local/bin/python-primary-audit'
SOURCE = 'v0.4.7 source suite'
# Independent of focused capsules and every original test's own deadline.
SOURCE_BUDGET = {'root_seconds': 7200, 'collection_seconds': 300, 'drain_seconds': 60}
TEST_CASE = 'tests/test_stdio_startup.py::test_real_startup_rejection_is_bounded_and_body_free[invalid0-worker]'

TEST_SEAM_CASES = (
    'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct',
    'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix[claude]',
    'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix[codex]',
    'tests/test_distribution_check.py::test_checker_builds_and_executes_15_cases_with_extracted_provenance',
)

TEST_STARTUP_CASES = tuple(
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[' + failure + '-' + role + ']'
    for failure in ('exit', 'deadline', 'cancel')
    for role in ('work', 'validate', 'terminal_reviewer'))
TEST_READINESS_CASES = tuple(
    'tests/test_acp_runner.py::test_readiness_attributes_local_child_and_drains[' + mode + ']'
    for mode in ('early_exit', 'never_ready', 'ready', 'cancel'))
TEST_INVENTORY_CASES = tuple(
    'tests/test_acp_runner.py::test_real_mcp_inventory_fd_redacts_before_crash_and_restart[' + mode + ']'
    for mode in ('worker', 'terminal-reviewer'))
TEST_STREAM_CASES = tuple(
    'tests/test_acp_runner.py::test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained[' + mode + ']'
    for mode in ('worker', 'terminal-reviewer'))
TEST_FORMAT_CASES = tuple(
    'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[' + role + '-' + provider + ']'
    for role in ('worker', 'validator') for provider in ('claude', 'codex'))
TEST_NATIVE_SLEEP_CASES = ('tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[worker-claude]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[worker-codex]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[validator-claude]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[validator-codex]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[worker-claude]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[worker-codex]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[validator-claude]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[validator-codex]', 'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[claude]', 'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[codex]', 'tests/test_acp_runner.py::test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[claude]', 'tests/test_acp_runner.py::test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[codex]', 'tests/test_acp_runner.py::test_owned_node_launch_uses_one_identical_plan[work]', 'tests/test_acp_runner.py::test_owned_node_launch_uses_one_identical_plan[validate]', 'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[work]', 'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[validate]', 'tests/test_acp_runner.py::test_terminal_real_startup_failure_is_safe_and_starts_no_protocol')
TEST_CLEANUP_CASES = (
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[exit-work]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[exit-validate]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[exit-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[deadline-work]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[deadline-validate]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[deadline-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[cancel-work]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[cancel-validate]',
    'tests/test_acp_cleanup.py::test_startup_failure_attribution_and_owned_cleanup[cancel-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[deep_json-work]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[deep_json-validate]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[deep_json-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[array_id-work]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[array_id-validate]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[array_id-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[object_id-work]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[object_id-validate]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[object_id-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-work]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-validate]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[reader-work]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[reader-validate]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[reader-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[client-work]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[client-validate]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[client-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[progress-work]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[progress-validate]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[progress-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[cancel-work]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[cancel-validate]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[cancel-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[primary-work]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[primary-validate]',
    'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[primary-terminal_reviewer]',
    'tests/test_acp_cleanup.py::test_client_cleanup_reaps_main_after_reader_failure',
    'tests/test_acp_cleanup.py::test_client_exhausts_terminals_pending_and_main[False]',
    'tests/test_acp_cleanup.py::test_client_exhausts_terminals_pending_and_main[True]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[1_0]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[1_1]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[None]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[True]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[1.0]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[rid5]',
    'tests/test_acp_cleanup.py::test_response_correlation_keeps_numeric_identity[rid6]',
    'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[observer]',
    'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[cancel]',
    'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[transport]',
    'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[False]',
    'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[True]',
)
TEST_CANDIDATE_FIXTURE_CASES = (
    'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[work]',
    'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[validate]',
    'tests/test_acp_runner.py::test_terminal_real_startup_failure_is_safe_and_starts_no_protocol',
    'tests/test_experimental_candidate.py::test_literal_manifest_and_independent_oracle',
)
TEST_CANDIDATE_ORACLE_CASES = ('tests/test_experimental_candidate.py::test_literal_manifest_and_independent_oracle',)
TEST_NATIVE_TERMINAL_CASES = (
    'tests/test_acp_runner.py::test_run_node_with_mock_agent',
    'tests/test_acp_runner.py::test_terminal_create_optional_nulls_use_omission_defaults[params0]',
    'tests/test_acp_runner.py::test_terminal_create_optional_nulls_use_omission_defaults[params1]',
)
TEST_LAUNCH_PLAN_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_launch_preflight.py::test_relative_and_empty_path_entries_use_launch_cwd[tools]', 'tests/test_launch_preflight.py::test_relative_and_empty_path_entries_use_launch_cwd[]', 'tests/test_launch_preflight.py::test_real_direct_launch_preserves_original_argv0[relative]', 'tests/test_launch_preflight.py::test_real_direct_launch_preserves_original_argv0[absolute]', 'tests/test_launch_preflight.py::test_real_bare_launch_uses_later_valid_path_candidate', 'tests/test_launch_preflight.py::test_real_spawn_preserves_exact_plan_fields', 'tests/test_launch_preflight.py::test_direct_plan_copies_mutable_inputs_before_real_spawn', 'tests/test_launch_preflight.py::test_plan_preserves_legal_empty_environment_name_and_equals_value', 'tests/test_launch_preflight.py::test_real_invalid_format_is_distinct_safe_startup_failure')
TEST_APPROVAL_UNIX_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_approval_recovery.py::test_exact_supported_backend_admission[cc0a05e34876414280a79726153d0fe8d55c93f704ef6c292ec409bfe36d5b06]', 'tests/test_approval_recovery.py::test_exact_supported_backend_admission[09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be]', 'tests/test_approval_recovery.py::test_exact_supported_backend_admission[0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28]', 'tests/test_approval_recovery.py::test_selection_rechecks_unsafe_display_without_opening_form', 'tests/test_approval_recovery.py::test_actual_mcp_accept_single_submit_and_receipt', 'tests/test_approval_recovery.py::test_pending_inspection_reference_is_read_only')
TEST_SOCKET_CARRIER_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_supervision_paths.py::test_static_carrier_refuses_without_outside_effects[socket-False]', 'tests/test_supervision_paths.py::test_static_carrier_refuses_without_outside_effects[socket-True]')
TEST_APPROVAL_CLOSURE_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[decline-None-True]', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[cancel-None-True]', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[accept-content2-True]', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[accept-content3-True]', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[accept-content4-True]', 'tests/test_approval_recovery.py::test_actual_mcp_nonconsent_never_submits[accept-content5-False]', 'tests/test_approval_recovery.py::test_expiry_cancel_commit_and_wrong_id_refuse[expiry]', 'tests/test_approval_recovery.py::test_expiry_cancel_commit_and_wrong_id_refuse[cancel]', 'tests/test_approval_recovery.py::test_expiry_cancel_commit_and_wrong_id_refuse[completion]', 'tests/test_approval_recovery.py::test_expiry_cancel_commit_and_wrong_id_refuse[wrong_id]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[success]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[delayed_interrupt]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[drop_ack]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[re_denied]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[multiple]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[failed_interrupt]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[outstanding]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[late_ack]', 'tests/test_approval_recovery.py::test_actual_acp_owner_native_subprocess_order_and_cleanup[crash_after_send]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[success]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel_after_send]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash_after_send]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel_after_continue]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash_after_continue]', 'tests/test_approval_recovery.py::test_duplicate_review_does_not_open_or_clobber_first_form', 'tests/test_approval_recovery.py::test_exact_expiry_boundary_and_fixed_retention', 'tests/test_approval_recovery.py::test_real_deadline_timer_erases_memory_and_cleans_reader', 'tests/test_approval_recovery.py::test_completion_commits_during_human_response_before_submit', 'tests/test_approval_recovery.py::test_cleanup_failure_preserves_first_and_exhausts_owned_paths', 'tests/test_approval_recovery.py::test_host_disconnect_during_form_never_submits')
TEST_APPROVAL_REMAINING_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[success]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel_after_send]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash_after_send]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[cancel_after_continue]', 'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[crash_after_continue]', 'tests/test_approval_recovery.py::test_duplicate_review_does_not_open_or_clobber_first_form', 'tests/test_approval_recovery.py::test_exact_expiry_boundary_and_fixed_retention', 'tests/test_approval_recovery.py::test_real_deadline_timer_erases_memory_and_cleans_reader', 'tests/test_approval_recovery.py::test_completion_commits_during_human_response_before_submit', 'tests/test_approval_recovery.py::test_cleanup_failure_preserves_first_and_exhausts_owned_paths', 'tests/test_approval_recovery.py::test_host_disconnect_during_form_never_submits')
TEST_APPROVAL_EXPIRY_CASES = ('tests/test_acp_runner.py::test_run_node_with_mock_agent', 'tests/test_approval_recovery.py::test_real_deadline_timer_erases_memory_and_cleans_reader', 'tests/test_approval_recovery.py::test_real_deadline_expires_during_settlement_handshake', 'tests/test_approval_recovery.py::test_expiry_cleanup_closes_owner_after_writer_error[reset]', 'tests/test_approval_recovery.py::test_expiry_cleanup_closes_owner_after_writer_error[other]')
TEST_CLEANUP_SUCCESS_CASES = (
    'tests/test_acp_runner.py::test_run_node_with_mock_agent',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-work]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-validate]',
    'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-terminal_reviewer]',
)
TEST_CLEANUP_FIXTURE_CASES = TEST_STARTUP_CASES + (
    'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[False]',
    'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[True]',
)
TEST_TERMINAL_ORDER_CASES = tuple(
    'tests/test_capability_policy.py::test_real_terminal_create_excludes_raw_wrappers_and_preserves_transform[' + profile + '-' + role + '-' + provider + ']'
    for profile in ('safe', 'unsafe-development-unrestricted')
    for role in ('worker', 'validator', 'terminal_reviewer') for provider in ('claude', 'codex')) + tuple(
    'tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[' + mode + ']'
    for mode in ('cancel', 'crash', 'cancel_after_send', 'crash_after_send', 'cancel_after_continue', 'crash_after_continue'))

TEST_COMPLETION_PIPE_CASES = tuple(
    'tests/test_completion_setup.py::test_real_roles_first_use[' + scenario + '-' + role + '-targets' + targets + ']'
    for scenario in ('invalid-invalid', 'valid-invalid', 'valid-valid', 'distinct')
    for role, targets in (('work', '0'), ('work', '1'), ('validate', '2'))) + TEST_CLEANUP_SUCCESS_CASES


TEST_RECEIPT_CLEANUP_CASES = TEST_COMPLETION_PIPE_CASES + tuple(
    'tests/test_controlled_python_acp.py::test_real_local_boundaries[' + case + ']'
    for case in ('receipts', 'correction', 'uncertainty', 'completion_failure',
                 'journal_failure', 'expiry', 'identity', 'bridge_marking'))


INITIALIZATION_POSTIMAGE_CASES = ('tests/test_controlled_python_acp.py::test_programmatic_private_preflight', 'tests/test_experimental_startup_diagnostics.py::test_initialization_probe_real_controlled_path_no_prompt', 'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[refusal]', 'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[timeout]', 'tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close[permission]', 'tests/test_experimental_startup_diagnostics.py::test_initialized_owner_has_no_http_mutation_authority', 'tests/test_experimental_startup_diagnostics.py::test_coordinator_persists_startup_and_separate_cleanup_failure')
REGISTRATION_POSTIMAGE_CASES = tuple('tests/test_controlled_python_acp.py::test_actual_registration[' + case + ']' for case in ('delayed-1', 'delayed-2', 'late-1', 'late-2'))
CANCELLATION_POSTIMAGE_CASES = tuple('tests/test_controlled_python_acp.py::test_cancel_at_actual_boundary[' + stage + ']' for stage in ('backend_registered', 'adapter_registered', 'auth', 'forwarding'))
TEST_INITIALIZATION_CASES = INITIALIZATION_POSTIMAGE_CASES + ('tests/test_experimental_startup_diagnostics.py::test_broker_start_preserves_primary_over_cleanup', 'tests/test_controlled_python_acp.py::test_native_pin_refusal_stays_native[launcher]', 'tests/test_controlled_python_acp.py::test_native_pin_refusal_stays_native[runtime]')

# Read literal diagnostic data without importing source-only guard code. Native
# import machinery would create a cache that the unchanged READY guard refuses.
_BACKEND_POSTIMAGES = ast.literal_eval(ast.parse(
    (Path(__file__).parent / 'finite/backend_postimage_catalog.py').read_bytes()).body[2].value)
_SETUP_CASES = ast.literal_eval(ast.parse(
    (Path(__file__).parent / 'finite/orders_git_data.py').read_bytes()).body[3].value)
_BACKEND_CONFIG = tuple(c for c, row in _BACKEND_POSTIMAGES.items()
                        if c not in INITIALIZATION_POSTIMAGE_CASES + CANCELLATION_POSTIMAGE_CASES + REGISTRATION_POSTIMAGE_CASES and row['script_sha256'] == 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53')
_BACKEND_MISC = tuple(c for c in _BACKEND_POSTIMAGES if c not in _SETUP_CASES and c not in _BACKEND_CONFIG and c not in INITIALIZATION_POSTIMAGE_CASES + CANCELLATION_POSTIMAGE_CASES + REGISTRATION_POSTIMAGE_CASES)
_BACKEND_ORDERS = tuple(c for c in _BACKEND_POSTIMAGES if 'finite_orders.py::' in c)
_SETUP_ADDITIONAL = tuple(c for c in _SETUP_CASES if 'finite_orders.py::' not in c
                          and c not in INITIALIZATION_POSTIMAGE_CASES)
TEST_BACKEND_POSTIMAGE_GROUPS = (
    _BACKEND_MISC[:20], _BACKEND_MISC[20:35], _BACKEND_MISC[35:],
    _BACKEND_ORDERS[:10], _BACKEND_ORDERS[10:20], _BACKEND_ORDERS[20:],
) + tuple(_SETUP_ADDITIONAL[i:i + 10] for i in range(0, len(_SETUP_ADDITIONAL), 10)) + (_BACKEND_CONFIG[:4], _BACKEND_CONFIG[4:])

TEST_GIT_OVERHEAD_CASES = (_BACKEND_ORDERS[0],)
TEST_COHORT_STARTUP_CASES = TEST_GIT_OVERHEAD_CASES + tuple(
    'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success['
    + name + ']' for name in ('claude', 'codex'))

TEST_APPROVAL_STARTUP_COST_CASES = ('tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[success]',)

TEST_CONTROLLED_CANCEL_CASES = tuple(
    'tests/test_controlled_python_acp.py::test_cancel_at_actual_boundary[' + stage + ']'
    for stage in ('backend_registered', 'adapter_registered', 'auth', 'forwarding'))

TEST_CONTROLLED_REGISTRATION_CASES = tuple(
    'tests/test_controlled_python_acp.py::test_actual_registration[' + case + '-' + str(number) + ']'
    for case in ('delayed', 'late') for number in (1, 2))

TEST_JOURNAL_CONTEXT_CASES = TEST_CONTROLLED_REGISTRATION_CASES + (TEST_CONTROLLED_CANCEL_CASES[-1],)

TEST_RECORDED_CLEANUP_GROUPS = tuple(
    tuple(case for case in TEST_CLEANUP_CASES
          if '::test_recorded_transport_failures[' + fault + '-' in case)
    for fault in ('deep_json', 'array_id', 'object_id', 'success'))

TEST_SELECTIONS = ((TEST_CASE,), TEST_SEAM_CASES, PREFLIGHT_CASES, TEST_STARTUP_CASES, TEST_CLEANUP_CASES, TEST_READINESS_CASES, TEST_INVENTORY_CASES, TEST_STREAM_CASES, TEST_FORMAT_CASES, TEST_NATIVE_SLEEP_CASES, TEST_CANDIDATE_FIXTURE_CASES, TEST_CANDIDATE_ORACLE_CASES, TEST_NATIVE_TERMINAL_CASES, TEST_LAUNCH_PLAN_CASES, TEST_APPROVAL_UNIX_CASES, TEST_SOCKET_CARRIER_CASES, TEST_APPROVAL_CLOSURE_CASES, TEST_APPROVAL_REMAINING_CASES, TEST_APPROVAL_EXPIRY_CASES, TEST_CLEANUP_SUCCESS_CASES, TEST_CLEANUP_FIXTURE_CASES, TEST_TERMINAL_ORDER_CASES, TEST_COMPLETION_PIPE_CASES, TEST_RECEIPT_CLEANUP_CASES, TEST_GIT_OVERHEAD_CASES, TEST_COHORT_STARTUP_CASES, TEST_APPROVAL_STARTUP_COST_CASES, TEST_CONTROLLED_CANCEL_CASES, TEST_CONTROLLED_REGISTRATION_CASES, TEST_JOURNAL_CONTEXT_CASES, TEST_INITIALIZATION_CASES) + TEST_BACKEND_POSTIMAGE_GROUPS + TEST_RECORDED_CLEANUP_GROUPS
TEST_SEAM_ROOT_SECONDS = 600


def sha(body):
    return hashlib.sha256(body).hexdigest()


def plan(script, workflow, source_input=None):
    duty = bind_generated(script, workflow)
    if duty['name'] == SOURCE:
        from primary_source_inputs import require_full_input
        require_full_input(source_input, script, workflow)
        commands = [shlex.split(line) for line in script.decode().splitlines()]
        if commands != [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']]:
            raise RuntimeError('primary_source_literal_drift')
        return {'schema': 'unrest.v046.primary-script-plan.v1', 'duty': SOURCE,
                'script_sha256': duty['script_sha256'], 'workflow_sha256': sha(workflow.encode()),
                'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
                'commands': commands, 'source_checkpoint_ready': False, 'selected_carrier': None,
                'timeout_seconds': SOURCE_BUDGET['root_seconds'], 'source_mode': 'SOURCE',
                'source_budget': SOURCE_BUDGET, 'source_input_sha256': sha(canonical(source_input))}
    from primary_custody import ORDER
    if duty['name'] in ORDER:
        from primary_package_inputs import plan as package_plan
        return package_plan(script, workflow, source_input)
    if duty['name'] not in FOCUSED:
        # Package-domain and final source-carrier closure are separate data
        # obligations. A focused capsule cannot grant their authority.
        raise RuntimeError('primary_full_or_package_closure_missing')
    commands = [shlex.split(line) for line in script.decode().splitlines()]
    if any(not row or row[0] != 'uv' for row in commands):
        raise RuntimeError('primary_focused_renderer_drift')
    return {'schema': 'unrest.v046.primary-script-plan.v1', 'duty': duty['name'],
            'script_sha256': duty['script_sha256'], 'workflow_sha256': sha(workflow.encode()),
            'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
            'commands': commands, 'source_checkpoint_ready': False, 'selected_carrier': None,
            'timeout_seconds': 180}


def environment(*, source=False):
    result = {'HOME': '/work/home', 'PATH': '/opt/source-bootstrap/bin:/usr/local/bin:/usr/bin:/bin',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'TMPDIR': '/work/owned/tmp' if source else '/work/tmp',
            'UV_CACHE_DIR': '/work/cache', 'UV_OFFLINE': '1', 'UV_NO_INDEX': '1',
            'UV_FIND_LINKS': '/opt/source-bootstrap/wheelhouse',
            'UV_PYTHON': PYTHON, 'UV_PYTHON_DOWNLOADS': 'never',
            'UV_CONFIG_FILE': '/inputs/uv.toml', 'PYTHONDONTWRITEBYTECODE': '1',
            'SOURCE_DATE_EPOCH': '1700000000', 'GITHUB_WORKSPACE': '/source'}
    if source:
        # Existing byte-pinned adapter data satisfies stat-only preflight.
        # Its Node image stays nonexecutable; no execution route is admitted.
        result['PATH'] += ':/native/bin'
    from primary_type_cache import runtime_environment
    return runtime_environment(result, source=source)


def command_environment(value, root, *, source=False):
    """Only Bash and pinned UV's documented finite additions are admissible."""
    actual = dict(value)
    virtual = actual.pop('VIRTUAL_ENV', None)
    build = Path(virtual) if isinstance(virtual, str) else None
    if (virtual is not None and virtual != '/source/.venv'
            and not (build.parent == Path('/work/cache/builds-v0') and build.name.startswith('.tmp')
                     and build.resolve() == build)):
        return False
    recursion = actual.pop('UV_RUN_RECURSION_DEPTH', None)
    if recursion not in (None, '1'):
        return False
    for key, allowed in {'PWD': {'/source'}, 'OLDPWD': {'/source'}, 'SHLVL': {'0', '1'},
                         '_': {SHELL, UV} | ({'/usr/bin/env', '/bin/env'} if source else set()),
                         'UV': {UV}, 'VIRTUAL_ENV': {'/source/.venv'},
                         'PYTHONIOENCODING': {'utf-8:backslashreplace'}}.items():
        if key in actual and actual.pop(key) not in allowed:
            return False
    path = actual.pop('PATH', None)
    if path not in {root['PATH'], '/source/.venv/bin:' + root['PATH'],
                    (virtual + '/bin:' + root['PATH']) if virtual else root['PATH']}:
        return False
    return actual == {key: value for key, value in root.items() if key != 'PATH'}


def backend_request(script, cache='/work/cache'):
    """Exact pinned UV PEP517 renderer; output paths remain finite owned data."""
    import ast
    try:
        nodes = ast.parse(script).body
        request = nodes[-1].items[0].context_expr.args[0].value
    except (SyntaxError, AttributeError, IndexError):
        return None
    path = Path(request)
    if (path.parent.parent != Path(cache) / 'builds-v0' or not path.parent.name.startswith('.tmp')
            or path.resolve() != path):
        return None
    prefix = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
              'sys.path = [] + sys.path\n\nimport setuptools.build_meta as backend\n')
    requires = (prefix + '\nimport json\n\nget_requires_for_build = getattr(backend, "get_requires_for_build_editable", None)\n'
                'if get_requires_for_build:\n    requires = get_requires_for_build({})\nelse:\n    requires = []\n\n'
                f'with open("{request}", "w") as fp:\n    json.dump(requires, fp)\n')
    if path.name == 'get_requires_for_build_editable.txt' and script == requires:
        return 'get_requires_for_build_editable'
    # The output directory is a native UV-owned sibling of the response file.
    calls = [node for node in ast.walk(ast.parse(script)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'build_editable']
    if len(calls) != 1 or len(calls[0].args) != 3 or not isinstance(calls[0].args[0], ast.Constant):
        return None
    output = calls[0].args[0].value
    if not isinstance(output, str):
        return None
    target = Path(output)
    if (target.resolve() != target or not target.is_relative_to(cache)
            or not any(target.is_relative_to(Path(cache) / name)
                       for name in ('builds-v0', 'built-wheels-v5'))):
        return None
    build = (prefix + f'\n\nwheel_filename = backend.build_editable("{output}", {{}}, None)\n'
             f'with open("{request}", "w") as fp:\n    fp.write(wheel_filename)\n')
    if path.name == 'build_editable.txt' and script == build:
        return 'build_editable'
    return None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def console(name, interpreter='/source/.venv/bin/python'):
    entries = {'unrest': ('unrest_harness.cli', 'cli'),
               'unrest-server': ('unrest_harness.server', 'main'),
               'mypy': ('mypy.__main__', 'console_entry'), 'pytest': ('pytest', 'console_main')}
    module, function = entries[name]
    return ('#!' + interpreter + '\n# -*- coding: utf-8 -*-\n'
            'import sys\nfrom ' + module + ' import ' + function + '\n'
            'if __name__ == "__main__":\n'
            '    if sys.argv[0].endswith("-script.pyw"):\n'
            '        sys.argv[0] = sys.argv[0][:-11]\n'
            '    elif sys.argv[0].endswith(".exe"):\n'
            '        sys.argv[0] = sys.argv[0][:-4]\n'
            '    sys.exit(' + function + '())\n').encode()


def public_plan(spec):
    """Public evidence carries only closed identities/counts and input hashes."""
    import re
    from primary_custody import ORDER
    if (spec['duty'] not in FOCUSED | {SOURCE, 'TEST-source-positive', 'TEST-source-poison', *ORDER}
            or spec['timeout_seconds'] != root_seconds(spec)
            or spec['source_checkpoint_ready'] is not False or spec['selected_carrier'] is not None
            or any(not isinstance(spec[key], str) or not re.fullmatch('[0-9a-f]{64}', spec[key])
                   for key in ('script_sha256', 'workflow_sha256'))):
        raise RuntimeError('primary_public_plan_refused')
    return {'schema': 'unrest.v046.primary-script-identity.v1', 'duty': spec['duty'],
            'script_sha256': spec['script_sha256'], 'workflow_sha256': spec['workflow_sha256'],
            'command_count': len(spec['commands']), 'timeout_seconds': spec['timeout_seconds'],
            'source_checkpoint_ready': False, 'selected_carrier': None}


def root_seconds(spec):
    """Closed setup resources; none of these values changes a test deadline."""
    mode = spec.get('source_mode')
    if mode == 'SOURCE':
        return SOURCE_BUDGET['root_seconds']
    if mode in {'TEST-positive', 'TEST-poison'}:
        scripts = {('env -u CODEX_PATH uv run pytest -q ' + ' '.join(cases)).encode()
                   for cases in (TEST_SEAM_CASES, TEST_CLEANUP_CASES, TEST_APPROVAL_CLOSURE_CASES, TEST_APPROVAL_REMAINING_CASES, TEST_TERMINAL_ORDER_CASES, TEST_COMPLETION_PIPE_CASES, TEST_RECEIPT_CLEANUP_CASES, TEST_GIT_OVERHEAD_CASES, TEST_COHORT_STARTUP_CASES, *TEST_BACKEND_POSTIMAGE_GROUPS)}
        for script in scripts:
            if (spec['commands'] == [shlex.split(script.decode())]
                    and spec['script_sha256'] == sha(script)
                    and spec['shell_argv'] == [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh']
                    and spec['duty'] == 'TEST-source-' + mode.removeprefix('TEST-')
                    and spec['source_budget'] == SOURCE_BUDGET
                    and spec['source_input_sha256'] == sha(canonical({'mode': mode}))):
                return TEST_SEAM_ROOT_SECONDS
    return 180


class PrimaryRootAllocation(NamedTuple):
    seconds: int
    binding_sha256: str
    shell_argv: tuple[str, ...]


def primary_root_allocation():
    """Read the trusted controller inputs afresh, before trace attachment.

    No requested cap or payload switch is accepted. Reconstruct the exact plan,
    including full SOURCE readiness, and bind the current head/support bytes.
    """
    from primary_source_inputs import test_plan, decode
    from checkpoint_receipt import DEFINITION_FIELDS
    import re
    from structured_evidence import source_binding
    script = Path('/inputs/github-script.sh').read_bytes()
    workflow = Path('/source/.github/workflows/ci.yml').read_text()
    source_path = Path('/inputs/source-input.json')
    source_input = decode(source_path.read_bytes()) if source_path.is_file() else None
    mode_path = Path('/inputs/test-mode')
    mode = mode_path.read_text() if mode_path.is_file() else None
    spec = test_plan(script, workflow, mode) if mode else plan(script, workflow, source_input)
    supplied = json.loads(Path('/inputs/plan.json').read_bytes())
    expected = json.loads(Path('/inputs/identity.json').read_bytes())
    identity = source_binding(Path('/inputs/transport-identity.json').read_bytes())['identity']
    support = Path(__file__).resolve().parent
    pins = {str(path.relative_to(support)): sha(path.read_bytes())
            for path in sorted(support.rglob('*'))
            if path.is_file() and path.suffix in {'.py', '.json', '.pem', '.c'}}
    seconds = root_seconds(spec)
    kind = 'primary-source' + ('-' + mode.removeprefix('TEST-') if mode else '')
    if (type(expected) is not dict or set(expected) != set(DEFINITION_FIELDS)
            or any(type(pin) is not str or not re.fullmatch(
                '[0-9a-f]{40}' if key in {'head_sha', 'source_tree'} else '[0-9a-f]{64}', pin)
                for key, pin in expected.items())
            or identity['artifact_name'] != f"v046-source-{kind}-{identity['run_id']}-{identity['run_attempt']}"):
        raise ValueError('primary_root_allocation_identity')
    if (canonical(spec) != canonical(supplied)
            or type(supplied['timeout_seconds']) is not int
            or supplied['timeout_seconds'] != seconds or seconds not in {600, 7200}
            or Path('/source/.git/HEAD').read_text() != expected['head_sha'] + '\n'
            or expected['head_sha'] != identity['head_sha']
            or expected['workflow_sha256'] != sha(workflow.encode())
            or expected['guard_definition_sha256'] != sha(json.dumps(pins, sort_keys=True).encode())
            or identity['support_sha256'] != sha(canonical(pins))
            or (mode is None and source_input['definition'] != expected)):
        raise ValueError('primary_root_allocation_refused')
    public_plan(spec)
    binding = {'plan': spec, 'expected': expected, 'identity': identity, 'source_input': source_input}
    return PrimaryRootAllocation(seconds, sha(canonical(binding)), tuple(spec['shell_argv']))


def require_primary_root_allocation(value, timeout, child, allowed):
    if (type(value) is not PrimaryRootAllocation or type(timeout) is not int
            or timeout != value.seconds or value != primary_root_allocation()
            or len(allowed) != 1 or allowed[0].get('pid') != child
            or allowed[0]['path'] != value.shell_argv[0]
            or allowed[0]['argv'] != list(value.shell_argv)):
        raise ValueError('primary_root_allocation_refused')
