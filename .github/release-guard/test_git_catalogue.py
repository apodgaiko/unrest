"""Retired per-node Git observations; never imported by enforcement."""

CANDIDATE_TEST='tests/test_experimental_candidate.py'

CANDIDATE_PIN='6827bd92719ed7e138980b9e4dc3d9e6fdc775444093609fe78c0e806981c39e'

CANDIDATE_CONSUMERS={
    'test_literal_manifest_and_independent_oracle':(None,),
    'test_immutable_binding_and_failed_observation':(None,),
    'test_input_changes_refuse':('content', 'delete', 'mode', 'staged', 'index-delete', 'index-add', 'assume', 'skip', 'intent', 'unmerged', 'extra', 'extra-delete', 'untracked', 'ignored'),
    'test_hardlinks_refuse':('tracked/output', 'extra/output', 'tracked/tracked', 'input/outside', 'output/outside'),
    'test_equal_independent_files_and_outputs':(None,),
    'test_noncanonical_declarations':('../escape', '/absolute', './out', 'out/', 'a//b', 'a/../b', '*.txt', '.git', 'a/.GiT/x', '.unrest/x', 'a\\\\b', 'trailing.', '\\xe9', 'a\\n'),
    'test_overlap':('extras0-outputs0', 'extras1-outputs1', 'extras2-outputs2', 'extras3-outputs3', 'extras4-outputs4', 'extras5-outputs5'),
    'test_unsafe_files':('input-symlink', 'output-symlink', 'output-leaf-symlink', 'fifo', 'nested', 'alias', 'missing-output', 'output-file'),
    'test_symlink_ancestor_and_git_indirection':(None,),
    'test_config_canaries_never_called':('filter.canary.clean-CANARY', 'filter.canary.smudge-CANARY', 'diff.canary.textconv-CANARY', 'diff.external-CANARY', 'core.fsmonitor-CANARY', 'core.hooksPath-CANARY', 'credential.helper-CANARY', 'remote.origin.url-ext::CANARY', 'remote.origin.uploadpack-CANARY', 'include.path-CANARY', 'extensions.partialclone-origin', 'remote.origin.promisor-true', 'core.sparsecheckout-true', 'extensions.objectformat-sha256'),
    'test_ambient_overrides_scrubbed':(None,),
    'test_metadata_refusal_before_git':('shallow', 'objects/info/alternates', 'objects/info/http-alternates', 'objects/pack/pack-x.promisor', 'objects/pack/pack-x.pack', 'refs/replace/replaced', 'info/grafts', 'commondir', 'hooks/pre-commit', 'config.worktree'),
    'test_wrong_ids_types_and_unrelated_history':(None,),
    'test_raw_object_integrity':('wrong-content-candidate', 'wrong-content-base', 'wrong-content-tree', 'wrong-content-blob', 'wrong-content-ancestry', 'wrong-type-candidate', 'wrong-type-base', 'wrong-type-tree', 'wrong-type-blob', 'wrong-type-ancestry', 'missing-candidate', 'missing-base', 'missing-tree', 'missing-blob', 'missing-ancestry', 'truncated-candidate', 'truncated-base', 'truncated-tree', 'truncated-blob', 'truncated-ancestry'),
    'test_object_size_count_aggregate_deadlines':(None,),
    'test_observer_leaves_all_repository_bytes_and_modes_unchanged':(None,),
    'test_unsupported_tree_entries':('120000', '160000'),
    'test_manifest_constructor_cannot_retain_mutable_values':(None,),
    'test_index_independent_refusals':('mode', 'checksum', 'version', 'extension', 'missing'),
    'test_nested_bare_repository_refuses':(None,),
    'test_executable_tracked_file_and_nested_extra':(None,),
    'test_declarations_reject_custom_containers':(None,),
    'test_declaration_deadline_starts_before_validation':(None,),
    'test_overlap_loop_checks_deadline':(None,),
    'test_observation_and_verification_create_no_object_read_children':(None,),
}

CANDIDATE_CASES=tuple(CANDIDATE_TEST+'::'+name+('['+parameter+']' if parameter is not None else '') for name,parameters in CANDIDATE_CONSUMERS.items() for parameter in parameters)

MEASUREMENT_TEST='tests/test_measurement.py'

MEASUREMENT_PIN='d850dcaf77c4b4ebd08efa87089cbc7b59762d5eb8d7fd0b673a9e043bc3e97f'

MEASUREMENT_SYNTHETIC=('test_successful_exact_protocol_publishes_sanitized_recomputable_bundle',
    *(f'test_oracle_cache_and_cost_fail_closed[provider{index}-invalid]' for index in range(3)),
    'test_noise_over_fifteen_percent_is_inconclusive','test_unknown_reported_cost_is_not_collapsed_to_zero',
    'test_publication_rejects_unknown_or_private_fields_and_preserves_existing')

MEASUREMENT_NAMES=(*MEASUREMENT_SYNTHETIC,'test_evolution_cases_use_real_public_state_machine_and_cold_state',
    'test_project_cases_use_real_run_control_and_nested_acp','test_confirmation_and_protocol_drift_do_not_invoke_provider',
    'test_product_digest_excludes_only_results')

MEASUREMENT_CASES=tuple(MEASUREMENT_TEST+'::'+name for name in MEASUREMENT_NAMES)

FIXTURE_SERVER_INQUIRY='tests/test_server.py::test_real_run_inquiry_workspace_and_campaign_results_cross_validator'

FIXTURE_SLOTS={
    'tests/test_foundation_authority.py::test_workspace_mutations_replay_exactly_and_collision_precedes_events':('repo',),
    'tests/test_foundation_authority.py::test_integration_requires_retained_exact_grant_and_consumes_it_once':('repo',),
    'tests/test_foundation_authority.py::test_scope_mismatched_retained_grant_fails_before_parent_effect':('repo',),
    'tests/test_foundation_authority.py::test_tool_error_mapping_is_closed_and_private_details_survive_async_run':('repo',),
    'tests/test_foundation_authority.py::test_async_project_lock_contention_is_public_busy_with_private_cause':('repo',),
    'tests/test_foundation_authority.py::test_evolution_provider_and_git_faults_reconcile_without_reexecution':('repo',),
    'tests/test_foundation_integration.py::test_two_disjoint_mutable_tasks_use_distinct_worktrees_and_integrate':('repo',),
    'tests/test_foundation_integration.py::test_scope_escape_withholds_entire_parallel_batch':('repo',),
    'tests/test_project_adapter.py::test_two_isolated_leaves_join_in_deterministic_order_and_serialize':('project',),
    'tests/test_project_adapter.py::test_leaf_failure_blocks_join_and_withholds_integration':('project',),
    'tests/test_project_adapter.py::test_cancellation_stops_after_atomic_leaf_batch':('project',),
    'tests/test_project_adapter.py::test_execution_bound_leaves_join_pending':('project',),
    'tests/test_project_adapter.py::test_invalid_graphs_and_mismatched_runtime_fail_closed':('project',),
    **{'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step['+value+']':('project',)
       for value in ('0','-1','True','1.5','1','None')},
    'tests/test_project_adapter.py::test_missing_submitted_dag_is_exact_and_never_coordinates':('project',),
    'tests/test_improve_adapter.py::test_nominal_provider_free_open_add_evaluate_review_inspect':('project',),
    'tests/test_improve_adapter.py::test_success_stops_at_reviewed_decision_needed':('project',),
    'tests/test_improve_adapter.py::test_resume_from_persisted_candidate':('project',),
    'tests/test_improve_adapter.py::test_missing_campaign_freeze_is_exact_and_inert':('project',),
    'tests/test_improve_adapter.py::test_missing_lease_and_candidate_are_distinct_and_inert':('project',),
    'tests/test_improve_adapter.py::test_mismatched_freeze_lease_and_candidate_are_exact':('project',),
    'tests/test_improve_adapter.py::test_expired_active_lease_mismatch_is_exact_and_inert':('project',),
    'tests/test_improve_adapter.py::test_resume_preserves_existing_review_outcome':('project',),
    'tests/test_improve_adapter.py::test_serialization_is_canonical_and_resume_stable':('project',),
    'tests/test_improve_adapter.py::test_public_result_preserves_provenance_without_private_content':('project',),
    'tests/test_improve_adapter.py::test_no_later_decision_network_or_external_effect':('project',),
    **{f'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[{value}-{field}]':('project',)
       for value in ('-1','True','1.5','1') for field in ('candidate_cost_steps','evaluation_cost_steps')},
    'tests/test_improve_adapter.py::test_configured_provider_is_rejected_before_any_campaign_operation':('project',),
    'tests/test_v04_activation.py::test_project_direct_and_api_carriers_preserve_topology_and_state':('repo-direct', 'repo-api'),
    'tests/test_v04_activation.py::test_improvement_direct_and_api_carriers_stop_private_and_provider_free':('improve-parity',),
    'tests/test_v04_activation.py::test_improvement_invalid_and_provider_reject_before_campaign_effect':('improve-invalid', 'improve-provider'),
    'tests/test_v04_activation.py::test_project_click_and_subprocess_stop_without_exact_request':('repo-click', 'repo-subprocess'),
    'tests/test_v04_activation.py::test_improvement_click_and_subprocess_stop_without_exact_request':('improve-click-cli', 'improve-subprocess-cli'),
}

FIXTURE_SLOTS.update(dict.fromkeys(CANDIDATE_CASES,('repository',)))

FIXTURE_SLOTS.update(dict.fromkeys(MEASUREMENT_CASES,('source','workspace')))

SITE_CASES = (
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

FIXTURE_SLOTS[FIXTURE_SERVER_INQUIRY]=('repository',)
