"""Original extracted persistence probe; no extra process authority."""
COMMAND='from archive_leaf import main;raise SystemExit(main())'
CASES=tuple('tests/test_persistence_schema_v1.py::'+name for name in (
    'test_frozen_fixture_hash_and_candidate_binding',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[planning-mission_planning-None]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[running-mission_running-cleared]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[running_validation-mission_running-cleared]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[attention-attention_needed-None]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[quiescent-mission_running-cleared]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[done-done-None]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[failed-failed-None]',
    'test_fixed_reference_load_restart_resume_matrix_is_repeatable[aborted-aborted-None]',
    'test_absent_member_handoffs_bind_once_across_two_restarts_without_rewrite[legacy-work]',
    'test_absent_member_handoffs_bind_once_across_two_restarts_without_rewrite[legacy-validation]',
    'test_state_mutations_fail_closed_without_rewrite[malformed]',
    'test_state_mutations_fail_closed_without_rewrite[unsupported-state]',
    'test_state_mutations_fail_closed_without_rewrite[future-version]',
    'test_legacy_absent_lineage_projects_empty_without_write_on_inspect',
))
