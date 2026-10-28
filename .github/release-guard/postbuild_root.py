"""Original extracted persistence probe; no extra process authority."""
import sys

from content_manifest import Refused

COMMAND='from source_root import main;raise SystemExit(main())'
CASES=('tests/test_persistence_schema_v1.py::test_frozen_fixture_hash_and_candidate_binding', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[planning-mission_planning-None]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[running-mission_running-cleared]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[running_validation-mission_running-cleared]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[attention-attention_needed-None]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[quiescent-mission_running-cleared]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[done-done-None]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[failed-failed-None]', 'tests/test_persistence_schema_v1.py::test_fixed_reference_load_restart_resume_matrix_is_repeatable[aborted-aborted-None]', 'tests/test_persistence_schema_v1.py::test_absent_member_handoffs_bind_once_across_two_restarts_without_rewrite[legacy-work]', 'tests/test_persistence_schema_v1.py::test_absent_member_handoffs_bind_once_across_two_restarts_without_rewrite[legacy-validation]', 'tests/test_persistence_schema_v1.py::test_state_mutations_fail_closed_without_rewrite[malformed]', 'tests/test_persistence_schema_v1.py::test_state_mutations_fail_closed_without_rewrite[unsupported-state]', 'tests/test_persistence_schema_v1.py::test_state_mutations_fail_closed_without_rewrite[future-version]', 'tests/test_persistence_schema_v1.py::test_legacy_absent_lineage_projects_empty_without_write_on_inspect')


def run(policy,plugin):
    import pytest
    from release_distribution_oracle import _PYTEST_PROBE
    original=pytest.main
    def main(args,plugins):
        if args!=['-q','tests/test_persistence_schema_v1.py']:
            raise Refused('archive original pytest arguments')
        return original(args,plugins=[*plugins,plugin])
    pytest.main=main
    sys.argv=[policy.profile['native'],policy.profile['argv'][-1]]
    try:
        exec(compile(_PYTEST_PROBE,'<original-distribution-probe>','exec'),{'__name__':'__main__'})
    except SystemExit as result:
        if result.code!=0 or tuple(plugin.completed)!=CASES or policy.poison:
            raise Refused('archive original persistence completion')
    finally:
        pytest.main=original
    from source_profile import case_seal
    policy.client.request('root-finish',case_seal(CASES))
    return 0
