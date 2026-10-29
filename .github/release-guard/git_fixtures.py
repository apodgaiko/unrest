"""Exact additional Git fixture slots; no module-wide execution authority."""
from pathlib import Path
from dataclasses import dataclass
import re

from content_manifest import Refused
from launch_policy import source_unit
from owned_fixture import acquire
from candidate_git import CASES as CANDIDATE_CASES,TEST as CANDIDATE_TEST,PIN as CANDIDATE_PIN


@dataclass(frozen=True)
class Fixture:
    family: str
    init: tuple[str,...]
    user: str
    email: str
    stage: tuple[str,...]
    phase: str

    @property
    def commands(self):
        return (self.init,('config','user.name',self.user),('config','user.email',self.email),
                ('add',*self.stage),('commit','-m','base'))


MODULES={
    CANDIDATE_TEST:Fixture('candidate',('init','--initial-branch=main','--object-format=sha1'),'Fixture','fixture@example.invalid',('.',),'setup'),
    'tests/test_foundation_authority.py':Fixture('workspaces',('init',),'Authority Test','authority@example.test',('.',),'call'),
    'tests/test_foundation_integration.py':Fixture('workspaces',('init',),'Foundation Integration','foundation@example.test',('.',),'call'),
    'tests/test_project_adapter.py':Fixture('workspaces',('init','-b','main'),'Project Adapter Test','project-adapter@example.test',('README.md','.gitignore'),'setup'),
    'tests/test_improve_adapter.py':Fixture('evolution',('init','-b','main'),'Improve Adapter Test','improve@example.test',('README.md',),'setup'),
    'tests/test_v04_activation.py':Fixture('activation',('init','-b','main'),'ACT-190 Activation','act190@example.test',('README.md',),'call'),
}
PINS={
    CANDIDATE_TEST:CANDIDATE_PIN,
    'tests/test_foundation_authority.py':'c8f63d70d4dcc3d74215a9db538632fc9115086d32d42f633235135dcaea2c70',
    'tests/test_foundation_integration.py':'bcbddfff3ffabd8b4374be17fa22b35872bd347d2daa8ca9ee3132f007caa8ef',
    'tests/test_improve_adapter.py':'d3c9c1fa8461db4e30b3d3239bf52746018a56b957f4699ddff7572c10be3290',
    'tests/test_project_adapter.py':'b48d315875eedb9350219fcc3c203c778f329389f32d8f787de0c574390235cf',
    'tests/test_v04_activation.py':'4741feb6a71d9c06be777a08a34e064be0610c1f8b755ebfffef21489621c435',
}
SLOTS={
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
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[0]':('project',),
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[-1]':('project',),
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[True]':('project',),
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[1.5]':('project',),
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[1]':('project',),
    'tests/test_project_adapter.py::test_invalid_step_matrix_fails_before_coordinator_step[None]':('project',),
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
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[-1-candidate_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[-1-evaluation_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[True-candidate_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[True-evaluation_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[1.5-candidate_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[1.5-evaluation_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[1-candidate_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_invalid_costs_fail_during_request_construction[1-evaluation_cost_steps]':('project',),
    'tests/test_improve_adapter.py::test_configured_provider_is_rejected_before_any_campaign_operation':('project',),
    'tests/test_v04_activation.py::test_project_direct_and_api_carriers_preserve_topology_and_state':('repo-direct', 'repo-api'),
    'tests/test_v04_activation.py::test_improvement_direct_and_api_carriers_stop_private_and_provider_free':('improve-parity',),
    'tests/test_v04_activation.py::test_improvement_invalid_and_provider_reject_before_campaign_effect':('improve-invalid', 'improve-provider'),
    'tests/test_v04_activation.py::test_project_click_and_subprocess_stop_without_exact_request':('repo-click', 'repo-subprocess'),
    'tests/test_v04_activation.py::test_improvement_click_and_subprocess_stop_without_exact_request':('improve-click-cli', 'improve-subprocess-cli'),
}
SLOTS.update(dict.fromkeys(CANDIDATE_CASES,('repository',)))


def fixture(case):
    if case not in SLOTS:
        raise Refused('Git exact additional fixture case')
    value=MODULES[case.split('::')[0]]
    if value.family=='activation':
        from dataclasses import replace
        value=replace(value,family='evolution' if SLOTS[case][0].startswith('improve-') else 'workspaces')
    return value


def root(host,case,repository):
    file=case.split('::')[0]
    source_unit(Path(host.meta['checkout']),file,PINS[file])
    path=Path(repository)
    parent,info=acquire(str(path.parent),Path(host.meta['owned']),re.sub(r'[\W]','_',case.split('::')[1])[:30],20000)
    if path.name not in SLOTS[case] or path.resolve()!=path:
        raise Refused('Git exact additional repository slot')
    generation=(str(parent),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(('git-fixture',case),generation)!=generation:
        raise Refused('Git additional pytest generation changed')


GROUPS={
    'candidate113':CANDIDATE_CASES,
    'foundation8':tuple(case for case in SLOTS if case.startswith(('tests/test_foundation_authority.py::','tests/test_foundation_integration.py::'))),
    'project12':tuple(case for case in SLOTS if case.startswith('tests/test_project_adapter.py::')),
    'improve20':tuple(case for case in SLOTS if case.startswith('tests/test_improve_adapter.py::')),
    'activation5':tuple(case for case in SLOTS if case.startswith('tests/test_v04_activation.py::')),
}
