"""Additional explicit controlled fixtures, separate from Git capabilities."""
from typing import NamedTuple


class Transport(NamedTuple):
    pairs: int
    variant: int = 0
    backend_only: bool = False


SESSION='tests/test_experimental_session.py'
RETAINED='tests/test_experimental_retained.py'
PRIORITY='tests/test_experimental_finite_priority.py'
TTL='tests/test_experimental_finite_ttl.py'
RESOURCES='tests/test_experimental_finite_resources.py'
DRAIN='tests/test_experimental_cohort_drain.py'
STARTUP='tests/test_v046_startup_optin.py::test_literal_true_preserves_admission_and_initializes_controlled_owner'
SESSION_NAMES=frozenset('test_'+name for name in '''
installed_adapter_two_prompts_and_http_completion
missing_completion_stops
roles_correction_and_independent_candidate_scope
exclusive_policy_revokes_and_never_calls_ordinary
parked_transport_eof_stops
broker_loss_stops_parked_session
budget_expiry_while_parked
final_reservations_not_consumed_by_early_turns
journal_failure_revokes_without_sending
stop_record_failure_is_not_success
wait_failure_still_kills_owned_process
cancel_during_registration_retains_handle
restart_rejected_and_ordinary_files_untouched
real_active_deadline_cancellation_and_kill
rotated_tokens_stale_identity_candidate_and_duplicates
transport_lost_after_durable_completion_is_not_success
malformed_open_session_rejected
reservation_precedes_transmission_and_send_requires_pipe_write
broker_completion_failure_consumes_send
cleanup_failure_quarantines_but_still_reaps
private_json_broker_unaffected_by_other_sse_server_shutdown
second_launch_failure_reaps_registered_backend
independent_component_loss_revokes_and_retains_reservations
cancel_after_registration_or_during_bridge_keeps_cleanup_owner
registration_after_close_deadline_bounded
transport_uncertainty_persists_quarantine_without_cancelling_waiter
duplicate_pump_failures_keep_first_cause_and_one_owned_cleanup
'''.split())
BACKEND_ONLY=frozenset('test_'+name for name in (
    'cancel_during_registration_retains_handle[1]','registration_after_close_deadline_bounded[1]',
    'cancel_after_registration_or_during_bridge_keeps_cleanup_owner[backend_registered]',
    'second_launch_failure_reaps_registered_backend'))
RETAINED_PAIRS={'test_retained_correction_rotation_then_one_shot':4,
    'test_noncorrectable_real_mcp_never_correction':2,'test_second_generation_failure_cannot_correct':4,
    'test_retained_expected_never_resnapshots':1,'test_missing_completion_consumes_campaign_and_reaps':1,
    'test_two_independent_controlled_lanes_share_campaign_capacity':4}
PRIORITIES={PRIORITY+'::test_all_actual_priority_pairs[PRIORITY-'+str(a+1)+str(b+1)+']':Transport(left+right+1)
    for a,left in enumerate((3,2,1,4,0)) for b,right in enumerate((3,2,1,4,0))}
TTLS=tuple(TTL+'::test_retained_owner_exact_parked_ttl['+str(offset)+']' for offset in (3599,3600,3601))
DRIFTS=(RESOURCES+'::test_observed_input_drift_during_actual_overlap',
    *(RESOURCES+'::test_actual_declared_input_drift_stops_dispatch['+boundary+']' for boundary in ('before-validation','after-validation','pre-integration')))
RESOURCE_NEGATIVES=tuple(RESOURCES+'::test_resource_refusals_have_no_dispatch['+kind+']'
    for kind in ('overlapping-writes','writer-read','cache','output','service','alias','undeclared'))
DRAINS=(*(DRAIN+'::test_persistent_fault_after_backend_receipt_drains['+kind+']' for kind in ('journal','state','completion','consume','combined','cancel','timeout','refusal')),
    *(DRAIN+'::test_failed_or_unsent_owner_revokes_while_received_sibling_drains['+kind+']' for kind in ('timeout','refusal','unsent')),
    DRAIN+'::test_campaign_status_write_failure_cannot_report_success')
IMMUTABLE=tuple('tests/test_immutable_custody.py::test_'+name for name in (
    'persist_reuses_digest_without_caching_observation_or_projection',
    'persist_refuses_manifest_substitution_before_publication'))
GIT_CASES=(*PRIORITIES,*TTLS,*DRIFTS,*RESOURCE_NEGATIVES,*DRAINS,*IMMUTABLE)


def selection(case):
    if type(case) is not str or case.count('::')!=1:
        return None
    file,node=case.split('::')
    name=node.split('[',1)[0]
    if file==SESSION and name in SESSION_NAMES:
        return Transport(2 if name in ('test_roles_correction_and_independent_candidate_scope','test_final_reservations_not_consumed_by_early_turns') else 1,backend_only=node in BACKEND_ONLY)
    if file==RETAINED and name in RETAINED_PAIRS and (name!='test_retained_expected_never_resnapshots' or node.endswith('[parked]')):
        return Transport(RETAINED_PAIRS[name])
    if case in PRIORITIES:
        return PRIORITIES[case]
    if case in (*TTLS,*DRIFTS,*DRAINS):
        return Transport(20 if case in DRAINS else 6)
    if case==STARTUP:
        return Transport(1,1)
    return None
