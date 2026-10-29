"""Exact original cohort cases and finite process admission ceilings."""
TEST = 'tests/test_experimental_cohort.py'


def rows(name, parameters, pairs, git):
    return {TEST+'::test_'+name+('['+value+']' if value is not None else ''):(pairs,git) for value in parameters}


CAMPAIGNS = {
    **rows('real_controlled_campaign_and_streaming',(None,),20,68),
    **rows('actual_four_arm_timing_and_model_conformance',
        (f'{timing}-{streaming}-{reuse}' for timing in ('straggler','equal','long-validator')
         for streaming in (False,True) for reuse in (False,True)),6,20),
    **rows('two_lane_rotation_uses_controlled_budget_only',('False',),12,36),
    **rows('two_lane_rotation_uses_controlled_budget_only',('True',),10,28),
    **rows('observed_mutation_during_overlap_stops_integration',(None,),4,12),
    **rows('actual_parked_ttl_forbids_next_dispatch',(None,),1,8),
    **rows('stop_while_worker_active_drains_without_validation',(None,),1,8),
    **rows('final_gate_rejects_stale_reused_and_dissent',('stale','early-session','early-generation','dissent'),3,12),
    **rows('final_gate_rejects_stale_reused_and_dissent',('repeated-session',),4,12),
    **rows('failed_final_transport_keeps_consumed_budget',(None,),3,12),
    **rows('runtime_capacity_parking_and_correction_priority',('1-2','2-2','4-4','8-4'),8,28),
    **rows('stop_boundaries_preserve_consumption_and_no_new_sends',('reservation','dispatch'),0,4),
    **rows('stop_boundaries_preserve_consumption_and_no_new_sends',('completion',),1,8),
    **rows('runtime_budget_before_recheck_retains_dissent',(None,),2,12),
    **rows('stop_after_sibling_pass_drains_and_retains_both_verdicts',('z-first','a-second'),4,12),
    **rows('actual_completion_batches_use_authored_ties_in_every_phase',(None,),8,28),
}
GIT_ONLY = {
    **rows('sealing_is_drained_and_only_last_seal_recovers',(None,),0,8),
    **rows('snapshot_copy_race_refuses_without_publishing_or_following_link',('body','symlink'),0,8),
    **rows('custody_undeclared_and_changed_inputs_refuse',('extra','tracked','config','symlink'),0,4),
    **rows('custody_undeclared_and_changed_inputs_refuse',('index',),0,5),
    **rows('actual_target_verdict_required',('None','verdicts1','verdicts2','verdicts3','verdicts4'),0,4),
    **rows('target_verdict_immutable_and_cross_lane_substitution',(None,),0,4),
    **rows('integrates_in_authored_order_and_rechecks_base',(None,),0,22),
    **rows('combined_candidate_authority_seal_refuses_substitution',('writes','targets','resource','permissions'),0,4),
    **rows('integration_scope_and_conflict_negatives',('outside-scope','base','staged-conflict','overlap'),0,12),
    **rows('active_broker_mutation_prevents_candidate_validation_seal',(None,),0,4),
}
CASES = {**CAMPAIGNS, **GIT_ONLY}
EXTRA = {
    TEST+'::test_custody_undeclared_and_changed_inputs_refuse[index]':(('add','b'),),
    TEST+'::test_integrates_in_authored_order_and_rechecks_base':(('show','HEAD~1:a'),('show','HEAD~1:b')),
    **{TEST+'::test_integration_scope_and_conflict_negatives['+attack+']':commands+(('show','HEAD:a'),)
       for attack,commands in (
           ('outside-scope',(('add','b'),('commit','-m','unauthorized'))),
           ('base',(('add','b'),('commit','-m','different base'))),
           ('staged-conflict',(('add','a'),)),('overlap',()))},
}
