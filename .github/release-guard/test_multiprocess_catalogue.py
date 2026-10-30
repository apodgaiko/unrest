"""Historical fixture shapes retained only as test data, not launch authority."""
from typing import NamedTuple

from content_manifest import Refused


class Spawn(NamedTuple):
    resources: tuple[str,...]
    maximum: int = 1


def route(module,name,targets,*,target_module=None):
    return {'tests/'+module+'.py::'+name:{('tests.'+(target_module or module),target):spec for target,spec in targets.items()}}


ATTENTION=route('test_attention','test_whole_envelope_bytes_match_in_independent_process_after_restart',
    {'_inspect_in_process':Spawn(('queue',))})
PATCH={
    **route('test_patch_transaction','test_two_mutators_and_two_inspectors_are_process_linearizable',
        {'_mutator_process':Spawn(('arena','queue'),2),'_inspector_process':Spawn(('queue',),2)}),
    **route('test_patch_transaction','test_interrupted_probe_coexists_with_committed_recovery',
        {'_interrupt_rename_probe':Spawn(())}),
}
LOCK={
    **route('test_project_lock','test_legacy_lock_survives_nine_target_project_record_replacement',
        {'_legacy_replacement_holder':Spawn(('queue',)),'_legacy_lock_contender':Spawn(('queue',),2)}),
    **route('test_project_lock','test_spawned_public_mutations_are_exclusive_and_project_scoped',
        {'_holder_process':Spawn(()),'_competitor_process':Spawn(('queue',))}),
    **route('test_project_lock','test_os_releases_lock_after_abrupt_holder_death',
        {'_holder_process':Spawn(()),'_single_call_process':Spawn(('queue',))}),
}
SUPERVISION={**{key:value for role in ('worker','validator','terminal_reviewer')
    for key,value in route('test_supervision','test_independent_child_process_adapter_observes_bound_action['+role+']',
        {'_process_wait_for_steering':Spawn(('queue','queue'))}).items()}}
FINALIZATION={key:value for failed in ('False','True') for ordering in ('finalization_first','publication_first')
    for role in ('worker','validator','terminal_reviewer') for key,value in route('test_supervision_finalization',
        f'test_process_orderings_preserve_carrier_and_terminal_fence[{failed}-{ordering}-{role}]',{'_publisher':Spawn(('pipe',))}).items()}
FINALIZATION.update(route('test_supervision_finalization','test_finalization_real_snapshot_contention_is_bounded',{'_hold_snapshot':Spawn(('pipe',))}))
NESTED={key:value for mode in ('blocked','checkpoint','continue','nudge','other-checkpoint','other-steer','other-stop','recovery','stop','timeout')
    for key,value in route('test_supervision_nested',f'test_real_held_snapshot_refuses_and_reconciles[{mode}]',{'_hold_snapshot':Spawn(('pipe',))}).items()}
NESTED.update(route('test_supervision_nested','test_supplemental_exact_cutoff_and_recovery_rows_share_context',{'_hold_snapshot':Spawn(('pipe',))}))
PATHS={key:value for change in ('hardlink','mode','remove','replace','symlink') for held in ('False','True')
    for key,value in route('test_supervision_paths',f'test_detectable_change_while_real_owner_holds[{change}-{held}]',
        {'_hold_snapshot':Spawn(('pipe',))},target_module='test_supervision_nested').items()}
PATHS.update(route('test_supervision_paths','test_competing_first_use_and_restart_share_carrier',{'_first_save':Spawn(('pipe',),2)}))
TRANSACTIONS={key:value for state in ('cancelled-client','held-inbox','held-recovery') for role in ('worker','validator','terminal_reviewer')
    for key,value in route('test_supervision_transactions',f'test_actual_role_excludes_both_diagnostic_interleavings[{state}-{role}]',{'_child':Spawn(('pipe',))}).items()}
for name in ('test_nonwaiter_contention_is_finite_and_checkpoint_cannot_publish',
        'test_contended_owner_release_before_original_cutoff_succeeds',
        *(f'test_real_contended_wait_uses_original_deadline_without_false_timeout[{delay}]' for delay in ('0','0.06','0.15')),
        *(f'test_exact_and_after_deadline_do_not_retry_ownership[{delay}]' for delay in ('1.0','1.001'))):
    TRANSACTIONS.update(route('test_supervision_transactions',name,{'_child':Spawn(('pipe',))}))
TRANSACTIONS.update(route('test_supervision_transactions','test_distinct_processes_share_tail_and_compete_for_one_action',{'_child':Spawn(('pipe',),5)}))
for cut in ('after_pending_inbox_fsync-steer-True','before_consumed_inbox_fsync-wait-True',
        'after_consumed_inbox_fsync-wait-False','after_receipt_fsync:nudge_consumed-wait-False'):
    TRANSACTIONS.update(route('test_supervision_transactions',f'test_process_death_releases_stable_carrier_and_recovery_never_replays[{cut}]',{'_child':Spawn(('pipe',))}))
TERMINAL=route('test_terminal_review_report_ordering','test_crash_report_survives_finalization_refusal[held_snapshot]',
    {'_hold_snapshot':Spawn(('pipe',))},target_module='test_supervision_finalization')
ROUTES={**ATTENTION,**PATCH,**LOCK,**SUPERVISION,**FINALIZATION,**NESTED,**PATHS,**TRANSACTIONS,**TERMINAL}


def plan(case,target):
    if type(target) is not list or len(target)!=2 or any(type(part) is not str for part in target):
        raise Refused('spawn target metadata schema')
    value=ROUTES.get(case,{}).get(tuple(target))
    if value is None:
        raise Refused('spawn undeclared case and target metadata')
    return value
