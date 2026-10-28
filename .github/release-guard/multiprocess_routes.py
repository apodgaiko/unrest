"""Finite Queue/shared-value families; target names are descriptive metadata."""
from typing import NamedTuple

from content_manifest import Refused


class Spawn(NamedTuple):
    resources: tuple[str,...]
    maximum: int = 1
    status: int = 0


def route(module,name,targets):
    return {'tests/'+module+'.py::'+name:{('tests.'+module,target):spec for target,spec in targets.items()}}


ATTENTION=route('test_attention','test_whole_envelope_bytes_match_in_independent_process_after_restart',
    {'_inspect_in_process':Spawn(('queue',))})
PATCH={
    **route('test_patch_transaction','test_two_mutators_and_two_inspectors_are_process_linearizable',
        {'_mutator_process':Spawn(('arena','queue'),2),'_inspector_process':Spawn(('queue',),2)}),
    **route('test_patch_transaction','test_interrupted_probe_coexists_with_committed_recovery',
        {'_interrupt_rename_probe':Spawn((),status=73)}),
}
LOCK={
    **route('test_project_lock','test_legacy_lock_survives_nine_target_project_record_replacement',
        {'_legacy_replacement_holder':Spawn(('queue',)),'_legacy_lock_contender':Spawn(('queue',),2)}),
    **route('test_project_lock','test_spawned_public_mutations_are_exclusive_and_project_scoped',
        {'_holder_process':Spawn(()),'_competitor_process':Spawn(('queue',))}),
    **route('test_project_lock','test_os_releases_lock_after_abrupt_holder_death',
        {'_holder_process':Spawn((),status=-15),'_single_call_process':Spawn(('queue',))}),
}
SUPERVISION={**{key:value for role in ('worker','validator','terminal_reviewer')
    for key,value in route('test_supervision','test_independent_child_process_adapter_observes_bound_action['+role+']',
        {'_process_wait_for_steering':Spawn(('queue','queue'))}).items()}}
ROUTES={**ATTENTION,**PATCH,**LOCK,**SUPERVISION}
GROUPS={'mp-attention1':tuple(ATTENTION),'mp-patch2':tuple(PATCH),'mp-lock3':tuple(LOCK),'mp-supervision3':tuple(SUPERVISION)}


def plan(case,target):
    if type(target) is not list or len(target)!=2 or any(type(part) is not str for part in target):
        raise Refused('spawn target metadata schema')
    value=ROUTES.get(case,{}).get(tuple(target))
    if value is None:
        raise Refused('spawn undeclared case and target metadata')
    return value
