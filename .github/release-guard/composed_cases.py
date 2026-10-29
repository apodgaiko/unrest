"""Authored process topology for the original local composed-server cases."""
TEST='tests/test_server.py'
HERMETIC=TEST+'::test_composed_hermetic_acp_topology_uses_public_attached_control'
STOP=TEST+'::test_composed_restart_stop_replacement_and_cancel_are_distinct'
PARITY=tuple(TEST+'::test_composed_all_role_parity_restart_and_cooperative_stop['+role+']'
    for role in ('worker','validator','terminal_reviewer'))
MATRIX=tuple(TEST+'::test_composed_completion_refusal_matrix_uses_original_generation['+variant+'-'+role+']'
    for variant in ('repair-restart','second-invalid-restart','second-invalid-live') for role in ('worker','validator'))
DEFECT=TEST+'::test_composed_defective_work_reaches_independent_validator_dissent'
UNDELIVERABLE=TEST+'::test_composed_undeliverable_nudge_continues_without_body_persistence'
DIRECT=tuple(TEST+'::test_real_targetless_dispatch_consumption['+str(attention)+']' for attention in (False,True))
WORK=(('worker-1','work'),)
PAIR=(*WORK,('validator-1','validate'))
REVIEW=((None,'terminal_reviewer'),)
# Each row binds HTTP parent slot, operation, project slot, and node/role sequence.
STEPS={
    HERMETIC:((0,'advance_project',0,PAIR),(0,'decide_attention',0,()),(0,'end_mission',0,REVIEW)),
    STOP:((0,'advance_project',0,PAIR),(1,'decide_attention',0,()),
        (1,'advance_project',0,(('validator-2','validate'),)),(1,'advance_project',1,(('cancel-worker','work'),))),
    PARITY[0]:((0,'advance_project',0,WORK),),
    PARITY[1]:((0,'advance_project',0,PAIR),),
    PARITY[2]:((0,'advance_project',0,PAIR),(0,'decide_attention',0,()),(0,'end_mission',0,REVIEW)),
    **{case:((0,'advance_project',0,PAIR if index in (0,1,3,5) else WORK),) for index,case in enumerate(MATRIX)},
    DEFECT:((0,'advance_project',0,PAIR),),UNDELIVERABLE:((0,'advance_project',0,WORK),),
    **dict.fromkeys(DIRECT,()),
}
DIRECT_NODES={DIRECT[0]:(('measure','work'),('publish','work')),DIRECT[1]:(('measure','work'),)}
HTTP={HERMETIC:1,STOP:4,**dict.fromkeys(PARITY,3),
    **{case:2 if index<4 else 1 for index,case in enumerate(MATRIX)},
    DEFECT:1,UNDELIVERABLE:1,**dict.fromkeys(DIRECT,1)}
ADOPT={STOP:0,PARITY[0]:0,PARITY[1]:0,PARITY[2]:2,**dict.fromkeys(MATRIX[:4],0)}
CASES=tuple(HTTP)


def nodes(case):
    return tuple(node for row in STEPS[case] for node in row[3])+DIRECT_NODES.get(case,())


def queries(case):
    return sum(query_count(case,role) for _,role in nodes(case))



def query_count(case,role):
    return (1 if case in DIRECT else 2) if role=='work' else 0


def targets(case,node):
    return ([] if node=='measure' else ['VAL-RESULT']) if case in DIRECT else ['VAL-COMPOSED']


def ps_limit(case):
    # Original cleanup polls at 20ms for at most five seconds per owned group.
    return 20+252*(HTTP[case]+len(STEPS[case]))
