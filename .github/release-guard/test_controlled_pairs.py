"""Cross-owner/replay negatives for the finite controlled owner graph."""
from pathlib import Path

import pytest

from content_manifest import Refused
from controlled_cases import CASES
from controlled_pairs import before_spawn, limits, scope


def test_every_catalogue_case_has_a_finite_source_bound():
    assert len(CASES) == 123
    assert all(1 <= limits(case)[0] <= 12 and 0 <= limits(case)[1] <= 43 for case in CASES)


def test_pair_cannot_borrow_another_owner_backend():
    case = next(case for case in CASES if 'test_ack_durability[' in case)
    records = [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}]
    actors = {12:{'returned':True}}
    before_spawn(case,'/owned/pytest/a/worker','acp',records,actors)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/b/worker','acp',records,actors)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/a/validator','acp',records,actors)
    actors[12]['returned'] = False
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/a/worker','acp',records,actors)


def test_pair_replay_and_case_bound_refuse():
    case = next(case for case in CASES if limits(case)[0] == 1)
    records = [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}]
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/a/worker','backend',records,{})
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/b/worker','backend',records,{})
    with pytest.raises(Refused):
        before_spawn('foreign','/owned/pytest/a/worker','backend',[],{})


@pytest.mark.parametrize('value', ['/foreign/worker', '/owned/pytest/../worker', '/owned/pytest/a/foreign', object()])
def test_listener_scope_refuses_foreign_paths_and_roles(value):
    with pytest.raises(Refused):
        scope(next(iter(CASES)),'bridge',value,Path('/owned'))


def test_listener_only_owner_and_role_proliferation_refuse():
    from controlled_pairs import before_bind
    case = next(case for case in CASES if limits(case)[0] == 1)
    records = [{'tag':'broker','scope':'/owned/pytest/a'}]
    with pytest.raises(Refused):
        before_bind(case,'broker','/owned/pytest/b',records)
    with pytest.raises(Refused):
        before_bind(case,'lifetime','/owned/pytest/b/worker',records)
    before_bind(case,'lifetime','/owned/pytest/a/worker',records)
    records.append({'tag':'lifetime','scope':'/owned/pytest/a/worker'})
    with pytest.raises(Refused):
        before_bind(case,'lifetime','/owned/pytest/a/validator',records)
    with pytest.raises(Refused):
        before_bind(case,'bridge','/owned/pytest/a/validator',records)
    before_bind(case,'bridge','/owned/pytest/a/worker',records)


def test_finite_component_partitions_keep_every_original_case_exactly_once():
    from controlled_cases import GROUPS
    members = [case for group in GROUPS.values() for case in group]
    assert len(members) == 123 and len(set(members)) == 123 and set(members) == set(CASES)
    assert len(GROUPS['controlled-cancellation4']) == len(GROUPS['controlled-registration4']) == 4
    assert len(GROUPS['controlled-witness1']) == 1


def test_startup_failure_cannot_start_an_adapter():
    from controlled_cases import STARTUP_FAILURE
    before_spawn(STARTUP_FAILURE, '/owned/pytest/a/worker', 'backend', [], {})
    with pytest.raises(Refused):
        before_spawn(STARTUP_FAILURE, '/owned/pytest/a/worker', 'acp',
                     [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}],
                     {12:{'returned':True}})


@pytest.mark.parametrize('case', CASES)
def test_each_case_rejects_one_more_backend_than_its_declared_bound(case):
    maximum, _ = limits(case)
    records = [{'cwd':f'/owned/pytest/owner{index}/worker','role':'backend','consumed':True,'pid':100+index}
               for index in range(maximum)]
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/extra/worker','backend',records,{})
