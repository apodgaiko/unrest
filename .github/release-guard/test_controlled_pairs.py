"""Cross-owner/replay negatives for the finite controlled owner graph."""
from pathlib import Path

import pytest

from content_manifest import Refused
from test_controlled_catalogue import CASES
from controlled_pairs import before_spawn, limits, scope


def test_every_catalogue_case_has_a_finite_source_bound():
    assert len(CASES) == 193
    assert all(0 <= limits(case) <= 20 for case in CASES)


def test_pair_cannot_borrow_another_owner_backend():
    case = next(case for case in CASES if 'test_ack_durability[' in case)
    records = [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}]
    def executed(row):
        return True
    assert before_spawn(case,'/owned/pytest/a/worker','acp',records,executed)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/b/worker','acp',records,executed)
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/a/validator','acp',records,executed)
    assert before_spawn(case,'/owned/pytest/a/worker','acp',records,lambda row:False) is False



def test_pair_replay_and_case_bound_refuse():
    case = next(case for case in CASES if limits(case)==20)
    records = [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}]
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/a/worker','backend',records,{})
    before_spawn(case,'/owned/pytest/b/worker','backend',records,{})
    with pytest.raises(Refused):
        before_spawn('foreign','/owned/pytest/a/worker','backend',[],{})


@pytest.mark.parametrize('value', ['/foreign/worker', '/owned/pytest/../worker', '/owned/pytest/a/foreign', object()])
def test_listener_scope_refuses_foreign_paths_and_roles(value):
    with pytest.raises(Refused):
        scope(next(iter(CASES)),'bridge',value,Path('/owned'))


def test_every_original_controlled_case_remains_declared():
    assert len(CASES)==193 and len(set(CASES))==193


def test_startup_failure_cannot_start_an_adapter():
    from controlled_cases import STARTUP_FAILURE
    before_spawn(STARTUP_FAILURE, '/owned/pytest/a/worker', 'backend', [], {})
    with pytest.raises(Refused):
        before_spawn(STARTUP_FAILURE, '/owned/pytest/a/worker', 'acp',
                     [{'cwd':'/owned/pytest/a/worker','role':'backend','consumed':True,'pid':12}],
                     {12:{'returned':True}})


@pytest.mark.parametrize('case', CASES)
def test_each_case_rejects_one_more_backend_than_its_declared_bound(case):
    maximum = limits(case)
    records = [{'cwd':f'/owned/pytest/owner{index}/worker','role':'backend','consumed':True,'pid':100+index}
               for index in range(maximum)]
    with pytest.raises(Refused):
        before_spawn(case,'/owned/pytest/extra/worker','backend',records,{})


def test_exact_crash_and_campaign_bounds_are_not_replaced_by_the_common_ceiling():
    from cohort_cases import CAMPAIGNS
    from cohort_controller import CASES as CRASH
    assert all(limits(case)==value[0] for case,value in CAMPAIGNS.items())
    assert [limits(case) for case in CRASH]==[0,1,1,1]
