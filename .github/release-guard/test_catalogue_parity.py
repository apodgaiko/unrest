"""Ordered pre-factoring declarations: data equality, never runtime authority."""
import hashlib
import json

import pytest

import test_controlled_catalogue as catalogue

# Frozen before factoring expanded parameter products. Hash the ordered item
# sequence: sorting here would hide a changed execution frontier or case seal.
PINS = {
    'ROOT_HTTP': 'c260f4fd7011dc396081446c107ebdf9397c90a867586b0678308336ce94755c',
    'ADMISSION': 'f18fd2e632e256a09674877d334bd0096368f2bb3d8dcb82400d8a5948f9b268',
    'WARNING_REFUSALS': 'b8318e20ad9bb103fa0262307abceca1f91cf26a10da343f4c7303ddc1adf964',
    'NOTIFICATION_STARTUP': 'c3bda57d18d4a361fed498f892b40f90bc98697a24822c337fbbcc9ea91af360',
    'NOTIFICATION_SIGNALS': '6f58338ebfea5b7cbc3349615d08d6fc0f8e97c662f630a64eddf8cf39b0d3d3',
    'POPULATED': 'c6e88849a9665abcc40f58276457d2828cfb32e53b2a80f6a63ca53230514ac8',
    'FRESH': '9296f8b7380c0d14ce4f30b30e70aa80dd9bc3519435efc59ef351a5dbddcaba',
    'CASES': '297dbc4ffce7118d4c822e403da3c65174526323bd48d015158b60964fd412a8',
}


@pytest.mark.parametrize('name', PINS)
def test_complete_ordered_mapping_is_identical(name):
    from cohort_cases import CAMPAIGNS
    from cohort_controller import CASES as CRASH
    rows=getattr(catalogue,name).items()
    if name=='CASES':
        rows=[(case,value) for case,value in rows if case not in (*CAMPAIGNS,*CRASH)]
    body = json.dumps(list(rows), separators=(',', ':')).encode()
    assert hashlib.sha256(body).hexdigest() == PINS[name]


def test_preflight_axes_and_positive_bootstrap_projection_are_identical():
    from dataclasses import asdict
    from test_preflight_inventory import CASES
    from bootstrap_cases import DECLARATIONS
    original = [{'children': 2,
      'configured': True,
      'delay': 32,
      'name': 'test_actual_thirty_two_second_readiness'},
     {'children': 2,
      'configured': True,
      'delay': 60,
      'name': 'test_actual_launch_lifetime_and_interruptions[near]'},
     {'children': 0,
      'configured': True,
      'delay': 60,
      'name': 'test_actual_launch_lifetime_and_interruptions[exhausted]'},
     {'children': 2,
      'configured': True,
      'delay': 60,
      'name': 'test_actual_launch_lifetime_and_interruptions[cancel]'},
     {'children': 2,
      'configured': True,
      'delay': 60,
      'name': 'test_actual_launch_lifetime_and_interruptions[stop]'},
     {'children': 0,
      'configured': False,
      'delay': None,
      'name': 'test_phases_share_one_deadline_across_tasks'},
     {'children': 0,
      'configured': False,
      'delay': None,
      'name': 'test_absolute_ledger_includes_setup_and_cleanup'},
     {'children': 0,
      'configured': False,
      'delay': None,
      'name': 'test_capped_body_free_observation_is_pre_cleanup'},
     {'children': 0,
      'configured': False,
      'delay': None,
      'name': 'test_turn_reservation_does_not_restart_clock_after_bootstrap'},
     {'children': 2,
      'configured': False,
      'delay': 32,
      'name': 'test_delayed_turn_uses_only_original_remaining_time'},
     {'children': 2,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[False-turn]'},
     {'children': 2,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[False-episode]'},
     {'children': 2,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[False-campaign]'},
     {'children': 0,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[True-turn]'},
     {'children': 0,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[True-episode]'},
     {'children': 0,
      'configured': False,
      'delay': 60,
      'name': 'test_original_limits_refuse_before_grant_or_send[True-campaign]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[expire-reserve]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[expire-grant]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[expire-send]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[expire-serialize]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[stop-reserve]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[stop-grant]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[stop-send]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_boundary_recheck_blocks_expired_or_stopped_send[stop-serialize]'},
     {'children': 2,
      'configured': False,
      'delay': None,
      'name': 'test_actual_sequential_initialize_and_session_share_cutoff'},
     {'children': 2,
      'configured': False,
      'delay': 0.5,
      'name': 'test_startup_subtracts_from_actual_inference_timeout'},
     {'children': 0,
      'configured': False,
      'delay': None,
      'name': 'test_expiry_during_seal_cannot_publish_grant'}]
    assert [asdict(value) for value in DECLARATIONS] == [
        {key:value for key,value in row.items() if key!='children'} for row in original if row['children']==2]
    snapshots = (
        (CASES, 'decd3ed6e0c3435bfc8ff57adcd5fd28cc51804ad21d9894a47f68d3134088be'),
        ([{key:row[key] for key in ('name','delay','configured','children')} for row in original],
         '48fb21f65e272f2f709b5ecc6b9ff98c8be8762b00b34e05c58a56b187fa61cf'),
    )
    for value, pin in snapshots:
        body = json.dumps(value, separators=(',', ':')).encode()
        assert hashlib.sha256(body).hexdigest() == pin
