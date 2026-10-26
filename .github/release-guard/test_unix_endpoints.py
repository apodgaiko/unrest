"""Pair mutation controls; synthetic rows are not kernel execution evidence."""
from dataclasses import replace

import pytest

from content_manifest import Refused
from endpoint_policy import Endpoints
from process_ledger import Birth
from test_endpoint_policy import ready
from test_process_ledger import setup
from unix_endpoints import Member, UnixPairs


def prepared():
    ledger, birth, _ = setup()
    owner = ready(ledger, birth)
    endpoints = Endpoints(ledger)
    pairs = UnixPairs(endpoints)
    left = Member(birth, 7, 1000, 2000, birth.uid, 1001, 1)
    right = Member(birth, 8, 1001, 2001, birth.uid, 1000, 1)
    return pairs, owner, (left, right)


def test_self_pair_retains_survivor_after_peer_close():
    pairs, owner, members = prepared()
    pair = pairs.admit(owner, 'case[one]', members)
    pairs.retained(pair, owner, members[0])
    pairs.retained(pair, owner, replace(members[0], peer=0))
    pairs.retained(pair, owner, replace(members[1], peer=0, state=7))


@pytest.mark.parametrize('field,value', [('fd', 9), ('inode', 3000), ('cookie', 4000), ('peer', 1002)])
def test_retained_pair_rejects_fd_alias_replacement_or_foreign_peer(field, value):
    pairs, owner, members = prepared()
    pair = pairs.admit(owner, 'case[one]', members)
    with pytest.raises(Refused):
        pairs.retained(pair, owner, replace(members[0], **{field: value}))
    assert pairs.poison is pairs.endpoints.poison and pairs.poison


@pytest.mark.parametrize('field,value', [('fd', 7), ('inode', 1000), ('cookie', 2000), ('peer', 1002), ('state', 7)])
def test_new_pair_requires_two_fresh_reciprocal_connected_members(field, value):
    pairs, owner, members = prepared()
    with pytest.raises(Refused):
        pairs.admit(owner, 'case[one]', (members[0], replace(members[1], **{field: value})))
    assert pairs.poison


def test_duplicate_pair_cannot_launder_an_fd_alias():
    pairs, owner, members = prepared()
    pairs.admit(owner, 'case[one]', members)
    with pytest.raises(Refused):
        pairs.admit(owner, 'case[one]', tuple(replace(member, fd=member.fd + 10) for member in members))
    assert pairs.poison


@pytest.mark.parametrize('change', ['case', 'owner', 'readiness', 'exit', 'ledger-poison', 'endpoint-poison'])
def test_pair_admission_requires_current_body_ready_owner(change):
    pairs, owner, members = prepared()
    case = 'case[one]'
    process = pairs.endpoints.ledger.process(owner.birth)
    if change == 'case':
        case = 'case[two]'
    elif change == 'owner':
        owner = replace(owner, birth=Birth(owner.birth.pid + 100, owner.birth.tgid, owner.birth.parent,
                                          owner.birth.ticks, owner.birth.boot, owner.birth.uid))
    elif change == 'readiness':
        process.stage = 'core-ready'
    elif change == 'exit':
        process.exit = (15, 15)
    elif change == 'ledger-poison':
        pairs.endpoints.ledger.poison.append('original refusal')
    else:
        pairs.poison.append('original refusal')
    with pytest.raises(Refused):
        pairs.admit(owner, case, members)
    assert pairs.poison


def test_pair_object_cannot_be_replaced_by_equivalent_claim():
    pairs, owner, members = prepared()
    pair = pairs.admit(owner, 'case[one]', members)
    with pytest.raises(Refused):
        pairs.retained(replace(pair), owner, members[0])
    assert pairs.poison


@pytest.mark.parametrize('field,value', [('fd', True), ('inode', 0), ('socket_cookie', True),
                                        ('socket_uid', True), ('state', True), ('type', True),
                                        ('peer_inode', False), ('extra', 1)])
def test_kernel_row_schema_and_integer_types_are_strict(field, value):
    _, owner, _ = prepared()
    row = {'fd': 7, 'inode': 1000, 'socket_cookie': 2000, 'socket_uid': owner.birth.uid,
           'state': 1, 'type': 1, 'peer_inode': 1001, field: value}
    with pytest.raises(Refused):
        Member.read(owner.birth, row)


@pytest.mark.parametrize('descriptors', [[True, 2], [1, '2'], [-1, 2], [1, 1], (1, 2)])
def test_bad_pair_descriptors_refuse_before_kernel_acquisition(descriptors, monkeypatch):
    import socket_observation
    def no_kernel_effect():
        raise AssertionError('malformed descriptors reached kernel acquisition')
    monkeypatch.setattr(socket_observation, 'unix_table', no_kernel_effect)
    with pytest.raises(ValueError):
        socket_observation.unix_pair(1, descriptors)
