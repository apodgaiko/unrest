"""A killed caller gets no payload permission or fabricated descriptor proof."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from endpoint_policy import Owner
from source_observer import Observer,PARK_SELF_PAIR
import source_observer
from test_unix_endpoints import prepared


def model(monkeypatch,observed=None,signals=(9,)):
    pairs,owner,members=prepared()
    pair=pairs.admit(owner,'case[one]',members)
    observer=object.__new__(Observer)
    observer.ledger,observer.pairs=pairs.endpoints.ledger,pairs
    observer.owner=lambda actor:Owner(actor['birth'],actor['token'],owner.generation)
    observer.eof_fds,observer.mp_pipes={},{}
    observer.descriptors={(owner.birth,members[0].fd):pair}
    actor={'birth':owner.birth,'token':owner.token,'signals':set(signals)}
    monkeypatch.setattr(source_observer,'acquire_unix_member',lambda *args:observed)
    payload={'fd':members[0].fd,'operation':'send','bytes':1}
    return observer,actor,pair,payload,members


def test_missing_member_is_parked_without_grant_and_only_actual_sigkill_cancels(monkeypatch):
    observer,actor,pair,payload,_=model(monkeypatch)
    assert observer.socket_payload(actor,payload) is PARK_SELF_PAIR
    process=observer.ledger.process(actor['birth'])
    closed=[]
    frame=SimpleNamespace(check=lambda:None,poison=False,
        binding=(actor['birth'],actor['token'],process.generation),
        stream=SimpleNamespace(close=lambda:closed.append(True)))
    channel={'frame':frame,'actor':actor,'request':{'id':'a'*32,'payload':payload},'cancelled_pair':pair}
    observer.frames=[channel]
    observer.interrupted_records=[]
    observer.settle_cancelled_channels()
    assert observer.frames==[channel] and not closed and not observer.ledger.poison
    # Parking never retries the missing descriptor, including if it reappears.
    monkeypatch.setattr(source_observer,'acquire_unix_member',lambda *args:pytest.fail('parked RPC resumed'))
    process.exit,process.terminal=(4,9),(5,9,-9)
    observer.settle_cancelled_channels()
    assert not observer.frames and closed==[True]
    record=observer.interrupted_records[0]
    assert record['payload_executed'] is False and record['descriptor_retention_proven'] is False
    assert record['original_parent_wait_proven'] is False  # Finalization still owes the actual join.


@pytest.mark.parametrize('mutation',['no-signal','different-member','wrong-status','changed-token','deadline'])
def test_cancellation_cannot_hide_live_replacement_or_unproved_death(monkeypatch,mutation):
    observer,actor,pair,payload,members=model(monkeypatch,signals=() if mutation=='no-signal' else (9,))
    if mutation=='different-member':
        monkeypatch.setattr(source_observer,'acquire_unix_member',lambda *args:replace(members[0],cookie=999))
    if mutation in ('no-signal','different-member'):
        with pytest.raises(Refused,match='replacement'):
            observer.socket_payload(actor,payload)
        assert observer.pairs.poison
        return
    process=observer.ledger.process(actor['birth'])
    def check():
        if mutation=='deadline':
            raise Refused('original frame deadline')
    frame=SimpleNamespace(check=check,poison=False,binding=(actor['birth'],actor['token'],process.generation),
        stream=SimpleNamespace(close=lambda:pytest.fail('unproved cancellation')))
    observer.frames=[{'frame':frame,'actor':actor,'request':{'id':'a'*32,'payload':payload},'cancelled_pair':pair}]
    observer.interrupted_records=[]
    if mutation=='wrong-status':
        process.exit,process.terminal=(4,0),(5,0,0)
    elif mutation=='changed-token':
        actor['token']='foreign'
    with pytest.raises(Refused):
        observer.settle_cancelled_channels()
    assert observer.frames and not observer.interrupted_records
