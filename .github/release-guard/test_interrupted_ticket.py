"""Synthetic cancelled-ticket joins; actual waits remain native evidence."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bootstrap_cases import BOOTSTRAP
from content_manifest import Refused
from endpoint_policy import Endpoints,Owner,Route,Socket
from source_observer import Observer
from test_endpoint_policy import ready
from test_process_ledger import setup,terminal,wait4,receipt


def pending(stage='complete'):
    ledger,root,child=setup()
    server,client=ready(ledger,root),ready(ledger,child)
    case=BOOTSTRAP[1]
    for birth in (root,child):ledger.process(birth).case=case
    server=Owner(root,'root-token',0)
    client=Owner(child,'child-token',0)
    endpoints=Endpoints(ledger)
    route=Route('child-token:lifetime',case,server,client,12345)
    endpoints.declare(route)
    listener=Socket(root,7,1000,2000,10,20000,('127.0.0.1',12345),None)
    endpoints.listen(route.name,listener)
    ticket=endpoints.connect(route.name,listener,Socket(child,6,1001,2001,7,20000,('0.0.0.0',0),None))
    if stage!='none':terminal(ledger,child,15)
    if stage in ('kernel-wait','complete'):wait4(ledger,root,child,15)
    if stage=='complete':ledger.control(root,'root-token',0,2,'parent-wait',receipt(ledger,root,child,15))
    observer=object.__new__(Observer)
    observer.case,observer.root=case,root.pid
    observer.actors={root.pid:{'birth':root,'token':'root-token'},child.pid:{'birth':child,'token':'child-token','role':'acp','case':case,'signals':{15}}}
    observer.ledger,observer.endpoints=ledger,endpoints
    observer.eof_drains,observer.interrupted_records={},[]
    # This model ledger uses generation0; production source actors use1.
    observer.owner=lambda actor:Owner(actor['birth'],actor['token'],0)
    return observer,ticket,child


def test_pending_ticket_retires_only_as_unjoined_without_connection_or_close_claim():
    observer,ticket,_=pending()
    observer.retire_cancelled_tickets()
    assert not observer.endpoints.tickets and not observer.endpoints.connections
    assert observer.interrupted_records==[{'kind':'cancelled-unjoined','ticket':ticket.serial,'actual_original_parent_reap':True,'accepted_peer_proven':False,'descriptor_close_proven':False}]


@pytest.mark.parametrize('stage',['none','terminal','kernel-wait'])
def test_missing_full_original_parent_join_cannot_retire(stage):
    observer,ticket,_=pending(stage)
    with pytest.raises(Refused):observer.retire_cancelled_tickets()
    assert observer.endpoints.tickets[ticket.serial] is ticket and not observer.interrupted_records


@pytest.mark.parametrize('mutation',['positive','token','server','case','role','signal','status','route'])
def test_other_authority_cannot_retire_ticket(mutation):
    observer,ticket,child=pending()
    actor=observer.actors[child.pid]
    if mutation=='positive':observer.case=BOOTSTRAP[0]
    elif mutation=='token':actor['token']='foreign'
    elif mutation=='server':observer.actors[observer.root]['token']='foreign'
    elif mutation=='case':actor['case']='foreign'
    elif mutation=='role':actor['role']='backend'
    elif mutation=='signal':actor['signals'].clear()
    elif mutation=='status':observer.ledger.process(child).terminal=(10,0,0)
    else:
        changed=replace(ticket,route=replace(ticket.route,name='foreign'))
        observer.endpoints.tickets[ticket.serial]=changed
    with pytest.raises(Refused):observer.retire_cancelled_tickets()
    assert ticket.serial in observer.endpoints.tickets and not observer.interrupted_records


def test_existing_eof_drain_remains_on_its_distinct_path():
    observer,ticket,_=pending()
    observer.eof_drains[ticket.serial]={'ticket':ticket}
    observer.retire_cancelled_tickets()
    assert observer.endpoints.tickets[ticket.serial] is ticket and not observer.interrupted_records
