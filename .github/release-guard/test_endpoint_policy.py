"""Endpoint mutation controls; fabricated rows never count as kernel proof."""
from dataclasses import replace

import pytest

from content_manifest import Refused
from endpoint_policy import Endpoints, Owner
from test_process_ledger import PINS, SEAL, setup, terminal


def ready(ledger, birth, *, body=True):
    process = ledger.process(birth)
    ledger.control(birth, process.token, process.generation, 0, 'core-ready', {'pins': PINS})
    if body:
        ledger.control(birth, process.token, process.generation, 1, 'body-ready', {'seal': SEAL})
    return Owner(birth, process.token, process.generation)




























@pytest.mark.parametrize('mutation',('case','token','generation','core','exit','poison','retired'))
def test_unix_owner_epoch_and_readiness_are_required(mutation):
    ledger,root,_=setup()
    owner=ready(ledger,root,body=mutation!='core')
    endpoints=Endpoints(ledger)
    if mutation=='case':
        ledger.process(root).case='foreign'
    elif mutation=='token':
        owner=replace(owner,token='foreign')
    elif mutation=='generation':
        ledger.process(root).generation+=1
    elif mutation=='exit':
        terminal(ledger,root,0)
    elif mutation=='poison':
        ledger.poison.append('prior refusal')
    elif mutation=='retired':
        endpoints.retire_case('case[one]')
    with pytest.raises(Refused):
        endpoints.owner(owner,'case[one]',body=True)
