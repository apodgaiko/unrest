"""Git stdout can be reported only by its actual ready constructor parent."""
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from git_observer import Git
from process_ledger import Birth
from test_process_ledger import setup,emit,identity,PINS,SEAL


def fixture():
    ledger,root,server=setup()
    ledger.control(server,'child-token',0,0,'core-ready',{'pins':PINS})
    ledger.control(server,'child-token',0,1,'body-ready',{'seal':SEAL})
    data=identity(102,server.pid)
    query=Birth.read(data)
    emit(ledger,'kernel_child',parent=server.pid,child=query.pid,event=1,identity=data)
    ledger.register(query,'query-token',PINS,SEAL,case='case[one]',command_class='native-git-command')
    host=SimpleNamespace(ledger=ledger)
    actor={'birth':server,'token':'child-token'}
    intent={'parent':server,'birth':query,'consumed':True}
    return Git(host),ledger,root,actor,intent


def test_exact_server_parent_is_not_confused_with_the_pytest_ancestor():
    git,ledger,root,actor,intent=fixture()
    git.reporting_parent(actor,intent)
    with pytest.raises(Refused,match='reporting parent'):
        git.reporting_parent({'birth':root,'token':'root-token'},intent)


@pytest.mark.parametrize('mutation',['intent','kernel','consumed','token','readiness'])
def test_foreign_or_stale_parent_cannot_claim_query_stdout(mutation):
    git,ledger,root,actor,intent=fixture()
    if mutation=='intent':
        intent['parent']=root
    elif mutation=='kernel':
        ledger.process(intent['birth']).parent=root
    elif mutation=='consumed':
        intent['consumed']=False
    elif mutation=='token':
        actor['token']='foreign'
    else:
        ledger.process(actor['birth']).stage='registered'
    with pytest.raises(Refused,match='reporting parent'):
        git.reporting_parent(actor,intent)
