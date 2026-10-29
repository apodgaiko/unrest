"""Git helpers require actual native parent waits; no stdout-value certification."""
from types import SimpleNamespace

import pytest

from git_observer import Git
from process_ledger import Birth,Ledger
from test_process_ledger import identity,emit,terminal,wait4,PINS,SEAL

CASE="case[one]"


def setup(*, command_class='native-git-command', execute=True, pins=(('native-fixture', 'a' * 64),)):
    ledger = Ledger('git-values-control')
    root_id, child_id = identity(100, 99), identity(101, 100)
    root, child = Birth.read(root_id), Birth.read(child_id)
    emit(ledger, 'kernel_root', identity=root_id)
    ledger.register(root, 'root-token', PINS, SEAL, case=CASE, command_class='root')
    emit(ledger, 'kernel_child', parent=100, child=101, event=1, identity=child_id)
    ledger.register(child, 'child-token', pins, SEAL, case=CASE, command_class=command_class, expected_generation=1)
    if execute:
        emit(ledger, 'kernel_exec', pid=child.pid)
    return ledger, root, child



def complete(ledger, root, child, sequence, raw=0):
    terminal(ledger, child, raw)
    wait4(ledger, root, child, raw)
    return ledger.process(child).life_token



def native_descendant(ledger, parent, pid=102):
    data = identity(pid, parent.pid)
    birth = Birth.read(data)
    emit(ledger, 'kernel_child', parent=parent.pid, child=pid, event=1, identity=data)
    ledger.register(birth, f'helper-{pid}', (('native-fixture', 'a' * 64),), SEAL,
        case=CASE, command_class='native-git-helper', expected_generation=1)
    emit(ledger, 'kernel_exec', pid=pid)
    return birth


def test_actual_native_parent_wait_settles_every_helper_without_python_receipt():
    ledger,root,parent=setup()
    helper=native_descendant(ledger,parent)
    nested=native_descendant(ledger,helper,103)
    terminal(ledger,nested,0)
    wait4(ledger,helper,nested,0)
    terminal(ledger,helper,0)
    wait4(ledger,parent,helper,0)
    complete(ledger,root,parent,0)
    git=Git(SimpleNamespace(ledger=ledger))
    assert git.descendants_reaped(parent)
    assert git.native_child_reaped(parent,helper,CASE,ledger.process(parent).pins)


@pytest.mark.parametrize('mutation',('missing-wait','missing-terminal','failed','class','case','pin','epoch','options'))
def test_native_descendant_wait_has_no_generic_reap_exception(mutation):
    ledger,root,parent=setup()
    helper=native_descendant(ledger,parent)
    raw=256 if mutation=='failed' else 0
    if mutation!='missing-terminal':
        terminal(ledger,helper,raw)
        if mutation!='missing-wait':
            wait4(ledger,parent,helper,raw)
    process=ledger.process(helper)
    if mutation=='class':
        process.command_class='foreign'
    elif mutation=='case':
        process.case='foreign'
    elif mutation=='pin':
        process.pins=(('native-fixture','b'*64),)
    elif mutation=='epoch':
        process.generation=2
    elif mutation=='options':
        process.parent_wait=(*process.parent_wait[:3],1)
    complete(ledger,root,parent,0)
    git=Git(SimpleNamespace(ledger=ledger))
    assert not git.descendants_reaped(parent)
    assert not git.native_child_reaped(parent,helper,CASE,ledger.process(parent).pins)

