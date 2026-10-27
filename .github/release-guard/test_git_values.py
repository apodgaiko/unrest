"""Synthetic reducer controls; real stdout and native waits require integration."""
import pytest

from content_manifest import Refused
from git_values import Values
from process_ledger import Birth, Ledger
from test_process_ledger import identity, emit, terminal, wait4, receipt, PINS, SEAL

BASE, TREE, NEW, MESSAGE = '1' * 40, '2' * 40, '3' * 40, '4' * 64
DATE, CASE, REPO = '2026-10-27T00:00:00+00:00', 'case[one]', '/owned/project'


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
    ledger.control(root, 'root-token', 0, sequence, 'parent-wait', receipt(ledger, root, child, raw))
    return ledger.process(child).life_token


def producer(ledger, root, pid, sequence):
    info = identity(pid, root.pid)
    child = Birth.read(info)
    emit(ledger, 'kernel_child', parent=root.pid, child=pid, event=1, identity=info)
    ledger.register(child, f'token-{pid}', (('native-fixture', 'a' * 64),), SEAL, case=CASE, command_class='native-git-command', expected_generation=1)
    emit(ledger, 'kernel_exec', pid=child.pid)
    return child, complete(ledger, root, child, sequence)


def flow():
    ledger, root, child = setup()
    values = Values(ledger)
    token = complete(ledger, root, child, 0)
    values.observe(child, token, CASE, REPO, 'parent', 'commit', BASE + '\n')
    return values, ledger, root, child, token


def test_tree_predecessor_date_and_message_remain_distinct_causal_inputs():
    values, ledger, root, _, _ = flow()
    child, token = producer(ledger, root, 102, 1)
    values.observe(child, token, CASE, REPO, 'integration-one', 'tree', TREE + '\n')
    child, token = producer(ledger, root, 103, 2)
    values.observe(child, token, CASE, REPO, 'parent', 'date', DATE + '\n', inputs=(BASE,))
    child, token = producer(ledger, root, 104, 3)
    record = values.observe(child, token, CASE, REPO, 'integration-one', 'integration-commit', NEW + '\n',
        inputs=(TREE, BASE, DATE, MESSAGE))
    assert values.require(CASE, REPO, 'integration-one', 'integration-commit', NEW,
        (TREE, BASE, DATE, MESSAGE)) is record
    for case, repository, location, kind, value in (
        ('other-case', REPO, 'parent', 'commit', BASE), (CASE, '/other', 'parent', 'commit', BASE),
        (CASE, REPO, 'lease-child', 'commit', BASE), (CASE, REPO, 'parent', 'tree', BASE),
        (CASE, REPO, 'parent', 'commit', TREE)):
        with pytest.raises(Refused):
            values.require(case, repository, location, kind, value)


@pytest.mark.parametrize('missing', ('wait', 'receipt', 'terminal'))
def test_no_observation_can_replace_a_missing_actual_join(missing):
    ledger, root, child = setup()
    if missing == 'terminal':
        emit(ledger, 'kernel_exit', pid=child.pid, raw=0)
    else:
        terminal(ledger, child, 0)
        if missing != 'wait':
            wait4(ledger, root, child, 0)
    if missing != 'receipt':
        ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, 0))
    values = Values(ledger)
    with pytest.raises(Refused):
        values.observe(child, 'child-token', CASE, REPO, 'parent', 'commit', BASE + '\n')
    assert values.poison and not values.values


@pytest.mark.parametrize('mutation', ('failed', 'extra-line', 'missing-newline', 'wrong-token', 'wrong-case', 'wrong-repo', 'bool', 'digest', 'unknown-kind'))
def test_failed_malformed_or_foreign_producers_cannot_register_values(mutation):
    ledger, root, child = setup()
    token = complete(ledger, root, child, 0, raw=256 if mutation == 'failed' else 0)
    values = Values(ledger)
    args = [child, token, CASE, REPO, 'parent', 'commit', BASE + '\n']
    if mutation == 'extra-line':
        args[-1] += BASE + '\n'
    elif mutation == 'missing-newline':
        args[-1] = BASE
    elif mutation == 'wrong-token':
        args[1] = 'other-token'
    elif mutation == 'wrong-case':
        args[2] = 'other-case'
    elif mutation == 'wrong-repo':
        args[3] = '/owned/../other'
    elif mutation == 'bool':
        args[-1] = True
    elif mutation == 'digest':
        args[-1] = 'x' * 40 + '\n'
    elif mutation == 'unknown-kind':
        args[-2] = 'arbitrary'
    with pytest.raises(Refused):
        values.observe(*args)
    assert values.poison and not values.values


def test_reused_receipt_and_unsettled_descendants_never_become_new_values():
    values, ledger, root, child, token = flow()
    with pytest.raises(Refused):
        values.observe(child, token, CASE, REPO, 'parent', 'commit', BASE + '\n')
    assert values.poison
    ledger, root, child = setup()
    data = identity(102, child.pid)
    descendant = Birth.read(data)
    emit(ledger, 'kernel_child', parent=child.pid, child=102, event=1, identity=data)
    ledger.register(descendant, 'unsettled', PINS, SEAL, case=CASE, command_class='native-git-helper')
    token = complete(ledger, root, child, 0)
    values = Values(ledger)
    with pytest.raises(Refused, match='unsettled native descendants'):
        values.observe(child, token, CASE, REPO, 'parent', 'commit', NEW + '\n')
    assert values.poison


@pytest.mark.parametrize('mutation', ('class', 'exec', 'pins'))
def test_only_the_admitted_native_git_image_can_produce_a_value(mutation):
    ledger, root, child = setup(command_class='other' if mutation == 'class' else 'native-git-command',
        execute=mutation != 'exec', pins=(('other', 'a' * 64),) if mutation == 'pins' else (('native-fixture', 'a' * 64),))
    token = complete(ledger, root, child, 0)
    values = Values(ledger)
    with pytest.raises(Refused):
        values.observe(child, token, CASE, REPO, 'parent', 'commit', BASE + '\n')
    assert values.poison


def native_descendant(ledger, parent, pid=102):
    data = identity(pid, parent.pid)
    birth = Birth.read(data)
    emit(ledger, 'kernel_child', parent=parent.pid, child=pid, event=1, identity=data)
    ledger.register(birth, f'helper-{pid}', (('native-fixture', 'a' * 64),), SEAL,
        case=CASE, command_class='native-git-helper', expected_generation=1)
    emit(ledger, 'kernel_exec', pid=pid)
    return birth


def test_actual_native_parent_wait_settles_helper_without_python_receipt():
    ledger, root, child = setup()
    helper = native_descendant(ledger, child)
    nested = native_descendant(ledger, helper, 103)
    terminal(ledger, nested, 0)
    wait4(ledger, helper, nested, 0)
    terminal(ledger, helper, 0)
    wait4(ledger, child, helper, 0)
    assert ledger.children[child] == [helper]
    assert ledger.children[helper] == [nested]
    assert not ledger.reaped(helper, 'helper-102')
    token = complete(ledger, root, child, 0)
    values = Values(ledger)
    assert values.observe(child, token, CASE, REPO, 'parent', 'commit', BASE + '\n').value == BASE
    assert ledger.process(helper).receipt is None


@pytest.mark.parametrize('mutation', ('missing-wait', 'missing-terminal', 'failed', 'class', 'case', 'pin', 'epoch', 'receipt', 'options'))
def test_native_descendant_wait_has_no_generic_reap_exception(mutation):
    ledger, root, child = setup()
    helper = native_descendant(ledger, child)
    raw = 256 if mutation == 'failed' else 0
    if mutation != 'missing-terminal':
        terminal(ledger, helper, raw)
        if mutation != 'missing-wait':
            wait4(ledger, child, helper, raw)
    process = ledger.process(helper)
    # Direct field mutations model corrupt reducer state, never native evidence.
    if mutation == 'class':
        process.command_class = 'other'
    elif mutation == 'case':
        process.case = 'other'
    elif mutation == 'pin':
        process.pins = (('native-fixture', 'b' * 64),)
    elif mutation == 'epoch':
        process.generation = 2
    elif mutation == 'receipt':
        ledger.control(child, 'child-token', 1, 0, 'parent-wait', receipt(ledger, child, helper, raw))
    elif mutation == 'options':
        assert process.parent_wait is not None
        process.parent_wait = (*process.parent_wait[:3], 1)
    token = complete(ledger, root, child, 0)
    values = Values(ledger)
    with pytest.raises(Refused, match='unsettled native descendants'):
        values.observe(child, token, CASE, REPO, 'parent', 'commit', BASE + '\n')
    assert values.poison


@pytest.mark.parametrize('value', ('2026-10-27T18:25:07Z', '2026-10-27T18:25:07+00:00', '2026-10-27T18:25:07+04:00'))
def test_actual_git_date_forms_remain_exact_and_predecessor_bound(value):
    values, ledger, root, _, _ = flow()
    child, token = producer(ledger, root, 102, 1)
    record = values.observe(child, token, CASE, REPO, 'parent', 'date', value + '\n', inputs=(BASE,))
    assert record.value == value and record.inputs == (BASE,)
    with pytest.raises(Refused):
        values.require(CASE, REPO, 'parent', 'date', value, ('9' * 40,))
