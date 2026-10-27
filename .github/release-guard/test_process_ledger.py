"""Incremental reduction controls; kernel provenance needs the native integration."""
from __future__ import annotations

from copy import deepcopy
import signal

import pytest

from content_manifest import Refused
from process_ledger import Birth, Ledger, canonical

PINS = (('runtime', 'a' * 64),)
SEAL = 'b' * 64


def identity(pid, parent, *, tgid=None):
    return {'pid': pid, 'tgid': tgid or pid, 'ppid': parent, 'start_ticks': pid * 100,
            'boot_id': 'boot', 'uids': [20000] * 4, 'pgid': 100, 'sid': 100,
            'clock_ticks_per_second': 100}


def emit(ledger, kind, **values):
    ledger.kernel(ledger.next_kernel, {'kind': kind, **values})


def setup(*, new_session=False):
    ledger = Ledger('nonce')
    root_id, child_id = identity(100, 99), identity(101, 100)
    root, child = Birth.read(root_id), Birth.read(child_id)
    emit(ledger, 'kernel_root', identity=root_id)
    ledger.register(root, 'root-token', PINS, SEAL, case='case[one]', command_class='root')
    emit(ledger, 'kernel_child', parent=100, child=101, event=1, identity=child_id)
    ledger.register(child, 'child-token', PINS, SEAL, case='case[one]', command_class='child',
                    new_session=new_session)
    return ledger, root, child


def receipt(ledger, root, child, raw):
    code = __import__('os').waitstatus_to_exitcode(raw)
    return {'pid': child.pid, 'child_token': ledger.process(child).life_token,
            'nonce': ledger.nonce, 'owner_pid': root.pid,
            'owner_identity': dict(ledger.process(root).registered_identity),
            'owner_token': ledger.process(root).life_token, 'requested_pid': child.pid,
            'wait_event': 'actual_os_waitpid_return', 'raw_status': raw,
            'numeric_returncode': code, 'options': 0}


def terminal(ledger, child, raw):
    emit(ledger, 'kernel_exit', pid=child.pid, raw=raw)
    emit(ledger, 'tracer_terminal_wait', pid=child.pid, raw=raw,
         normalized=__import__('os').waitstatus_to_exitcode(raw),
         identity=ledger.process(child).identity)


def wait4(ledger, root, child, raw):
    emit(ledger, 'original_parent_wait4', parent=root.pid, parent_tgid=root.tgid,
         child=child.pid, raw=raw, normalized=__import__('os').waitstatus_to_exitcode(raw), options=0)


@pytest.mark.parametrize('raw', [0, 17 << 8, int(signal.SIGTERM)])
@pytest.mark.parametrize('early_receipt', [False, True])
def test_only_complete_cross_stream_parent_join_establishes_reap(raw, early_receipt):
    ledger, root, child = setup()
    if early_receipt:
        ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, raw))
    assert not ledger.reaped(child, 'child-token')
    terminal(ledger, child, raw)
    assert not ledger.reaped(child, 'child-token')
    wait4(ledger, root, child, raw)
    if not early_receipt:
        assert not ledger.reaped(child, 'child-token')
        ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, raw))
    assert ledger.reaped(child, 'child-token')
    assert not ledger.reaped(child, 'different-token')


@pytest.mark.parametrize('field,value', [
    ('pid', 102), ('child_token', 'forged'), ('nonce', 'other'), ('owner_pid', 99),
    ('owner_token', 'forged'), ('requested_pid', -1), ('wait_event', 'cached'),
    ('raw_status', True), ('numeric_returncode', -99), ('options', True),
    ('owner_identity', identity(100, 98)),
])
def test_forged_parent_receipt_is_sticky_failure(field, value):
    ledger, root, child = setup()
    terminal(ledger, child, 17 << 8)
    wait4(ledger, root, child, 17 << 8)
    row = receipt(ledger, root, child, 17 << 8)
    row[field] = value
    with pytest.raises((Refused, TypeError)):
        ledger.control(root, 'root-token', 0, 0, 'parent-wait', row)
    assert ledger.poison and not ledger.reaped(child, 'child-token')


def test_receipt_options_must_join_actual_kernel_options():
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    row = receipt(ledger, root, child, 0)
    row['options'] = 1
    ledger.control(root, 'root-token', 0, 0, 'parent-wait', row)
    assert not ledger.reaped(child, 'child-token')


@pytest.mark.parametrize('missing', ['exit', 'terminal', 'wait4', 'receipt'])
def test_missing_facts_never_become_success(missing):
    ledger, root, child = setup()
    if missing not in ('exit', 'terminal'):
        terminal(ledger, child, 0)
    if missing == 'terminal':
        emit(ledger, 'kernel_exit', pid=child.pid, raw=0)
    if missing not in ('exit', 'terminal', 'wait4'):
        wait4(ledger, root, child, 0)
    if missing != 'receipt':
        ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, 0))
    assert not ledger.reaped(child, 'child-token')


def test_waitid_wnowait_and_tracer_wait_do_not_retire():
    ledger, root, child = setup()
    terminal(ledger, child, 23 << 8)
    emit(ledger, 'original_parent_waitid', parent=100, child=101,
         reaps=False, options=0x1000000, code=1, status=23)
    ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, 23 << 8))
    assert not ledger.reaped(child, 'child-token')
    wait4(ledger, root, child, 23 << 8)
    assert ledger.reaped(child, 'child-token')


def test_readiness_needs_registration_core_and_execution_seal():
    ledger, root, child = setup()
    assert not ledger.body_ready(root, 'root-token')
    ledger.control(root, 'root-token', 0, 0, 'core-ready', {'pins': PINS})
    assert not ledger.body_ready(root, 'root-token')
    ledger.control(root, 'root-token', 0, 1, 'body-ready', {'seal': SEAL})
    assert ledger.body_ready(root, 'root-token')
    emit(ledger, 'kernel_exec', pid=root.pid)
    assert not ledger.body_ready(root, 'root-token')
    with pytest.raises(Refused, match='stale readiness'):
        ledger.control(root, 'root-token', 0, 2, 'body-ready', {'seal': SEAL})
    assert not ledger.body_ready(root, 'root-token')


def test_delayed_wait_fact_from_prior_exec_epoch_is_joined_but_never_restores_ready():
    ledger, root, child = setup()
    row = receipt(ledger, root, child, 0)
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    emit(ledger, 'kernel_exec', pid=root.pid)
    ledger.register(root, 'root-epoch2', PINS, SEAL, case='case[one]', command_class='root')
    ledger.control(root, 'root-token', 0, 0, 'parent-wait', row)
    assert ledger.reaped(child, 'child-token')
    assert not ledger.body_ready(root, 'root-token')
    assert not ledger.body_ready(root, 'root-epoch2')


@pytest.mark.parametrize('bad', ['body_before_core', 'wrong_pins', 'wrong_seal', 'sequence', 'replay'])
def test_readiness_or_stream_errors_poison(bad):
    ledger, root, child = setup()
    if bad in ('wrong_seal', 'replay'):
        ledger.control(root, 'root-token', 0, 0, 'core-ready', {'pins': PINS})
    with pytest.raises(Refused):
        if bad == 'body_before_core':
            ledger.control(root, 'root-token', 0, 0, 'body-ready', {'seal': SEAL})
        elif bad == 'wrong_pins':
            ledger.control(root, 'root-token', 0, 0, 'core-ready', {'pins': (('runtime', 'c' * 64),)})
        elif bad == 'wrong_seal':
            ledger.control(root, 'root-token', 0, 1, 'body-ready', {'seal': 'wrong'})
        elif bad == 'sequence':
            ledger.control(root, 'root-token', 0, 1, 'core-ready', {'pins': PINS})
        else:
            ledger.control(root, 'root-token', 0, 0, 'core-ready', {'pins': PINS})
    assert ledger.poison and not ledger.body_ready(root, 'root-token')


def test_preexec_intent_can_only_become_ready_in_its_actual_exec_generation():
    ledger = Ledger('nonce')
    root_id = identity(100, 99)
    root = Birth.read(root_id)
    emit(ledger, 'kernel_root', identity=root_id)
    ledger.register(root, 'root-token', PINS, SEAL, case='case[one]', command_class='root', expected_generation=1)
    emit(ledger, 'kernel_exec', pid=root.pid)
    ledger.control(root, 'root-token', 1, 0, 'core-ready', {'pins': PINS})
    ledger.control(root, 'root-token', 1, 1, 'body-ready', {'seal': SEAL})
    assert ledger.body_ready(root, 'root-token')


def session_records():
    common = {'owner_pid': 100, 'token': 'child-token', 'case': 'case[one]', 'class': 'child'}
    return ({**common, 'kind': 'admitted'},
            {**common, 'kind': 'registered', 'pid': 101, 'python': True},
            {**common, 'kind': 'launch_lifecycle_binding', 'start_new_session': True})


def test_session_transition_changes_only_registered_view_not_original_birth():
    ledger, root, child = setup(new_session=True)
    original = deepcopy(ledger.process(child).identity)
    current = {**original, 'pgid': child.pid, 'sid': child.pid}
    ledger.session(child, current, session_records())
    assert ledger.process(child).identity == original
    assert ledger.process(child).registered_identity == current
    ledger.control(child, 'child-token', 0, 0, 'core-ready', {'pins': PINS})
    ledger.control(child, 'child-token', 0, 1, 'body-ready', {'seal': SEAL})
    assert ledger.body_ready(child, 'child-token')


@pytest.mark.parametrize('mutation', ['case', 'class', 'start_new_session', 'pid', 'duplicate', 'stable_birth'])
def test_session_transition_cannot_launder_other_missing_identity(mutation):
    ledger, root, child = setup(new_session=True)
    records = list(session_records())
    current = {**ledger.process(child).identity, 'pgid': 101, 'sid': 101}
    if mutation == 'case':
        records[0]['case'] = 'wrong'
    elif mutation == 'class':
        records[0]['class'] = 'wrong'
    elif mutation == 'start_new_session':
        records[2]['start_new_session'] = False
    elif mutation == 'pid':
        records[1]['pid'] = 102
    elif mutation == 'duplicate':
        records[2] = records[1]
    else:
        current['start_ticks'] += 1
    with pytest.raises(Refused):
        ledger.session(child, current, tuple(records))
    assert ledger.poison


def test_waiting_thread_uses_actual_parent_thread_group():
    ledger, root, child = setup()
    thread_id = identity(102, root.parent, tgid=root.tgid)
    emit(ledger, 'kernel_child', parent=root.pid, child=102, event=3, identity=thread_id)
    terminal(ledger, child, 0)
    emit(ledger, 'original_parent_wait4', parent=102, parent_tgid=100, child=101,
         raw=0, normalized=0, options=0)
    ledger.control(root, 'root-token', 0, 0, 'parent-wait', receipt(ledger, root, child, 0))
    assert ledger.reaped(child, 'child-token')


def test_root_actual_parent_wait_does_not_become_descendant_parent_wait():
    ledger, root, child = setup()
    terminal(ledger, root, 0)
    assert not ledger.reaped(root, 'root-token')
    assert canonical(ledger.process(root).identity) == ledger.process(root).identity


@pytest.mark.parametrize('operation', ['body-ready', 'core-ready', 'exec'])
def test_observed_exit_fences_authority_before_actual_terminal_wait(operation):
    ledger, root, child = setup()
    ledger.control(root, 'root-token', 0, 0, 'core-ready', {'pins': PINS})
    ledger.control(root, 'root-token', 0, 1, 'body-ready', {'seal': SEAL})
    assert ledger.body_ready(root, 'root-token')
    emit(ledger, 'kernel_exit', pid=root.pid, raw=0)
    assert ledger.process(root).terminal is None and not ledger.body_ready(root, 'root-token')
    with pytest.raises(Refused):
        if operation == 'exec':
            emit(ledger, 'kernel_exec', pid=root.pid)
        else:
            ledger.control(root, 'root-token', 0, 2, operation,
                           {'seal': SEAL} if operation == 'body-ready' else {'pins': PINS})
    assert ledger.poison and not ledger.body_ready(root, 'root-token')


def test_reused_numeric_parent_tgid_never_inherits_original_parent_birth():
    ledger, root, child = setup()
    survivor_id = identity(102, 101)
    emit(ledger, 'kernel_child', parent=101, child=102, event=1, identity=survivor_id)
    terminal(ledger, child, 0)
    terminal(ledger, root, 0)
    reused = identity(100, 102)
    reused['start_ticks'] += 100000
    emit(ledger, 'kernel_child', parent=102, child=100, event=1, identity=reused)
    with pytest.raises(Refused, match='waiting parent birth'):
        emit(ledger, 'original_parent_wait4', parent=100, parent_tgid=100, child=101,
             raw=0, normalized=0, options=0)
    assert ledger.poison and not ledger.reaped(child, 'child-token')


def test_terminal_waiting_thread_cannot_supply_new_parent_wait():
    ledger, root, child = setup()
    thread_id = identity(102, root.parent, tgid=root.tgid)
    thread_birth = Birth.read(thread_id)
    emit(ledger, 'kernel_child', parent=root.pid, child=102, event=3, identity=thread_id)
    terminal(ledger, thread_birth, 0)
    terminal(ledger, child, 0)
    with pytest.raises(Refused, match='waiting parent birth'):
        emit(ledger, 'original_parent_wait4', parent=102, parent_tgid=100, child=101,
             raw=0, normalized=0, options=0)
    assert ledger.poison


@pytest.mark.parametrize('duplicate', ['kernel', 'receipt', 'token'])
def test_duplicate_stream_facts_and_tokens_never_replay(duplicate):
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    row = receipt(ledger, root, child, 0)
    ledger.control(root, 'root-token', 0, 0, 'parent-wait', row)
    assert ledger.reaped(child, 'child-token')
    with pytest.raises(Refused):
        if duplicate == 'kernel':
            ledger.kernel(ledger.next_kernel - 1, {'kind': 'kernel_exec', 'pid': root.pid})
        elif duplicate == 'receipt':
            ledger.control(root, 'root-token', 0, 1, 'parent-wait', row)
        else:
            ledger.register(child, 'root-token', PINS, SEAL, case='case[one]', command_class='child')
    assert ledger.poison and not ledger.reaped(child, 'child-token')


@pytest.mark.parametrize('missing_wait', (False, True))
def test_many_children_keep_individual_parent_joins_beyond_epoch_bound(missing_wait):
    ledger, root, child = setup()
    for index in range(129):
        if index:
            data = identity(101 + index, root.pid)
            child = Birth.read(data)
            emit(ledger, 'kernel_child', parent=root.pid, child=child.pid, event=1, identity=data)
            ledger.register(child, f'child-{index}', PINS, SEAL, case='case[one]', command_class='child')
        raw = (index % 2) << 8
        terminal(ledger, child, raw)
        if not (missing_wait and index == 128):
            wait4(ledger, root, child, raw)
        ledger.control(root, 'root-token', 0, index, 'parent-wait', receipt(ledger, root, child, raw))
        assert ledger.reaped(child, ledger.process(child).life_token) == (not missing_wait or index != 128)
    with pytest.raises(Refused, match='duplicate parent receipt'):
        ledger.control(root, 'root-token', 0, 129, 'parent-wait', receipt(ledger, root, child, raw))
    assert ledger.poison


def test_exec_epoch_bound_is_independent_of_parent_receipt_capacity():
    from process_ledger import MAX_EXEC_EPOCHS, MAX_CONTROL_ROWS
    ledger, root, child = setup()
    assert MAX_CONTROL_ROWS > MAX_EXEC_EPOCHS == 128
    for generation in range(1, MAX_EXEC_EPOCHS):
        emit(ledger, 'kernel_exec', pid=child.pid)
        ledger.register(child, f'epoch-{generation}', PINS, SEAL, case='case[one]', command_class='child')
    emit(ledger, 'kernel_exec', pid=child.pid)
    with pytest.raises(Refused, match='unbounded exec epoch'):
        ledger.register(child, 'overflow-epoch', PINS, SEAL, case='case[one]', command_class='child')
    assert ledger.poison
