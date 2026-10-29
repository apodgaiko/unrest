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
    if kind == 'original_parent_wait4':
        values.setdefault('requested_pid', values['child'])
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


def terminal(ledger, child, raw):
    emit(ledger, 'kernel_exit', pid=child.pid, raw=raw)
    emit(ledger, 'tracer_terminal_wait', pid=child.pid, raw=raw,
         normalized=__import__('os').waitstatus_to_exitcode(raw),
         identity=ledger.process(child).identity)


def wait4(ledger, root, child, raw):
    emit(ledger, 'original_parent_wait4', parent=root.pid, parent_tgid=root.tgid,
         child=child.pid, raw=raw, normalized=__import__('os').waitstatus_to_exitcode(raw), options=0)


@pytest.mark.parametrize('raw', [0, 17 << 8, int(signal.SIGTERM)])
def test_only_complete_kernel_parent_join_establishes_reap(raw):
    ledger, root, child = setup()
    ledger.wait_entry(root, child.pid)
    assert not ledger.reaped(child, 'child-token')
    terminal(ledger, child, raw)
    assert not ledger.reaped(child, 'child-token')
    wait4(ledger, root, child, raw)
    assert ledger.reaped(child, 'child-token')
    assert not ledger.reaped(child, 'different-token')


@pytest.mark.parametrize('requested', [-2, -1, 0, 99, 100, 102, True, None])
def test_foreign_wildcard_or_unregistered_wait_is_refused_before_syscall(requested):
    ledger, root, child = setup()
    with pytest.raises(Refused):
        ledger.wait_entry(root, requested)
    assert ledger.poison and not ledger.reaped(child, 'child-token')


@pytest.mark.parametrize('mutation', ['parent', 'token', 'thread', 'caller-exit', 'caller-birth'])
def test_wait_entry_requires_admitted_child_and_current_living_parent(mutation):
    ledger, root, child = setup()
    if mutation == 'parent':
        ledger.process(child).parent = child
    elif mutation == 'token':
        ledger.process(child).life_token = None
    elif mutation == 'thread':
        ledger.process(child).birth = __import__('dataclasses').replace(child, tgid=root.tgid)
    elif mutation == 'caller-exit':
        emit(ledger, 'kernel_exit', pid=root.pid, raw=0)
    else:
        ledger.current[root.pid] = child
    with pytest.raises(Refused):
        ledger.wait_entry(root, child.pid)
    assert ledger.poison


@pytest.mark.parametrize('command_class', ['native-git-command', 'native-git-helper', 'native-full-uv', 'other', 'root'])
def test_native_wildcard_wait_is_selected_by_admitted_command_class(command_class):
    ledger, root, child = setup()
    ledger.process(root).command_class = command_class
    if command_class in ('native-git-command', 'native-git-helper', 'native-full-uv'):
        ledger.wait_entry(root, -1)
        assert not ledger.reaped(child, 'child-token')
    else:
        with pytest.raises(Refused):
            ledger.wait_entry(root, -1)


@pytest.mark.parametrize('missing', ['exit', 'terminal', 'wait4'])
def test_missing_facts_never_become_success(missing):
    ledger, root, child = setup()
    if missing not in ('exit', 'terminal'):
        terminal(ledger, child, 0)
    if missing == 'terminal':
        emit(ledger, 'kernel_exit', pid=child.pid, raw=0)
    if missing not in ('exit', 'terminal', 'wait4'):
        wait4(ledger, root, child, 0)
    assert not ledger.reaped(child, 'child-token')


def test_waitid_wnowait_and_tracer_wait_do_not_retire():
    ledger, root, child = setup()
    terminal(ledger, child, 23 << 8)
    emit(ledger, 'original_parent_waitid', parent=100, child=101,
         reaps=False, options=0x1000000, code=1, status=23)
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
    with pytest.raises(Refused, match='epoch or sequence'):
        ledger.control(root, 'root-token', 0, 2, 'body-ready', {'seal': SEAL})
    assert not ledger.body_ready(root, 'root-token')


def test_delayed_wait_fact_from_prior_exec_epoch_is_joined_but_never_restores_ready():
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    emit(ledger, 'kernel_exec', pid=root.pid)
    ledger.register(root, 'root-epoch2', PINS, SEAL, case='case[one]', command_class='root')
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


@pytest.mark.parametrize('duplicate', ['kernel', 'wait', 'token'])
def test_duplicate_stream_facts_and_tokens_never_replay(duplicate):
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    assert ledger.reaped(child, 'child-token')
    with pytest.raises(Refused):
        if duplicate == 'kernel':
            ledger.kernel(ledger.next_kernel - 1, {'kind': 'kernel_exec', 'pid': root.pid})
        elif duplicate == 'wait':
            wait4(ledger, root, child, 0)
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
        assert ledger.reaped(child, ledger.process(child).life_token) == (not missing_wait or index != 128)
    if missing_wait:
        wait4(ledger, root, child, raw)
        assert ledger.reaped(child, ledger.process(child).life_token)
    with pytest.raises(Refused, match='parent wait join'):
        wait4(ledger, root, child, raw)
    assert ledger.poison


def test_exec_epoch_bound_is_independent_of_parent_wait_count():
    from process_ledger import MAX_EXEC_EPOCHS, MAX_CONTROL_ROWS
    ledger, root, child = setup()
    assert MAX_CONTROL_ROWS == 2 and MAX_EXEC_EPOCHS == 128
    for generation in range(1, MAX_EXEC_EPOCHS):
        emit(ledger, 'kernel_exec', pid=child.pid)
        ledger.register(child, f'epoch-{generation}', PINS, SEAL, case='case[one]', command_class='child')
    emit(ledger, 'kernel_exec', pid=child.pid)
    with pytest.raises(Refused, match='unbounded exec epoch'):
        ledger.register(child, 'overflow-epoch', PINS, SEAL, case='case[one]', command_class='child')
    assert ledger.poison


@pytest.mark.parametrize(
    "leader_status,thread_terminal,valid", [(1, 1, True), (2, 1, False), (1, 0, True)]
)
def test_thread_terminal_can_join_actual_group_exit_without_becoming_a_parent_reap(
    leader_status, thread_terminal, valid
):
    ledger = Ledger("thread-exit")
    leader_id, thread_id = identity(100, 99), identity(101, 99, tgid=100)
    leader, thread = Birth.read(leader_id), Birth.read(thread_id)
    emit(ledger, "kernel_root", identity=leader_id)
    emit(ledger, "kernel_child", parent=100, child=101, event=3, identity=thread_id)
    emit(ledger, "kernel_exit", pid=101, raw=0)
    emit(ledger, "kernel_exit", pid=100, raw=leader_status << 8)
    if valid:
        emit(
            ledger,
            "tracer_terminal_wait",
            pid=101,
            raw=thread_terminal << 8,
            normalized=thread_terminal,
            identity=thread_id,
        )
        assert ledger.process(thread).exit[1] == 0
        assert ledger.process(thread).terminal[1] == thread_terminal << 8
        assert not ledger.pending_waits and ledger.process(leader).parent_wait is None
    else:
        with pytest.raises(Refused, match="terminal birth or exit"):
            emit(
                ledger,
                "tracer_terminal_wait",
                pid=101,
                raw=thread_terminal << 8,
                normalized=thread_terminal,
                identity=thread_id,
            )
        assert ledger.poison


def test_process_leader_cannot_borrow_parent_or_thread_terminal_status():
    ledger, root, child = setup()
    emit(ledger, "kernel_exit", pid=root.pid, raw=1 << 8)
    emit(ledger, "kernel_exit", pid=child.pid, raw=0)
    with pytest.raises(Refused, match="terminal birth or exit"):
        emit(
            ledger,
            "tracer_terminal_wait",
            pid=child.pid,
            raw=1 << 8,
            normalized=1,
            identity=ledger.process(child).identity,
        )
    assert not ledger.process(child).parent_wait


@pytest.mark.parametrize('requested', [None, -1, 0, 102, True])
def test_terminal_wait_cannot_borrow_a_different_requested_child(requested):
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    with pytest.raises(Refused):
        emit(ledger, 'original_parent_wait4', parent=root.pid, parent_tgid=root.tgid,
             requested_pid=requested, child=child.pid, raw=0, normalized=0, options=0)
    assert ledger.poison and not ledger.reaped(child, 'child-token')


def test_waiting_thread_entry_binds_original_group_and_cannot_borrow_another_child():
    ledger, root, child = setup()
    thread_id = identity(102, root.parent, tgid=root.tgid)
    thread = Birth.read(thread_id)
    emit(ledger, 'kernel_child', parent=root.pid, child=102, event=3, identity=thread_id)
    ledger.wait_entry(thread, child.pid)
    with pytest.raises(Refused):
        ledger.wait_entry(thread, root.pid)


@pytest.mark.parametrize('token', [None, '', 'unregistered', True])
def test_native_owned_fork_wait_cannot_retire_without_child_admission(token):
    ledger, root, child = setup()
    ledger.process(root).command_class = 'native-full-uv'
    ledger.process(child).life_token = None
    del ledger.by_token['child-token']
    ledger.wait_entry(root, child.pid)
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    assert not ledger.reaped(child, token)
    assert not ledger.reaped(child, 'child-token')


@pytest.mark.parametrize('leader_raw,terminal_raw,valid',[(9,9,True),(0,0,False),(15,9,False),(9,15,False)])
def test_missing_thread_exit_stop_accepts_only_actual_group_sigkill(leader_raw,terminal_raw,valid):
    ledger=Ledger('missing-thread-exit')
    leader_id,thread_id=identity(100,99),identity(101,99,tgid=100)
    leader,thread=Birth.read(leader_id),Birth.read(thread_id)
    emit(ledger,'kernel_root',identity=leader_id)
    emit(ledger,'kernel_child',parent=100,child=101,event=3,identity=thread_id)
    emit(ledger,'kernel_exit',pid=100,raw=leader_raw)
    row=dict(pid=101,raw=terminal_raw,normalized=__import__('os').waitstatus_to_exitcode(terminal_raw),identity=thread_id)
    if valid:
        emit(ledger,'tracer_terminal_wait',**row)
        assert ledger.process(thread).exit is None  # Never manufacture the missing per-thread stop.
        assert ledger.process(thread).terminal[1:]==(9,-9)
        assert ledger.process(leader).terminal is None
        assert not ledger.reaped(thread,'unregistered') and not ledger.reaped(leader,'unregistered')
    else:
        with pytest.raises(Refused,match='terminal birth or exit'):
            emit(ledger,'tracer_terminal_wait',**row)
