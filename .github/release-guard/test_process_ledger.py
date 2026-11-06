"""Incremental reduction controls; kernel provenance needs the native integration."""
from __future__ import annotations

from copy import deepcopy
import os
import re
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
    ledger.register(root, 'root-token', PINS, case='case[one]', command_class='root')
    emit(ledger, 'kernel_child', parent=100, child=101, event=1, identity=child_id)
    ledger.register(child, 'child-token', PINS, case='case[one]', command_class='child',
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
    assert not ledger.reaped(child, 'child-token')


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


def test_tracer_wait_does_not_retire_without_original_parent_wait4():
    ledger, root, child = setup()
    terminal(ledger, child, 23 << 8)
    assert not ledger.reaped(child, 'child-token')
    wait4(ledger, root, child, 23 << 8)
    assert ledger.reaped(child, 'child-token')


def test_readiness_needs_registered_current_execution():
    ledger, root, child = setup()
    assert not ledger.body_ready(root, 'root-token')
    ledger.ready(root, 'body-ready', {})
    assert ledger.body_ready(root, 'root-token')
    emit(ledger, 'kernel_exec', pid=root.pid)
    assert not ledger.body_ready(root, 'root-token')
    with pytest.raises(Refused, match='stale readiness epoch'):
        ledger.ready(root, 'body-ready', {})
    assert not ledger.body_ready(root, 'root-token')


def test_delayed_wait_fact_from_prior_exec_epoch_is_joined_but_never_restores_ready():
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    emit(ledger, 'kernel_exec', pid=root.pid)
    ledger.register(root, 'root-epoch2', PINS, case='case[one]', command_class='root')
    assert ledger.reaped(child, 'child-token')
    assert not ledger.body_ready(root, 'root-token')
    assert not ledger.body_ready(root, 'root-epoch2')


@pytest.mark.parametrize('bad', ['old_core', 'wrong_payload', 'replay'])
def test_readiness_rejects_old_protocol_extra_payload_and_replay(bad):
    ledger, root, child = setup()
    if bad=='replay':
        ledger.ready(root,'body-ready',{})
    with pytest.raises(Refused):
        ledger.ready(root,'core-ready' if bad=='old_core' else 'body-ready',
                     {'seal':'wrong'} if bad=='wrong_payload' else {})
    assert ledger.body_ready(root,'root-token') == (bad=='replay')


def test_preexec_intent_can_only_become_ready_in_its_actual_exec_generation():
    ledger = Ledger('nonce')
    root_id = identity(100, 99)
    root = Birth.read(root_id)
    emit(ledger, 'kernel_root', identity=root_id)
    ledger.register(root, 'root-token', PINS, case='case[one]', command_class='root', expected_generation=1)
    emit(ledger, 'kernel_exec', pid=root.pid)
    ledger.ready(root, 'body-ready', {})
    assert ledger.body_ready(root, 'root-token')


def test_session_transition_changes_only_registered_view_not_original_birth():
    ledger, root, child = setup(new_session=True)
    original = deepcopy(ledger.process(child).identity)
    current = {**original, 'pgid': child.pid, 'sid': child.pid}
    ledger.session(child, current)
    assert ledger.process(child).identity == original
    assert ledger.process(child).registered_identity == current
    ledger.ready(child, 'body-ready', {})
    assert ledger.body_ready(child, 'child-token')


@pytest.mark.parametrize('mutation', ('not-declared','repeat','pgid','sid','stable_birth','original-group','unknown-parent'))
def test_session_transition_requires_actual_birth_parent_and_group(mutation):
    ledger,root,child=setup(new_session=mutation!='not-declared')
    current={**ledger.process(child).identity,'pgid':101,'sid':101}
    if mutation=='repeat':
        ledger.session(child,current)
    elif mutation in ('pgid','sid'):
        current[mutation]=100
    elif mutation=='stable_birth':
        current['start_ticks']+=1
    elif mutation=='original-group':
        ledger.process(child).identity['pgid']=102
    elif mutation=='unknown-parent':
        ledger.process(child).parent=None
    with pytest.raises(Refused):
        ledger.session(child,current)


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
    ledger.ready(root, 'body-ready', {})
    assert ledger.body_ready(root, 'root-token')
    emit(ledger, 'kernel_exit', pid=root.pid, raw=0)
    assert ledger.process(root).terminal is None and not ledger.body_ready(root, 'root-token')
    with pytest.raises(Refused):
        if operation == 'exec':
            emit(ledger, 'kernel_exec', pid=root.pid)
        else:
            ledger.ready(root, operation, {} if operation == 'body-ready' else {'pins': PINS})
    assert not ledger.body_ready(root, 'root-token')


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
    assert not ledger.reaped(child, 'child-token')


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


@pytest.mark.parametrize('duplicate', ['kernel', 'wait', 'token'])
def test_duplicate_stream_facts_raise_without_overwriting_history(duplicate):
    ledger, root, child = setup()
    terminal(ledger, child, 0)
    wait4(ledger, root, child, 0)
    assert ledger.reaped(child, 'child-token')
    previous=ledger.process(child).parent_wait
    with pytest.raises(Refused):
        if duplicate == 'kernel':
            ledger.kernel(ledger.next_kernel - 1, {'kind': 'kernel_exec', 'pid': root.pid})
        elif duplicate == 'wait':
            wait4(ledger, root, child, 0)
        else:
            ledger.register(child, 'root-token', PINS, case='case[one]', command_class='child')
    assert ledger.process(child).parent_wait==previous


@pytest.mark.parametrize('missing_wait', (False, True))
def test_many_children_keep_individual_parent_joins_beyond_epoch_bound(missing_wait):
    ledger, root, child = setup()
    for index in range(129):
        if index:
            data = identity(101 + index, root.pid)
            child = Birth.read(data)
            emit(ledger, 'kernel_child', parent=root.pid, child=child.pid, event=1, identity=data)
            ledger.register(child, f'child-{index}', PINS, case='case[one]', command_class='child')
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


def test_exec_epoch_bound_is_independent_of_parent_wait_count():
    from process_ledger import MAX_EXEC_EPOCHS
    ledger, root, child = setup()
    assert MAX_EXEC_EPOCHS == 128
    for generation in range(1, MAX_EXEC_EPOCHS):
        emit(ledger, 'kernel_exec', pid=child.pid)
        ledger.register(child, f'epoch-{generation}', PINS, case='case[one]', command_class='child')
    emit(ledger, 'kernel_exec', pid=child.pid)
    with pytest.raises(Refused, match='unbounded exec epoch'):
        ledger.register(child, 'overflow-epoch', PINS, case='case[one]', command_class='child')


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
    assert not ledger.reaped(child, 'child-token')


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


@pytest.mark.parametrize('own_exit',(False,True))
@pytest.mark.parametrize('leader_raw',(0,9,15,256))
def test_thread_kill_terminal_before_group_exit_requires_the_later_actual_group_status(leader_raw,own_exit):
    ledger,root,leader=setup()
    thread_id=identity(102,root.pid,tgid=leader.pid)
    thread=Birth.read(thread_id)
    emit(ledger,'kernel_child',parent=leader.pid,child=thread.pid,event=3,identity=thread_id)
    if own_exit:
        emit(ledger,'kernel_exit',pid=thread.pid,raw=0)
    emit(ledger,'tracer_terminal_wait',pid=thread.pid,raw=9,normalized=-9,identity=thread_id)
    assert (ledger.process(thread).exit[1] if own_exit else ledger.process(thread).exit)==(0 if own_exit else None)
    assert ledger.process(thread).terminal[1:]==(9,-9)
    assert not ledger.reaped(leader,'child-token')
    assert ledger.process(leader).exit is None
    if leader_raw!=9:
        with pytest.raises(Refused,match='pending thread group status'):
            emit(ledger,'kernel_exit',pid=leader.pid,raw=leader_raw)
        assert ledger.process(leader).exit is None
        return
    terminal(ledger,leader,9)
    assert not ledger.reaped(leader,'child-token')
    wait4(ledger,root,leader,9)
    assert ledger.reaped(leader,'child-token')


@pytest.mark.parametrize('raw,own_exit',((15,False),(0,False),(256,False),(15,True)))
def test_unjoined_thread_terminal_does_not_gain_a_general_status_exception(raw,own_exit):
    ledger,root,leader=setup()
    thread_id=identity(102,root.pid,tgid=leader.pid)
    emit(ledger,'kernel_child',parent=leader.pid,child=102,event=3,identity=thread_id)
    if own_exit:
        emit(ledger,'kernel_exit',pid=102,raw=0)
    with pytest.raises(Refused,match='terminal birth or exit'):
        emit(ledger,'tracer_terminal_wait',pid=102,raw=raw,normalized=__import__('os').waitstatus_to_exitcode(raw),identity=thread_id)


@pytest.mark.parametrize('own_exit',(False,True))
@pytest.mark.parametrize('mutation',('birth','group','duplicate'))
def test_deferred_group_kill_keeps_exact_thread_identity_and_single_terminal(mutation,own_exit):
    ledger,root,leader=setup()
    thread_id=identity(102,root.pid,tgid=leader.pid)
    thread=Birth.read(thread_id)
    emit(ledger,'kernel_child',parent=leader.pid,child=102,event=3,identity=thread_id)
    if own_exit:
        emit(ledger,'kernel_exit',pid=102,raw=0)
    if mutation=='group':
        ledger.process(thread).group=root
    elif mutation=='birth':
        thread_id={**thread_id,'start_ticks':thread_id['start_ticks']+1}
    else:
        emit(ledger,'tracer_terminal_wait',pid=102,raw=9,normalized=-9,identity=thread_id)
    with pytest.raises(Refused):
        emit(ledger,'tracer_terminal_wait',pid=102,raw=9,normalized=-9,identity=thread_id)


@pytest.mark.parametrize('denied',(False,True))
def test_excluded_socket_or_ring_record_is_never_source_completion(denied):
    ledger,_,_=setup()
    with pytest.raises(Refused,match='denied syscall'):
        emit(ledger,'denied_syscall_return',pid=100,syscall=41,denied=denied,return_code=-1)


def test_pending_missing_thread_stop_cannot_close_with_failure_cleanup():
    ledger,root,leader=setup()
    thread_id=identity(102,root.pid,tgid=leader.pid)
    thread=Birth.read(thread_id)
    emit(ledger,'kernel_child',parent=leader.pid,child=thread.pid,event=3,identity=thread_id)
    emit(ledger,'tracer_terminal_wait',pid=thread.pid,raw=9,normalized=-9,identity=thread_id)
    assert ledger.process(thread).exit is None
    with pytest.raises(Refused,match='failure cleanup cannot retire'):
        emit(ledger,'failure_cleanup_tracer_wait',pid=leader.pid,raw=9,normalized=-9,identity=ledger.process(leader).identity)
    assert not ledger.reaped(leader,'child-token')


# Ledger event-order contract V3 + amendment 1: ledger-API controls. Plausibility labels
# describe kernel orders only; none of these sequences is kernel trace evidence.
LEADER, ROOT_PID = 101, 100


def thread(ledger, pid, *, creator=LEADER, tgid=LEADER):
    value = identity(pid, ROOT_PID, tgid=tgid)
    emit(ledger, 'kernel_child', parent=creator, child=pid, event=3, identity=value)
    return Birth.read(value)


def reap(ledger, birth, raw):
    emit(ledger, 'tracer_terminal_wait', pid=birth.pid, raw=raw,
         normalized=os.waitstatus_to_exitcode(raw), identity=ledger.process(birth).identity)


def refused(ledger, text, kind, **values):
    before, sequence = deepcopy(vars(ledger)), ledger.next_kernel
    with pytest.raises(Refused, match='^' + re.escape(text) + '$'):
        emit(ledger, kind, **values)
    assert ledger.next_kernel == sequence and vars(ledger) == before


def test_unjoined_canonical_normal_terminal_with_own_exit_is_pending_not_closure():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    assert ledger.process(member).terminal[1:] == (256, 1) and ledger.process(member).exit[1] == 0
    assert ledger.process(leader).exit is None and ledger.debt_of(member)
    assert not ledger.settled((leader,)) and not ledger.reaped(leader, 'child-token')


# Each thread: (own exit-stop raw or None for exact SIGKILL without a stop, terminal raw).
FAMILIES = {'F1a': ([(0, 256)], 256), 'F1b': ([(0, 256), (0, 256)], 256),
            'F2': ([(0, 0), (0, 256)], 256), 'F3a': ([(0, 256)], 0),
            'F3b': ([(0, 256), (0, 512)], 256), 'F4': ([(None, 9)], 9),
            'F5-9': ([(None, 9), (0, 256)], 9), 'F5-256': ([(None, 9), (0, 256)], 256),
            'F6': ([(256, 0), (9, 9)], 0)}
COUNTS = {'F1a': 10, 'F1b': 210, 'F2': 210, 'F3a': 10, 'F3b': 210, 'F4': 4,
          'F5-9': 60, 'F5-256': 60, 'F6': 210}
NARROW = {'F1a': 3, 'F1b': 30, 'F2': 30, 'F3a': 3, 'F3b': 30, 'F4': 2, 'F5-9': 12, 'F5-256': 12, 'F6': 30}
# Label of the subset whose thread terminals all precede the leader terminal; the rest is
# implausible by delayed leader reaping. Labels are contract claims, not observations.
NARROW_LABEL = {'F1a': 'plausible-candidate', 'F1b': 'plausible-candidate', 'F2': 'plausible-candidate',
                'F3a': 'implausible', 'F3b': 'implausible', 'F4': 'plausible-candidate',
                'F5-9': 'implausible', 'F5-256': 'implausible', 'F6': 'unknown'}
PENDING, CONTRADICTION = 'ledger pending thread group status', 'ledger group status contradiction'
TERMINAL = 'ledger terminal birth or exit'


def chains(family):
    threads, _ = FAMILIES[family]
    rows = [[('eT', index), ('tT', index)] if own is not None else [('tT', index)]
            for index, (own, _) in enumerate(threads)]
    return rows + [[('eL', None), ('tL', None), ('wL', None)]]


def interleavings(rows):
    if not any(rows):
        yield ()
        return
    for index, row in enumerate(rows):
        if row:
            rest = rows[:index] + [row[1:]] + rows[index + 1:]
            for tail in interleavings(rest):
                yield (row[0],) + tail


def extensions(family):
    return list(interleavings(chains(family)))


def narrow(order):
    position = {event: index for index, event in enumerate(order)}
    return all(position[event] < position[('tL', None)] for event in order if event[0] == 'tT')


def plausibility(family, order):
    return NARROW_LABEL[family] if narrow(order) else 'implausible'


def expected_refusal(family, order):
    """Refusing event and text, fixed only by each thread terminal's place against eL."""
    position = {event: index for index, event in enumerate(order)}
    before = {index for (kind, index) in order if kind == 'tT' and position[('tT', index)] < position[('eL', None)]}
    if family in ('F1a', 'F1b', 'F2', 'F4', 'F6'):
        return None
    if before == {0, 1}:
        return (max(('tT', 0), ('tT', 1), key=position.get), CONTRADICTION)
    mismatch = {'F3a': 0, 'F3b': 1, 'F5-9': 1, 'F5-256': 0}[family]  # terminal raw differs from eL
    if before == {mismatch}:
        return (('eL', None), PENDING)
    return (('tT', mismatch), TERMINAL)


def run_extension(family, order):
    """Feed one extension to a fresh ledger; return the observed refusal or None."""
    threads, leader_raw = FAMILIES[family]
    ledger, root, leader = setup()
    members = [thread(ledger, 102 + index) for index in range(len(threads))]
    done = set()
    for event in order:
        kind, index = event
        if kind == 'eT':
            row = dict(kind='kernel_exit', pid=members[index].pid, raw=threads[index][0])
        elif kind == 'tT':
            raw = threads[index][1]
            row = dict(kind='tracer_terminal_wait', pid=members[index].pid, raw=raw,
                       normalized=os.waitstatus_to_exitcode(raw), identity=ledger.process(members[index]).identity)
        elif kind == 'eL':
            row = dict(kind='kernel_exit', pid=leader.pid, raw=leader_raw)
        elif kind == 'tL':
            row = dict(kind='tracer_terminal_wait', pid=leader.pid, raw=leader_raw,
                       normalized=os.waitstatus_to_exitcode(leader_raw), identity=ledger.process(leader).identity)
        else:
            row = dict(kind='original_parent_wait4', parent=root.pid, parent_tgid=root.tgid, child=leader.pid,
                       raw=leader_raw, normalized=os.waitstatus_to_exitcode(leader_raw), options=0)
        before, sequence = deepcopy(vars(ledger)), ledger.next_kernel
        try:
            emit(ledger, **row)
        except Refused as error:
            assert ledger.next_kernel == sequence and vars(ledger) == before
            return event, str(error)
        done.add(kind)
        if ledger.process(leader).exit is not None:
            assert ledger.settled((leader,))
        assert ledger.reaped(leader, 'child-token') == ('wL' in done)
    assert ledger.final_settled() and ledger.settled((leader,))
    for member, (own, raw) in zip(members, threads):
        process = ledger.process(member)
        assert process.terminal[1] == raw and (process.exit is None if own is None else process.exit[1] == own)
    return None


@pytest.mark.parametrize('family', tuple(FAMILIES))
def test_order_family_linear_extensions(family):
    for order in extensions(family):
        assert run_extension(family, order) == expected_refusal(family, order), order


def test_order_enumerator_self_check():
    total = narrow_total = 0
    for family, count in COUNTS.items():
        orders = extensions(family)
        rows = chains(family)
        assert len(orders) == count and len(set(orders)) == count
        assert sum(map(narrow, orders)) == NARROW[family]
        for order in orders:
            assert sorted(order, key=repr) == sorted((event for row in rows for event in row), key=repr)
            assert all([event for event in order if event in row] == row for row in rows)
            assert plausibility(family, order) in ('plausible-candidate', 'implausible', 'unknown')
        total, narrow_total = total + count, narrow_total + NARROW[family]
    assert (total, narrow_total) == (984, 152)


def test_order_ci_reordered_normal_status_is_pending_then_resolved():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    assert ledger.debt_of(member) and not ledger.final_settled()
    terminal(ledger, leader, 256)
    assert not ledger.debt_of(member) and ledger.settled((leader,)) and ledger.final_settled()
    wait4(ledger, root, leader, 256)
    assert ledger.reaped(leader, 'child-token')


@pytest.mark.parametrize('own,raw', ((256, 0), (0, 256), (0, 65280)), ids=('own256-raw0', 'own0-raw256', 'own0-raw65280'))
def test_order_canonical_normal_boundaries(own, raw):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=own)
    reap(ledger, member, raw)
    assert ledger.debt_of(member)
    terminal(ledger, leader, raw)
    assert not ledger.debt_of(member) and ledger.settled((leader,))


@pytest.mark.parametrize('raw', (0, 256, 65280))
def test_order_normal_requires_actual_own_stop(raw):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    refused(ledger, TERMINAL, 'tracer_terminal_wait', pid=102, raw=raw,
            normalized=os.waitstatus_to_exitcode(raw), identity=ledger.process(member).identity)


@pytest.mark.parametrize('raw,normalized,text', ((15, -15, TERMINAL), (143, -15, TERMINAL),
                         (256, 2, 'ledger terminal status'), (True, 1, 'ledger integer')),
                         ids=('raw15', 'raw143', 'normalized-mismatch', 'bool-raw'))
def test_order_noncanonical_status_gets_no_pending(raw, normalized, text):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    refused(ledger, text, 'tracer_terminal_wait', pid=102, raw=raw, normalized=normalized,
            identity=ledger.process(member).identity)


@pytest.mark.parametrize('leader_raw', (0, 9, 512))
def test_order_leader_exit_must_match_received_dependents(leader_raw):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    refused(ledger, PENDING, 'kernel_exit', pid=leader.pid, raw=leader_raw)
    assert ledger.process(leader).exit is None


def test_order_three_task_leader_exit_before_group_exit_refuses_at_leader_exit():
    # The leader exited with 0 before another thread's exit_group(1); its stop is seen last.
    ledger, root, leader = setup()
    first, second = thread(ledger, 102), thread(ledger, 103)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    emit(ledger, 'kernel_exit', pid=103, raw=256)
    reap(ledger, second, 256)
    reap(ledger, first, 256)
    refused(ledger, PENDING, 'kernel_exit', pid=leader.pid, raw=0)


def test_order_late_dependent_must_match_leader_exit():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    emit(ledger, 'kernel_exit', pid=leader.pid, raw=256)
    refused(ledger, TERMINAL, 'tracer_terminal_wait', pid=102, raw=512, normalized=2,
            identity=ledger.process(member).identity)


def contradiction_prefix(second_raw):
    ledger, root, leader = setup()
    first, second = thread(ledger, 102), thread(ledger, 103)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    emit(ledger, 'kernel_exit', pid=103, raw=0)
    reap(ledger, first, 256)
    row = dict(pid=103, raw=second_raw, normalized=os.waitstatus_to_exitcode(second_raw),
               identity=ledger.process(second).identity)
    return ledger, second, row


@pytest.mark.parametrize('variant', ('same', 'different'))
def test_order_dependent_status_contradiction_refuses_eagerly(variant):
    ledger, second, row = contradiction_prefix(256 if variant == 'same' else 512)
    if variant == 'same':
        emit(ledger, 'tracer_terminal_wait', **row)
        assert ledger.debt_of(second)
        return
    refused(ledger, CONTRADICTION, 'tracer_terminal_wait', **row)
    assert ledger.process(second).terminal is None


@pytest.mark.parametrize('variant', ('own0-dep256-eL256', 'own9-eL0'))
def test_order_self_supported_terminals_create_no_debt(variant):
    ledger, root, leader = setup()
    own, dependent = thread(ledger, 102), thread(ledger, 103)
    own_raw, dependent_own, dependent_raw, leader_raw = (0, 0, 256, 256) if variant == 'own0-dep256-eL256' else (9, 256, 0, 0)
    emit(ledger, 'kernel_exit', pid=102, raw=own_raw)
    emit(ledger, 'kernel_exit', pid=103, raw=dependent_own)
    reap(ledger, own, own_raw)
    reap(ledger, dependent, dependent_raw)
    assert not ledger.debt_of(own) and ledger.debt_of(dependent)
    terminal(ledger, leader, leader_raw)
    assert ledger.final_settled()


def late_exit_prefix():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    reap(ledger, member, 9)
    return ledger, member


@pytest.mark.parametrize('variant', ('c9', 'a-terminal'))
def test_order_late_own_exit_after_terminal_is_refused(variant):
    if variant == 'c9':
        ledger, member = late_exit_prefix()
        refused(ledger, 'ledger exit after terminal', 'kernel_exit', pid=102, raw=9)
        return
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 0)
    refused(ledger, 'ledger duplicate exit', 'kernel_exit', pid=102, raw=0)


@pytest.mark.parametrize('variant', ('c9', 'normal'))
def test_order_exec_with_group_status_debt_is_refused(variant):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    if variant == 'normal':
        emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 9 if variant == 'c9' else 256)
    refused(ledger, 'ledger exec with group status debt', 'kernel_exec', pid=leader.pid)
    assert ledger.process(leader).generation == 0


def epoch_prefix(variant):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    if variant == 'normal':
        emit(ledger, 'kernel_exit', pid=102, raw=0)
    emit(ledger, 'kernel_exec', pid=leader.pid)
    raw = 256 if variant == 'normal' else 9
    return ledger, dict(pid=102, raw=raw, normalized=os.waitstatus_to_exitcode(raw),
                        identity=ledger.process(member).identity)


@pytest.mark.parametrize('variant', ('normal', 'c9'))
def test_order_membership_epoch_binds_pending(variant):
    ledger, row = epoch_prefix(variant)
    refused(ledger, TERMINAL, 'tracer_terminal_wait', **row)


@pytest.mark.parametrize('variant', ('members-exited-before-exec', 'members-exit-after-exec'))
def test_order_exec_without_debt_keeps_live_members(variant):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    if variant == 'members-exited-before-exec':
        emit(ledger, 'kernel_exit', pid=102, raw=9)
    emit(ledger, 'kernel_exec', pid=leader.pid)
    if variant == 'members-exit-after-exec':
        emit(ledger, 'kernel_exit', pid=102, raw=9)
    reap(ledger, member, 9)
    assert ledger.process(leader).generation == 1 and not ledger.debt_of(member)


@pytest.mark.parametrize('mutation', ('start_ticks', 'boot', 'uid', 'tgid', 'duplicate', 'live-replacement'))
def test_order_pending_keeps_exact_identity(mutation):
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    changed = dict(ledger.process(member).identity)
    if mutation == 'duplicate':
        reap(ledger, member, 256)
        refused(ledger, 'ledger duplicate terminal', 'tracer_terminal_wait', pid=102, raw=256, normalized=1, identity=changed)
        return
    if mutation == 'live-replacement':
        replacement = {**identity(101, 100), 'start_ticks': 1}
        refused(ledger, 'ledger live PID replacement', 'kernel_child', parent=100, child=101, event=1, identity=replacement)
        return
    updates = {'start_ticks': {'start_ticks': changed['start_ticks'] + 1}, 'boot': {'boot_id': 'other'},
               'uid': {'uids': [20001] * 4}, 'tgid': {'tgid': 100}}
    changed.update(updates[mutation])
    refused(ledger, TERMINAL, 'tracer_terminal_wait', pid=102, raw=256, normalized=1, identity=changed)


def test_order_synthetic_group_mutation_is_refused():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    ledger.process(member).group = root  # synthetic state, defensive only
    refused(ledger, TERMINAL, 'tracer_terminal_wait', pid=102, raw=256, normalized=1,
            identity=ledger.process(member).identity)


@pytest.mark.parametrize('variant', ('terminal-before-exit', 'wait-before-terminal', 'wait-raw-mismatch', 'foreign-caller'))
def test_order_leader_rules_unchanged(variant):
    ledger, root, leader = setup()
    if variant == 'terminal-before-exit':
        refused(ledger, TERMINAL, 'tracer_terminal_wait', pid=leader.pid, raw=0, normalized=0,
                identity=ledger.process(leader).identity)
        return
    wait = dict(parent=root.pid, parent_tgid=root.tgid, child=leader.pid, requested_pid=leader.pid, raw=0, normalized=0, options=0)
    if variant == 'wait-before-terminal':
        emit(ledger, 'kernel_exit', pid=leader.pid, raw=0)
        refused(ledger, 'ledger parent wait join', 'original_parent_wait4', **wait)
        return
    if variant == 'foreign-caller':
        emit(ledger, 'kernel_child', parent=100, child=103, event=1, identity=identity(103, 100))
    terminal(ledger, leader, 0)
    if variant == 'wait-raw-mismatch':
        refused(ledger, 'ledger parent wait join', 'original_parent_wait4', **{**wait, 'raw': 256, 'normalized': 1})
    else:
        refused(ledger, 'ledger actual waiting parent birth', 'original_parent_wait4', **{**wait, 'parent': 103})


def test_order_failure_cleanup_never_settles_debt():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    refused(ledger, 'ledger failure cleanup cannot retire a process', 'failure_cleanup_tracer_wait', pid=leader.pid,
            raw=256, normalized=1, identity=ledger.process(leader).identity)
    assert not ledger.settled((leader,)) and not ledger.final_settled()


def test_order_interrupted_debt_is_unsettled():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    assert not ledger.settled((leader,)) and not ledger.final_settled()
    assert not ledger.reaped(leader, 'child-token') and ledger.process(leader).exit is None


def test_order_settled_is_not_reaped():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    reap(ledger, member, 256)
    emit(ledger, 'kernel_exit', pid=leader.pid, raw=256)
    assert ledger.settled((leader,)) and not ledger.reaped(leader, 'child-token')


def test_order_missing_member_terminal_is_not_debt():
    ledger, root, leader = setup()
    thread(ledger, 102)
    emit(ledger, 'kernel_exit', pid=102, raw=0)
    terminal(ledger, leader, 0)
    wait4(ledger, root, leader, 0)
    assert ledger.settled((leader,)) and ledger.final_settled() and ledger.reaped(leader, 'child-token')


def test_order_synthetic_retire_adopted_debt_refuses():
    ledger, root, leader = setup()
    member = thread(ledger, 102)
    terminal(ledger, leader, 0)
    process = ledger.process(member)  # synthetic state, defensive only
    process.exit, process.terminal = (90, 0), (91, 256, 1)
    ledger.process(leader).adopted_identity = dict(ledger.process(leader).identity)
    with pytest.raises(Refused, match='^ledger actual namespace init terminal join$'):
        ledger.retire_adopted(leader, 0)
    assert ledger.process(leader).init_wait is None


def nonleader_parent_prefix():
    """Ledger-API order whose kernel reachability is unknown: a reused leader PID is a thread."""
    ledger, root, leader = setup()
    emit(ledger, 'kernel_child', parent=100, child=103, event=1, identity=identity(103, 100))
    thread(ledger, 102)
    terminal(ledger, leader, 0)
    reused = {**identity(101, 100, tgid=103), 'start_ticks': 1}
    emit(ledger, 'kernel_child', parent=103, child=101, event=3, identity=reused)
    return ledger, dict(parent=102, child=104, event=3, identity=identity(104, 100, tgid=103))


def test_order_thread_child_with_nonleader_normalized_parent_is_refused():
    ledger, row = nonleader_parent_prefix()
    refused(ledger, 'ledger child parent group', 'kernel_child', **row)


@pytest.mark.parametrize('variant', ('thread-of-thread', 'process-child-of-thread'))
def test_order_thread_child_parent_normalization(variant):
    ledger, root, leader = setup()
    emit(ledger, 'kernel_exec', pid=leader.pid)
    creator = thread(ledger, 102)
    if variant == 'thread-of-thread':
        child = thread(ledger, 103, creator=102)
        assert ledger.process(child).group == leader and ledger.process(child).epoch == 1
        assert ledger.members(leader) == [creator, child]
        return
    value = identity(103, leader.pid)
    emit(ledger, 'kernel_child', parent=102, child=103, event=1, identity=value)
    child = Birth.read(value)
    assert ledger.process(child).group == child and ledger.process(child).parent == leader
    assert ledger.process(child).epoch == 0 and ledger.members(leader) == [creator]


def atomic_case(name):
    if name == 'contradiction':
        ledger, second, row = contradiction_prefix(512)
        return ledger, CONTRADICTION, 'tracer_terminal_wait', row
    if name == 'exit-after-terminal':
        ledger, member = late_exit_prefix()
        return ledger, 'ledger exit after terminal', 'kernel_exit', dict(pid=102, raw=9)
    if name == 'exec-debt':
        ledger, member = late_exit_prefix()
        return ledger, 'ledger exec with group status debt', 'kernel_exec', dict(pid=LEADER)
    if name == 'child-parent-group':
        ledger, row = nonleader_parent_prefix()
        return ledger, 'ledger child parent group', 'kernel_child', row
    ledger, row = epoch_prefix('c9')
    return ledger, TERMINAL, 'tracer_terminal_wait', row


@pytest.mark.parametrize('name', ('contradiction', 'exit-after-terminal', 'exec-debt', 'child-parent-group', 'epoch'))
def test_order_new_refusals_are_atomic(name):
    ledger, text, kind, row = atomic_case(name)
    refused(ledger, text, kind, **row)
