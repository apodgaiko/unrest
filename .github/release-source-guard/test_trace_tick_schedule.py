"""Idle-only suppression; every actual decision retains fresh original checks."""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

import trace_tick_schedule as scheduling
from owned_multiprocess_authority import OwnedMultiprocessCustody


def objects():
    first, second = socket.socketpair()
    trace = SimpleNamespace(records=[], active={1}, pending={}, poison=[])
    supervisor = SimpleNamespace(channel=first, clients={}, poisoned=False)
    return first, second, trace, supervisor


def test_empty_spins_do_not_reacquire_and_ten_ms_uses_actual_clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        assert service.due(trace, supervisor)
        service.complete(trace)
        assert not any(service.due(trace, supervisor) for _ in range(1000))
        now[0] += 0.009
        assert not service.due(trace, supervisor)
        now[0] += 0.002
        assert service.due(trace, supervisor)
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize('event', ['records', 'active', 'pending', 'poison', 'clients', 'readable', 'final', 'supervisor_poison'])
def test_each_pending_or_decision_boundary_forces_service_without_reading_request(monkeypatch, event):
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: 100.0)
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        service.complete(trace)
        if event == 'records':
            trace.records.append({'kind': 'actual_kernel_stop'})
        elif event == 'active':
            trace.active.add(2)
        elif event == 'pending':
            trace.pending[1] = {'syscall': 59}
        elif event == 'poison':
            trace.poison.append('actual refusal')
        elif event == 'clients':
            supervisor.clients[first] = {'pending_reason': 'frame'}
        elif event == 'readable':
            second.sendall(b'unchanged request bytes')
        elif event == 'final':
            trace.active.clear()
        else:
            supervisor.poisoned = True
        assert service.due(trace, supervisor)
        if event == 'readable':
            assert first.recv(100) == b'unchanged request bytes'
    finally:
        first.close()
        second.close()


def test_clock_reversal_cannot_be_ignored(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        service.complete(trace)
        now[0] -= 1
        with pytest.raises(RuntimeError, match='clock_reversed'):
            service.due(trace, supervisor)
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize('failure', [None, 'poison', 'exception'])
def test_exec_decision_forces_original_callback_before_original_resolver(failure):
    calls = []
    trace = SimpleNamespace(poison=[])
    cause = RuntimeError('fresh acquisition refused')
    class Original:
        def tick(self, actual):
            assert actual is trace
            calls.append('full_callback')
            if failure == 'exception':
                raise cause
            if failure == 'poison':
                self.supervisor.poisoned = True
        def resolve(self, *args):
            calls.append('original_resolver')
            return True
    class Authority(OwnedMultiprocessCustody, Original):
        pass
    authority = Authority()
    authority.supervisor = SimpleNamespace(poisoned=False)
    if failure == 'exception':
        with pytest.raises(RuntimeError) as caught:
            authority.resolve(trace, 2, '/native', [], {}, '/source')
        assert caught.value is cause
    else:
        assert authority.resolve(trace, 2, '/native', [], {}, '/source') is (failure is None)
    assert calls == (['full_callback', 'original_resolver'] if failure is None else ['full_callback'])


def test_idle_callback_completion_follows_full_acquisition_and_propagates_failure(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    calls = []
    cause = RuntimeError('full callback failure')
    class Original:
        def tick(self, actual):
            assert actual is trace
            calls.append(now[0])
            now[0] += 1
            if len(calls) == 2:
                raise cause
    class Authority(OwnedMultiprocessCustody, Original):
        pass
    authority = Authority()
    authority.supervisor = supervisor
    try:
        authority.tick(trace)
        assert authority._source_tick_schedule.last == 101.0
        authority.tick(trace)
        assert len(calls) == 1
        now[0] += .011
        with pytest.raises(RuntimeError) as caught:
            authority.tick(trace)
        assert caught.value is cause and authority._source_tick_schedule.last == 101.0
    finally:
        first.close()
        second.close()



def test_actual_failed_root_enters_existing_failure_drain_without_mutating_records():
    from types import SimpleNamespace
    from source_failure_drain import check
    rows = [{'kind': 'tracer_terminal_wait', 'pid': 9, 'raw': 256, 'normalized': 1}]
    active = {27, 29, 32}
    trace = SimpleNamespace(child=9, root_parent_wait=256, active=active, records=rows)
    with pytest.raises(RuntimeError, match='failed_source_root_has_live_owned_descendants'):
        check(trace)
    assert trace.records is rows and rows == [
        {'kind': 'tracer_terminal_wait', 'pid': 9, 'raw': 256, 'normalized': 1}]
    assert trace.active is active and active == {27, 29, 32}


@pytest.mark.parametrize('root, active', [(None, {27}), (0, {27}), (256, set())])
def test_live_passing_or_already_finished_root_keeps_original_path(root, active):
    from types import SimpleNamespace
    from source_failure_drain import check
    assert check(SimpleNamespace(root_parent_wait=root, active=active)) is None


@pytest.mark.parametrize('drift', ['missing', 'foreign_pid', 'raw', 'normalized', 'duplicate'])
def test_failed_root_drain_requires_its_actual_unique_matching_numeric_wait(drift):
    from types import SimpleNamespace
    from source_failure_drain import check
    rows = [{'kind': 'tracer_terminal_wait', 'pid': 9, 'raw': 256, 'normalized': 1}]
    if drift == 'missing':
        rows.clear()
    elif drift == 'foreign_pid':
        rows[0]['pid'] = 10
    elif drift == 'raw':
        rows[0]['raw'] = 9
    elif drift == 'normalized':
        rows[0]['normalized'] = 0
    else:
        rows.append(dict(rows[0]))
    with pytest.raises(RuntimeError, match='failed_source_root_wait_binding'):
        check(SimpleNamespace(child=9, root_parent_wait=256, active={27}, records=rows))


@pytest.mark.parametrize('number', [61, 247])
def test_wait_entry_and_empty_exit_do_not_amplify_idle_census(monkeypatch, number):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        service.complete(trace)
        for _ in range(1000):
            trace.pending[1] = {'syscall': number, 'status_address': 123}
            assert not service.due(trace, supervisor)
            trace.pending.pop(1)
            assert not service.due(trace, supervisor)
        now[0] += .011
        assert service.due(trace, supervisor)
        service.complete(trace)
        trace.records.append({'kind': 'original_parent_wait4', 'child': 2, 'raw': 0})
        assert service.due(trace, supervisor)
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize('row', [{'syscall': 59}, {'syscall': 322}, {'syscall': 999},
                               {'syscall': '61'}, {'syscall': True}, {}, None])
def test_exec_unknown_and_malformed_pending_keep_immediate_acquisition(monkeypatch, row):
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: 100.0)
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        service.complete(trace)
        trace.pending[1] = row
        assert service.due(trace, supervisor)
    finally:
        first.close()
        second.close()


def test_receipt_wakes_service_during_an_inflight_wait(monkeypatch):
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: 100.0)
    first, second, trace, supervisor = objects()
    try:
        trace.pending[1] = {'syscall': 61}
        service = scheduling.TickSchedule()
        service.complete(trace)
        second.sendall(b'original receipt bytes')
        assert service.due(trace, supervisor)
        assert first.recv(100) == b'original receipt bytes'
    finally:
        first.close()
        second.close()
