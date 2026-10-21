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
