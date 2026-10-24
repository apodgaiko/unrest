"""Idle-only suppression; every actual decision retains fresh original checks."""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

import trace_tick_schedule as scheduling
import resolver_cost_profile as profile
import linux_producers
from owned_multiprocess_authority import OwnedMultiprocessCustody


def objects():
    first, second = socket.socketpair()
    trace = SimpleNamespace(records=[], active={1}, pending={}, poison=[])
    supervisor = SimpleNamespace(channel=first, clients={}, poisoned=False)
    return first, second, trace, supervisor


def test_empty_spins_do_not_reacquire_and_idle_period_uses_actual_clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    try:
        service = scheduling.TickSchedule()
        assert service.due(trace, supervisor)
        service.complete(trace)
        assert not any(service.due(trace, supervisor) for _ in range(1000))
        now[0] += scheduling.IDLE_SECONDS - 0.001
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
        now[0] += scheduling.IDLE_SECONDS + .001
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
        now[0] += scheduling.IDLE_SECONDS + .001
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


def test_idle_journal_poison_is_acquired_before_exec_and_final_barriers(tmp_path, monkeypatch):
    """A less frequent idle census is never an authorization snapshot."""
    from event_journal import EventJournal
    now = [100.0]
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: now[0])
    first, second, trace, supervisor = objects()
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ready"}\n')
    reader, calls = EventJournal(), []
    class Original:
        def tick(self, actual):
            calls.append('fresh')
            self.supervisor.poisoned = any(row['kind'] == 'forbidden' for row in reader.events(tmp_path))
        def resolve(self, *args):
            calls.append('grant')
            return True
    class Authority(OwnedMultiprocessCustody, Original):
        pass
    authority = Authority()
    authority.supervisor = supervisor
    try:
        authority.tick(trace)
        path.write_text('{"kind":"forbidden","reason":"current"}\n')
        now[0] += 0.001
        authority.tick(trace)
        assert calls == ['fresh'] and not supervisor.poisoned
        assert authority.resolve(trace, 2, '/native', [], {}, '/source') is False
        assert calls == ['fresh', 'fresh'] and supervisor.poisoned
        supervisor.poisoned = False
        trace.active.clear()
        authority.tick(trace)
        assert calls == ['fresh', 'fresh', 'fresh'] and supervisor.poisoned
    finally:
        first.close()
        second.close()


def owned_trace():
    from linux_trace import OwnedTrace
    trace = OwnedTrace.__new__(OwnedTrace)
    trace.child, trace.allowed = 1, [{'pid': 1}]
    trace.records, trace.active, trace.pending, trace.poison = [], {1, 2}, {}, []
    return trace


def exec_bookkeeping(pid=2):
    return [
        {'kind': 'exec_memory_boundary', 'pid': pid, 'path_address': 10,
         'argv_address': 20, 'environment_address': 30,
         'observer_identity': {}, 'tracee_identity': {}},
        {'kind': 'exec_attempt', 'pid': pid, 'path': '/native', 'argv': ['/native'],
         'cwd': '/source', 'environment': {}, 'accepted': True},
        {'kind': 'exec_syscall_return', 'pid': pid, 'return': 0},
    ]


def test_resolver_owned_bookkeeping_retains_raw_history_without_duplicate_idle_scan(monkeypatch):
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: 100.0)
    first, second, _, supervisor = objects()
    trace = owned_trace()
    try:
        service = scheduling.TickSchedule()
        service.complete(trace)
        rows = exec_bookkeeping()
        for row in rows:
            trace.records.append(row)
            assert not service.due(trace, supervisor)
        trace.pending[2] = {'syscall': 59}
        assert not service.due(trace, supervisor)
        assert trace.records == rows
        trace.allowed.append({'pid': 2})
        assert service.due(trace, supervisor)  # Current table; eligibility is never cached.
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize('layout', ['root', 'wildcard', 'bool', 'nonroot', 'empty',
                                    'tuple', 'malformed', 'subclass'])
def test_static_or_unproven_admission_keeps_bookkeeping_effectful(layout):
    trace = owned_trace()
    pid = 2
    if layout == 'root':
        pid = 1
    elif layout == 'wildcard':
        trace.allowed = [{}]
    elif layout == 'bool':
        trace.allowed = [{'pid': True}]
    elif layout == 'nonroot':
        trace.allowed.append({'pid': 2})
    elif layout == 'empty':
        trace.allowed = []
    elif layout == 'tuple':
        trace.allowed = ({'pid': 1},)
    elif layout == 'malformed':
        trace.allowed = [None]
    else:
        from linux_trace import OwnedTrace
        class Other(OwnedTrace):
            pass
        trace.__class__ = Other
    trace.records = exec_bookkeeping(pid)
    assert scheduling.record_progress(trace) == len(trace.records)
    trace.pending[pid] = {'syscall': 59}
    assert scheduling.progress(trace)[2] == frozenset({pid})


@pytest.mark.parametrize('index, change', [
    (0, {'path_address': True}), (0, {'observer_identity': None}),
    (1, {'accepted': False}), (1, {'accepted': 1}), (1, {'argv': ()}),
    (2, {'return': False}), (2, {'return': -2}), (2, {'denied': False}),
    (2, {'extra': 0}), (2, {'kind': 'unknown'}),
])
def test_only_exact_successful_bookkeeping_shapes_are_idle(index, change):
    trace = owned_trace()
    trace.records = exec_bookkeeping()[:index + 1]
    trace.records[-1].update(change)
    assert scheduling.record_progress(trace) == len(trace.records)


@pytest.mark.parametrize('kind', ['kernel_exec', 'kernel_child', 'kernel_exit',
                                  'kernel_vfork_done', 'original_parent_wait4',
                                  'tracer_terminal_wait', 'unknown'])
def test_actual_trace_effects_are_never_suppressed_by_benign_suffix(kind):
    trace = owned_trace()
    trace.records = exec_bookkeeping() + [{'kind': kind, 'pid': 2}] + exec_bookkeeping()
    assert scheduling.record_progress(trace) == 4


@pytest.mark.parametrize('number', [322, 999, '59', True, None])
def test_nonroot_unknown_pending_still_forces_service(number):
    trace = owned_trace()
    trace.pending[2] = {'syscall': number}
    assert scheduling.progress(trace)[2] == frozenset({2})


@pytest.mark.parametrize('failure', [None, 'poison', 'exception'])
def test_actual_primary_dispatch_keeps_fresh_source_barrier_when_idle(monkeypatch, failure):
    import sys
    from pathlib import Path
    from types import ModuleType
    # Only unrelated Linux import-time package-query setup is isolated.
    # Compile the complete current authority; its dispatch method is unchanged.
    queries = ModuleType('producer_profile')
    queries.query_package = lambda *args: None
    module = ModuleType('primary_dispatch_control')
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, 'producer_profile', queries)
        path = Path(__file__).with_name('primary_authority.py')
        exec(compile(path.read_bytes(), str(path), 'exec'), vars(module))
    PrimaryAuthority = module.Authority
    monkeypatch.setattr(scheduling.time, 'monotonic', lambda: 100.0)
    first, second, _, supervisor = objects()
    trace = owned_trace()
    trace.identities = {2: {'ppid': 1}}
    calls = []
    cause = RuntimeError('fresh callback failed')
    class Original:
        def tick(self, actual):
            assert actual is trace
            calls.append('fresh_callback')
            if failure == 'exception':
                raise cause
            if failure == 'poison':
                self.supervisor.poisoned = True
        def resolve(self, *args):
            calls.append('original_resolver')
            return True
    class Source(OwnedMultiprocessCustody, Original):
        pass
    source = Source()
    source.supervisor = supervisor
    source._source_tick_schedule = scheduling.TickSchedule()
    source._source_tick_schedule.complete(trace)
    trace.records = exec_bookkeeping()
    primary = PrimaryAuthority.__new__(PrimaryAuthority)
    primary.source, primary.denials = source, []
    try:
        assert not source._source_tick_schedule.due(trace, supervisor)
        if failure == 'exception':
            with pytest.raises(RuntimeError) as caught:
                primary.resolve(trace, 2, '/native', ['/native'], {}, '/source')
            assert caught.value is cause
        else:
            assert primary.resolve(trace, 2, '/native', ['/native'], {}, '/source') is (failure is None)
        assert calls == (['fresh_callback', 'original_resolver'] if failure is None else ['fresh_callback'])
    finally:
        first.close()
        second.close()




@pytest.fixture
def owner(monkeypatch):
    class Producer:
        def __init__(self):
            self.records = []
    monkeypatch.setattr(linux_producers, 'NativeProducers', Producer)
    return SimpleNamespace(producers=Producer())


VECTOR = ['/usr/bin/git', '--no-replace-objects', 'cat-file', '-t', '0' * 40]


def test_one_shot_closed_metadata_never_copies_vectors(owner):
    for _ in range(2):
        with profile.observe(owner, '/usr/bin/git', VECTOR):
            sum(range(20))
    assert len(owner.producers.records) == 1
    result = owner.producers.records[0]
    assert set(result) == {'kind', 'diagnostic_only', 'eligible_certificate', 'elapsed_ns', 'rows'}
    assert result['diagnostic_only'] and result['eligible_certificate'] is False
    assert 0 < len(result['rows']) <= 64
    for row in result['rows']:
        assert set(row) == {'location_sha256', 'calls', 'recursive_calls', 'self_ns', 'total_ns'}
        assert len(row['location_sha256']) == 64
        assert all(type(value) is int and value >= 0 for key, value in row.items() if key != 'location_sha256')


@pytest.mark.parametrize('failure', [RuntimeError, MemoryError, KeyboardInterrupt])
def test_profile_failure_never_replaces_the_body_exception(owner, monkeypatch, failure):
    class Broken:
        def __init__(self, **kwargs):
            pass
        def enable(self):
            pass
        def disable(self):
            raise failure('diagnostic')
    monkeypatch.setattr(profile.cProfile, 'Profile', Broken)
    original = ValueError('original')
    with pytest.raises(ValueError) as caught:
        with profile.observe(owner, '/usr/bin/git', VECTOR):
            raise original
    assert caught.value is original and owner.producers.records == []


def test_profile_construction_failure_leaves_body_unchanged(owner, monkeypatch):
    def broken(**kwargs):
        raise RuntimeError('diagnostic')
    monkeypatch.setattr(profile.cProfile, 'Profile', broken)
    observed = []
    with profile.observe(owner, '/usr/bin/git', VECTOR):
        observed.append('actual')
    assert observed == ['actual'] and owner.producers.records == []


@pytest.mark.parametrize('path,vector', [('/other', VECTOR), ('/usr/bin/git', []),
                                       ('/usr/bin/git', ['/usr/bin/git', 'status'])])
def test_other_routes_are_not_profiled(owner, path, vector):
    with profile.observe(owner, path, vector):
        pass
    assert not hasattr(owner, '_resolver_cost_attempted') and owner.producers.records == []


def test_existing_profile_hook_and_events_remain_unchanged(owner):
    import sys
    events = []
    def hook(frame, event, arg):
        events.append(event)
    before = sys.getprofile()
    sys.setprofile(hook)
    try:
        with profile.observe(owner, '/usr/bin/git', VECTOR):
            assert sys.getprofile() is hook
            sum(range(20))
        assert sys.getprofile() is hook and events
        assert not hasattr(owner, '_resolver_cost_attempted')
        assert owner.producers.records == []
    finally:
        sys.setprofile(before)


def test_partial_enable_failure_attempts_disable_before_body(owner, monkeypatch):
    calls = []
    class Partial:
        def __init__(self, **kwargs):
            pass
        def enable(self):
            calls.append('enable')
            raise RuntimeError('partial')
        def disable(self):
            calls.append('disable')
    monkeypatch.setattr(profile.cProfile, 'Profile', Partial)
    with profile.observe(owner, '/usr/bin/git', VECTOR):
        calls.append('body')
    assert calls == ['enable', 'disable', 'body']
    assert owner.producers.records == []
