"""Only no-decision service is deferred; all effect barriers acquire fresh bytes."""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from journal_service import complete, due, fresh_census
from journal_supervisor import JournalSupervisor
from linux_supervisor import Supervisor
from test_trace_tick_schedule import owned_trace


@pytest.fixture
def service(monkeypatch):
    import journal_service
    clock = [100.0]
    monkeypatch.setattr(journal_service.time, 'monotonic', lambda: clock[0])
    first, second = socket.socketpair()
    owner = Supervisor.__new__(Supervisor)
    owner.channel, owner.clients, owner.poisoned = first, {}, False
    owner.owned_trace = owned_trace()
    JournalSupervisor.adopt(owner)
    from owned_multiprocess_authority import SourceAuthority
    from linux_producers import NativeProducers
    source = SourceAuthority.__new__(SourceAuthority)
    source.supervisor = owner
    source.producers = NativeProducers.__new__(NativeProducers)
    source.producers.uv, source.producers.children = {}, {}
    source.producers.supervisor = owner
    owner.source_census_owner = source
    try:
        yield owner, second, clock
    finally:
        first.close()
        second.close()


def test_empty_service_does_not_consume_a_decision_and_keeps_actual_idle_clock(service, monkeypatch):
    owner, _, clock = service
    calls = []
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: calls.append(actual))
    owner.tick()
    for kind in ['kernel_child', 'kernel_exec', 'kernel_exit', 'original_parent_wait4']:
        owner.owned_trace.records.append({'kind': kind, 'pid': 2})
        owner.tick()
    assert calls == [owner]
    clock[0] += .099
    owner.tick()
    assert calls == [owner]
    clock[0] += .002
    owner.tick()
    assert calls == [owner, owner]


@pytest.mark.parametrize('event', ['client', 'readable', 'trace_poison', 'owner_poison', 'final', 'unknown', 'unknown_pending'])
def test_effect_boundaries_and_unknown_progress_never_defer(service, event):
    owner, peer, _ = service
    complete(owner)
    trace = owner.owned_trace
    if event == 'client':
        owner.clients[peer] = {'pending_reason': 'frame'}
    elif event == 'readable':
        peer.sendall(b'original bytes')
    elif event == 'trace_poison':
        trace.poison.append('actual refusal')
    elif event == 'owner_poison':
        owner.poisoned = True
    elif event == 'final':
        trace.active.clear()
    elif event == 'unknown':
        trace.records.append({'kind': 'unknown', 'pid': 2})
    else:
        trace.pending[2] = {'syscall': 322}
    assert due(owner)
    if event == 'readable':
        assert owner.channel.recv(100) == b'original bytes'


@pytest.mark.parametrize('kind', ['exec_memory_boundary', 'exec_attempt', 'exec_syscall_return', 'kernel_exec', 'pending'])
def test_static_root_exec_keeps_fresh_service_without_source_resolve(service, kind):
    owner, _, _ = service
    complete(owner)
    if kind == 'pending':
        owner.owned_trace.pending[1] = {'syscall': 59}
    else:
        owner.owned_trace.records.append({'kind': kind, 'pid': 1})
    assert due(owner)


@pytest.mark.parametrize('shape', ['wildcard', 'nonroot_static', 'foreign_trace', 'foreign_owner'])
def test_unproven_composition_retains_original_service(service, shape):
    owner, _, _ = service
    complete(owner)
    if shape == 'wildcard':
        owner.owned_trace.allowed = [{}]
    elif shape == 'nonroot_static':
        owner.owned_trace.allowed.append({'pid': 2})
    elif shape == 'foreign_trace':
        owner.owned_trace = SimpleNamespace(active={1}, poison=[], records=[], pending={})
    else:
        class Other(JournalSupervisor):
            pass
        owner.__class__ = Other
    assert due(owner)


def test_force_context_nests_restores_and_propagates_first_error(service):
    owner, _, _ = service
    complete(owner)
    cause = RuntimeError('original callback failed')
    with pytest.raises(RuntimeError) as caught:
        with fresh_census(owner):
            assert due(owner) and owner._journal_census_depth == 1
            with fresh_census(owner):
                assert due(owner) and owner._journal_census_depth == 2
                raise cause
    assert caught.value is cause
    assert owner._journal_census_depth == 0 and not due(owner)


def test_failed_service_never_advances_acquisition_clock(service, monkeypatch):
    owner, _, clock = service
    complete(owner)
    before = owner._journal_census_completed
    clock[0] += .101
    cause = RuntimeError('actual acquisition failed')
    def fail(actual):
        raise cause
    monkeypatch.setattr(Supervisor, 'tick', fail)
    with pytest.raises(RuntimeError) as caught:
        owner.tick()
    assert caught.value is cause and owner._journal_census_completed == before
    clock[0] = before - 1
    with pytest.raises(RuntimeError, match='clock_reversed'):
        owner.tick()


def test_original_source_callback_still_observes_each_kernel_event_when_census_idle(service, monkeypatch):
    from primary_source_authority import SourceAuthority as Original
    owner, _, _ = service
    trace = owner.owned_trace
    complete(owner)
    calls = []
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: calls.append('journal_service'))
    source = owner.source_census_owner
    monkeypatch.setattr(type(source.producers), 'tick',
                        lambda actual, observed: calls.append(('kernel', len(observed.records))))
    for kind in ['kernel_child', 'kernel_exec', 'kernel_exit', 'original_parent_wait4']:
        trace.records.append({'kind': kind, 'pid': 2})
        Original.tick(source, trace)
        assert owner.trace_progress['records'] == len(trace.records)
    assert calls == [('kernel', i) for i in range(1, 5)]
    trace.poison.append('kernel refused')
    owner.poison = lambda reason: calls.append(reason)
    Original.tick(source, trace)
    assert calls[-3:] == [('kernel', 4), 'journal_service', 'kernel_exec_poison']


@pytest.mark.parametrize('failure', ['poison', 'io_error'])
def test_real_mixin_exec_reacquires_changed_current_journal_before_original_resolver(service, tmp_path, monkeypatch, failure):
    from owned_multiprocess_authority import OwnedMultiprocessCustody
    owner, _, _ = service
    owner.manifest = {'events': str(tmp_path)}
    owner.registered, owner.timed_events, owner.event_timings = {}, set(), []
    owner.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    effects = []
    def poison(reason):
        effects.append(reason)
        owner.poisoned = True
    owner.poison = poison
    path = tmp_path / '1.jsonl'
    path.write_text('{"kind":"ordinary"}\n')
    owner.refresh()
    complete(owner)
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: actual.refresh())
    trace = owner.owned_trace
    class Original:
        def tick(self, actual):
            assert actual is trace
            owner.tick()
        def resolve(self, *args):
            effects.append('grant')
            return True
    class Source(OwnedMultiprocessCustody, Original):
        pass
    source = Source()
    source.supervisor = owner
    if failure == 'poison':
        path.write_text('{"kind":"forbidden","reason":"changed current bytes"}\n')
        assert source.resolve(trace, 2, '/native', ['/native'], {}, '/source') is False
        assert effects == ['finite_guard:changed current bytes']
    else:
        path.unlink()
        path.mkdir()
        with pytest.raises(IsADirectoryError):
            source.resolve(trace, 2, '/native', ['/native'], {}, '/source')
        assert effects == []
    assert owner._journal_census_depth == 0


def test_any_native_producer_context_retains_fresh_service_between_events(service, tmp_path, monkeypatch):
    from primary_source_authority import SourceAuthority as Original
    owner, _, _ = service
    source, trace = owner.source_census_owner, owner.owned_trace
    producer = source.producers
    producer.cache_current, producer.cache_completed = {}, set()
    producer.uv = {2: {}}
    producer.poisoned_exits = set()
    owner.manifest = {'events': str(tmp_path)}
    owner.registered, owner.timed_events, owner.event_timings = {}, set(), []
    owner.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    effects = []
    def poison(reason):
        effects.append(reason)
        owner.poisoned = True
    owner.poison = poison
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: actual.refresh())
    complete(owner)
    (tmp_path / '1.jsonl').write_text('{"kind":"forbidden","reason":"between events"}\n')
    trace.records.append({'kind': 'kernel_exit', 'pid': 3, 'raw': 0})
    Original.tick(source, trace)
    assert owner.poisoned and effects == ['finite_guard:between events']
    trace.records.append({'kind': 'kernel_exit', 'pid': 2, 'raw': 0})
    with pytest.raises(RuntimeError, match='primary_cache_poisoned_producer'):
        Original.tick(source, trace)
    assert producer.cache_completed == set()


@pytest.mark.parametrize('change', ['child', 'uv', 'foreign', 'owner'])
def test_unknown_or_any_producer_context_always_keeps_full_service(service, change):
    owner, _, _ = service
    complete(owner)
    if change == 'child':
        owner.source_census_owner.producers.children[2] = {}
    elif change == 'uv':
        owner.source_census_owner.producers.uv[2] = {}
    elif change == 'foreign':
        owner.source_census_owner.producers = SimpleNamespace(uv={}, children={})
    else:
        owner.source_census_owner = None
    assert due(owner)


def completed_producer(owner):
    producer = owner.source_census_owner.producers
    producer.common = {'primary_producer': {'enabled': True}}
    producer.cache_current, producer.cache_completed = {}, {89, 105}
    producer.response_receipts, producer.poisoned_exits = {}, set()
    producer.uv = {}
    for pid, operation in [(89, 'source-build'), (105, 'source-install')]:
        producer.uv[pid] = dict(pid=pid, identity={'pid': pid}, owner_pid=20,
                               launch_token='a' * 32, token='b' * 32,
                               operation=operation, record_sha256='c' * 64,
                               profile={}, binding={}, seen_requests=set(), children=[])
    producer.children = {}
    for pid, parent, role in [(97, 89, 'isolated-uv-helper'), (98, 89, 'isolated-uv-helper'),
                              (101, 89, 'isolated-uv-helper'), (102, 89, 'isolated-uv-helper'),
                              (108, 105, 'isolated-uv-query')]:
        child = dict(kind='native_source_child', pid=pid, parent=parent, identity={'pid': pid},
                     role=role, helper='main', token='d' * 32, profile_sha256='e' * 64,
                     original_argv_sha256='f' * 64, environment_sha256='1' * 64,
                     flags=[1, 0, 1], cwd='/owned/build', source_operation_token='b' * 32)
        producer.children[pid] = child
        producer.uv[parent]['children'].append(child)
        if role == 'isolated-uv-helper':
            producer.response_receipts[pid] = {'completed': True}
    return producer


def test_completed_build_query_contexts_execute_original_tick_without_journal_effects(service, monkeypatch):
    from linux_producers import NativeProducers
    from primary_source_authority import SourceAuthority as Original
    owner, _, _ = service
    producer = completed_producer(owner)
    complete(owner)
    trace = owner.owned_trace
    trace.records = ([{'kind': 'kernel_exit', 'pid': pid, 'raw': 0} for pid in producer.uv]
                     + [{'kind': 'original_parent_wait4', 'child': pid, 'parent_tgid': child['parent'],
                         'raw': 0} for pid, child in producer.children.items()])
    def forbidden(*args, **kwargs):
        pytest.fail('completed original producer attempted journal-sensitive work')
    monkeypatch.setattr(Supervisor, 'tick', forbidden)
    monkeypatch.setattr(owner, 'events', forbidden)
    monkeypatch.setattr(producer, 'interface', SimpleNamespace(response_receipt=forbidden, cache_view=forbidden), raising=False)
    # Real original producer methods are not replaced: both completion branches
    # return before reading the journal or writing any new receipt/cache grant.
    NativeProducers.tick(producer, trace)
    Original.tick(owner.source_census_owner, trace)
    assert not due(owner) and producer.cache_completed == {89, 105}


@pytest.mark.parametrize('change', ['cache', 'receipt', 'new_uv', 'new_child', 'unknown_role',
                                    'unknown_uv_field', 'unknown_child_field', 'bad_key'])
def test_completed_state_is_rechecked_before_next_original_producer_tick(service, monkeypatch, change):
    from primary_source_authority import SourceAuthority as Original
    owner, _, _ = service
    producer = completed_producer(owner)
    complete(owner)
    assert not due(owner)
    if change == 'cache':
        producer.cache_completed.remove(89)
    elif change == 'receipt':
        producer.response_receipts.pop(97)
    elif change == 'new_uv':
        producer.uv[110] = {**producer.uv[105], 'pid': 110, 'children': []}
    elif change == 'new_child':
        child = {**producer.children[97], 'pid': 111}
        producer.children[111] = child
        producer.uv[89]['children'].append(child)
    elif change == 'unknown_role':
        producer.children[97]['role'] = 'unknown'
    elif change == 'unknown_uv_field':
        producer.uv[89]['unknown'] = True
    elif change == 'unknown_child_field':
        producer.children[97]['unknown'] = True
    else:
        producer.response_receipts['97'] = {}
    calls = []
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: calls.append('fresh'))
    monkeypatch.setattr(type(producer), 'tick', lambda actual, trace: calls.append('producer'))
    Original.tick(owner.source_census_owner, owner.owned_trace)
    assert calls == ['producer', 'fresh']


def test_completed_producer_exit86_refusal_is_still_immediate(service):
    from linux_producers import NativeProducers
    owner, _, _ = service
    producer = completed_producer(owner)
    complete(owner)
    observed = []
    def poison(reason):
        observed.append(reason)
        owner.poisoned = True
    owner.poison = poison
    owner.owned_trace.records = [{'kind': 'kernel_exit', 'pid': 97, 'raw': 86 << 8}]
    NativeProducers.tick(producer, owner.owned_trace)
    assert observed == ['native_preinitialization_refusal'] and due(owner)


def test_pending_producer_is_classified_before_completion_not_after(service, monkeypatch):
    from primary_source_authority import SourceAuthority as Original
    from journal_service import producer_census
    owner, _, _ = service
    producer = completed_producer(owner)
    producer.cache_completed.remove(89)
    complete(owner)
    calls = []
    def finish(actual, trace):
        assert due(owner)  # Pre-tick force remains active during the callback.
        actual.cache_completed.add(89)
        calls.append('producer_completed')
    monkeypatch.setattr(type(producer), 'tick', finish)
    monkeypatch.setattr(Supervisor, 'tick', lambda actual: calls.append('original_full_service'))
    with producer_census(owner):
        Original.tick(owner.source_census_owner, owner.owned_trace)
    assert calls == ['producer_completed', 'original_full_service']
    assert not due(owner)


@pytest.mark.parametrize('change', ['operation', 'role', 'context_child_pid', 'common_primary',
                                    'cache_current', 'context_pid', 'child_pid'])
def test_malformed_completed_contexts_fall_back_to_original_service(service, change):
    owner, _, _ = service
    producer = completed_producer(owner)
    complete(owner)
    if change == 'operation':
        producer.uv[89]['operation'] = []
    elif change == 'role':
        producer.children[97]['role'] = []
    elif change == 'context_child_pid':
        producer.uv[89]['children'] = [{'pid': []}]
    elif change == 'common_primary':
        producer.common['primary_producer'] = []
    elif change == 'cache_current':
        producer.cache_current = []
    elif change == 'context_pid':
        producer.uv[89]['pid'] = True
    else:
        producer.children[97]['pid'] = True
    assert due(owner)
