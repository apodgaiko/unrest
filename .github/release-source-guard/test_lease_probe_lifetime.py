"""Own-method lifetime controls; simulated handles confer no launch authority."""
from __future__ import annotations

import ast
import errno
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import types

import pytest

SUPPORT = Path(__file__).resolve().parent


class Stream:
    def __init__(self, child, blocked=False):
        self.child = child
        self.blocked = blocked
        self.closed = False

    def readline(self):
        self.child.reading.set()
        if self.blocked:
            self.child.dead.wait()
            return b'ready\n' if getattr(self.child, 'late_ready', False) else b''
        return b'ready\n'

    def close(self):
        self.closed = True


class Child:
    def __init__(self, pid, mode, blocked=False):
        self.pid, self.mode = pid, mode
        self.returncode = None
        self.status = None
        self.dead, self.reading = threading.Event(), threading.Event()
        self.stdin, self.stderr = Stream(self), Stream(self)
        self.stdout = Stream(self, blocked)
        self.reaps = 0
        self.lock = threading.Lock()

    def poll(self):
        if self.dead.is_set():
            self.wait()
        return self.returncode

    def terminate(self):
        if self.mode != 'ignore':
            self.status = -15
            self.dead.set()

    def kill(self):
        self.status = -9
        self.dead.set()

    def wait(self, timeout=None):
        if self.status is None:
            raise subprocess.TimeoutExpired('own-control', timeout)
        with self.lock:
            self.returncode = self.status
            if not self.reaps:
                self.reaps += 1
        return self.returncode


def leaves(error):
    if isinstance(error, BaseExceptionGroup):
        return [leaf for member in error.exceptions for leaf in leaves(member)]
    return [error]


@pytest.fixture
def probe(tmp_path, monkeypatch):
    import unrest_harness.experimental_lease as lease
    monkeypatch.syspath_prepend(str(SUPPORT.parents[1]))
    path = SUPPORT / 'multiprocess_guard_methods.py'
    spec = importlib.util.spec_from_file_location('own_lifetime_methods', path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    events, children = [], []
    route = tmp_path / 'multiprocess_routes.py'
    class Broker:
        def __init__(self, *args):
            self.quarantined = False
        def park(self):
            pass
        def close(self):
            pass
    monkeypatch.setattr(lease, 'TurnBroker', Broker)
    state = {'owned_root': str(tmp_path), 'guard': str(tmp_path / 'runtime_guard.py'),
             'direct_support': {'files': {str(route): 'control'}},
             'events': str(tmp_path), 'manifest_path': 'control'}
    from finite.multiprocess_routes import journal_rows
    guard = types.SimpleNamespace(
        _STATE=state, append=events.append,
        checked_source=lambda *args: {'endpoint_ready': lambda *args: True,
                                      'journal_rows': journal_rows},
        summarize=lambda *args: {'events': [
            {'kind': 'registered', 'pid': child.pid, 'token': 'control'} for child in children]})
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    original_listdir = module.os.listdir
    monkeypatch.setattr(module.os, 'listdir', lambda path:
                        [] if path == '/proc/self/fd' else original_listdir(path))
    options = {}
    cancellation = threading.Event()
    def append(row):
        events.append(row)
        if row.get('stage') == 'cancellation_published':
            cancellation.set()
        if (row.get('mode') == 'spawn' and options.get('diagnostic_stage') is not None
                and row.get('stage') == options['diagnostic_stage']):
            raise OSError(errno.ENOSPC, 'private control message')
    guard.append = append
    def construct(original, mode, *args, **kwargs):
        if mode == 'spawn' and options.get('constructor_error'):
            raise options['constructor_error']
        if mode == 'spawn' and options.get('late_handle'):
            cancellation.wait()
        child = Child(100 + len(children), mode,
                      mode == 'spawn' and options.get('blocked_stdout', False))
        child.late_ready = mode == 'spawn' and options.get('late_ready', False)
        children.append(child)
        (tmp_path / f'{child.pid}.jsonl').write_text('{}\n')
        return child
    monkeypatch.setattr(module, '_lease_popen', construct)
    original_summary = guard.summarize
    def summarize(*args):
        if children[-1].mode == 'spawn' and options.get('lookup_error'):
            raise options['lookup_error']
        return original_summary(*args)
    guard.summarize = summarize
    return module, events, children, options


def assert_settled(children):
    assert children
    assert all(child.dead.is_set() and child.reaps == 1 for child in children)
    assert all(stream.closed for child in children
               for stream in (child.stdin, child.stdout, child.stderr))
    assert not any(thread.name.startswith('ThreadPoolExecutor')
                   for thread in threading.enumerate())


def test_success_keeps_all_modes_and_actual_future_observation(probe):
    module, events, children, _ = probe
    module._lease_factories()
    assert [row['mode'] for row in events if row['kind'] == 'guard_lease_factory_proof'] == [
        'ignore', 'cleanup', 'spawn', 'registration']
    assert len([row for row in events if row.get('stage') == 'future_joined_observation']) == 4
    for mode in ('spawn', 'registration'):
        stages = [row['stage'] for row in events if row.get('mode') == mode and 'stage' in row]
        assert stages.index('constructor_return') < stages.index('registration_lookup_complete')
        assert stages.index('endpoint_complete') < stages.index('stdout_complete') < stages.index('entered_set')
    assert_settled(children)


@pytest.mark.parametrize('failure', ['constructor_error', 'lookup_error', 'blocked_stdout', 'late_handle'])
def test_main_timeout_preserves_worker_and_settles_before_shutdown(probe, failure):
    module, events, children, options = probe
    cause = OSError(errno.EMFILE, 'private failure text')
    options[failure] = cause if failure.endswith('error') else True
    with pytest.raises(BaseException) as caught:
        module._lease_factories()
    failures = leaves(caught.value)
    assert any(isinstance(error, AssertionError) for error in failures)
    if failure.endswith('error'):
        assert any(error is cause for error in failures)
    stages = [row['stage'] for row in events if row.get('mode') == 'spawn' and 'stage' in row]
    assert stages.index('cancellation_published') < stages.index('future_joined_observation')
    if failure == 'late_handle':
        assert stages.index('cancellation_published') < stages.index('constructor_return')
        assert 'registration_lookup_begin' not in stages
    if failure == 'blocked_stdout':
        assert 'stdout_begin' in stages and 'stdout_complete' not in stages
    assert_settled(children)
    serialized = json.dumps(events)
    assert 'private failure text' not in serialized and 'private control message' not in serialized
    assert all('source_sha256' in frame for row in events if row.get('stage') == 'failure'
               for frame in row['frames'])


def test_diagnostic_failure_cannot_erase_main_or_worker(probe):
    module, events, children, options = probe
    cause = OSError(errno.EMFILE, 'worker')
    options.update(lookup_error=cause, diagnostic_stage='registration_lookup_begin')
    with pytest.raises(BaseExceptionGroup) as caught:
        module._lease_factories()
    failures = leaves(caught.value)
    assert cause in failures
    assert any(isinstance(error, AssertionError) for error in failures)
    assert any(isinstance(error, OSError) and error.errno == errno.ENOSPC for error in failures)
    assert_settled(children)


def test_cleanup_failure_retains_initiating_assertion(probe, monkeypatch):
    module, events, children, options = probe
    options['blocked_stdout'] = True
    original = Child.wait
    failure = OSError(errno.EIO, 'cleanup')
    failed = False
    def wait(child, timeout=None):
        nonlocal failed
        if child.mode == 'spawn' and not failed:
            failed = True
            raise failure
        return original(child, timeout)
    monkeypatch.setattr(Child, 'wait', wait)
    with pytest.raises(BaseExceptionGroup) as caught:
        module._lease_factories()
    assert failure in leaves(caught.value)
    assert any(isinstance(error, AssertionError) for error in leaves(caught.value))
    assert_settled(children)


def test_original_assertions_and_deadlines_have_ordered_unchanged_inventory():
    # This inventory is a product control; the full parent/current byte audit is
    # separately sealed in the private handoff. No original source is embedded.
    tree = ast.parse((SUPPORT / 'multiprocess_guard_methods.py').read_bytes())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_lease_factories')
    assertions = [ast.unparse(n.test) for n in sorted(ast.walk(node), key=lambda n: getattr(n, 'lineno', 0))
                  if isinstance(n, ast.Assert)]
    assert assertions == [
        'child.poll() is None and time.monotonic() < deadline',
        "child.stdout.readline() == b'ready\\n'", 'release.wait(5)', 'release.wait(5)',
        'owner.close(0.05) and child.returncode == -9',
        'not owner.close(0.05) and owner.quarantined and broker.quarantined',
        'entered.wait(5)', 'not closed.wait(0.1)',
        'launch.result(timeout=5) is children[0]', 'cleanup.result(timeout=5)',
        "len(os.listdir('/proc/self/fd')) == census"]
    deadline = [ast.unparse(n) for n in ast.walk(node) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'deadline' for t in n.targets)]
    assert deadline == ['deadline = time.monotonic() + 5']


@pytest.mark.parametrize('index', range(11))
def test_each_original_assertion_failure_remains_failure(probe, index):
    module, events, children, options = probe
    tree = ast.parse((SUPPORT / 'multiprocess_guard_methods.py').read_bytes())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_lease_factories')
    assertions = sorted((n for n in ast.walk(node) if isinstance(n, ast.Assert)), key=lambda n: n.lineno)
    assertions[index].test = ast.copy_location(ast.Constant(False), assertions[index].test)
    ast.fix_missing_locations(tree)
    constructor = module._lease_popen
    exec(compile(tree, str(SUPPORT / 'multiprocess_guard_methods.py'), 'exec'), module.__dict__)
    module._lease_popen = constructor
    # The endpoint-loop assertion requires an actual loop iteration.
    if index == 0:
        from finite.multiprocess_routes import journal_rows
        sys.modules['runtime_guard'].checked_source = lambda *args: {
            'endpoint_ready': lambda *args: False, 'journal_rows': journal_rows}
    with pytest.raises(BaseException) as caught:
        module._lease_factories()
    assert any(isinstance(error, AssertionError) for error in leaves(caught.value))
    assert_settled(children)


def test_late_entered_never_supersedes_original_main_timeout(probe):
    module, events, children, options = probe
    options.update(blocked_stdout=True, late_ready=True)
    with pytest.raises(AssertionError):
        module._lease_factories()
    stages = [row['stage'] for row in events if row.get('mode') == 'spawn' and 'stage' in row]
    assert stages.index('cancellation_published') < stages.index('stdout_complete') < stages.index('entered_set')
    assert any(row.get('stage') == 'future_joined_observation' and row['role'] == 'worker'
               and row['failed'] is False for row in events)
    assert_settled(children)


def test_simultaneous_child_cleanup_is_serial_and_waits_are_labeled(probe):
    module, events, children, options = probe
    options['blocked_stdout'] = True
    original_append = sys.modules['runtime_guard'].append
    cancelled = threading.Event()
    def append(row):
        original_append(row)
        if row.get('mode') == 'spawn' and row.get('stage') == 'cancellation_published':
            cancelled.set()
        if row.get('mode') == 'spawn' and row.get('stage') == 'endpoint_complete':
            cancelled.wait()
    sys.modules['runtime_guard'].append = append
    with pytest.raises(BaseExceptionGroup):
        module._lease_factories()
    active = False
    completions = []
    for row in events:
        if row.get('mode') != 'spawn':
            continue
        if row.get('stage') == 'child_cleanup_begin':
            assert not active
            active = True
        elif row.get('stage') == 'child_cleanup_complete':
            assert active
            active = False
            completions.append(row)
    assert not active and len(completions) >= 2
    assert completions[0]['wait_cached'] is False
    assert all(row['wait_cached'] is True for row in completions[1:])
    assert_settled(children)


@pytest.mark.parametrize(('mode', 'earlier'), [('spawn', 'none'), ('spawn', 'poll'),
                                                    ('spawn', 'wait'), ('spawn', 'stop'),
                                                    ('cleanup', 'none'), ('cleanup', 'wait')])
def test_independent_owned_descriptor_failures_attempt_every_stream(probe, monkeypatch, earlier, mode):
    import os
    module, events, children, options = probe
    lookup = OSError(errno.EIO, 'own lookup')
    if mode == 'spawn':
        options['lookup_error'] = lookup
    original = module._lease_popen
    streams, failures = [], []
    action_error = OSError(errno.EIO, 'own earlier action')
    original_action = getattr(Child, {'stop': 'kill'}.get(earlier, earlier), None)
    injected = False
    if earlier != 'none':
        def action(child, *args, **kwargs):
            nonlocal injected
            if (child.mode == mode and not injected
                    and (sys._getframe(1).f_code.co_name == 'finish_child'
                         or mode == 'cleanup' and kwargs.get('timeout') == 3)):
                injected = True
                raise action_error
            return original_action(child, *args, **kwargs)
        monkeypatch.setattr(Child, {'stop': 'kill'}.get(earlier, earlier), action)
    class OwnedStream:
        def __init__(self, fail):
            self.fd, write = os.pipe()
            os.close(write)
            self.identity = descriptor_identity(self.fd)
            self.closed, self.fail, self.calls = False, fail, 0
            self.error = OSError(errno.EIO, 'own close')
            streams.append(self)
        def close(self):
            self.calls += 1
            if self.closed:
                raise AssertionError('closed stream retried')
            assert descriptor_identity(self.fd) == self.identity
            os.close(self.fd)
            self.closed = True
            if self.fail:
                failures.append(self.error)
                raise self.error
    def construct(*args, **kwargs):
        child = original(*args, **kwargs)
        if child.mode == mode:
            child.stdin, child.stdout, child.stderr = (OwnedStream(True), OwnedStream(True), OwnedStream(False))
        return child
    monkeypatch.setattr(module, '_lease_popen', construct)
    try:
        with pytest.raises(BaseExceptionGroup) as caught:
            module._lease_factories()
        actual = leaves(caught.value)
        assert len(failures) == 2 and all(error in actual for error in failures)
        if mode == 'spawn':
            assert lookup in actual and any(isinstance(error, AssertionError) for error in actual)
        if earlier != 'none':
            # Poll/stop can occur in owner.close too; every actual error must survive.
            assert injected and action_error in actual
        assert len(streams) == 3 and all(stream.closed and stream.calls == 1 for stream in streams)
        for stream in streams:
            with pytest.raises(OSError) as bad:
                os.fstat(stream.fd)
            assert bad.value.errno == errno.EBADF
        assert_settled(children)
        assert not any(row.get('stage') == 'mode_settled' and row.get('mode') == mode for row in events)
    finally:
        for stream in streams:
            if not stream.closed:
                assert descriptor_identity(stream.fd) == stream.identity
                os.close(stream.fd)
                stream.closed = True


@pytest.mark.parametrize('stage', ['child_cleanup_begin', 'child_cleanup_complete', 'stream_close_error'])
def test_cleanup_diagnostic_errors_preserve_every_owned_action(probe, monkeypatch, stage):
    module, events, children, options = probe
    options.update(lookup_error=OSError(errno.EIO, 'worker'), diagnostic_stage=stage)
    close_error = OSError(errno.EIO, 'stream')
    original = Stream.close
    def close(stream):
        original(stream)
        if stream.child.mode == 'spawn' and stream is stream.child.stdin:
            raise close_error
    monkeypatch.setattr(Stream, 'close', close)
    with pytest.raises(BaseExceptionGroup) as caught:
        module._lease_factories()
    failures = leaves(caught.value)
    assert options['lookup_error'] in failures and close_error in failures
    assert any(isinstance(error, AssertionError) for error in failures)
    assert any(isinstance(error, OSError) and error.errno == errno.ENOSPC for error in failures)
    assert_settled(children)


def test_unsettled_stream_is_retained_without_closing_a_reused_number(probe, monkeypatch):
    import os
    module, events, children, options = probe
    options['lookup_error'] = OSError(errno.EIO, 'worker')
    original = module._lease_popen
    held = []
    failure = OSError(errno.EIO, 'close refused before consumption')
    class RefusingStream:
        closed = False
        def __init__(self):
            self.fd, write = os.pipe()
            os.close(write)
            self.identity = descriptor_identity(self.fd)
            self.calls = 0
        def close(self):
            self.calls += 1
            raise failure
    def construct(*args, **kwargs):
        child = original(*args, **kwargs)
        if child.mode == 'spawn':
            held.append(RefusingStream())
            child.stdin = held[-1]
        return child
    monkeypatch.setattr(module, '_lease_popen', construct)
    try:
        with pytest.raises(BaseExceptionGroup) as caught:
            module._lease_factories()
        assert failure in leaves(caught.value)
        stream = held[0]
        assert stream.calls >= 2 and descriptor_identity(stream.fd) == stream.identity
        rows = [row for row in events if row.get('mode') == 'spawn']
        assert any(row.get('stage') == 'child_cleanup_unsettled' and row['unsettled_streams'] == ['stdin'] for row in rows)
        assert not any(row.get('stage') in {'child_cleanup_complete', 'mode_settled'} for row in rows)
        assert children[-1].stdout.closed and children[-1].stderr.closed
        assert not any(thread.name.startswith('ThreadPoolExecutor') for thread in threading.enumerate())
    finally:
        for stream in held:
            assert descriptor_identity(stream.fd) == stream.identity
            os.close(stream.fd)
            stream.closed = True


def descriptor_identity(fd):
    import os
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_rdev


def test_closed_stream_number_reuse_is_not_closed_by_later_cleanup(probe, monkeypatch):
    import os
    module, events, children, options = probe
    options['lookup_error'] = OSError(errno.EIO, 'worker')
    original = module._lease_popen
    owned, replacements = [], []
    failure = OSError(errno.EIO, 'close consumed descriptor')
    class ReusedStream:
        closed = False
        def __init__(self):
            self.fd, self.write = os.pipe()
            self.identity = descriptor_identity(self.fd)
            owned.append(self)
        def close(self):
            assert not self.closed and descriptor_identity(self.fd) == self.identity
            os.close(self.fd)
            self.closed = True
            # All lower descriptors remain occupied: the new unrelated pipe
            # acquires exactly the consumed read descriptor number.
            read, write = os.pipe()
            replacements.append((read, write, descriptor_identity(read)))
            assert read == self.fd and descriptor_identity(read) != self.identity
            raise failure
    def construct(*args, **kwargs):
        child = original(*args, **kwargs)
        if child.mode == 'spawn':
            child.stdin = ReusedStream()
        return child
    monkeypatch.setattr(module, '_lease_popen', construct)
    try:
        with pytest.raises(BaseExceptionGroup) as caught:
            module._lease_factories()
        assert failure in leaves(caught.value)
        assert_settled(children)
        assert len(replacements) == 1
        assert descriptor_identity(replacements[0][0]) == replacements[0][2]
    finally:
        for read, write, identity in replacements:
            assert descriptor_identity(read) == identity
            os.close(read)
            os.close(write)
        for stream in owned:
            if not stream.closed:
                assert descriptor_identity(stream.fd) == stream.identity
                os.close(stream.fd)
            os.close(stream.write)
