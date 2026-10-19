"""Public constructor and exact factory ownership; no provider or child launch."""
from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path

import pytest

from unrest_harness.experimental_lease import LeaseRefused, PilotLedger, TurnBroker
from unrest_harness.experimental_session import ControlledTransport, _SessionOwner
from tests.session_lifetime import own_session_fixture
from tests import test_controlled_python_acp as controlled
from tests import test_experimental_session as experimental

local_session = controlled.local_session
transport = controlled.transport
session = experimental.session


@pytest.fixture(autouse=True)
def lifetime(request):
    for name in ('local_session', 'session'):
        own_session_fixture(request, name)


def assert_closed(fds):
    for fd in fds:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('stage', ['root', 'mkdir', 'records', 'ledger', 'write', 'fsync'])
def test_constructor_failure_releases_exact_acquisitions(tmp_path, monkeypatch, stage):
    candidate = tmp_path / 'candidate'
    records = tmp_path / 'owner/completions'
    journal = tmp_path / 'owner/journal.jsonl'
    acquired = []
    original_open, original_mkdir = os.open, Path.mkdir
    failure = OSError(errno.EIO, 'owned acquisition fault')

    def acquire(path, flags, *args, **kwargs):
        if (stage == 'root' and path == candidate or stage == 'records' and path == records
                or stage == 'ledger' and path == journal):
            raise failure
        fd = original_open(path, flags, *args, **kwargs)
        if path in (candidate, records, journal):
            acquired.append(fd)
        return fd

    def mkdir(path, *args, **kwargs):
        if stage == 'mkdir' and path == records:
            raise failure
        return original_mkdir(path, *args, **kwargs)

    original_write, original_fsync = os.write, os.fsync

    def write(fd, data):
        if stage == 'write' and fd in acquired:
            raise failure
        return original_write(fd, data)

    def fsync(fd):
        if stage == 'fsync' and fd in acquired:
            raise failure
        return original_fsync(fd)

    monkeypatch.setattr(os, 'open', acquire)
    monkeypatch.setattr(Path, 'mkdir', mkdir)
    monkeypatch.setattr(os, 'write', write)
    monkeypatch.setattr(os, 'fsync', fsync)
    with pytest.raises((OSError, LeaseRefused)) as caught:
        local_session.__wrapped__(tmp_path, ControlledTransport(
            Path(__file__).with_name('fixtures') / 'controlled_python_acp.py',
            Path(os.sys.executable)))
    if stage in ('write', 'fsync'):
        assert str(caught.value) == 'journal_unavailable'
        assert journal.exists()  # Failed durability never deletes evidence.
    else:
        assert caught.value is failure
    assert_closed(acquired)


def test_exact_two_argument_factory_unstarted_close(local_session):
    owner = local_session
    fds = [owner.broker._root_fd, owner.broker._record_fd, owner.ledger._fd]
    owner.close_unstarted()
    owner.close_unstarted()
    assert_closed(fds)
    assert owner.stopped
    assert '"event": "stop"' in (owner.root / 'journal.jsonl').read_text()


def test_original_session_factory_selection(session):
    assert session.transport is not None
    session.close_unstarted()


def test_borrowed_ledger_is_not_closed_or_halted(local_session, tmp_path):
    ledger = PilotLedger(tmp_path / 'borrowed.jsonl')
    try:
        owner = _SessionOwner(tmp_path / 'borrower', local_session.broker._root, ('a',),
            adapter=local_session.adapter, fixture=local_session.backend_launcher,
            policy=local_session.policy, transport=local_session.transport, ledger=ledger)
        owner.close_unstarted()
        owner.close_unstarted()
        os.fstat(ledger._fd)
        ledger.admit('P2')
        assert ledger.accounting()['campaign'] == 0
    finally:
        ledger.close()


def test_broker_close_is_idempotent_and_does_not_close_reused_fds(tmp_path):
    broker = TurnBroker(tmp_path, tmp_path / 'records')
    broker.close()
    ledger = PilotLedger(tmp_path / 'journal')
    try:
        broker.close()
        os.fstat(ledger._fd)
    finally:
        ledger.close()
        ledger.close()


async def test_started_owner_requires_original_async_teardown(local_session):
    await local_session.start()
    with pytest.raises(LeaseRefused, match='session_requires_async_close'):
        local_session.close_unstarted()
    await local_session.close()
    local_session.close_unstarted()
    assert local_session._close_task.done()
    assert local_session.ledger._fd == -1 and local_session.broker._closed


async def test_cancelled_close_retains_cleanup_and_propagates_cancellation(local_session):
    await local_session.start()
    entered, release = asyncio.Event(), asyncio.Event()
    original = local_session._close

    async def delayed():
        entered.set()
        await release.wait()
        await original()

    local_session._close = delayed
    closing = asyncio.create_task(local_session.close())
    await entered.wait()
    closing.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert local_session._close_task.done()
    local_session.close_unstarted()
    assert local_session.ledger._fd == -1 and local_session.broker._closed


@pytest.mark.parametrize('async_test', [False, True])
def test_prebody_failure_finalizer_owns_exact_factory(tmp_path, transport, monkeypatch, async_test):
    import tests.session_lifetime as lifetime_module
    finalizers = []
    owner = local_session.__wrapped__(tmp_path, transport)
    fds = [owner.broker._root_fd, owner.broker._record_fd, owner.ledger._fd]
    runner = asyncio.Runner() if async_test else None

    class Request:
        fixturenames = ['local_session']
        node = object()

        def getfixturevalue(self, name):
            return runner if name == '_function_scoped_runner' else owner

        def addfinalizer(self, finish):
            finalizers.append(finish)

    monkeypatch.setattr(lifetime_module.pytest_asyncio, 'is_async_test', lambda _: async_test)
    try:
        own_session_fixture(Request(), 'local_session')
        # Simulate a later fixture refusing before the test body can run.
        assert len(finalizers) == 1
        finalizers.pop()()
        owner.close_unstarted()
        assert_closed(fds)
    finally:
        owner.close_unstarted()
        if runner is not None:
            runner.close()


def test_failed_runner_setup_never_acquires_owner(monkeypatch):
    import tests.session_lifetime as lifetime_module
    failure = RuntimeError('original loop constructor refusal')
    calls = []

    class Request:
        fixturenames = ['local_session']
        node = object()

        def getfixturevalue(self, name):
            calls.append(name)
            raise failure

    monkeypatch.setattr(lifetime_module.pytest_asyncio, 'is_async_test', lambda _: True)
    with pytest.raises(RuntimeError) as caught:
        own_session_fixture(Request(), 'local_session')
    assert caught.value is failure
    assert calls == ['_function_scoped_runner']
