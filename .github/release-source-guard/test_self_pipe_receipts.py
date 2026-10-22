"""Small deterministic receipt/close reproduction; no provider or subprocess."""
from __future__ import annotations

import asyncio
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import time

import pytest

SUPPORT = Path(__file__).parent


def load(name, path, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def rig(tmp_path, monkeypatch):
    # Restore actual native methods after each isolated local control. The
    # production hook installs under pinned READY; these tests model the RPC.
    for name in ('connect', 'connect_ex', 'setsockopt', 'listen', 'send', 'sendall', 'recv', 'recv_into', 'close'):
        monkeypatch.setattr(socket.socket, name, getattr(socket.socket, name))
    monkeypatch.setattr(socket, 'socketpair', socket.socketpair)
    audit_hooks = []
    monkeypatch.setattr(sys, 'addaudithook', audit_hooks.append)
    endpoint = load('self_pipe_control_endpoint', SUPPORT / 'finite/endpoint.py', monkeypatch)
    helper = load('self_pipe_control_hook', SUPPORT / 'finite/self_pipe_receipts.py', monkeypatch)
    (tmp_path / 'HOST-FDS.json').write_text(json.dumps({'nonce': 'control', 'objects': []}))
    records = []
    local_records = []
    identities = {}
    gate = {'eligible': True, 'audit_hooks': audit_hooks, 'pair_drift': None, 'journal_failure': False, 'entered': threading.Event(), 'release': threading.Event(), 'active': False}
    def receipt(kind, **values):
        records.append((kind, values))
        if kind == 'socketpair':
            for fd in values['fds']:
                info = os.fstat(fd)
                identities[fd] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid)
        if kind == 'payload':
            if gate['active']:
                gate['entered'].set()
                assert gate['release'].wait(2), 'control barrier was not released'
            try:
                info = os.fstat(values['fd'])
                observed = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid)
                if observed != identities.get(values['fd']):
                    raise OSError(errno.EBADF, f'socket identity changed: {observed} != {identities.get(values["fd"])}')
            except OSError as error:
                endpoint.STATE['poison'] = True
                raise endpoint.EndpointRefusal('unregistered_payload_socket:null') from error
        if kind == 'socketpair':
            left, right = values['fds']
            rows = []
            for fd, peer in ((left, right), (right, left)):
                cookie = (int.from_bytes(endpoint._CONTROL_GETSOCKOPT(
                    sys._getframe(1).f_locals['left' if fd == left else 'right'], socket.SOL_SOCKET, 57, 8), sys.byteorder)
                    if sys.platform == 'linux' else None)
                rows.append({'fd': fd, 'inode': identities[fd][1], 'peer_inode': identities[peer][1],
                             'socket_uid': os.getuid(), 'type': socket.SOCK_STREAM,
                             'socket_cookie': cookie})
            if gate['pair_drift'] is not None:
                rows[0][gate['pair_drift']] = -1
            return {'ok': True, 'pair': rows, 'request': {'id': '0' * 32}}
        return {'ok': True}
    endpoint._control_original_request = endpoint.request
    endpoint.request = receipt
    if sys.platform != 'linux':
        original_iterdir = Path.iterdir
        monkeypatch.setattr(Path, 'iterdir', lambda path: original_iterdir(
            Path('/dev/fd') if path == Path('/proc/self/fd') else path))
    endpoint.early({'responses': str(tmp_path), 'nonce': 'control'})
    endpoint.STATE['ready'] = True
    def install():
        import asyncio.selector_events as selector_events
        # Actual endpoint closures and actual CPython self-pipe caller. Only
        # the observer transport is substituted in these deterministic controls.
        pipe = selector_events.BaseSelectorEventLoop._make_self_pipe
        def refuse(reason):
            endpoint.STATE['poison'] = True
            raise endpoint.EndpointRefusal(reason)
        def append(row):
            if gate['journal_failure']:
                raise OSError('journal unavailable')
            local_records.append(row)
        helper.bridge(endpoint, pipe, vars(selector_events), socket.socketpair.__code__,
                      helper.named(compile(Path(endpoint.__file__).read_bytes(), endpoint.__file__,
                                           'exec', dont_inherit=True), 'early.<locals>.payload'), refuse, append,
                      lambda: {'process_identity': {'pid': os.getpid()}, 'token': 'control',
                               'ready_sha256': '1' * 64} if gate['eligible'] else None)
    endpoint._local_records = local_records
    yield endpoint, install, records, gate
    gate['release'].set()


@pytest.mark.parametrize('fixed', [False, True])
def test_remote_receipt_close_race_is_reproduced_and_serialized(rig, fixed):
    endpoint, install, records, gate = rig
    if fixed:
        install()
    loop = asyncio.new_event_loop()
    errors = []
    gate['active'] = True
    def write():
        try:
            loop._write_to_self()
        except BaseException as error:
            errors.append(error)
    writer = threading.Thread(target=write)
    writer.start()
    if fixed:
        writer.join(2)
        assert not writer.is_alive() and not gate['entered'].is_set()
        loop.close()
    else:
        assert gate['entered'].wait(2)
        loop.close()
        gate['release'].set()
        writer.join(2)
    assert not writer.is_alive()
    assert loop.is_closed() and loop._ssock is None and loop._csock is None
    assert bool(errors) is (not fixed)
    assert endpoint.STATE['poison'] is (not fixed)
    if errors:
        assert isinstance(errors[0], endpoint.EndpointRefusal)
    assert [kind for kind, _ in records] == (['socketpair'] if fixed else ['socketpair', 'payload'])
    assert len(endpoint._local_records) == 2 * int(fixed)


def test_already_closed_exact_object_keeps_native_ebadf_without_rpc(rig):
    endpoint, install, records, _ = rig
    install()
    loop = asyncio.new_event_loop()
    stream = loop._csock
    loop.close()
    before = list(records)
    with pytest.raises(OSError) as error:
        stream.send(b'x')
    assert error.value.errno == errno.EBADF
    assert records == before and not endpoint.STATE['poison']


def test_detach_is_not_a_successful_original_close(rig):
    endpoint, install, records, _ = rig
    install()
    loop = asyncio.new_event_loop()
    stream = loop._csock
    fd = stream.detach()
    try:
        with pytest.raises(endpoint.EndpointRefusal, match='unregistered_payload_socket'):
            stream.send(b'x')
        assert records[-1] == ('payload', {'fd': -1})
        assert endpoint.STATE['poison']
    finally:
        os.close(fd)
        loop.close()


def test_close_does_not_hold_lock_through_blocking_recv(rig):
    _, install, _, _ = rig
    install()
    loop = asyncio.new_event_loop()
    right = loop._csock
    right.setblocking(True)
    started = threading.Event()
    finished = threading.Event()
    def read():
        started.set()
        try:
            right.recv(1)
        except OSError as error:
            assert error.errno == errno.EBADF
        finally:
            finished.set()
    reader = threading.Thread(target=read)
    reader.start()
    assert started.wait(2)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        frame = sys._current_frames().get(reader.ident)
        if frame is not None and frame.f_code.co_name == 'recv' and frame.f_code.co_filename.endswith('/finite/endpoint.py'):
            break
        time.sleep(0.001)
    else:
        pytest.fail('reader did not enter the original native recv')
    # Use the receipt event to ensure the receive has passed its guard before
    # closing. A bounded join would fail if the wrapper locked the I/O itself.
    closed = threading.Event()
    closer = threading.Thread(target=lambda: (right.close(), closed.set()))
    closer.start()
    assert closed.wait(2)
    loop.close()
    reader.join(2)
    closer.join(2)
    assert finished.is_set() and not reader.is_alive()
    loop.close()


def test_unregistered_pair_still_uses_original_receipts(rig):
    endpoint, install, records, _ = rig
    install()
    left, right = socket.socketpair()
    right.close()
    with pytest.raises(endpoint.EndpointRefusal):
        right.send(b'x')
    assert records[-1] == ('payload', {'fd': -1})
    left.close()


def test_reinitialized_object_retains_original_supervisor_refusal(rig):
    endpoint, install, records, _ = rig
    install()
    loop = asyncio.new_event_loop()
    stream = loop._csock
    original_fd = stream.detach()
    other = socket.socket()
    replacement_fd = other.detach()
    socket.socket.__init__(stream, fileno=replacement_fd)
    try:
        with pytest.raises(endpoint.EndpointRefusal):
            stream.send(b'x')
        assert records[-1] == ('payload', {'fd': replacement_fd})
        assert endpoint.STATE['poison']
    finally:
        os.close(original_fd)
        loop.close()


@pytest.mark.parametrize('drift', [None, 'endpoint', 'pipe'])
def test_selected_install_authenticates_live_code_and_current_pins(rig, monkeypatch, drift):
    endpoint, _, _, _ = rig
    helper = sys.modules['self_pipe_control_hook']
    from types import SimpleNamespace
    import asyncio.selector_events as selectors
    import hashlib
    endpoint.request = endpoint._control_original_request
    state = {'setup_mode': 'source', 'direct_support': {'files': {
        endpoint.__file__: hashlib.sha256(Path(endpoint.__file__).read_bytes()).hexdigest(),
        str(SUPPORT / 'finite/self_pipe_authority.py'): 'bound-source-pin'}}}
    calls = []
    def refuse(reason):
        raise RuntimeError(reason)
    guard = SimpleNamespace(_STATE=state, refuse=refuse, checked_source=lambda *args: {
        'prepare': lambda *args: lambda: {'process_identity': {'pid': os.getpid()}}},
                            require_ready=lambda token: calls.append(('ready', token)),
                            append=lambda row: calls.append(('append', row)))
    monkeypatch.setattr(helper, 'bridge', lambda *args: calls.append(('install', args)))
    if drift == 'endpoint':
        endpoint.request = lambda *args, **kwargs: None
    elif drift == 'pipe':
        monkeypatch.setattr(selectors.BaseSelectorEventLoop, '_make_self_pipe', lambda self: None)
    if drift is not None:
        with pytest.raises(RuntimeError, match='self_pipe_'):
            helper.install(guard, endpoint)
        assert not any(kind == 'install' for kind, _ in calls)
    else:
        helper.install(guard, endpoint)
        assert [kind for kind, _ in calls] == ['install', 'append']


@pytest.mark.parametrize('fixed', [False, True])
def test_hundred_wakeups_keep_fresh_identity_records_without_payload_rpc(rig, fixed):
    endpoint, install, records, _ = rig
    if fixed:
        install()
    loop = asyncio.new_event_loop()
    try:
        for _ in range(100):
            loop._write_to_self()
        assert [kind for kind, _ in records] == ['socketpair'] + ([] if fixed else ['payload'] * 100)
        if fixed:
            pair, *payloads = endpoint._local_records
            assert pair['kind'] == 'self_pipe_pair_local_binding'
            assert len(payloads) == 100
            assert all(row['kind'] == 'self_pipe_payload_identity' and row['before_effect'] is True
                       and row['pair_receipt_id'] == pair['pair_receipt_id'] for row in payloads)
        else:
            assert not endpoint._local_records
        assert endpoint._CONTROL_RECV(loop._ssock, 100) == b'\0' * 100
    finally:
        loop.close()



def test_local_journal_failure_prevents_native_payload(rig):
    endpoint, install, _, gate = rig
    install()
    loop = asyncio.new_event_loop()
    try:
        gate['journal_failure'] = True
        with pytest.raises(OSError, match='journal unavailable'):
            loop._csock.send(b'x')
        with pytest.raises(BlockingIOError):
            endpoint._CONTROL_RECV(loop._ssock, 1)
    finally:
        loop.close()


@pytest.mark.parametrize('field', ['fd', 'inode', 'peer_inode', 'socket_cookie', 'socket_uid', 'type'])
def test_pair_response_drift_refuses_without_local_payload_authority(rig, field):
    endpoint, install, _, gate = rig
    install()
    gate['pair_drift'] = field
    # Use the original CPython self-pipe caller without constructing a complete
    # selector loop, so this refusal control owns only the two original sockets.
    import asyncio.selector_events as selectors
    from types import SimpleNamespace
    owner = SimpleNamespace(_internal_fds=0, _add_reader=lambda *args: None)
    with pytest.raises(endpoint.EndpointRefusal, match='self_pipe_pair_'):
        selectors.BaseSelectorEventLoop._make_self_pipe(owner)
    assert endpoint.STATE['poison'] and not endpoint._local_records


def test_reconnect_of_exact_registered_pair_is_refused_before_effect(rig):
    endpoint, install, _, gate = rig
    install()
    loop = asyncio.new_event_loop()
    try:
        audit = gate['audit_hooks'][-1]
        other = socket.socket()
        try:
            audit('socket.connect', (other, '/unrelated'))
            assert not endpoint.STATE['poison']
        finally:
            other.close()
        with pytest.raises(endpoint.EndpointRefusal, match='self_pipe_reconnect_refused'):
            audit('socket.connect', (loop._csock, '/changed-peer'))
        assert endpoint.STATE['poison']
    finally:
        loop.close()


def test_fresh_socket_owner_uid_drift_uses_original_refusal(rig, monkeypatch):
    endpoint, install, records, _ = rig
    install()
    loop = asyncio.new_event_loop()
    fd = loop._csock.fileno()
    actual = os.fstat
    from types import SimpleNamespace
    def changed(target):
        info = actual(target)
        if target != fd:
            return info
        return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                               st_mode=info.st_mode, st_uid=info.st_uid + 1)
    try:
        monkeypatch.setattr(os, 'fstat', changed)
        with pytest.raises(endpoint.EndpointRefusal):
            loop._csock.send(b'x')
        assert records[-1] == ('payload', {'fd': fd})
        assert endpoint.STATE['poison']
        assert len(endpoint._local_records) == 1  # pair only; no local payload grant
    finally:
        loop.close()


def test_changed_authority_uses_only_original_observer_route(rig):
    endpoint, install, records, gate = rig
    install()
    loop = asyncio.new_event_loop()
    try:
        gate['eligible'] = False
        before = len(endpoint._local_records)
        loop._csock.send(b'x')
        assert records[-1] == ('payload', {'fd': loop._csock.fileno()})
        assert len(endpoint._local_records) == before
        assert endpoint._CONTROL_RECV(loop._ssock, 1) == b'x'
    finally:
        loop.close()


def test_non_source_install_leaves_original_endpoint_and_close(rig):
    endpoint, _, _, _ = rig
    helper = sys.modules['self_pipe_control_hook']
    from types import SimpleNamespace
    request, close = endpoint.request, socket.socket.close
    helper.install(SimpleNamespace(_STATE={'setup_mode': 'ordinary'}), endpoint)
    assert endpoint.request is request and socket.socket.close is close
