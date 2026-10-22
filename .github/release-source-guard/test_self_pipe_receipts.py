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
    monkeypatch.setattr(sys, 'addaudithook', lambda hook: None)
    endpoint = load('self_pipe_control_endpoint', SUPPORT / 'finite/endpoint.py', monkeypatch)
    helper = load('self_pipe_control_hook', SUPPORT / 'finite/self_pipe_receipts.py', monkeypatch)
    (tmp_path / 'HOST-FDS.json').write_text(json.dumps({'nonce': 'control', 'objects': []}))
    records = []
    identities = {}
    gate = {'entered': threading.Event(), 'release': threading.Event(), 'active': False}
    def receipt(kind, **values):
        records.append((kind, values))
        if kind == 'socketpair':
            for fd in values['fds']:
                info = os.fstat(fd)
                identities[fd] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        if kind == 'payload':
            if gate['active']:
                gate['entered'].set()
                assert gate['release'].wait(2), 'control barrier was not released'
            try:
                info = os.fstat(values['fd'])
                observed = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                if observed != identities.get(values['fd']):
                    raise OSError(errno.EBADF, f'socket identity changed: {observed} != {identities.get(values["fd"])}')
            except OSError as error:
                endpoint.STATE['poison'] = True
                raise endpoint.EndpointRefusal('unregistered_payload_socket:null') from error
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
        helper.bridge(endpoint, pipe, vars(selector_events), socket.socketpair.__code__,
                      helper.named(compile(Path(endpoint.__file__).read_bytes(), endpoint.__file__,
                                           'exec', dont_inherit=True), 'early.<locals>.payload'))
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
    assert gate['entered'].wait(2)
    closed = threading.Event()
    def close():
        loop.close()
        closed.set()
    closer = threading.Thread(target=close)
    closer.start()
    if fixed:
        assert not closed.wait(0.05), 'close crossed an in-flight receipt'
    else:
        assert closed.wait(2)
    gate['release'].set()
    writer.join(2)
    closer.join(2)
    assert not writer.is_alive() and not closer.is_alive()
    assert loop.is_closed() and loop._ssock is None and loop._csock is None
    assert bool(errors) is (not fixed), [(repr(e), repr(e.__cause__)) for e in errors]
    assert endpoint.STATE['poison'] is (not fixed)
    if errors:
        assert isinstance(errors[0], endpoint.EndpointRefusal)
    assert [kind for kind, _ in records] == ['socketpair', 'payload']


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


def test_selection_is_exact_and_does_not_install_for_other_cases(rig):
    endpoint, _, _, _ = rig
    spec = importlib.util.spec_from_file_location('scope_control', SUPPORT / 'finite/self_pipe_receipts.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    request = endpoint.request
    close = socket.socket.close
    from types import SimpleNamespace
    for state in ({'class': helper.CLASS, 'case': 'other'},
                  {'class': 'root', 'case': next(iter(helper.CASES))}):
        helper.install(SimpleNamespace(_STATE=state), endpoint)
        assert endpoint.request is request and socket.socket.close is close
    assert len(helper.CASES) == 12


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


@pytest.mark.parametrize('drift', [None, 'pin', 'endpoint', 'pipe'])
def test_selected_install_authenticates_live_code_and_current_pins(rig, monkeypatch, drift):
    endpoint, _, _, _ = rig
    helper = sys.modules['self_pipe_control_hook']
    from types import SimpleNamespace
    import asyncio.selector_events as selectors
    import hashlib
    endpoint.request = endpoint._control_original_request
    root = SUPPORT.parent.parent
    state = {'class': helper.CLASS, 'case': sorted(helper.CASES)[0], 'checkout': str(root),
             'token': 'current-ready-token', 'product_pins': {helper.SOURCE: helper.SOURCE_PIN},
             'direct_support': {'files': {endpoint.__file__: hashlib.sha256(
                 Path(endpoint.__file__).read_bytes()).hexdigest()}}}
    calls = []
    def refuse(reason):
        raise RuntimeError(reason)
    guard = SimpleNamespace(_STATE=state, refuse=refuse,
                            require_ready=lambda token: calls.append(('ready', token)),
                            append=lambda row: calls.append(('append', row)))
    monkeypatch.setattr(helper, 'bridge', lambda *args: calls.append(('install', args)))
    if drift == 'pin':
        state['product_pins'][helper.SOURCE] = '0' * 64
    elif drift == 'endpoint':
        endpoint.request = lambda *args, **kwargs: None
    elif drift == 'pipe':
        monkeypatch.setattr(selectors.BaseSelectorEventLoop, '_make_self_pipe', lambda self: None)
    if drift is not None:
        with pytest.raises(RuntimeError, match='self_pipe_'):
            helper.install(guard, endpoint)
        assert not any(kind == 'install' for kind, _ in calls)
    else:
        helper.install(guard, endpoint)
        assert [kind for kind, _ in calls] == ['ready', 'install', 'append']
        assert calls[0][1] == state['token']
