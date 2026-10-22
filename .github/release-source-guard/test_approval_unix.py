"""Finite approval-channel boundaries retain unrelated IPC and launch refusals."""
from __future__ import annotations

from copy import deepcopy
import os
from types import SimpleNamespace

import pytest

from finite import approval_unix as client
import approval_unix_custody as host
from journal_supervisor import JournalSupervisor


def root(tmp_path):
    directory = tmp_path / 'tmp/unrest-approval-abcdefgh'
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    return directory / 'control'


def test_exact_private_directory_without_execution_authority(tmp_path):
    address = root(tmp_path)
    assert client.owned_address(str(address), str(tmp_path), os.getuid())
    assert not client.owned_address(str(address), str(tmp_path), os.getuid() + 1)
    for foreign in ('', '\0abstract', str(tmp_path / 'control'), str(address) + '/foreign', '../control'):
        assert not client.owned_address(foreign, str(tmp_path), os.getuid())
    address.parent.chmod(0o755)
    assert not client.owned_address(str(address), str(tmp_path), os.getuid())


def test_missing_or_symlink_parent_is_not_owned(tmp_path):
    address = root(tmp_path)
    alias = tmp_path / 'tmp/unrest-approval-ijklmnop'
    alias.symlink_to(address.parent, target_is_directory=True)
    assert not client.owned_address(str(alias / 'control'), str(tmp_path), os.getuid())
    assert not client.owned_address(str(tmp_path / 'tmp/unrest-approval-00000000/control'), str(tmp_path), os.getuid())


def test_case_owners_are_closed_and_all_three_original_source_pins_required():
    state = {'case': client.TEST + '::test_exact_supported_backend_admission[original]',
             'product_pins': dict(client.PINS)}
    assert client.scope(state)
    for key in client.PINS:
        changed = deepcopy(state)
        changed['product_pins'][key] = 'foreign'
        assert not client.scope(changed)
    for case in ('foreign::test', client.TEST + '::test_foreign', None):
        assert not client.scope({**state, 'case': case})


def test_every_non_unix_or_nonstream_socket_stays_with_original_endpoint():
    state = {'case': client.TEST + '::test_exact_supported_backend_admission[original]',
             'product_pins': dict(client.PINS)}
    stream = SimpleNamespace(family=2, type=1)
    assert client.bound(stream, state) is None


def test_poisoned_supervisor_never_admits_an_approval_channel():
    supervisor = JournalSupervisor.__new__(JournalSupervisor)
    supervisor.poisoned = True
    with pytest.raises(RuntimeError, match='global_poison_retained'):
        supervisor.handle({'kind': 'approval_unix'}, [])


def test_new_channel_uses_original_authentication_before_kernel_handler(monkeypatch):
    supervisor = JournalSupervisor.__new__(JournalSupervisor)
    supervisor.poisoned = False
    calls = []
    supervisor.authenticate = lambda request, events: calls.append(('authenticate', request, events))
    monkeypatch.setattr(host, 'handle', lambda owner, request, events: calls.append(('kernel', owner, request, events)) or {'checked': True})
    request, events = {'kind': 'approval_unix'}, [{'kind': 'actual'}]
    assert supervisor.handle(request, events) == {'checked': True}
    assert [c[0] for c in calls] == ['authenticate', 'kernel']
    assert calls[0][1:] == (request, events)
    assert calls[1][1:] == (supervisor, request, events)


def test_original_authentication_refusal_is_not_replaced_by_new_channel(monkeypatch):
    supervisor = JournalSupervisor.__new__(JournalSupervisor)
    supervisor.poisoned = False
    def refuse(*args):
        raise RuntimeError('original-auth-refusal')
    supervisor.authenticate = refuse
    monkeypatch.setattr(host, 'handle', lambda *args: pytest.fail('must not handle unauthenticated request'))
    with pytest.raises(RuntimeError, match='original-auth-refusal'):
        supervisor.handle({'kind': 'approval_unix'}, [])


def host_context(monkeypatch):
    birth = {'pid': 20, 'uid': 20000, 'start_ticks': 1}
    supervisor = SimpleNamespace(manifest={'owned_root': '/work/owned', 'product_pins': dict(client.PINS)},
                                 registered={20: {'identity': birth}})
    case = client.TEST + '::test_exact_supported_backend_admission[original]'
    address = '/work/owned/tmp/unrest-approval-abcdefgh/control'
    request = {'pid': 20, 'fd': 4, 'address': address, 'case': case, 'operation': 'bind',
               'source_binding': {'path': '/source/src/unrest_harness/approval_recovery.py',
                                  'line': 215, 'sha256': client.PINS['src/unrest_harness/approval_recovery.py']}}
    current = {'fd': 4, 'inode': 100, 'device': 9, 'uid': 20000, 'cookie': 1000, 'owner_identity': birth,
               'local': '', 'remote': None, 'peer': None, 'listening': False}
    carrier = SimpleNamespace(st_mode=0o140600, st_uid=20000, st_nlink=1, st_ino=77, st_dev=9)
    monkeypatch.setattr(host, 'identity', lambda pid: birth if pid == 20 else {'pid': pid})
    snapshots = {}
    def observe(pid, fd):
        if fd == current['fd']:
            snapshots[fd] = deepcopy(current)
        if fd not in snapshots:
            raise RuntimeError('closed original fd')
        return deepcopy(snapshots[fd])
    monkeypatch.setattr(host, 'observe', observe)
    monkeypatch.setattr(host, 'owned_address', lambda address, root, uid: True)
    monkeypatch.setattr(host, 'Path', lambda path: SimpleNamespace(exists=lambda: False, lstat=lambda: carrier))
    return supervisor, request, current, carrier


def test_actual_fd_plan_precedes_listener_and_peer_payload(monkeypatch):
    supervisor, request, current, _ = host_context(monkeypatch)
    assert host.handle(supervisor, request, [])['approval_unix'] == 'bind'
    current.update(local=request['address'], listening=True)
    assert host.handle(supervisor, {**request, 'operation': 'listen'}, [])['approval_unix'] == 'listen'
    current.update(fd=5, inode=101, cookie=1001, local='', listening=False)
    connect = {**request, 'fd': 5, 'operation': 'connect',
               'source_binding': {'path': '/source/' + client.TEST, 'line': 325, 'sha256': client.PINS[client.TEST]}}
    assert host.handle(supervisor, connect, [])['approval_unix'] == 'connect'
    current.update(remote=request['address'], peer={'pid': 20, 'uid': 20000, 'gid': 20000})
    assert host.handle(supervisor, {**connect, 'operation': 'connected'}, [])['approval_unix'] == 'connected'
    assert host.handle(supervisor, {**connect, 'operation': 'payload'}, [])['peer_identity']['start_ticks'] == 1


@pytest.mark.parametrize('field', ['operation', 'case', 'fd', 'source_binding', 'source_pin', 'uid', 'owner_identity'])
def test_unknown_scope_or_kernel_fd_never_creates_listener(monkeypatch, field):
    supervisor, request, current, _ = host_context(monkeypatch)
    if field == 'source_pin':
        supervisor.manifest['product_pins'][client.TEST] = 'foreign'
    elif field in {'uid', 'owner_identity'}:
        current[field] = 'foreign'
    else:
        request[field] = -1 if field == 'fd' else 'foreign'
    with pytest.raises(RuntimeError):
        host.handle(supervisor, request, [])
    assert not getattr(supervisor, 'approval_unix_listeners', {})


@pytest.mark.parametrize('field', ['cookie', 'path_inode', 'peer_uid', 'peer_gid', 'peer_pid', 'case'])
def test_changed_listener_or_peer_cannot_send_payload(monkeypatch, field):
    supervisor, request, current, carrier = host_context(monkeypatch)
    host.handle(supervisor, request, [])
    current.update(local=request['address'], listening=True)
    host.handle(supervisor, {**request, 'operation': 'listen'}, [])
    current.update(fd=5, inode=101, cookie=1001, local='', listening=False)
    connect = {**request, 'fd': 5, 'operation': 'connect',
               'source_binding': {'path': '/source/' + client.TEST, 'line': 325, 'sha256': client.PINS[client.TEST]}}
    host.handle(supervisor, connect, [])
    current.update(remote=request['address'], peer={'pid': 20, 'uid': 20000, 'gid': 20000})
    payload = {**connect, 'operation': 'payload'}
    if field == 'cookie':
        current['cookie'] += 1
    elif field == 'path_inode':
        carrier.st_ino += 1
    elif field == 'case':
        payload['case'] = client.TEST + '::test_actual_mcp_accept_single_submit_and_receipt'
    else:
        current['peer'][field.removeprefix('peer_')] += 1
    with pytest.raises(RuntimeError):
        host.handle(supervisor, payload, [])


def test_connect_requires_a_registered_same_case_listener_before_effect(monkeypatch):
    supervisor, request, current, _ = host_context(monkeypatch)
    current.update(fd=5, inode=101, cookie=1001)
    connect = {**request, 'fd': 5, 'operation': 'connect',
               'source_binding': {'path': '/source/' + client.TEST, 'line': 325, 'sha256': client.PINS[client.TEST]}}
    with pytest.raises(RuntimeError, match='unknown_listener'):
        host.handle(supervisor, connect, [])
    assert not supervisor.approval_unix_plans


def connected_context(monkeypatch):
    supervisor, request, current, carrier = host_context(monkeypatch)
    host.handle(supervisor, request, [])
    current.update(local=request['address'], listening=True)
    host.handle(supervisor, {**request, 'operation': 'listen'}, [])
    current.update(fd=5, inode=101, cookie=1001, local='', listening=False)
    connect = {**request, 'fd': 5, 'operation': 'connect',
               'source_binding': {'path': '/source/' + client.TEST, 'line': 325, 'sha256': client.PINS[client.TEST]}}
    host.handle(supervisor, connect, [])
    current.update(remote=request['address'], peer={'pid': 20, 'uid': 20000, 'gid': 20000})
    host.handle(supervisor, {**connect, 'operation': 'connected'}, [])
    return supervisor, {**connect, 'operation': 'payload'}, current, carrier


def test_existing_kernel_connection_survives_listener_unlink_only(monkeypatch):
    supervisor, request, _, _ = connected_context(monkeypatch)
    def missing():
        raise FileNotFoundError('unlinked original Unix listener')
    monkeypatch.setattr(host, 'Path', lambda path: SimpleNamespace(lstat=missing))
    monkeypatch.setattr(host, 'owned_address', lambda *args: False)
    result = host.handle(supervisor, request, [])
    assert result['retained_connection'] and not result['listener_path_present']
    with pytest.raises(RuntimeError, match='source_scope'):
        host.handle(supervisor, {**request, 'operation': 'connect'}, [])


@pytest.mark.parametrize('change', ['cookie', 'inode', 'peer_uid', 'peer_pid', 'case', 'address',
                                    'replacement', 'peer_birth', 'owner_birth'])
def test_unlinked_connection_proof_never_covers_identity_or_path_replacement(monkeypatch, change):
    supervisor, request, current, carrier = connected_context(monkeypatch)
    if change in {'cookie', 'inode'}:
        current[change] += 1
    elif change.startswith('peer_') and change != 'peer_birth':
        current['peer'][change.removeprefix('peer_')] += 1
    elif change == 'replacement':
        carrier.st_ino += 1
    elif change in {'peer_birth', 'owner_birth'}:
        monkeypatch.setattr(host, 'identity', lambda pid: {'pid': pid, 'uid': 20000, 'start_ticks': 999})
    else:
        request[change] += '-foreign'
    with pytest.raises(RuntimeError):
        host.handle(supervisor, request, [])


def test_retained_socket_does_not_infer_missing_peer_birth(monkeypatch):
    supervisor, request, _, _ = connected_context(monkeypatch)
    old = host.identity
    count = 0
    def identity(pid):
        nonlocal count
        count += 1
        if count >= 2:
            raise FileNotFoundError('peer gone')
        return old(pid)
    monkeypatch.setattr(host, 'identity', identity)
    with pytest.raises(RuntimeError, match='retained_peer_unavailable'):
        host.handle(supervisor, request, [])


def test_successful_kernel_receipt_replaces_recycled_descriptor_cache(monkeypatch):
    import socket
    address = '/work/owned/tmp/unrest-approval-abcdefgh/control'
    state = {'case': client.TEST + '::test_actual_mcp_accept_single_submit_and_receipt',
             'product_pins': dict(client.PINS), 'owned_root': '/work/owned',
             'approval_unix_fds': {8: {'address': 'old', 'device': 1, 'inode': 1}}}
    stream = SimpleNamespace(family=socket.AF_UNIX, type=socket.SOCK_STREAM,
                             fileno=lambda: 8, getsockname=lambda: address)
    monkeypatch.setattr(client.os, 'fstat', lambda fd: SimpleNamespace(st_dev=1, st_ino=2))
    monkeypatch.setattr(client, 'owned_address', lambda *args: True)
    calls = []
    endpoint = SimpleNamespace(request=lambda *args, **kwargs: calls.append((args, kwargs)))
    assert client.receipt('payload', stream, state, endpoint)
    assert len(calls) == 1 and state['approval_unix_fds'][8]['inode'] == 2
    monkeypatch.setattr(client, 'owned_address', lambda *args: False)
    assert client.bound(stream, state) == address
    monkeypatch.setattr(client.os, 'fstat', lambda fd: SimpleNamespace(st_dev=1, st_ino=3))
    stream.getpeername = lambda: address
    assert client.bound(stream, state) is None
