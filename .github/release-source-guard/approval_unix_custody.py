"""Observe only private approval Unix sockets with live kernel FD and peer custody."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import struct

from finite.approval_unix import PINS, TEST, SITES, OWNERS, owned_address
from finite.linux_identity import identity
from linux_sockets import duplicate_descriptor


def observe(pid, fd):
    birth = identity(pid)
    original = Path('/proc') / str(pid) / 'fd' / str(fd)
    before = os.readlink(original)
    copied = duplicate_descriptor(pid, fd)
    with socket.socket(fileno=copied) as stream:
        if (stream.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
            raise RuntimeError('approval_unix_kernel_socket_kind')
        info = os.fstat(stream.fileno())
        cookie = struct.unpack('=Q', stream.getsockopt(socket.SOL_SOCKET, 57, 8))[0]
        local = stream.getsockname()
        try:
            remote = stream.getpeername()
            peer = dict(zip(('pid', 'uid', 'gid'), struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)), strict=True))
        except OSError:
            remote, peer = None, None
        value = {'inode': info.st_ino, 'device': info.st_dev, 'uid': info.st_uid, 'cookie': cookie,
                 'local': local, 'remote': remote, 'peer': peer,
                 'listening': bool(stream.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))}
    if identity(pid) != birth or before != 'socket:[' + str(value['inode']) + ']' or os.readlink(original) != before or cookie == (1 << 64) - 1:
        raise RuntimeError('approval_unix_descriptor_changed')
    return {**value, 'owner_identity': birth}


def handle(supervisor, request, events):
    manifest = supervisor.manifest
    pid, fd, address, case = (request[k] for k in ('pid', 'fd', 'address', 'case'))
    operation = request.get('operation')
    saved = supervisor.registered[pid]['identity']
    if (operation not in {'bind', 'connect', 'listen', 'connected', 'payload'}
            or type(fd) is not int or fd < 0 or fd > 4095
            or type(case) is not str or not case.startswith(TEST + '::')
            or case.removeprefix(TEST + '::').split('[')[0] not in OWNERS
            or any(manifest['product_pins'].get(name) != pin for name, pin in PINS.items())
            or identity(pid) != saved or saved['uid'] != 20000):
        raise RuntimeError('approval_unix_source_scope')
    observed = observe(pid, fd)
    if observed['uid'] != saved['uid'] or observed['owner_identity'] != saved:
        raise RuntimeError('approval_unix_descriptor_uid')
    key = (pid, fd, observed['inode'], observed['cookie'])
    sessions = getattr(supervisor, 'approval_unix_sessions', {})
    supervisor.approval_unix_sessions = sessions
    retained = sessions.get(key)
    if operation == 'payload' and retained is not None:
        try:
            peer_now = identity(retained['peer_identity']['pid'])
        except OSError as error:
            raise RuntimeError('approval_unix_retained_peer_unavailable') from error
        if (retained['address'] != address or retained['case'] != case
                or retained['socket'] != observed
                or supervisor.registered.get(retained['peer_identity']['pid'], {}).get('identity') != retained['peer_identity']
                or peer_now != retained['peer_identity']):
            raise RuntimeError('approval_unix_retained_connection_drift')
        listener = supervisor.approval_unix_listeners.get(address)
        if listener != retained['listener']:
            raise RuntimeError('approval_unix_retained_listener_drift')
        try:
            carrier = Path(address).lstat()
        except FileNotFoundError:
            present = False
        else:
            present = True
            if (not stat.S_ISSOCK(carrier.st_mode) or stat.S_IMODE(carrier.st_mode) != 0o600
                    or carrier.st_uid != saved['uid']
                    or (carrier.st_dev, carrier.st_ino) != (listener['path_device'], listener['path_inode'])):
                raise RuntimeError('approval_unix_retained_path_replaced')
        if identity(pid) != saved:
            raise RuntimeError('approval_unix_final_owner_drift')
        return {'approval_unix': operation, 'kernel_fd': observed,
                'listener_owner': listener['owner'], 'peer_identity': retained['peer_identity'],
                'retained_connection': True, 'listener_path_present': present}
    if not owned_address(address, manifest['owned_root'], saved['uid']):
        raise RuntimeError('approval_unix_source_scope')

    def answer(**values):
        if identity(pid) != saved or not owned_address(address, manifest['owned_root'], saved['uid']):
            raise RuntimeError('approval_unix_final_owner_drift')
        return values

    key = (pid, fd, observed['inode'], observed['cookie'])
    listeners = getattr(supervisor, 'approval_unix_listeners', {})
    plans = getattr(supervisor, 'approval_unix_plans', {})
    supervisor.approval_unix_listeners, supervisor.approval_unix_plans = listeners, plans
    if operation in {'bind', 'connect'}:
        binding = request.get('source_binding')
        permitted = [{'path': '/source/' + source, 'line': line, 'sha256': PINS[source]}
                     for (event, source, _), (line, _) in SITES.items()
                     if event == 'socket.' + operation]
        if binding not in permitted or observed['local'] not in ('', address) or observed['remote'] is not None:
            raise RuntimeError('approval_unix_effect_binding')
        if key in plans:
            raise RuntimeError('approval_unix_duplicate_effect')
        if operation == 'bind' and os.path.lexists(address):
            raise RuntimeError('approval_unix_existing_listener_path')
        if operation == 'connect':
            listener = listeners.get(address)
            if listener is None or listener['case'] != case:
                raise RuntimeError('approval_unix_unknown_listener')
            owner = listener['owner']
            live = observe(owner['pid'], listener['key'][1])
            info = Path(address).lstat()
            if (identity(owner['pid']) != owner
                    or supervisor.registered.get(owner['pid'], {}).get('identity') != owner
                    or not live['listening'] or live['local'] != address
                    or (owner['pid'], listener['key'][1], live['inode'], live['cookie']) != listener['key']
                    or not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != saved['uid']
                    or (info.st_dev, info.st_ino) != (listener['path_device'], listener['path_inode'])):
                raise RuntimeError('approval_unix_preconnect_listener_drift')
        plans[key] = {'operation': operation, 'address': address, 'case': case, 'owner': saved}
        return answer(approval_unix=operation, kernel_fd=observed)
    if operation == 'listen':
        plan = plans.get(key)
        info = Path(address).lstat()
        if (plan is None or plan != {'operation': 'bind', 'address': address, 'case': case, 'owner': saved}
                or not observed['listening'] or observed['local'] != address
                or not stat.S_ISSOCK(info.st_mode) or info.st_uid != saved['uid'] or info.st_nlink != 1
                or address in listeners):
            raise RuntimeError('approval_unix_listener_binding')
        listeners[address] = {'key': key, 'owner': saved, 'case': case,
                              'path_inode': info.st_ino, 'path_device': info.st_dev}
        return answer(approval_unix=operation, kernel_fd=observed)
    listener = listeners.get(address)
    if listener is None or listener['case'] != case:
        raise RuntimeError('approval_unix_unknown_listener')
    owner = listener['owner']
    info = Path(address).lstat()
    if (identity(owner['pid']) != owner or supervisor.registered.get(owner['pid'], {}).get('identity') != owner
            or not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (listener['path_device'], listener['path_inode'])):
        raise RuntimeError('approval_unix_listener_identity')
    peer = observed['peer']
    if peer is None or peer['uid'] != saved['uid'] or peer['gid'] != saved['uid']:
        raise RuntimeError('approval_unix_peer_credentials')
    registered_peer = supervisor.registered.get(peer['pid'])
    if registered_peer is None or identity(peer['pid']) != registered_peer['identity']:
        raise RuntimeError('approval_unix_peer_birth')
    if observed['remote'] == address:
        plan = plans.get(key)
        if peer['pid'] != owner['pid'] or plan is None or plan['operation'] != 'connect' or plan['address'] != address or plan['case'] != case:
            raise RuntimeError('approval_unix_client_binding')
    elif observed['local'] != address or pid != owner['pid']:
        raise RuntimeError('approval_unix_accepted_binding')
    sessions[key] = {'address': address, 'case': case, 'socket': observed,
                     'peer_identity': registered_peer['identity'], 'listener': dict(listener)}
    return answer(approval_unix=operation, kernel_fd=observed, listener_owner=owner,
                  peer_identity=registered_peer['identity'])
