"""A cancelled owned empty channel never becomes a request or an admission."""
from __future__ import annotations

import socket
import struct

import linux_trace
from listener_lifecycle import actually_waited


def capture(supervisor, stream, state, identity):
    """Capture kernel peer and fresh registered birth before reading any bytes."""
    pid, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    state['peer_pid'], state['peer_uid'] = pid, uid
    saved = supervisor.registered.get(pid)
    state['accepted_peer'] = None
    if saved is None or uid != supervisor.root['uid'] or pid == supervisor.root.get('pid'):
        return
    try:
        current = identity(pid)
    except (OSError, RuntimeError, ValueError):
        return
    if current == saved['identity']:
        state['accepted_peer'] = {'identity': dict(current), 'token': saved['token']}


def empty_exit(supervisor, state, events):
    """False waits only within the caller's unchanged four-second deadline."""
    pid = state.get('peer_pid')
    saved = supervisor.registered.get(pid)
    accepted = state.get('accepted_peer')
    if (state['buffer'] or state['request'] is not None or state['authenticated']
            or state['output'] is not None or saved is None or accepted != saved
            or state.get('peer_uid') != supervisor.root['uid']):
        raise RuntimeError('receipt_channel_closed_before_request')
    rows = [row for row in events if row.get('kind') == 'registered'
            and row.get('pid') == pid and row.get('token') == saved['token']]
    if (len(rows) != 1 or rows[0].get('class') != 'controlled-acp'
            or rows[0].get('python') is not True
            or rows[0].get('owner_pid') != saved['identity']['ppid']
            or type(getattr(supervisor, 'owned_trace', None)) is not linux_trace.OwnedTrace):
        raise RuntimeError('receipt_channel_closed_before_request')
    waits = [row for row in events if row.get('kind') == 'raw_actual_parent_waitpid'
             and row.get('pid') == pid and row.get('child_token') == saved['token']]
    if len(waits) != 1 or waits[0].get('raw_status') != 15 or waits[0].get('numeric_returncode') != -15:
        return False
    return actually_waited(pid, supervisor.registered, events,
                          supervisor.owned_trace.records, supervisor.spec['endpoint']['nonce'])
