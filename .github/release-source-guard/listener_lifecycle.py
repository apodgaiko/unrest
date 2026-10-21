"""Expire cached listeners only after birth-bound actual parent and kernel waits."""
from __future__ import annotations

import os

import linux_trace


def reaped(entry, registered, events, records, nonce):
    pid = entry.get('pid')
    saved = registered.get(pid)
    if type(pid) is not int or pid <= 0 or saved is None:
        return False
    birth, token = saved['identity'], saved['token']
    parent = registered.get(birth['ppid'])
    if (parent is None or entry.get('state') != 10 or entry.get('local_host') != '127.0.0.1'
            or entry.get('socket_uid') != birth['uid']):
        return False
    raw = [row for row in events if row.get('kind') == 'raw_actual_parent_waitpid'
           and row.get('pid') == pid and row.get('child_token') == token]
    if len(raw) != 1:
        return False
    row = raw[0]
    status, code = row.get('raw_status'), row.get('numeric_returncode')
    if (type(status) is not int or not 0 <= status <= 65535 or type(code) is not int
            or not (os.WIFEXITED(status) or os.WIFSIGNALED(status))
            or os.waitstatus_to_exitcode(status) != code or row.get('requested_pid') != pid
            or row.get('wait_event') != 'actual_os_waitpid_return'
            or row.get('nonce') != nonce or row.get('owner_pid') != birth['ppid']
            or row.get('owner_identity') != parent['identity']
            or row.get('owner_token') != parent['token'] or type(row.get('options')) is not int):
        return False
    def same_birth(observed):
        uids = observed.get('uids')
        if (type(uids) is not list or len(uids) != 4
                or any(type(uid) is not int or uid != birth['uid'] for uid in uids)):
            return False
        return {key: uids[0] if key == 'uid' else observed.get(key) for key in birth} == birth
    births = [i for i, item in enumerate(records) if item.get('kind') == 'kernel_child'
              and item.get('child') == pid and same_birth(item.get('identity', {}))]
    exits = [i for i, item in enumerate(records) if item.get('kind') == 'kernel_exit'
             and item.get('pid') == pid and item.get('raw') == status]
    tracer = [i for i, item in enumerate(records) if item.get('kind') == 'tracer_terminal_wait'
              and item.get('pid') == pid and item.get('raw') == status
              and item.get('normalized') == code and same_birth(item.get('identity', {}))]
    waits = [i for i, item in enumerate(records) if item.get('kind') == 'original_parent_wait4'
             and item.get('child') == pid and item.get('parent_tgid') == birth['ppid']
             and item.get('raw') == status and item.get('normalized') == code
             and item.get('options') == row['options']]
    return (len(births) == len(exits) == len(tracer) == len(waits) == 1
            and births[0] < exits[0] < tracer[0] < waits[0])


def retire(supervisor, request, events):
    """This removes old authority; it never supplies a replacement listener."""
    entry = supervisor.listeners.get(request['port'])
    trace = getattr(supervisor, 'owned_trace', None)
    if (entry is None or type(trace) is not linux_trace.OwnedTrace
            or entry.get('local_port') != request['port']
            or supervisor.plans.get(request['port']) is not request
            or request.get('kind') != 'plan' or request.get('host') != '127.0.0.1'
            or request.get('child_token') == supervisor.registered.get(entry.get('pid'), {}).get('token')):
        return
    if reaped(entry, supervisor.registered, events, trace.records, supervisor.spec['endpoint']['nonce']):
        del supervisor.listeners[request['port']]
