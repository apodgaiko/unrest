"""Expire cached listeners only after birth-bound actual parent and kernel waits."""
from __future__ import annotations

import os

import linux_trace


def actually_waited(pid, registered, events, records, nonce):
    """Require original-parent and ordered kernel terminal facts for this birth."""
    saved = registered.get(pid)
    if type(pid) is not int or pid <= 0 or saved is None:
        return False
    birth, token = saved['identity'], saved['token']
    parent = registered.get(birth['ppid'])
    if parent is None:
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
    lifecycle = [item for item in events if item.get('kind') == 'launch_lifecycle_binding'
                 and item.get('owner_pid') == birth['ppid'] and item.get('token') == token]
    registrations = [item for item in events if item.get('kind') == 'registered'
                     and item.get('owner_pid') == birth['ppid'] and item.get('pid') == pid
                     and item.get('token') == token]
    admissions = [item for item in events if item.get('kind') == 'admitted'
                  and item.get('owner_pid') == birth['ppid'] and item.get('token') == token]
    new_session = (len(lifecycle) == len(registrations) == len(admissions) == 1
                   and lifecycle[0].get('start_new_session') is True
                   and registrations[0].get('python') is True
                   and type(registrations[0].get('class')) is str and bool(registrations[0]['class'])
                   and type(lifecycle[0].get('case')) is str and bool(lifecycle[0]['case'])
                   and registrations[0].get('class') == admissions[0].get('class')
                   and lifecycle[0].get('case') == registrations[0].get('case') == admissions[0].get('case')
                   and (birth.get('pgid'), birth.get('sid')) == (pid, pid)
                   and type(parent['identity'].get('pgid')) is int
                   and type(parent['identity'].get('sid')) is int)
    def same_birth(observed):
        uids = observed.get('uids')
        if (type(uids) is not list or len(uids) != 4
                or any(type(uid) is not int or uid != birth['uid'] for uid in uids)):
            return False
        actual = {key: uids[0] if key == 'uid' else observed.get(key) for key in birth}
        if actual == birth:
            return True
        # Fork observation can precede the original, explicitly bound setsid().
        # PID/parent/start/boot/UID/tick identity and every numeric wait remain
        # exact; only this verified inherited-to-new-session transition varies.
        return (new_session
                and {key: value for key, value in actual.items() if key not in {'pgid', 'sid'}}
                    == {key: value for key, value in birth.items() if key not in {'pgid', 'sid'}}
                and (actual.get('pgid'), actual.get('sid'))
                    == (parent['identity']['pgid'], parent['identity']['sid']))
    births = [i for i, item in enumerate(records) if item.get('kind') == 'kernel_child'
              and item.get('child') == pid and same_birth(item.get('identity', {}))]
    exits = [i for i, item in enumerate(records) if item.get('kind') == 'kernel_exit'
             and item.get('pid') == pid and item.get('raw') == status]
    tracer = [i for i, item in enumerate(records) if item.get('kind') == 'tracer_terminal_wait'
              and item.get('pid') == pid and item.get('raw') == status
              and item.get('normalized') == code and len(births) == 1
              and item.get('identity') == records[births[0]].get('identity')
              and same_birth(item.get('identity', {}))]
    waits = [i for i, item in enumerate(records) if item.get('kind') == 'original_parent_wait4'
             and item.get('child') == pid and item.get('parent_tgid') == birth['ppid']
             and item.get('raw') == status and item.get('normalized') == code
             and item.get('options') == row['options']]
    return (len(births) == len(exits) == len(tracer) == len(waits) == 1
            and births[0] < exits[0] < tracer[0] < waits[0])


def reaped(entry, registered, events, records, nonce):
    saved = registered.get(entry.get('pid'))
    return (saved is not None and entry.get('state') == 10
            and entry.get('local_host') == '127.0.0.1'
            and entry.get('socket_uid') == saved['identity']['uid']
            and actually_waited(entry.get('pid'), registered, events, records, nonce))


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
