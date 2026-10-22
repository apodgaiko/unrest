"""A closed Unix peer needs real kernel birth, terminal status and parent wait."""
import os


def settled(supervisor, peer):
    trace = getattr(supervisor, 'owned_trace', None)
    if trace is None:
        raise RuntimeError('approval_unix_retained_peer_unavailable')
    from linux_supervisor import AwaitOwnedPeer
    rows = trace.records
    births = [row for row in rows if row['kind'] == 'kernel_child' and row['child'] == peer['pid']]
    def matches(value):
        return (all(value.get(key) == peer[key] for key in
                    ('pid', 'ppid', 'pgid', 'sid', 'start_ticks', 'boot_id', 'clock_ticks_per_second'))
                and value.get('uids') == [peer['uid']] * 4)
    if len(births) != 1 or not matches(births[0]['identity']):
        raise RuntimeError('approval_unix_terminal_peer_birth')
    terminal = [row for row in rows if row['kind'] == 'tracer_terminal_wait' and row['pid'] == peer['pid']]
    exits = [row for row in rows if row['kind'] == 'kernel_exit' and row['pid'] == peer['pid']]
    waits = [row for row in rows if row['kind'] == 'original_parent_wait4'
             and row['child'] == peer['pid'] and row['parent_tgid'] == peer['ppid']]
    if any(len(group) > 1 for group in (terminal, exits, waits)):
        raise RuntimeError('approval_unix_terminal_peer_cardinality')
    if not terminal or not exits or not waits:
        raise AwaitOwnedPeer('actual_parent_wait_record_still_pending')
    raw = terminal[0]['raw']
    if (not matches(terminal[0]['identity']) or not (os.WIFEXITED(raw) or os.WIFSIGNALED(raw))
            or exits[0]['raw'] != raw or waits[0]['raw'] != raw
            or terminal[0]['normalized'] != os.waitstatus_to_exitcode(raw)
            or waits[0]['normalized'] != os.waitstatus_to_exitcode(raw)):
        raise RuntimeError('approval_unix_terminal_peer_status')
    return {'birth': births[0], 'kernel_exit': exits[0],
            'terminal_wait': terminal[0], 'original_parent_wait': waits[0]}
