import hashlib
import json
import struct
import time

def channel_snapshot(self, state, outcome):
        request = state['request'] if type(state['request']) is dict else {}
        kind = request.get('kind')
        known = {'ready', 'poison', 'plan', 'listen', 'connect', 'connected',
                 'socketpair', 'payload', 'custody_owner', 'custody_peer',
                 'custody_submit', 'custody_close', 'custody_poll', 'custody_spawned',
                 'custody_signal', 'custody_cancel', 'drain_inventory', 'drain_child',
                 'drain_complete'}
        saved = self.registered.get(state.get('peer_pid'))
        now = time.monotonic()
        return {'kind': kind if isinstance(kind, str) and kind in known else 'unknown',
                'unknown_kind_sha256': (hashlib.sha256(json.dumps(kind, sort_keys=True).encode()).hexdigest()
                                        if kind is not None and (not isinstance(kind, str) or kind not in known) else None),
                'frame_bytes': len(state['buffer']),
                'declared_size': (struct.unpack('!I', state['buffer'][:4])[0]
                                  if len(state['buffer']) >= 4 else None),
                'received': state['request'] is not None,
                'authenticated': state['authenticated'],
                'output_pending': state['output'] is not None and bool(state['output']),
                'accepted_monotonic': state['started'], 'finished_monotonic': now,
                'elapsed': now - state['started'],
                'peer_pid': state.get('peer_pid'), 'peer_uid': state.get('peer_uid'),
                'registered_peer_birth': saved['identity'] if saved else None,
                'pending_reason': state['pending_reason'], 'outcome': outcome,
                'tick_count': self.tick_count, 'accepted_tick': state['accepted_tick'],
                'event_count': self.event_count, 'trace_progress': dict(self.trace_progress),
                'policy_attempts': state.get('policy_attempts', 0),
                'policy_seconds': state.get('policy_seconds', 0),
                'pure_phases': dict(getattr(self, 'pure_phases', {})),
                'diagnostic_schedule': dict(getattr(self, 'diagnostic_schedule', {}))}
