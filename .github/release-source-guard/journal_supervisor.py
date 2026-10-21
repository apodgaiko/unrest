"""Source census composition delegates every pending decision to original methods."""
from __future__ import annotations

from pathlib import Path
import time

from event_journal import EventJournal, JournalSnapshot
from linux_supervisor import Supervisor, AwaitOwnedPeer
from listener_lifecycle import retire


class RefreshInput:
    """Original refresh mutates the actual owner's state through existing references."""
    def __init__(self, owner, rows):
        self.owner, self.rows = owner, rows

    def events(self):
        return self.rows

    def __getattr__(self, name):
        return getattr(self.owner, name)


class JournalSupervisor(Supervisor):
    @classmethod
    def adopt(cls, supervisor):
        if type(supervisor) is not Supervisor:
            raise RuntimeError('journal_supervisor_original_type_required')
        supervisor.__class__ = cls
        return supervisor

    def journal(self):
        if not hasattr(self, '_current_event_journal'):
            self._current_event_journal = EventJournal()
        return self._current_event_journal

    def events(self):
        return self.journal().events(Path(self.manifest['events']))

    def refresh(self):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        old_wall = self.diagnostic_schedule['refresh_wall_ns']
        old_cpu = self.diagnostic_schedule['refresh_cpu_ns']
        snapshot = self.journal().snapshot(Path(self.manifest['events']))
        rows = snapshot.census(self.registered, self.timed_events)
        Supervisor.refresh(RefreshInput(self, rows))
        # Include acquisition and indexing; do not hide their cost in telemetry.
        self.diagnostic_schedule['refresh_wall_ns'] = old_wall + time.monotonic_ns() - wall
        self.diagnostic_schedule['refresh_cpu_ns'] = old_cpu + time.process_time_ns() - cpu
        return snapshot

    def handle(self, request, events):
        # The original handler still receives the entire current ordinary JSON list.
        if type(events) is JournalSnapshot:
            events = events.materialize()
        previous = set(self.connections) if request.get('kind') == 'connected' else None
        try:
            answer = Supervisor.handle(self, request, events)
            if request.get('kind') == 'plan':
                retire(self, request, events)
            return answer
        except AwaitOwnedPeer as error:
            if (request.get('kind') != 'connected'
                    or str(error) != 'accepted_peer_not_yet_observable'):
                raise
            # TCP readiness can precede application accept(). Reapply the
            # original payload policy's kernel-owned queue check instead of
            # retaining the provisional connection key made before the wait.
            provisional = set(self.connections)
            self.connections.intersection_update(previous)
            own = next((row for row in self.observe(request['pid'])
                        if row['fd'] == request['fd']), None)
            if own is None:
                raise RuntimeError('queued_connection_descriptor_changed') from error
            key = (request['pid'], own['socket_cookie'], own['inode'],
                   own['local_port'], own['remote_port'])
            if key not in provisional:
                raise RuntimeError('queued_connection_binding_changed') from error
            self.connections.discard(key)
            if own['state'] not in (1, 8):
                raise
            return Supervisor.handle(self, {**request, 'kind': 'payload'}, events)
