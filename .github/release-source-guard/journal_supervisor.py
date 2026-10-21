"""Parsing-only source-authority composition; base policy stays byte-identical."""
from __future__ import annotations

from pathlib import Path

from event_journal import EventJournal
from linux_supervisor import Supervisor


class JournalSupervisor(Supervisor):
    @classmethod
    def adopt(cls, supervisor):
        """Preserve the original instance, sockets, identities and callbacks."""
        if type(supervisor) is not Supervisor:
            raise RuntimeError('journal_supervisor_original_type_required')
        supervisor.__class__ = cls
        return supervisor

    def events(self):
        if not hasattr(self, '_current_event_journal'):
            self._current_event_journal = EventJournal()
        return self._current_event_journal.events(Path(self.manifest['events']))
