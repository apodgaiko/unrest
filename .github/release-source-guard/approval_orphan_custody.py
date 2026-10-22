"""Existing controlled cleanup keeps its birth binding after a proven parent death."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

from finite.approval_routes import DURABLE_PREFIX
from finite.approval_unix import PINS
from journal_supervisor import JournalSupervisor
from linux_supervisor import Supervisor, kernel, receipts

CLASSES = frozenset({'source-approval-adapter', 'source-approval-relay',
                     'source-approval-python-backend', 'source-approval-mcp'})
METHODS = frozenset({'payload', 'custody_close', 'custody_signal',
                     'drain_inventory', 'drain_child', 'drain_complete'})
CASES = frozenset(DURABLE_PREFIX + '[' + mode + ']'
                  for mode in ('cancel', 'crash', 'cancel_after_send', 'crash_after_send',
                               'cancel_after_continue', 'crash_after_continue'))


def proof(owner, pid, birth, current, method):
    if method not in METHODS or current == birth:
        return None
    if (set(current) != set(birth) or current.get('ppid') != os.getpid()
            or any(current[key] != birth[key] for key in birth if key != 'ppid')):
        return None
    events = owner.events()
    registrations = [row for row in events if row['kind'] == 'registered' and row['pid'] == pid]
    ready = [row for row in events if row['kind'] == 'ready' and row['owner_pid'] == pid]
    if len(registrations) != 1 or len(ready) != 1:
        return None
    registration = registrations[0]
    case = registration.get('case')
    if (case not in CASES or registration.get('class') not in CLASSES
            or registration['owner_pid'] != birth['ppid']
            or registration['token'] != owner.registered[pid]['token']
            or ready[0]['token'] != registration['token']):
        return None
    for name, pin in PINS.items():
        if (owner.manifest['product_pins'].get(name) != pin
                or hashlib.sha256(Path('/source', name).read_bytes()).hexdigest() != pin):
            return None
    trace = getattr(owner, 'owned_trace', None)
    if trace is None:
        return None
    parent = birth['ppid']
    parent_saved = owner.registered.get(parent)
    if parent_saved is None:
        return None
    terminals = [row for row in trace.records
                 if row['kind'] == 'tracer_terminal_wait' and row['pid'] == parent]
    exits = [row for row in trace.records if row['kind'] == 'kernel_exit' and row['pid'] == parent]
    if len(terminals) != 1 or len(exits) != 1:
        return None
    terminal = terminals[0]
    raw = terminal['raw']
    identity = terminal['identity']
    if (not os.WIFSIGNALED(raw) or os.WTERMSIG(raw) not in (9, 15)
            or exits[0]['raw'] != raw or terminal['normalized'] != os.waitstatus_to_exitcode(raw)
            or any(identity.get(key) != parent_saved['identity'][key]
                   for key in ('pid', 'ppid', 'start_ticks', 'boot_id', 'clock_ticks_per_second'))
            or identity.get('uids') != [parent_saved['identity']['uid']] * 4):
        return None
    parents = [row for row in events if row['kind'] == 'registered' and row['pid'] == parent]
    if len(parents) != 1 or parents[0].get('case') != case:
        return None
    if (os.WTERMSIG(raw) == 9 and (parents[0].get('class') != 'source-run-worker'
                                   or '[crash' not in case)):
        return None
    if os.WTERMSIG(raw) == 15 and '[cancel' not in case:
        return None
    return {'original_birth': birth, 'current_identity': current,
            'parent_terminal': terminal, 'parent_kernel_exit': exits[0],
            'case': case, 'method': method, 'new_effect_authority': False}


def view(owner, pid, current):
    result = copy.copy(owner)
    result.registered = dict(owner.registered)
    result.registered[pid] = {**owner.registered[pid], 'identity': current}
    return result


class ApprovalLedger(receipts.ReceiptLedger):
    def admit(self, stream, request):
        pid = request.get('pid')
        saved = self.registered.get(pid)
        if saved is not None:
            token, birth = saved
            current = receipts._identity.identity(pid)
            evidence = proof(self.supervisor, pid, birth, current, request.get('kind'))
            if evidence is not None and request.get('identity') == birth:
                selected = copy.copy(self)
                selected.registered = {**self.registered, pid: (token, current)}
                answer = receipts.ReceiptLedger.admit(selected, stream, {**request, 'identity': current})
                return {**answer, 'birth': birth, 'reparented_cleanup': evidence}
        return receipts.ReceiptLedger.admit(self, stream, request)


class ApprovalSupervisor(JournalSupervisor):
    def authenticate(self, request, events):
        pid = request.get('pid')
        saved = self.registered.get(pid)
        if saved is not None:
            current = kernel.identity(pid)
            evidence = proof(self, pid, saved['identity'], current, request.get('kind'))
            if evidence is not None and request.get('identity') == saved['identity']:
                return Supervisor.authenticate(view(self, pid, current),
                                               {**request, 'identity': current}, events)
        return Supervisor.authenticate(self, request, events)

    def observe(self, pid):
        saved = self.registered[pid]
        current = kernel.identity(pid)
        if proof(self, pid, saved['identity'], current, 'payload') is not None:
            return Supervisor.observe(view(self, pid, current), pid)
        return Supervisor.observe(self, pid)


def install(owner):
    if type(owner) is not JournalSupervisor or type(owner.ledger) is not receipts.ReceiptLedger:
        raise RuntimeError('approval_orphan_original_owner_required')
    owner.__class__ = ApprovalSupervisor
    owner.ledger.__class__ = ApprovalLedger
    owner.ledger.supervisor = owner
