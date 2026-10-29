"""Incremental process facts, readiness epochs and actual-parent reap joins.

Only trusted observers feed kernel rows and authenticated control envelopes.
This reducer does not authenticate sockets, admit launches or certify a release.
Waitid/WNOWAIT remains observation. Retirement requires the original parent's
terminal wait4, joined to the admitted child birth and tracer terminal status.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from functools import wraps
from typing import Any

from content_manifest import Refused

MAX_PROCESSES = 20000
MAX_EXEC_EPOCHS = 128
MAX_WAITID_ROWS = 128
# Two readiness records per independently registered execution epoch.
MAX_CONTROL_ROWS = 2


def fail_closed(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except BaseException:
            self.poison.append('invalid-' + method.__name__)
            raise
    return guarded


def canonical(identity: Any) -> dict:
    birth = Birth.read(identity)
    return {'pid': birth.pid, 'tgid': birth.tgid, 'ppid': birth.parent,
            'start_ticks': birth.ticks, 'boot_id': birth.boot, 'uids': [birth.uid] * 4,
            'pgid': integer(identity.get('pgid'), 1), 'sid': integer(identity.get('sid'), 1),
            'clock_ticks_per_second': integer(identity.get('clock_ticks_per_second'), 1)}


def integer(value: Any, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise Refused('ledger integer')
    return value


def text(value: Any) -> str:
    if type(value) is not str or not 0 < len(value) <= 4096:
        raise Refused('ledger text')
    return value


def status(raw: Any, normalized: Any) -> tuple[int, int]:
    raw = integer(raw, maximum=65535)
    if (type(normalized) is not int or not (os.WIFEXITED(raw) or os.WIFSIGNALED(raw))
            or os.waitstatus_to_exitcode(raw) != normalized):
        raise Refused('ledger terminal status')
    return raw, normalized


@dataclass(frozen=True)
class Birth:
    pid: int
    tgid: int
    parent: int
    ticks: int
    boot: str
    uid: int

    @classmethod
    def read(cls, identity: Any) -> Birth:
        if type(identity) is not dict:
            raise Refused('ledger identity')
        uids = identity.get('uids')
        if (type(uids) is not list or len(uids) != 4
                or any(type(uid) is not int or uid != uids[0] for uid in uids)):
            raise Refused('ledger identity uid')
        return cls(integer(identity.get('pid'), 1), integer(identity.get('tgid'), 1),
                   integer(identity.get('ppid')), integer(identity.get('start_ticks'), 1),
                   text(identity.get('boot_id')), integer(uids[0]))


@dataclass
class Epoch:
    token: str
    sequence: int = 0


@dataclass
class Process:
    birth: Birth
    identity: dict
    born: int
    parent: Birth | None
    group: Birth | None = None
    registered_identity: dict = field(default_factory=dict)
    case: str = ''
    command_class: str = ''
    new_session: bool = False
    session_complete: bool = False
    token: str | None = None
    life_token: str | None = None
    epochs: dict[int, Epoch] = field(default_factory=dict)
    pins: tuple[tuple[str, str], ...] = ()
    expected_seal: str | None = None
    generation: int = 0
    registered_generation: int = 0
    stage: str = 'born'
    control_sequence: int = 0
    exit: tuple[int, int] | None = None
    terminal: tuple[int, int, int] | None = None
    parent_wait: tuple[int, int, int, int] | None = None
    waitid: list[dict] = field(default_factory=list)


class Ledger:
    def __init__(self, nonce: str):
        self.nonce = text(nonce)
        self.next_kernel = 0
        self.processes: dict[Birth, Process] = {}
        self.current: dict[int, Birth] = {}
        self.children: dict[Birth, list[Birth]] = {}
        self.tokens: set[str] = set()
        self.by_token: dict[str, Birth] = {}
        self.pending_waits: dict[tuple[int, int, int, int], list[Birth]] = {}
        self.poison: list[str] = []
        self.root: Birth | None = None

    def process(self, birth: Birth) -> Process:
        if type(birth) is not Birth or birth not in self.processes:
            raise Refused('unknown ledger birth')
        return self.processes[birth]

    @fail_closed
    def register(self, birth: Birth, token: str, pins: tuple[tuple[str, str], ...], seal: str,
                 *, case: str, command_class: str, new_session: bool = False,
                 expected_generation: int | None = None) -> None:
        process = self.process(birth)
        token = text(token)
        if expected_generation is None:
            expected_generation = process.generation
        if (type(expected_generation) is not int
                or expected_generation not in (process.generation, process.generation + 1)
                or type(new_session) is not bool):
            raise Refused('ledger registration generation')
        if (token in self.tokens or process.stage not in ('born', 'exec-unregistered')
                or type(pins) is not tuple or not 0 < len(pins) <= 128
                or any(type(pair) is not tuple or len(pair) != 2 for pair in pins)):
            raise Refused('ledger registration')
        pins = tuple(sorted((text(key), text(value)) for key, value in pins))
        if len({key for key, _ in pins}) != len(pins):
            raise Refused('ledger duplicate pin')
        self.tokens.add(token)
        self.by_token[token] = birth
        process.token, process.pins, process.expected_seal = token, pins, text(seal)
        if process.life_token is None:
            process.life_token = token
        if expected_generation in process.epochs or len(process.epochs) >= MAX_EXEC_EPOCHS:
            raise Refused('ledger duplicate or unbounded exec epoch')
        process.epochs[expected_generation] = Epoch(token)
        process.registered_generation = expected_generation
        process.case, process.command_class = text(case), text(command_class)
        process.new_session = new_session
        process.stage, process.control_sequence = 'registered', 0

    @fail_closed
    def control(self, birth: Birth, token: str, generation: int, sequence: int,
                kind: str, payload: dict) -> None:
        process = self.process(birth)
        epoch = process.epochs.get(generation) if type(generation) is int else None
        if (epoch is None or type(token) is not str or token != epoch.token
                or type(sequence) is not int or sequence != epoch.sequence
                or sequence >= MAX_CONTROL_ROWS or type(payload) is not dict):
            raise Refused('ledger control epoch or sequence')
        if generation != process.generation or process.registered_generation != generation:
            raise Refused('stale readiness epoch')
        if kind in ('core-ready', 'body-ready') and (process.exit is not None or process.terminal is not None):
            raise Refused('readiness after terminal')
        if kind == 'core-ready':
            if (process.stage != 'registered' or set(payload) != {'pins'}
                    or type(payload['pins']) is not tuple or payload['pins'] != process.pins):
                raise Refused('ledger core readiness')
            process.stage = 'core-ready'
        elif kind == 'body-ready':
            if (self.poison or (process.new_session and not process.session_complete)
                    or process.stage != 'core-ready' or set(payload) != {'seal'}
                    or type(payload['seal']) is not str or payload['seal'] != process.expected_seal):
                raise Refused('ledger execution seal')
            process.stage = 'body-ready'
        else:
            raise Refused('ledger control operation')
        epoch.sequence += 1
        if generation == process.generation:
            process.control_sequence = epoch.sequence

    @fail_closed
    def wait_entry(self, caller: Birth, requested: int) -> None:
        process = self.process(caller)
        if (self.current.get(caller.pid) != caller or process.group is None
                or process.exit is not None or process.terminal is not None
                or type(requested) is not int):
            raise Refused('ledger waiting caller birth')
        owner = self.process(process.group)
        if owner.exit is not None or owner.terminal is not None or owner.life_token is None:
            raise Refused('ledger waiting parent authority')
        native = owner.command_class in ('native-git-command', 'native-git-helper', 'native-full-uv','native-stock-uv')
        if requested == -1 and native:
            return
        child = self.current.get(requested)
        if requested <= 0 or child is None:
            raise Refused('ledger wait outside admitted child')
        target = self.process(child)
        if (target.parent != owner.birth or target.life_token is None and not native
                or target.birth.pid != target.birth.tgid):
            raise Refused('ledger wait outside admitted child')

    @fail_closed
    def kernel(self, sequence: int, row: dict) -> None:
        if (type(sequence) is not int or sequence != self.next_kernel
                or type(row) is not dict or type(row.get('kind')) is not str):
            raise Refused('ledger kernel sequence')
        kind = row['kind']
        if kind in ('kernel_root', 'kernel_child'):
            birth = Birth.read(row.get('identity'))
            if len(self.processes) >= MAX_PROCESSES or birth in self.processes:
                raise Refused('ledger duplicate or unbounded birth')
            previous = self.current.get(birth.pid)
            if previous is not None and self.process(previous).terminal is None:
                raise Refused('ledger live PID replacement')
            if kind == 'kernel_root':
                if self.root is not None:
                    raise Refused('ledger duplicate root')
                parent = None
                self.root = birth
            else:
                parent = self.current.get(integer(row.get('parent'), 1))
                if (parent is None or row.get('child') != birth.pid
                        or type(row.get('event')) is not int or row['event'] not in (1, 2, 3)
                        or self.process(parent).terminal is not None):
                    raise Refused('ledger child parent binding')
                parent_process = self.process(parent)
                leader = self.current.get(parent_process.birth.tgid)
                if leader is None:
                    raise Refused('ledger missing parent thread group')
                parent = leader
                expected_parent = parent.pid if birth.pid == birth.tgid else parent.parent
                if (birth.uid != parent.uid or birth.parent != expected_parent
                        or (birth.pid != birth.tgid and (row['event'] != 3 or birth.tgid != parent.tgid))):
                    raise Refused('ledger child kernel identity')
            identity = canonical(row['identity'])
            self.processes[birth] = Process(birth, identity, sequence, parent,
                                             group=birth if birth.pid == birth.tgid else self.current.get(birth.tgid),
                                             registered_identity=dict(identity))
            self.current[birth.pid] = birth
            if parent is not None:
                self.children.setdefault(parent, []).append(birth)
        elif kind in ('kernel_exec', 'kernel_exit', 'tracer_terminal_wait', 'failure_cleanup_tracer_wait'):
            observed_birth = self.current.get(integer(row.get('pid'), 1))
            if observed_birth is None:
                raise Refused('ledger unknown kernel process')
            process = self.process(observed_birth)
            birth = observed_birth
            if kind == 'kernel_exec':
                if process.exit is not None or process.terminal is not None:
                    raise Refused('ledger exec after exit')
                process.generation += 1
                if process.registered_generation != process.generation:
                    process.stage = 'exec-unregistered'
                    process.expected_seal = None
            elif kind == 'kernel_exit':
                raw = integer(row.get('raw'), maximum=65535)
                status(raw, os.waitstatus_to_exitcode(raw))
                if process.exit is not None:
                    raise Refused('ledger duplicate exit')
                process.exit = (sequence, raw)
                process.stage = 'exited'
            else:
                raw, code = status(row.get('raw'), row.get('normalized'))
                if process.terminal is not None:
                    raise Refused('ledger duplicate terminal')
                if kind == 'failure_cleanup_tracer_wait':
                    self.poison.append('failure-cleanup')
                else:
                    group_exit=self.process(process.group).exit if birth.pid!=birth.tgid and process.group is not None else None
                    own_exit=process.exit is not None and process.exit[1]==raw
                    group_terminal=(group_exit is not None and group_exit[1]==raw
                                    and (process.exit is not None or raw==9))
                    if (not (own_exit or group_terminal) or Birth.read(row.get('identity')) != birth):
                        raise Refused('ledger terminal birth or exit')
                process.terminal = (sequence, raw, code)
                if process.parent is not None and process.birth.pid == process.birth.tgid:
                    key = (birth.pid, process.parent.tgid, raw, code)
                    self.pending_waits.setdefault(key, []).append(birth)
        elif kind == 'original_parent_wait4_entry':
            self.wait_entry(Birth.read(row.get('identity')), row.get('requested_pid'))
        elif kind == 'original_parent_wait4':
            child_pid = integer(row.get('child'), 1)
            raw, code = status(row.get('raw'), row.get('normalized'))
            key = (child_pid, integer(row.get('parent_tgid'), 1), raw, code)
            candidates = self.pending_waits.get(key, [])
            if len(candidates) != 1:
                raise Refused('ledger parent wait join')
            process = self.process(candidates[0])
            caller = self.current.get(integer(row.get('parent'), 1))
            if (caller is None or process.parent is None
                    or self.process(caller).group != process.parent
                    or self.process(caller).exit is not None or self.process(caller).terminal is not None):
                raise Refused('ledger actual waiting parent birth')
            requested = row.get('requested_pid')
            self.wait_entry(caller, requested)
            if requested != child_pid and requested != -1:
                raise Refused('ledger parent wait requested child')
            del self.pending_waits[key]
            process.parent_wait = (sequence, raw, code, integer(row.get('options')))
        elif kind == 'original_parent_waitid':
            # No route can retire from waitid alone. Retain the bounded observation.
            caller = self.current.get(integer(row.get('parent'), 1))
            if caller is None or len(self.process(caller).waitid) >= MAX_WAITID_ROWS:
                raise Refused('ledger waitid observation bound')
            self.process(caller).waitid.append(dict(row))
        elif kind == 'exec_attempt':
            if row.get('accepted') is not True:
                self.poison.append('denied-exec')
        elif kind in {'cleanup_incomplete', 'exec_syscall_return'}:
            if kind == 'cleanup_incomplete' or row.get('denied') is True:
                self.poison.append(kind)
        elif kind not in {'exec_memory_boundary', 'kernel_vfork_done'}:
            raise Refused('ledger unknown kernel record')
        self.next_kernel += 1

    @fail_closed
    def session(self, birth: Birth, observed: dict, records: tuple[dict, ...]) -> None:
        process = self.process(birth)
        if (not process.new_session or process.session_complete or process.parent is None
                or process.stage not in ('registered', 'core-ready')
                or type(records) is not tuple or len(records) != 3):
            raise Refused('ledger session transition')
        expected = {'admitted', 'registered', 'launch_lifecycle_binding'}
        if {row.get('kind') for row in records} != expected:
            raise Refused('ledger session witnesses')
        for row in records:
            if (row.get('owner_pid') != process.parent.pid or row.get('token') != process.token
                    or row.get('case') != process.case or row.get('class') != process.command_class):
                raise Refused('ledger session owner or case')
            if row['kind'] == 'registered' and (row.get('pid') != birth.pid or row.get('python') is not True):
                raise Refused('ledger session child')
            if row['kind'] == 'launch_lifecycle_binding' and row.get('start_new_session') is not True:
                raise Refused('ledger session method')
        current = canonical(observed)
        original = process.identity
        parent_identity = self.process(process.parent).registered_identity
        def stable(value):
            return {key: item for key, item in value.items() if key not in ('pgid', 'sid')}

        if (stable(current) != stable(original)
                or (current['pgid'], current['sid']) != (birth.pid, birth.pid)
                or (original['pgid'], original['sid']) != (parent_identity['pgid'], parent_identity['sid'])):
            raise Refused('ledger session identity')
        process.registered_identity = current
        process.session_complete = True

    def reaped(self, birth: Birth, token: str) -> bool:
        process = self.process(birth)
        if self.poison or type(token) is not str or token != process.life_token or self.by_token.get(token) != birth or process.parent is None:
            return False
        if process.exit is None or process.terminal is None or process.parent_wait is None:
            return False
        return (process.born < process.exit[0] < process.terminal[0] < process.parent_wait[0]
                and process.exit[1] == process.terminal[1] == process.parent_wait[1]
                and process.terminal[2] == process.parent_wait[2])

    def body_ready(self, birth: Birth, token: str) -> bool:
        process = self.process(birth)
        return (not self.poison and token == process.token and process.stage == 'body-ready'
                and process.registered_generation == process.generation
                and process.exit is None and process.terminal is None)
