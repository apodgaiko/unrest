"""Case-scoped Git values after original stdout custody and actual reap joins.

The caller must authenticate the original communicate result, pipe generation,
exact command and owned repository/location. This reducer does not acquire that
stdout independently and never grants a process or filesystem permission.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

from content_manifest import Refused
from process_ledger import Birth, Ledger, MAX_PROCESSES, fail_closed


def text(value):
    if type(value) is not str or not value or len(value) > 4096 or '\0' in value:
        raise Refused('git value primitive')
    try:
        if len(value.encode('utf-8')) > 4096:
            raise Refused('git value text bound')
    except UnicodeError:
        raise Refused('git value text encoding') from None
    return value


def digest(value, length=40):
    if type(value) is not str or len(value) != length or any(c not in '0123456789abcdef' for c in value):
        raise Refused('git value digest')
    return value


@dataclass(frozen=True)
class Value:
    case: str
    repository: str
    location: str
    kind: str
    value: str
    inputs: tuple[str, ...]
    producer: Birth
    token: str


class Values:
    def __init__(self, ledger: Ledger):
        if type(ledger) is not Ledger:
            raise Refused('git value ledger')
        self.ledger = ledger
        self.poison: list[str] = []
        self.values: list[Value] = []
        self.producers: set[Birth] = set()

    def require(self, case, repository, location, kind, value, inputs=()):
        if self.poison or self.ledger.poison:
            raise Refused('git value poisoned')
        for item in (case, repository, location, kind, value):
            text(item)
        if type(inputs) is not tuple or len(inputs) > 4:
            raise Refused('git value dependency primitives')
        for dependency in inputs:
            text(dependency)
        found = [row for row in self.values if (row.case, row.repository, row.location, row.kind, row.value, row.inputs)
                 == (case, repository, location, kind, value, inputs)]
        if not found:
            raise Refused('git value missing causal producer')
        return found[-1]

    def native_child_reaped(self, parent, birth, case, pins):
        # Stock Git has no Python control channel. Only its actual kernel wait
        # retires an independently admitted helper; this never retires a producer.
        child, owner = self.ledger.process(birth), self.ledger.process(parent)
        if (self.ledger.poison or child.parent != parent or child.case != case
                or owner.case != case or child.command_class != 'native-git-helper'
                or owner.command_class not in ('native-git-command', 'native-git-helper')
                or child.pins != pins or owner.pins != pins
                or child.generation != 1 or child.registered_generation != 1
                or owner.generation != 1 or owner.registered_generation != 1
                or child.receipt is not None
                or child.exit is None or child.terminal is None or child.parent_wait is None):
            return False
        exited, terminal, wait = child.exit, child.terminal, child.parent_wait
        return (child.born < exited[0] < terminal[0] < wait[0]
                and exited[1] == terminal[1] == wait[1]
                and terminal[2] == wait[2] == 0 and wait[3] == 0)

    @fail_closed
    def observe(self, birth, token, case, repository, location, kind, output, *, inputs=()):
        if (self.poison or self.ledger.poison or type(birth) is not Birth
                or birth in self.producers or len(self.values) >= MAX_PROCESSES):
            raise Refused('git value producer or bound')
        for item in (token, case, repository, location, kind):
            text(item)
        if (not repository.startswith('/') or str(PurePosixPath(repository)) != repository
                or repository.startswith('//') or '..' in PurePosixPath(repository).parts):
            raise Refused('git value canonical repository')
        process = self.ledger.process(birth)
        if (process.case != case or process.command_class != 'native-git-command'
                or process.generation != 1 or process.registered_generation != 1
                or len(process.pins) != 1 or process.pins[0][0] != 'native-fixture'
                or not self.ledger.reaped(birth, token)
                or process.terminal is None or process.terminal[2] != 0):
            raise Refused('git value needs successful actual parent join')
        digest(process.pins[0][1], 64)
        pending = [birth]
        checked = 0
        while pending:
            parent = pending.pop()
            for child in self.ledger.children.get(parent, ()):
                checked += 1
                if checked > 16 or not self.native_child_reaped(parent, child, case, process.pins):
                    raise Refused('git value has unsettled native descendants')
                pending.append(child)
        if (type(output) is not str or not 1 < len(output) <= 128
                or not output.endswith('\n') or '\n' in output[:-1] or '\r' in output):
            raise Refused('git value exact stdout line')
        if type(inputs) is not tuple or len(inputs) > 4:
            raise Refused('git value dependency primitives')
        for dependency in inputs:
            text(dependency)
        value = output[:-1]
        if kind in ('commit', 'tree'):
            if inputs:
                raise Refused('git value unexpected dependencies')
            digest(value)
        elif kind == 'date':
            if len(inputs) != 1:
                raise Refused('git date predecessor')
            self.require(case, repository, 'parent', 'commit', digest(inputs[0]))
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                raise Refused('git value date') from None
            if parsed.tzinfo is None or parsed.isoformat() != value:
                raise Refused('git value canonical date')
        elif kind == 'integration-commit':
            if len(inputs) != 4:
                raise Refused('git commit dependency set')
            tree, predecessor, date, message = inputs
            self.require(case, repository, location, 'tree', digest(tree))
            self.require(case, repository, 'parent', 'commit', digest(predecessor))
            self.require(case, repository, 'parent', 'date', date, (predecessor,))
            digest(message, 64)
            digest(value)
        else:
            raise Refused('git value unknown kind')
        row = Value(case, repository, location, kind, value, inputs, birth, token)
        self.values.append(row)
        self.producers.add(birth)
        return row
