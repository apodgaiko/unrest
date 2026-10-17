"""Receipt-controlled completion orders through the actual cohort run loop."""
import asyncio
import json
import hashlib
import time
from dataclasses import replace

import pytest

from unrest_harness.experimental_cohort import Coordinator
from unrest_harness.experimental_lease import PilotLedger, LeaseRefused
from unrest_harness import experimental_session as session
from tests.test_experimental_finite_priority import FIXTURE, NAMES, setup


def instructions(scripts):
    result = {}
    for lane, script, filename in zip(NAMES, scripts, ('a', 'b'), strict=True):
        rounds = {'P': 1, 'C': 2, 'R': 3}[script]
        turns = []
        for index in range(rounds):
            body = filename.upper() + '\n' if index == rounds - 1 else 'defective\n'
            turns.extend(('fixture:' + json.dumps({'writes': {filename: body}}),
                          'fixture:' + json.dumps({'expected': {filename: filename.upper() + '\n'}})))
        result[lane] = tuple(turns)
    return result


class CompletionBarriers:
    def __init__(self, monkeypatch, root):
        self.receipts, self.completed, self.paths = {}, {}, {}
        self.order = []
        self.rescued = False
        self.armed = False
        self.fixture = root / 'receipt-backend.py'
        source = FIXTURE.read_text()
        assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == session.FIXTURE_SHA256
        before = "assert set(script) <= {'writes', 'expected', 'delay'}"
        assert source.count(before) == 1 and source.count('                time.sleep(delay)') == 1
        source = source.replace(before, "assert set(script) <= {'writes', 'expected', 'delay', 'barrier'}")
        source = source.replace('                time.sleep(delay)', """                time.sleep(delay)
                if 'barrier' in script:
                    barrier = Path(script['barrier'])
                    barrier.with_suffix('.received').write_text('received')
                    deadline = time.monotonic() + 90
                    while not barrier.with_suffix('.release').exists():
                        if time.monotonic() >= deadline:
                            raise TimeoutError('controlled barrier')
                        time.sleep(.01)""")
        self.fixture.write_text(source)
        monkeypatch.setattr(session, 'FIXTURE_SHA256', hashlib.sha256(self.fixture.read_bytes()).hexdigest())
        original_turn = Coordinator._turn

        async def turn(coordinator, lane, instruction):
            assert coordinator.provider.controlled
            coordinator.provider = replace(coordinator.provider, backend=self.fixture)
            if not self.armed:
                return await original_turn(coordinator, lane, instruction)
            key = (lane.spec.id, lane.turns[-1].ordinal)
            path = coordinator.root / lane.spec.id / ('barrier-' + str(key[1]))
            self.paths[key] = path
            if self.rescued:
                path.with_suffix('.release').write_text('release')
            script = json.loads(instruction.removeprefix('fixture:'))
            script['barrier'] = str(path)
            result = await original_turn(coordinator, lane, 'fixture:' + json.dumps(script))
            self.order.append(key)
            self.completed[key].set()
            return result

        monkeypatch.setattr(Coordinator, '_turn', turn)

    def prepare(self, counts):
        self.armed = True
        for name, count in zip(NAMES, counts, strict=True):
            for ordinal in range(count):
                self.receipts[name, ordinal] = self.receipt(name, ordinal)
                self.completed[name, ordinal] = asyncio.Event()

    def receipt(self, name, ordinal):
        barriers = self
        class Receipt:
            async def wait(self):
                deadline = time.monotonic() + 75
                while True:
                    path = barriers.paths.get((name, ordinal))
                    if path is not None and path.with_suffix('.received').exists():
                        return
                    if time.monotonic() >= deadline:
                        raise TimeoutError('missing actual backend receipt')
                    await asyncio.sleep(.01)
        return Receipt()

    async def release(self, name, ordinal):
        await asyncio.wait_for(self.receipts[name, ordinal].wait(), 75)
        self.paths[name, ordinal].with_suffix('.release').write_text('release')
        await asyncio.wait_for(self.completed[name, ordinal].wait(), 45)

    def rescue(self):
        self.rescued = True
        for path in self.paths.values():
            path.with_suffix('.release').write_text('release')


async def run_order(tmp_path, monkeypatch, scripts, word, *, capacity=2, parking=4):
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 14)
    ledger = PilotLedger(tmp_path / 'journal.jsonl', provider='local-controlled-only')
    ledger.admit('C1')
    coordinator = setup(tmp_path / 'cohort', ledger, NAMES, capacity=capacity,
                        parking=parking, reuse=True)
    turns = instructions(scripts)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare(tuple(len(turns[name]) for name in NAMES))
    task = asyncio.create_task(coordinator.run(turns, 'fixture:' + json.dumps(
        {'expected': {'a': 'A\n', 'b': 'B\n'}})))
    counts = dict.fromkeys(NAMES, 0)
    try:
        for index in word:
            name = NAMES[index]
            await barriers.release(name, counts[name])
            counts[name] += 1
        result = await asyncio.wait_for(asyncio.shield(task), 60)
        assert result['outcome'] == 'passed'
        assert barriers.order == [(NAMES[index], sum(i == index for i in word[:position]))
                                  for position, index in enumerate(word)]
        assert (coordinator.destination / 'a').read_bytes() == b'A\n'
        assert (coordinator.destination / 'b').read_bytes() == b'B\n'
        assert all(row.verdicts for row in coordinator.final)
        assert len(coordinator.final) == 2
        assert all(row['active'] <= min(capacity, 2) for row in coordinator.events)
        assert all(row['parking_reserved'] <= parking for row in coordinator.events)
        for name in NAMES:
            completions = [c for c in coordinator.completions if c.identity.lane == name]
            if name == NAMES[0] and len(completions) >= 4:
                for first, second in ((0, 2), (1, 3)):
                    assert completions[first].identity.session == completions[second].identity.session
                    assert completions[first].identity.process_generation == completions[second].identity.process_generation
            if name == NAMES[1]:
                assert len({c.identity.process_generation for c in completions}) == len(completions)
        early = {c.identity.process_generation for c in coordinator.completions}
        assert not early & {c.identity.process_generation for c in coordinator.final}
        assert all(not owner.quarantined for owner in coordinator.all_owners)
    finally:
        barriers.rescue()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        for owner in coordinator.all_owners:
            await owner.close()
        ledger.close()


@pytest.mark.parametrize('scripts', ['PP', 'RR', 'RP', 'RC'])
@pytest.mark.parametrize('ordering', ['first', 'second', 'alternating-first', 'alternating-second'])
async def test_script_order_boundaries(tmp_path, monkeypatch, scripts, ordering):
    counts = [{'P': 2, 'C': 4, 'R': 6}[letter] for letter in scripts]
    first = 1 if ordering in ('second', 'alternating-second') else 0
    word = []
    if ordering.startswith('alternating'):
        while any(counts):
            for index in (first, 1 - first):
                if counts[index]:
                    word.append(index)
                    counts[index] -= 1
    else:
        word = [first] * counts[first] + [1 - first] * counts[1 - first]
    await run_order(tmp_path, monkeypatch, scripts, word)


@pytest.mark.parametrize('capacity', [1, 2, 3, 4, 8])
@pytest.mark.parametrize('parking', [2, 4])
async def test_actual_capacity_and_parking(tmp_path, monkeypatch, capacity, parking):
    await run_order(tmp_path, monkeypatch, 'PP', [0, 0, 1, 1] if capacity == 1
                    else [1, 0, 0, 1], capacity=capacity, parking=parking)


@pytest.mark.parametrize('workers', [(0, 1), (1, 0)])
@pytest.mark.parametrize('validators', [(0, 1), (1, 0)])
async def test_actual_simultaneous_completion_batches(tmp_path, monkeypatch, workers, validators):
    original = asyncio.wait
    batches = []

    async def wait(tasks, **kwargs):
        values = tuple(tasks)
        if len(values) == 2 and all(task.get_coro().__qualname__ ==
                'CompletionBarriers.__init__.<locals>.turn' for task in values):
            # The delivery barrier holds the controller until BOTH real turn
            # tasks finish. Their broker completion order remains independently
            # controlled, and the production controller still selects the tie.
            result = await original(values, timeout=45, return_when=asyncio.ALL_COMPLETED)
            assert not result[1]
            batches.append(len(result[0]))
            return result
        return await original(values, **kwargs)

    monkeypatch.setattr(asyncio, 'wait', wait)
    await run_order(tmp_path, monkeypatch, 'PP', [*workers, *validators])
    assert batches == [2, 2]
    state = json.loads((tmp_path / 'cohort/state.json').read_text())
    assert [row['lane'] for row in state['events'] if row['event'] == 'consumed'] == [*NAMES, *NAMES]


@pytest.mark.parametrize('parking', [0, 1])
def test_parking_admission_never_constructs_owner(tmp_path, monkeypatch, parking):
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    def forbidden(*args, **kwargs):
        raise AssertionError('owner constructed before parking admission')
    monkeypatch.setattr(Coordinator, '_new_owner', forbidden)
    try:
        with pytest.raises(LeaseRefused, match='model_admission_parking_capacity'):
            setup(tmp_path / 'cohort', ledger, NAMES, parking=parking, reuse=True)
        rows = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
        assert [row['event'] for row in rows] == ['campaign', 'admit']
    finally:
        ledger.close()
