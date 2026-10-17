"""Admission negatives and external-input drift on real disposable coordinators."""
import asyncio
import hashlib
import json

import pytest

from unrest_harness.experimental_candidate import CandidateInputError
from unrest_harness.experimental_cohort import Coordinator
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger
from unrest_harness.experimental_resources import Access, Resource, ResourceAdmission
from tests import test_experimental_finite_priority as fixture
from tests.test_experimental_finite_orders import CompletionBarriers, instructions


@pytest.mark.parametrize('case', ['overlapping-writes', 'writer-read', 'cache', 'output',
                                  'service', 'alias', 'undeclared'])
def test_resource_refusals_have_no_dispatch(tmp_path, monkeypatch, case):
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    common = tmp_path / 'common'
    common.mkdir()
    def admission(lanes):
        lanes = dict(lanes)
        if case == 'alias':
            alias = tmp_path / 'alias'
            alias.symlink_to(lanes[fixture.NAMES[0]][0].resource.identity)
            Resource.path(alias)
        elif case == 'undeclared':
            root = lanes[fixture.NAMES[0]][0].resource.identity
            from pathlib import Path
            (Path(root) / 'undeclared').write_text('unexpected')
        else:
            resource = (Resource.service('tcp', 'localhost', 12345) if case == 'service'
                        else Resource.path(common))
            for index, name in enumerate(fixture.NAMES):
                mode = 'read' if index == 1 and case == 'writer-read' else 'write'
                purpose = case if case in ('cache', 'output', 'service') else 'input' if mode == 'read' else 'output'
                lanes[name] = (*lanes[name], Access(resource, mode, purpose))
        return ResourceAdmission(lanes)
    def forbidden(*args, **kwargs):
        raise AssertionError('provider owner constructed despite admission refusal')
    monkeypatch.setattr(fixture, 'ResourceAdmission', admission)
    monkeypatch.setattr(Coordinator, '_new_owner', forbidden)
    try:
        with pytest.raises((LeaseRefused, CandidateInputError)):
            fixture.setup(tmp_path / 'cohort', ledger, fixture.NAMES, reuse=True)
        rows = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
        assert [row['event'] for row in rows] == ['campaign', 'admit']
        assert not list(tmp_path.rglob('received.jsonl'))
    finally:
        ledger.close()


async def test_observed_input_drift_during_actual_overlap(tmp_path, monkeypatch):
    external = tmp_path / 'declared-input'
    external.write_bytes(b'original\n')
    before = hashlib.sha256(external.read_bytes()).hexdigest()
    def admission(lanes):
        lanes = dict(lanes)
        name = fixture.NAMES[0]
        lanes[name] = (*lanes[name], Access(Resource.path(external), 'read', 'input'))
        return ResourceAdmission(lanes)
    monkeypatch.setattr(fixture, 'ResourceAdmission', admission)
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('C1')
    coordinator = fixture.setup(tmp_path / 'cohort', ledger, fixture.NAMES, capacity=2, reuse=True)
    barriers = CompletionBarriers(monkeypatch, tmp_path)
    barriers.prepare((2, 2))
    halted = asyncio.Event()
    original_halt = Coordinator._halt_owners
    def halt(self):
        original_halt(self)
        halted.set()
    monkeypatch.setattr(Coordinator, '_halt_owners', halt)
    task = asyncio.create_task(coordinator.run(instructions('PP'), 'fixture:' + json.dumps(
        {'expected': {'a': 'A\n', 'b': 'B\n'}})))
    try:
        for name in fixture.NAMES:
            await asyncio.wait_for(barriers.receipts[name, 0].wait(), 45)
        await barriers.release(fixture.NAMES[0], 0)
        await asyncio.wait_for(barriers.receipts[fixture.NAMES[0], 1].wait(), 45)
        assert coordinator.owners[fixture.NAMES[1]].sent_active
        index = len(coordinator.events)
        external.write_bytes(b'changed\n')
        barriers.paths[fixture.NAMES[0], 1].with_suffix('.release').write_text('release')
        await asyncio.wait_for(halted.wait(), 45)
        assert coordinator.state.halted and coordinator.owners[fixture.NAMES[1]].sent_active
        barriers.paths[fixture.NAMES[1], 0].with_suffix('.release').write_text('release')
        result = await asyncio.wait_for(asyncio.shield(task), 45)
        assert result['outcome'] == 'attention'
        assert coordinator.integrated is None and not coordinator.final
        assert hashlib.sha256(external.read_bytes()).hexdigest() != before
        assert not any(row['event'] in ('dispatch', 'prompt_sent', 'integrated', 'final')
                       for row in coordinator.events[index:])
        assert [lane.spec.targets for lane in coordinator.state.lanes] == [('VAL-A',), ('VAL-B',)]
        assert all(role.process.returncode is not None for owner in coordinator.all_owners
                   for role in owner.roles.values())
    finally:
        barriers.rescue()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        ledger.close()


@pytest.mark.parametrize('boundary', ['before-validation', 'after-validation', 'pre-integration'])
async def test_actual_declared_input_drift_stops_dispatch(tmp_path, monkeypatch, boundary):
    external = tmp_path / 'declared-input'
    external.write_bytes(b'original\n')
    original_sha = hashlib.sha256(external.read_bytes()).hexdigest()
    def admission(lanes):
        lanes = dict(lanes)
        name = fixture.NAMES[0]
        lanes[name] = (*lanes[name], Access(Resource.path(external), 'read', 'input'))
        return ResourceAdmission(lanes)
    monkeypatch.setattr(fixture, 'ResourceAdmission', admission)
    ledger = PilotLedger(tmp_path / 'journal.jsonl')
    ledger.admit('P1')
    coordinator = fixture.setup(tmp_path / 'cohort', ledger, (fixture.NAMES[0],), reuse=True)
    digest = coordinator.resources.digest
    observed = []
    original_event = Coordinator._event
    def event(self, name, lane, **fields):
        original_event(self, name, lane, **fields)
        selected = ((boundary == 'before-validation' and name == 'consumed' and fields.get('outcome') == 'sealed')
                    or (boundary == 'after-validation' and name == 'provider_completed' and fields.get('phase') == 'validate')
                    or (boundary == 'pre-integration' and name == 'consumed' and fields.get('outcome') == 'pass'))
        if selected and not observed:
            observed.append(len(self.events))
            external.write_bytes(b'changed\n')
    monkeypatch.setattr(Coordinator, '_event', event)
    try:
        result = await coordinator.run({fixture.NAMES[0]: (
            'fixture:' + json.dumps({'writes': {'a': 'A\n'}}),
            'fixture:' + json.dumps({'expected': {'a': 'A\n'}}))},
            'fixture:' + json.dumps({'expected': {'a': 'A\n', 'b': 'base\n'}}))
        assert observed and result['outcome'] == 'attention'
        assert coordinator.resources.stopped
        assert coordinator.lanes[fixture.NAMES[0]].resource_digest == digest
        assert hashlib.sha256(external.read_bytes()).hexdigest() != original_sha
        assert coordinator.integrated is None and not coordinator.final
        assert not any(row['event'] in ('dispatch', 'prompt_sent', 'integrated', 'final')
                       for row in coordinator.events[observed[0]:])
        assert all(role.process.returncode is not None for owner in coordinator.all_owners
                   for role in owner.roles.values())
    finally:
        ledger.close()
