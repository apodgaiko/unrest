"""Actual authenticated histories for the five-priority two-lane boundary.

Fresh single-lane controls establish each prefix independently. Their immutable
completed histories are joined only after all owned processes have closed; no
session or retained entitlement is invented by the join.
"""
import json
from pathlib import Path
import shutil

import pytest

from unrest_harness import experimental_model as model
from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_candidate import observe_candidate_inputs
from unrest_harness.experimental_cohort import Coordinator, ProviderSetup
from unrest_harness.experimental_custody import Custody, git
from unrest_harness.experimental_lease import PilotLedger
from unrest_harness.experimental_resources import Access, Resource, ResourceAdmission
from unrest_harness.providers import PROVIDERS


from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'
PREFIXES = (3, 2, 1, 4, 0)
PHASES = ('recheck', 'correction', 'validate', 'work', 'work')
NAMES = ('z-first', 'a-second')


def setup(root, ledger, names, *, capacity=1, parking=4, reuse=False):
    root.mkdir()
    original = root / 'base'
    original.mkdir()
    git(original, 'init', '--initial-branch=main', '--object-format=sha1')
    for name in ('a', 'b'):
        (original / name).write_bytes(b'base\n')
    git(original, 'add', '.')
    git(original, 'commit', '-m', 'finite fixture')
    oid = git(original, 'rev-parse', 'HEAD')
    destination = root / 'integration'
    shutil.copytree(original, destination)
    targets = tuple('VAL-' + ('A' if name == NAMES[0] else 'B') for name in names)
    base = observe_candidate_inputs(destination, oid, oid, (), (), targets)
    lanes, resources = [], {}
    for name, target in zip(names, targets, strict=True):
        candidate = root / (name + '-candidate')
        shutil.copytree(original, candidate)
        owned = root / name
        owned.mkdir()
        custody = Custody(candidate, root / (name + '-broker'), root / (name + '-seal.json'),
                          base=oid, commit=oid, writes=('a' if name == NAMES[0] else 'b',),
                          targets=(target,))
        lanes.append((name, custody))
        resources[name] = tuple(Access(Resource.path(path), 'write', purpose)
                               for path, purpose in ((candidate, 'candidate'),
                                   (custody.broker_root, 'broker'), (owned, 'owned')))
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(__file__).parents[1] / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=root, project_record=root)
    return Coordinator(root, tuple(lanes), destination=destination, base=base,
        resources=ResourceAdmission(resources), ledger=ledger,
        provider=ProviderSetup(ADAPTER, FIXTURE, policy, True, transport=controlled_transport()), trusted_process=True,
        config=model.Config(enabled=True, capacity=capacity, parking_capacity=parking,
                            reuse=reuse, turn_budget=14))


async def step(coordinator, expected_name):
    before = coordinator.state
    coordinator.state = model.reserve_next(before)
    assert coordinator.state != before and not coordinator.state.halted
    selected = next(lane for lane in coordinator.state.lanes if lane.active is not None)
    assert selected.spec.id == expected_name
    custody = coordinator.lanes[expected_name]
    ordinal = selected.turns[-1].ordinal
    coordinator._event('reservation', expected_name, ordinal=ordinal, phase=selected.phase,
                       candidate=custody.manifest.digest)
    # Both worker generations are deliberately defective; the test stops before
    # terminal validation. Expected dispositions do not come from model output.
    instruction = {'writes': {custody.writes[0]: 'defective\n'}} if selected.phase in (
        'work', 'correction') else {'expected': {custody.writes[0]: 'correct\n'}}
    result = await coordinator._turn(selected, 'fixture:' + json.dumps(instruction))
    assert result.disposition == ('sealed' if 'writes' in instruction else 'reproducible_product_defect')
    assert result.identity.lane == expected_name
    assert result.identity.targets == custody.manifest.targets
    owner = coordinator.owners[expected_name]
    receipts = [json.loads(line) for path in owner.root.rglob('received.jsonl')
                for line in path.read_text().splitlines()]
    assert len(receipts) == 1 and receipts[0]['method'] == 'turn/start'
    assert any(path.is_file() for path in (owner.root / 'completions').iterdir())
    coordinator._consume(expected_name, result)
    await coordinator.owners.pop(expected_name).close()
    assert not owner.quarantined
    assert all(role.process.returncode is not None for role in owner.roles.values())
    return result


@pytest.mark.parametrize('left,right', [(a, b) for a in range(5) for b in range(5)],
                         ids=[f'PRIORITY-{a+1}{b+1}' for a in range(5) for b in range(5)])
async def test_all_actual_priority_pairs(tmp_path, monkeypatch, left, right):
    # Local-only allowance supports two independent finite prefixes. This cannot
    # alter a provider campaign: the ledger is explicitly local-controlled-only.
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 14)
    ledger = PilotLedger(tmp_path / 'journal.jsonl', provider='local-controlled-only')
    ledger.admit('C1')
    combined = None
    try:
        combined = setup(tmp_path / 'combined', ledger, NAMES)
        config, base = combined.state.config, combined.state.base
        specifications = tuple(lane.spec for lane in combined.state.lanes)
        histories = []
        for specification, rank in zip(specifications, (left, right), strict=True):
            # Each prefix is an independent fresh control on its original bound
            # candidate. All histories come from reserve/send/HTTP completion;
            # only their join is test setup, never a restart/resume operation.
            admitted = model.admit((specification,), base=base, clean=True,
                                   isolated_dispatch=True, config=config)
            assert admitted.state is not None
            combined.state = admitted.state
            for _ in range(PREFIXES[rank]):
                await step(combined, specification.id)
            lane = combined.state.lanes[0]
            assert lane.phase == PHASES[rank]
            assert lane.admitted == (PREFIXES[rank] > 0)
            assert lane.active is None and not lane.leases and not lane.reuse_owner
            assert not combined.owners
            histories.append(lane)
        combined.state = model.State(config=config, base=base, lanes=tuple(histories))
        combined._persist()
        expected = NAMES[0 if left <= right else 1]
        result = await step(combined, expected)
        assert result.identity.lane == expected
        rows = [json.loads(line) for line in (tmp_path / 'journal.jsonl').read_text().splitlines()]
        count = PREFIXES[left] + PREFIXES[right] + 1
        assert sum(row['event'] == 'reserve' for row in rows) == count
        assert sum(row['event'] == 'send' for row in rows) == count
        assert sum(row['event'] == 'ack' for row in rows) == count
    finally:
        if combined is not None:
            for owner in combined.all_owners:
                await owner.close()
        ledger.close()
