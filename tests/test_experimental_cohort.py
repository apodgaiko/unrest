"""Disposable Git and actual controlled provider-to-MCP coordinator checks."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import time

import pytest

from unrest_harness import experimental_model as model
from unrest_harness.experimental_candidate import CandidateInputError, observe_candidate_inputs
from unrest_harness.experimental_cohort import campaign, recovered_status
from unrest_harness.experimental_custody import Custody, git, integrate, recover_sealed
from unrest_harness.experimental_lease import LeaseRefused, TurnBroker, TurnIdentity
from unrest_harness.experimental_resources import Access, Resource, ResourceAdmission

from tests.controlled_transport import controlled_transport

ADAPTER = Path(shutil.which('codex-acp') or '/missing').resolve()
FIXTURE = Path(__file__).parent / 'fixtures/experimental_session_app_server.py'


def footprint(root, lane):
    values = []
    for purpose in ('candidate', 'broker', 'owned'):
        path = root / (lane + '-' + purpose)
        path.mkdir()
        values.append(Access(Resource.path(path), 'write', purpose))
    return tuple(values)


def test_distinct_resources_and_late_identity_conflict(tmp_path):
    first, second = footprint(tmp_path, 'z'), footprint(tmp_path, 'a')
    admission = ResourceAdmission({'z': first, 'a': second})
    admission.verify()
    root = Path(second[0].resource.identity)
    root.rename(root.with_suffix('.old'))
    root.mkdir()
    with pytest.raises(LeaseRefused, match='resource_replaced'):
        admission.verify()
    with pytest.raises(LeaseRefused, match='stopped'):
        admission.verify()


@pytest.mark.parametrize('mode,purpose', [('read', 'input'), ('write', 'output'),
                                         ('write', 'cache'), ('write', 'service')])
def test_cross_lane_full_footprint_collisions(tmp_path, mode, purpose):
    first, second = footprint(tmp_path, 'z'), footprint(tmp_path, 'a')
    shared = tmp_path / 'shared'
    shared.mkdir()
    resource = (Resource.service('tcp', 'localhost', 12345) if purpose == 'service'
                else Resource.path(shared))
    with pytest.raises(LeaseRefused, match='cross_lane_resource_conflict'):
        ResourceAdmission({'z': (*first, Access(resource, 'write', purpose)),
                           'a': (*second, Access(resource, mode, purpose))})


def test_aliased_and_unresolved_roots_and_ports(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(root)
    with pytest.raises(LeaseRefused, match='alias'):
        Resource.path(alias)
    with pytest.raises(LeaseRefused, match='unresolved'):
        Resource.path(tmp_path / 'absent')
    assert Resource.service('tcp', 'localhost', 1000) == Resource.service('tcp', '::1', 1000)
    assert Resource.service('tcp', '0.0.0.0', 1000) == Resource.service('tcp', '127.0.0.1', 1000)
    with pytest.raises(LeaseRefused):
        Resource.service('tcp', 'unresolved.invalid', 1000)


def test_declared_input_changes_stop_admission(tmp_path):
    values = footprint(tmp_path, 'z')
    path = tmp_path / 'input'
    path.write_text('before')
    admission = ResourceAdmission({'z': (*values, Access(Resource.path(path), 'read', 'input'))})
    path.write_text('after!')
    with pytest.raises(LeaseRefused, match='declared_input_changed'):
        admission.verify()


def repository(root):
    root.mkdir()
    git(root, 'init', '--initial-branch=main', '--object-format=sha1')
    (root / 'a').write_text('base\n')
    (root / 'b').write_text('base\n')
    git(root, 'add', '.')
    git(root, 'commit', '-m', 'base')
    return git(root, 'rev-parse', 'HEAD')


def custody_setup(tmp_path):
    candidate = tmp_path / 'candidate'
    base = repository(candidate)
    custody = Custody(candidate, tmp_path / 'broker', tmp_path / 'seal.json',
                      base=base, commit=base, writes=('a',), targets=('VAL-A',))
    broker = TurnBroker(custody.broker_root, tmp_path / 'completions')
    broker.seal(('a',), custody.expected)
    identity = TurnIdentity('z', 'worker', 'child', 'handoff', 'session', 'process',
                            1, ('a',), custody.expected, ('VAL-A',))
    return custody, broker, identity


def test_sealing_is_drained_and_only_last_seal_recovers(tmp_path):
    custody, broker, identity = custody_setup(tmp_path)
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        digest = broker.replace(token, identity, 'a', 'A\n')
        completion = broker.complete(token, identity, digest, 'sealed')
        sealed = custody.seal(broker, completion)
        assert (custody.root / 'a').read_bytes() == b'A\n'
        (custody.root / 'a').write_text('unsealed\n')
        (custody.broker_root / 'a').write_text('unsealed\n')
        before = custody.record.read_bytes()
        restored = recover_sealed(custody.record, tmp_path / 'recovered')
        assert restored == sealed
        assert (tmp_path / 'recovered/a').read_bytes() == b'A\n'
        assert custody.record.read_bytes() == before
        with pytest.raises(CandidateInputError):
            custody.verify()
    finally:
        broker.close()


@pytest.mark.parametrize('mutation', ['body', 'symlink'])
def test_snapshot_copy_race_refuses_without_publishing_or_following_link(tmp_path, monkeypatch, mutation):
    import builtins
    import unrest_harness.experimental_custody as module
    custody, broker, identity = custody_setup(tmp_path)
    old_record = custody.record.read_bytes()
    outside = tmp_path / 'outside'
    outside.write_text('MUST_NOT_READ')
    original_copy, original_open = module.shutil.copytree, builtins.open
    def copy(source, destination, *args, **kwargs):
        if Path(source) == custody.root:
            path = custody.root / 'b'
            if mutation == 'body':
                path.write_text('changed after observation')
            else:
                path.unlink()
                path.symlink_to(outside)
        return original_copy(source, destination, *args, **kwargs)
    def guarded_open(file, *args, **kwargs):
        if isinstance(file, (str, Path)):
            assert Path(file).resolve() != outside
        return original_open(file, *args, **kwargs)
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        digest = broker.replace(token, identity, 'a', 'A\n')
        completion = broker.complete(token, identity, digest, 'sealed')
        with monkeypatch.context() as patch:
            patch.setattr(module.shutil, 'copytree', copy)
            patch.setattr(builtins, 'open', guarded_open)
            with pytest.raises(CandidateInputError):
                custody.seal(broker, completion)
        assert custody.record.read_bytes() == old_record
        recover_sealed(custody.record, tmp_path / 'recovered')
        assert (tmp_path / 'recovered/a').read_text() == 'base\n'
    finally:
        broker.close()


@pytest.mark.parametrize('mutation', ['extra', 'tracked', 'index', 'config', 'symlink'])
def test_custody_undeclared_and_changed_inputs_refuse(tmp_path, mutation):
    custody, broker, _ = custody_setup(tmp_path)
    try:
        if mutation == 'extra':
            (custody.root / 'secret').write_text('CANARY_PRIVATE')
        elif mutation == 'tracked':
            (custody.root / 'b').write_text('CANARY_PRIVATE')
        elif mutation == 'index':
            (custody.root / 'b').write_text('CANARY_PRIVATE')
            git(custody.root, 'add', 'b')
        elif mutation == 'config':
            with (custody.root / '.git/config').open('a') as stream:
                stream.write('[include]\npath = /private/tmp/private\n')
        else:
            (custody.root / 'b').unlink()
            (custody.root / 'b').symlink_to('/private/tmp/private')
        with pytest.raises(CandidateInputError) as failure:
            custody.verify()
        assert 'CANARY_PRIVATE' not in str(failure.value)
        assert 'CANARY_PRIVATE' not in custody.record.read_text()
    finally:
        broker.close()


@pytest.mark.parametrize('verdicts', [None, {}, {'VAL-B': True}, {'VAL-A': False}, {'VAL-A': 1}])
def test_actual_target_verdict_required(tmp_path, verdicts):
    custody, broker, _ = custody_setup(tmp_path)
    identity = TurnIdentity('z', 'validator', 'child', 'handoff', 'session', 'process',
                            1, ('a',), custody.expected, ('VAL-A',))
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        with pytest.raises(LeaseRefused, match='target_verdicts_invalid'):
            broker.complete(token, identity, custody.expected, 'pass', verdicts)
        assert not list((tmp_path / 'completions').iterdir())
    finally:
        broker.close()


def test_target_verdict_immutable_and_cross_lane_substitution(tmp_path):
    custody, broker, _ = custody_setup(tmp_path)
    identity = TurnIdentity('z', 'validator', 'child', 'handoff', 'session', 'process',
                            1, ('a',), custody.expected, ('VAL-A',))
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        substituted = TurnIdentity(**{**asdict(identity), 'lane': 'a'})
        with pytest.raises(LeaseRefused, match='authority_denied'):
            broker.complete(token, substituted, custody.expected, 'pass', {'VAL-A': True})
        result = broker.complete(token, identity, custody.expected, 'pass', {'VAL-A': True})
        assert result.verdicts == (('VAL-A', True),)
        with pytest.raises(LeaseRefused):
            broker.complete(token, identity, custody.expected, 'pass', {'VAL-A': True})
    finally:
        broker.close()


def test_integrates_in_authored_order_and_rechecks_base(tmp_path):
    original = tmp_path / 'original'
    oid = repository(original)
    destination = tmp_path / 'integration'
    shutil.copytree(original, destination)
    base = observe_candidate_inputs(destination, oid, oid, (), (), ('VAL-A', 'VAL-B'))
    lanes = []
    for index, (name, body) in enumerate((('a', 'A\n'), ('b', 'B\n'))):
        root = tmp_path / f'lane-{index}'
        shutil.copytree(original, root)
        c = Custody(root, tmp_path / f'broker-{index}', tmp_path / f'seal-{index}.json',
                    base=oid, commit=oid, writes=(name,), targets=('VAL-' + name.upper(),))
        broker = TurnBroker(c.broker_root, tmp_path / f'completions-{index}')
        try:
            identity = TurnIdentity(str(index), 'worker', 'child', 'handoff', 's', 'p', 1,
                                    (name,), c.expected)
            token = broker.grant(identity, deadline=time.monotonic() + 30)
            digest = broker.replace(token, identity, name, body)
            c.seal(broker, broker.complete(token, identity, digest, 'sealed'))
        finally:
            broker.close()
        lanes.append(c)
    integrated = integrate(destination, base, tuple(lanes))
    assert integrated.base_oid == oid
    assert (destination / 'a').read_bytes() == b'A\n'
    assert (destination / 'b').read_bytes() == b'B\n'
    assert git(destination, 'show', 'HEAD~1:a') == 'A'
    assert git(destination, 'show', 'HEAD~1:b') == 'base'
    with pytest.raises(CandidateInputError):
        integrate(destination, base, tuple(lanes))


async def test_real_controlled_campaign_and_streaming(tmp_path):
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, transport=controlled_transport())
    assert all(v['outcome'] == 'passed' for v in result['episodes'].values())
    journal = [json.loads(line) for line in (root / 'campaign.jsonl').read_text().splitlines()]
    assert sum(row['event'] == 'reserve' for row in journal) == 24
    assert sum(row['event'] == 'campaign' for row in journal) == 1
    for episode, count in [('P1', 4), ('P2', 6), ('P3', 8), ('C1', 6)]:
        data = json.loads((root / episode / 'state.json').read_text())
        assert len(data['completions']) + len(data['final']) == count
        assert data['turns_consumed'] == count
        assert data['final_turns_consumed'] == 2
        assert all(row['verdicts'] for row in data['final'])
        early = {row['identity']['process_generation'] for row in data['completions']}
        final = {row['identity']['process_generation'] for row in data['final']}
        assert not early & final and len(final) == 2
        assert recovered_status(root / episode / 'state.json')['resumable'] is False
    data = json.loads((root / 'C1/state.json').read_text())
    events = data['events']
    def stamp(event, lane, phase):
        return next(row['monotonic_seconds'] for row in events
                    if row['event'] == event and row['lane'] == lane and row.get('phase') == phase)
    assert stamp('completion', 'z-first', 'work') < stamp('dispatch', 'z-first', 'validate')
    assert stamp('prompt_sent', 'z-first', 'validate') < stamp('provider_completed', 'a-second', 'work')
    assert data['model']['lanes'][0]['reuse_owner']
    assert not data['model']['lanes'][1]['reuse_owner']
    assert not any('V-LIVE' in p.read_text() for p in root.rglob('state.json'))


async def test_missing_opt_in_refuses_without_creating_root(tmp_path):
    root = tmp_path / 'never-created'
    with pytest.raises(LeaseRefused, match='opt_in'):
        await campaign(root, trusted_process=False, adapter=ADAPTER, fixture=FIXTURE, package=None, transport=controlled_transport())
    assert not root.exists()


async def test_unresolved_provider_config_refuses_before_campaign_creation(tmp_path, monkeypatch):
    import unrest_harness.experimental_cohort as module
    monkeypatch.setattr(module, 'check_package', lambda package: Path('/not-launched/backend'))
    def unresolved(**kwargs):
        raise LeaseRefused('provider_configuration_unresolved')
    monkeypatch.setattr(module, 'ProviderConfig', unresolved)
    root = tmp_path / 'never-created'
    with pytest.raises(LeaseRefused, match='provider_configuration_unresolved'):
        await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=None,
                       package=tmp_path / 'package')
    assert not root.exists()


def check_scheduling_events(data, *, streaming, capacity=2):
    """Independent replay of ready priority; no product model functions as oracle."""
    names = [lane['spec']['id'] for lane in data['model']['lanes']]
    phases = dict.fromkeys(names, 'work')
    admitted, active, corrected = set(), set(), set()
    generations = dict.fromkeys(names, 0)
    priorities = {'recheck': 0, 'correction': 1, 'validate': 2, 'work': 3}
    for event in data['events']:
        name = event['lane']
        assert event['active'] <= capacity
        assert event['parked'] <= 4 and event['parking_reserved'] <= 4
        if event['event'] == 'reservation':
            ready = [n for n in names if n not in active and phases[n] in priorities]
            if not streaming:
                ready = [n for n in ready if phases[n] != 'validate'
                         or all(phases[other] != 'work' or generations[other] for other in names)]
            expected = min(ready, key=lambda n: (priorities[phases[n]] if n in admitted else 4, names.index(n)))
            assert name == expected
            assert event['phase'] == phases[name]
            assert len(active) < capacity
            admitted.add(name)
            active.add(name)
        elif event['event'] == 'consumed':
            assert name in active
            active.remove(name)
            if event['outcome'] == 'sealed':
                phases[name] = 'recheck' if phases[name] == 'correction' else 'validate'
            elif event['outcome'] == 'pass':
                phases[name] = 'passed'
            elif event['outcome'] == 'defect':
                if generations[name]:
                    phases[name] = 'attention'
                elif name not in corrected:
                    phases[name] = 'correction'
                    corrected.add(name)
                else:
                    generations[name] = 1
                    phases[name] = 'work'
            else:
                phases[name] = 'attention'


@pytest.mark.parametrize('streaming,reuse', [(False, False), (False, True), (True, False), (True, True)])
@pytest.mark.parametrize('timing', [((1, 9), (1, 1)), ((5, 5), (1, 1)), ((1, 2), (9, 1))],
                         ids=['straggler', 'equal', 'long-validator'])
async def test_actual_four_arm_timing_and_model_conformance(tmp_path, streaming, reuse, timing):
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',), streaming=streaming, reuse=reuse,
                            controlled_timing=timing, transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == 'passed'
    data = json.loads((root / 'C1/state.json').read_text())
    check_scheduling_events(data, streaming=streaming)
    assert [lane['phase'] for lane in data['model']['lanes']] == ['passed', 'passed']
    assert len(data['completions']) == 4 and len(data['final']) == 2
    assert (root / 'C1/integration/lane_a.txt').read_bytes() == b'A\n'
    assert (root / 'C1/integration/lane_b.txt').read_bytes() == b'B\n'


@pytest.mark.parametrize('terminal_defect', [False, True])
async def test_two_lane_rotation_uses_controlled_budget_only(tmp_path, monkeypatch, terminal_defect):
    from unrest_harness.experimental_lease import PilotLedger
    # Test-only local accounting, never a live pilot budget modification.
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 14)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',), controlled_rounds=3,
                            controlled_timing=((0, 0), (0, 0)),
                            controlled_terminal_defect=terminal_defect, transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == ('attention' if terminal_defect else 'passed')
    data = json.loads((root / 'C1/state.json').read_text())
    check_scheduling_events(data, streaming=True)
    assert any(lane['generation'] == 1 for lane in data['model']['lanes'])
    assert all(lane['correction_reserved'] for lane in data['model']['lanes'])
    if terminal_defect:
        assert not data['final'] and data['integrated'] is None
    else:
        assert len(data['completions']) == 12 and len(data['final']) == 2


async def test_observed_mutation_during_overlap_stops_integration(tmp_path, monkeypatch):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator._event
    def event(self, name, lane, **fields):
        original(self, name, lane, **fields)
        if name == 'prompt_sent' and fields.get('phase') == 'validate':
            (self.lanes[lane].root / 'lane_a.txt').write_text('CANARY_PRIVATE\n')
    monkeypatch.setattr(Coordinator, '_event', event)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',), transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == 'attention'
    data = json.loads((root / 'C1/state.json').read_text())
    assert data['integrated'] is None and not data['final']
    assert 'CANARY_PRIVATE' not in (root / 'C1/state.json').read_text()
    assert 'CANARY_PRIVATE' not in (root / 'campaign.jsonl').read_text()


async def test_actual_parked_ttl_forbids_next_dispatch(tmp_path, monkeypatch):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator._event
    def event(self, name, lane, **fields):
        original(self, name, lane, **fields)
        if name == 'consumed' and fields.get('outcome') == 'sealed':
            self.started -= 3601
    monkeypatch.setattr(Coordinator, '_event', event)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P1',), transport=controlled_transport())
    assert result['episodes']['P1']['outcome'] == 'attention'
    data = json.loads((root / 'P1/state.json').read_text())
    assert sum(row['event'] == 'prompt_sent' for row in data['events']) == 1
    assert data['model']['lanes'][0]['blocking'] == 'expired'
    assert not data['final']


def test_halted_shared_campaign_only_sent_turns_can_drain(tmp_path):
    from unrest_harness.experimental_lease import PilotLedger
    clock = [0.0]
    ledger = PilotLedger(tmp_path / 'ledger', clock=lambda: clock[0])
    try:
        ledger.admit('C1')
        one = TurnIdentity('a', 'worker', 'c', 'h', 's', 'p', 1, ('a',), '0' * 64)
        two = TurnIdentity('b', 'worker', 'c', 'h', 's', 'q', 1, ('b',), '0' * 64)
        sent, unsent = ledger.reserve(one), ledger.reserve(two)
        ledger.sent(sent)
        ledger.stop()
        assert ledger.remaining(sent, drain=True) == 300
        with pytest.raises(LeaseRefused):
            ledger.remaining(unsent, drain=True)
        with pytest.raises(LeaseRefused):
            ledger.sent(unsent)
        with pytest.raises(LeaseRefused):
            ledger.reserve(one)
        clock[0] = 300
        with pytest.raises(LeaseRefused):
            ledger.remaining(sent, drain=True)
    finally:
        ledger.close()


async def test_stop_while_worker_active_drains_without_validation(tmp_path, monkeypatch):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator._event
    def event(self, name, lane, **fields):
        original(self, name, lane, **fields)
        if name == 'prompt_sent' and fields.get('phase') == 'work':
            (self.root / 'stop-request').touch()
    monkeypatch.setattr(Coordinator, '_event', event)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P1',), transport=controlled_transport())
    assert result['episodes']['P1']['outcome'] == 'attention'
    data = json.loads((root / 'P1/state.json').read_text())
    assert not data['final'] and data['integrated'] is None
    assert sum(e['event'] == 'prompt_sent' for e in data['events']) == 1
    assert any(e['event'] == 'provider_completed' for e in data['events'])
    assert data['active'] == 0


@pytest.mark.parametrize('boundary', ['reservation', 'prompt_sent', 'backend_received', 'provider_completed'])
def test_actual_controller_crash_has_no_resume_authority(tmp_path, boundary):
    import subprocess
    import sys
    root = tmp_path / 'crashed'
    source = """
import asyncio, os
from pathlib import Path
from unrest_harness.experimental_cohort import Coordinator, campaign
from tests.controlled_transport import controlled_transport
original = Coordinator._event
def event(self, name, lane, **fields):
    original(self, name, lane, **fields)
    if name == BOUNDARY:
        os._exit(73)
Coordinator._event = event
async def received_crash():
    async with asyncio.timeout(60):
        while not list(ROOT.glob('P1/*/turn-*/worker/received.jsonl')):
            await asyncio.sleep(.01)
    os._exit(73)
async def run():
    if BOUNDARY == 'backend_received':
        asyncio.create_task(received_crash())
    await campaign(ROOT, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                   package=None, episodes=('P1',), transport=controlled_transport(),
                   controlled_timing=((10, 0), (0, 0)) if BOUNDARY == 'backend_received' else None)
asyncio.run(run())
"""
    script = ('BOUNDARY=' + repr(boundary) + '\n'
              + 'from pathlib import Path\n'
              + 'ROOT=Path(' + repr(str(root)) + ')\n'
              + 'ADAPTER=Path(' + repr(str(ADAPTER)) + ')\n'
              + 'FIXTURE=Path(' + repr(str(FIXTURE.resolve())) + ')\n' + source)
    result = subprocess.run([sys.executable, '-c', script], timeout=90,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert result.returncode == 73
    if boundary == 'backend_received':
        receipts = list(root.glob('P1/*/turn-*/worker/received.jsonl'))
        assert len(receipts) == 1
        assert json.loads(receipts[0].read_text())['method'] == 'turn/start'
        assert not receipts[0].with_name('trace.jsonl').exists()
        journal = [json.loads(line) for line in (root / 'campaign.jsonl').read_text().splitlines()]
        assert sum(row['event'] == 'reserve' for row in journal) == 1
        assert sum(row['event'] == 'send' for row in journal) == 1
        assert not any(row['event'] == 'ack' for row in journal)
    state = recovered_status(root / 'P1/state.json')
    assert state['outcome'] == 'attention' and state['resumable'] is False
    assert state['model']['lanes'][0]['turns'][0]['status'] == 'uncertain'
    restore = tmp_path / 'restored'
    recover_sealed(root / 'P1/seal-0.json', restore)
    assert (restore / 'lane_a.txt').read_bytes() == b'base\n'
    # A fresh run at the same campaign root cannot reset its consumed ledger.
    with pytest.raises(FileExistsError):
        root.mkdir()


async def test_cancellation_drains_controller_git_thread_before_return(tmp_path):
    import asyncio
    import threading
    from unrest_harness.experimental_cohort import controller_io
    started, release = threading.Event(), threading.Event()
    def mutate():
        started.set()
        assert release.wait(2)
        (tmp_path / 'finished').write_text('durable result')
    task = asyncio.create_task(controller_io(mutate))
    while not started.is_set():
        await asyncio.sleep(.001)
    task.cancel()
    await asyncio.sleep(.01)
    assert not task.done()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (tmp_path / 'finished').read_text() == 'durable result'


@pytest.mark.parametrize('stage', ['reserved', 'sent', 'acked'])
def test_recovery_consumes_every_uncertain_boundary(tmp_path, stage):
    state = model.admit((model.LaneSpec(id='z', writes=('a',), targets=('VAL-A',)),),
                        base='a' * 40, clean=True, isolated_dispatch=True,
                        config=model.Config(enabled=True)).state
    state = model.reserve_next(state)
    if stage in ('sent', 'acked'):
        state = model.transmission(state, 'z', 0, 'sent')
    if stage == 'acked':
        state = model.transmission(state, 'z', 0, 'acked')
    path = tmp_path / 'state.json'
    with path.open('w') as stream:
        json.dump({'model': state.model_dump(mode='json'), 'outcome': 'running'}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    observed = recovered_status(path)
    assert observed['outcome'] == 'attention' and observed['resumable'] is False
    assert observed['model']['lanes'][0]['turns'][0]['status'] == 'uncertain'
    assert observed['model']['lanes'][0]['targets'] == ['VAL-A']


@pytest.mark.parametrize('substitution', ['writes', 'targets', 'resource', 'permissions'])
def test_combined_candidate_authority_seal_refuses_substitution(tmp_path, substitution):
    from dataclasses import replace
    custody, broker, _ = custody_setup(tmp_path)
    owned = tmp_path / 'owned'
    owned.mkdir(mode=0o700)
    admission = ResourceAdmission({'z': (
        Access(Resource.path(custody.root), 'write', 'candidate'),
        Access(Resource.path(custody.broker_root), 'write', 'broker'),
        Access(Resource.path(owned), 'write', 'owned'))})
    custody.bind_resources(admission.digest)
    before = custody.record.read_bytes()
    try:
        if substitution == 'writes':
            custody.writes = ('b',)
        elif substitution == 'targets':
            custody.manifest = replace(custody.manifest, targets=('VAL-B',))
        elif substitution == 'resource':
            admission.lanes['z'] = (*admission.lanes['z'][:-1],
                                   Access(Resource.path(owned), 'read', 'owned'))
        else:
            owned.chmod(0o755)
        with pytest.raises(LeaseRefused):
            assert custody.resource_digest == admission.digest
            custody.verify()
        assert custody.record.read_bytes() == before
    finally:
        broker.close()


@pytest.mark.parametrize('attack', ['stale', 'early-session', 'early-generation',
                                  'repeated-session', 'dissent'])
async def test_final_gate_rejects_stale_reused_and_dissent(tmp_path, monkeypatch, attack):
    from dataclasses import replace
    from unrest_harness.experimental_session import _SessionOwner
    original = _SessionOwner.turn
    early = []
    finals = []
    async def turn(self, name, **kwargs):
        if kwargs.get('final') and attack == 'dissent':
            kwargs['instruction'] = 'fixture:' + json.dumps({'expected': {'lane_a.txt': 'wrong'}})
        result = await original(self, name, **kwargs)
        if not kwargs.get('final'):
            early.append(result)
            return result
        if attack == 'stale':
            result = replace(result, sealed_candidate='0' * 64)
        elif attack == 'early-session':
            result = replace(result, identity=replace(result.identity, session=early[0].identity.session))
        elif attack == 'early-generation':
            result = replace(result, identity=replace(result.identity,
                             process_generation=early[0].identity.process_generation))
        elif attack == 'repeated-session' and finals:
            result = replace(result, identity=replace(result.identity, session=finals[0].identity.session))
        finals.append(result)
        return result
    monkeypatch.setattr(_SessionOwner, 'turn', turn)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P1',), transport=controlled_transport())
    assert result['episodes']['P1']['outcome'] == 'attention'
    assert result['episodes']['P1']['reason'] == 'fresh_final_gate_failed'
    data = json.loads((root / 'P1/state.json').read_text())
    assert len(data['final']) == (2 if attack == 'repeated-session' else 1)
    reserved = sum(json.loads(row)['event'] == 'reserve'
                   for row in (root / 'campaign.jsonl').read_text().splitlines())
    assert data['turns_consumed'] == result['episodes']['P1']['turns_consumed'] == reserved
    assert recovered_status(root / 'P1/state.json')['turns_consumed'] == reserved
    if attack == 'dissent':
        assert data['final'][0]['verdicts'] == [['VAL-A', False]]


async def test_failed_final_transport_keeps_consumed_budget(tmp_path, monkeypatch):
    from unrest_harness.experimental_session import _SessionOwner
    original = _SessionOwner.turn
    async def turn(self, name, **kwargs):
        if kwargs.get('final'):
            kwargs['scenario'] = 'missing_completion'
        return await original(self, name, **kwargs)
    monkeypatch.setattr(_SessionOwner, 'turn', turn)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P1',), transport=controlled_transport())
    assert result['episodes']['P1']['outcome'] == 'attention'
    journal = [json.loads(row) for row in (root / 'campaign.jsonl').read_text().splitlines()]
    assert sum(row['event'] == 'reserve' for row in journal) == 3
    data = json.loads((root / 'P1/state.json').read_text())
    assert not data['final']
    assert data['turns_consumed'] == result['episodes']['P1']['turns_consumed'] == 3
    assert data['final_turns_consumed'] == 1
    status = recovered_status(root / 'P1/state.json')
    assert status['turns_consumed'] == status['campaign_turns_consumed'] == 3
    assert status['resumable'] is False


@pytest.mark.parametrize('capacity,parking', [(1, 2), (2, 2), (4, 4), (8, 4)])
async def test_runtime_capacity_parking_and_correction_priority(tmp_path, monkeypatch, capacity, parking):
    from unrest_harness.experimental_cohort import Coordinator
    from unrest_harness.experimental_lease import PilotLedger
    original = Coordinator.__init__
    def initialize(self, *args, **kwargs):
        kwargs['config'] = model.Config(**{**kwargs['config'].model_dump(),
                                          'capacity': capacity, 'parking_capacity': parking})
        original(self, *args, **kwargs)
    monkeypatch.setattr(Coordinator, '__init__', initialize)
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 10)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',), controlled_rounds=2,
                            controlled_timing=((0, 1), (1, 0)), transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == 'passed'
    data = json.loads((root / 'C1/state.json').read_text())
    check_scheduling_events(data, streaming=True, capacity=min(capacity, 4))
    reservations = [e for e in data['events'] if e['event'] == 'reservation']
    assert {e['phase'] for e in reservations} == {'work', 'validate', 'correction', 'recheck'}
    assert all(e['parking_reserved'] <= parking for e in data['events'])
    assert reservations[0]['lane'] == 'z-first' and reservations[0]['parking_reserved'] == 2
    if capacity == 1:
        assert [e['lane'] for e in reservations[:4]] == ['z-first'] * 4


@pytest.mark.parametrize('boundary', ['reservation', 'dispatch', 'completion'])
async def test_stop_boundaries_preserve_consumption_and_no_new_sends(tmp_path, monkeypatch, boundary):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator._event
    def event(self, name, lane, **fields):
        original(self, name, lane, **fields)
        if name == boundary:
            (self.root / 'stop-request').touch()
    monkeypatch.setattr(Coordinator, '_event', event)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P1',), transport=controlled_transport())
    assert result['episodes']['P1']['outcome'] == 'attention'
    data = json.loads((root / 'P1/state.json').read_text())
    assert len(data['model']['lanes'][0]['turns']) == 1
    assert sum(e['event'] == 'prompt_sent' for e in data['events']) == (1 if boundary == 'completion' else 0)
    assert not data['final'] and data['integrated'] is None


async def test_runtime_budget_before_recheck_retains_dissent(tmp_path, monkeypatch):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator.__init__
    def initialize(self, *args, **kwargs):
        kwargs['config'] = model.Config(**{**kwargs['config'].model_dump(), 'turn_budget': 5})
        original(self, *args, **kwargs)
    monkeypatch.setattr(Coordinator, '__init__', initialize)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('P2',), transport=controlled_transport())
    assert result['episodes']['P2']['outcome'] == 'attention'
    data = json.loads((root / 'P2/state.json').read_text())
    assert data['model']['halt'] == 'budget'
    assert len(data['completions']) == 3
    assert data['completions'][1]['verdicts'] == [['VAL-A', False]]
    assert data['model']['lanes'][0]['correction_reserved'] is True
    assert data['integrated'] is None and not data['final']


@pytest.mark.parametrize('attack', ['outside-scope', 'base', 'staged-conflict', 'overlap'])
def test_integration_scope_and_conflict_negatives(tmp_path, attack):
    custody, broker, identity = custody_setup(tmp_path)
    destination = tmp_path / 'integration'
    shutil.copytree(custody.root, destination)
    base = custody.manifest
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        digest = broker.replace(token, identity, 'a', 'A\n')
        custody.seal(broker, broker.complete(token, identity, digest, 'sealed'))
        if attack == 'outside-scope':
            (custody.root / 'b').write_text('unauthorized\n')
            git(custody.root, 'add', 'b')
            git(custody.root, 'commit', '-m', 'unauthorized')
        elif attack == 'base':
            (destination / 'b').write_text('different-base\n')
            git(destination, 'add', 'b')
            git(destination, 'commit', '-m', 'different base')
        elif attack == 'staged-conflict':
            (destination / 'a').write_text('conflict\n')
            git(destination, 'add', 'a')
        with pytest.raises((LeaseRefused, CandidateInputError)):
            integrate(destination, base, (custody, custody) if attack == 'overlap' else (custody,))
        assert git(destination, 'show', 'HEAD:a') == 'base'
    finally:
        broker.close()


def test_active_broker_mutation_prevents_candidate_validation_seal(tmp_path):
    from dataclasses import replace
    custody, broker, identity = custody_setup(tmp_path)
    try:
        token = broker.grant(identity, deadline=time.monotonic() + 30)
        completion = broker.complete(token, identity, identity.candidate, 'sealed')
        broker.grant(replace(identity, ordinal=2), deadline=time.monotonic() + 30)
        before = custody.record.read_bytes()
        with pytest.raises(LeaseRefused, match='mutation_not_drained'):
            custody.seal(broker, completion)
        assert custody.record.read_bytes() == before
    finally:
        broker.close()


@pytest.mark.parametrize('first', ['z-first', 'a-second'])
async def test_stop_after_sibling_pass_drains_and_retains_both_verdicts(tmp_path, monkeypatch, first):
    from unrest_harness.experimental_cohort import Coordinator
    original = Coordinator._event
    def event(self, name, lane, **fields):
        original(self, name, lane, **fields)
        if name == 'consumed' and lane == first and fields.get('outcome') == 'pass':
            (self.root / 'stop-request').touch()
    monkeypatch.setattr(Coordinator, '_event', event)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',),
                            controlled_timing=((0, 0), (8, 10) if first == 'z-first' else (10, 2)), transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == 'attention'
    data = json.loads((root / 'C1/state.json').read_text())
    assert [lane['phase'] for lane in data['model']['lanes']] == ['passed', 'passed']
    assert len(data['completions']) == 4
    assert not data['final'] and data['integrated'] is None
    assert [c['verdicts'] for c in data['completions'] if c['identity']['role'] == 'validator']


async def test_actual_completion_batches_use_authored_ties_in_every_phase(tmp_path, monkeypatch):
    import asyncio
    from unrest_harness.experimental_lease import PilotLedger
    original = asyncio.wait
    async def batch(tasks, **kwargs):
        values = tuple(tasks)
        if len(values) == 2 and all(getattr(t.get_coro(), '__name__', '') == '_turn' for t in values):
            return await original(values, timeout=60, return_when=asyncio.ALL_COMPLETED)
        return await original(values, **kwargs)
    monkeypatch.setattr(asyncio, 'wait', batch)
    monkeypatch.setitem(PilotLedger.maxima, 'C1', 10)
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=ADAPTER, fixture=FIXTURE,
                            package=None, episodes=('C1',), controlled_rounds=2,
                            controlled_timing=((0, 0), (0, 0)), transport=controlled_transport())
    assert result['episodes']['C1']['outcome'] == 'passed'
    data = json.loads((root / 'C1/state.json').read_text())
    check_scheduling_events(data, streaming=True)
    consumed = [e['lane'] for e in data['events'] if e['event'] == 'consumed']
    assert consumed == ['z-first', 'a-second'] * 4
