"""Approved local wire setup. Native-adapter execution remains UNVERIFIED."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

import pytest

from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_cohort import ProviderSetup, campaign
from unrest_harness.experimental_custody import Custody
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger, TurnBroker
from unrest_harness.providers import PROVIDERS
from unrest_harness.experimental_session import (
    ControlledTransport, LeaseLane, SyntheticSession, _SessionOwner,
)
from tests.test_experimental_session import (
    test_installed_adapter_two_prompts_and_http_completion as retained_receipts,
    test_roles_correction_and_independent_candidate_scope as correction,
    test_cancel_after_registration_or_during_bridge_keeps_cleanup_owner as cancelled,
    test_cancel_during_registration_retains_handle as delayed,
    test_registration_after_close_deadline_bounded as late,
    test_independent_component_loss_revokes_and_retains_reservations as component_loss,
    test_transport_uncertainty_persists_quarantine_without_cancelling_waiter as uncertainty,
    test_broker_completion_failure_consumes_send as completion_failure,
    test_journal_failure_revokes_without_sending as journal_failure,
    test_budget_expiry_while_parked as expiry,
    test_rotated_tokens_stale_identity_candidate_and_duplicates as identity,
    test_ambient_env_not_imported_and_launcher_pin as native_launcher_refusal,
    test_runtime_pin_rechecked_before_launch as native_runtime_refusal,
)
from tests.test_experimental_bridge_shutdown import (
    test_all_bridges_marked_before_first_adapter_stop as bridge_marking,
)
from tests.test_experimental_cohort import check_scheduling_events
from tests.test_experimental_retained import (
    test_retained_correction_rotation_then_one_shot as rotation,
    test_noncorrectable_real_mcp_never_correction as dissent,
)
from tests.test_experimental_startup_diagnostics import config, PROBE

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / 'tests/fixtures/experimental_session_app_server.py'
LOCAL = ROOT / 'tests/fixtures/controlled_python_acp.py'
NATIVE = Path(shutil.which('codex-acp') or '/missing').resolve()


@pytest.fixture
def transport():
    return ControlledTransport(LOCAL, Path(sys.executable))


@pytest.fixture
def local_session(tmp_path, transport):
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('synthetic\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(ROOT / 'src/unrest_harness/bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    return SyntheticSession(tmp_path / 'owner', candidate, ('a',), adapter=NATIVE,
                            fixture=BACKEND, policy=policy, transport=transport)


@pytest.mark.parametrize('attack', ['noncontrolled', 'package', 'fixture', 'interpreter', 'forged'])
def test_selection_refuses_before_root(local_session, tmp_path, transport, attack):
    values = {'controlled': True, 'provider_package': None, 'transport': transport}
    if attack == 'noncontrolled':
        values['controlled'] = False
    elif attack == 'package':
        values['provider_package'] = tmp_path
    elif attack == 'forged':
        values['transport'] = object()
    else:
        replaced = tmp_path / 'replaced'
        replaced.write_bytes(b'not approved')
        values['transport'] = ControlledTransport(
            replaced if attack == 'fixture' else LOCAL,
            replaced if attack == 'interpreter' else Path(sys.executable))
    root = tmp_path / 'refused'
    with pytest.raises(LeaseRefused):
        _SessionOwner(root, local_session.broker._root, ('a',), adapter=NATIVE,
                      fixture=BACKEND, policy=local_session.policy, **values)
    assert not root.exists()
    local_session.ledger.close()
    local_session.broker.close()


def test_provider_setup_cannot_admit_live_transport(local_session, transport):
    with pytest.raises(LeaseRefused):
        ProviderSetup(NATIVE, BACKEND, local_session.policy, False, transport=transport)
    local_session.ledger.close()
    local_session.broker.close()


@pytest.mark.parametrize('case', ['receipts', 'correction', 'uncertainty', 'completion_failure',
                                 'journal_failure', 'expiry', 'identity', 'bridge_marking'])
async def test_real_local_boundaries(local_session, monkeypatch, case):
    if case == 'receipts':
        await retained_receipts(local_session)
    elif case == 'correction':
        await correction(local_session)
    elif case == 'expiry':
        await expiry(local_session)
    else:
        await {'uncertainty': uncertainty, 'completion_failure': completion_failure,
               'journal_failure': journal_failure, 'identity': identity,
               'bridge_marking': bridge_marking}[case](local_session, monkeypatch)
    assert all(p.returncode is not None for p in (
        *(r.process for r in local_session.roles.values()),
        *(b.process for b in local_session.backends.values())))


@pytest.mark.parametrize('stage', ['backend_registered', 'adapter_registered', 'auth', 'forwarding'])
async def test_cancel_at_actual_boundary(local_session, monkeypatch, stage):
    await cancelled(local_session, monkeypatch, stage)


@pytest.mark.parametrize('number', [1, 2])
@pytest.mark.parametrize('case', ['delayed', 'late'])
async def test_actual_registration(local_session, monkeypatch, number, case):
    await {'delayed': delayed, 'late': late}[case](local_session, monkeypatch, number)


@pytest.mark.parametrize('component', ['backend', 'adapter', 'bridge'])
@pytest.mark.parametrize('active', [False, True])
async def test_actual_component_loss(local_session, monkeypatch, component, active):
    await component_loss(local_session, monkeypatch, component, active)


@pytest.mark.parametrize('case', ['launcher', 'runtime'])
async def test_native_pin_refusal_stays_native(local_session, monkeypatch, tmp_path, case):
    # Omitted selection must check native pins, without launching either child.
    native = SyntheticSession(tmp_path / 'native-owner', local_session.broker._root, ('a',),
                              adapter=NATIVE, fixture=BACKEND, policy=local_session.policy)
    if case == 'launcher':
        await native_launcher_refusal(native, monkeypatch)
    else:
        await native_runtime_refusal(native, monkeypatch, tmp_path)
    assert native.transport is None and not native.roles and not native.backends
    local_session.ledger.close()
    local_session.broker.close()


@pytest.mark.parametrize('disposition', [None, 'conflict', 'missing_authority', 'scope_expansion',
                                       'unknown', 'malformed_handoff'])
async def test_lane_selection_survives_correction_rotation(local_session, tmp_path, transport, disposition):
    candidate = local_session.broker._root
    (candidate / 'a').write_text('base\n')
    (candidate / 'b').write_text('unchanged\n')
    expected = hashlib.sha256(json.dumps([
        (p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(candidate.iterdir())
    ], separators=(',', ':')).encode()).hexdigest()
    ledger = PilotLedger(tmp_path / 'campaign.jsonl')
    ledger.admit('P3')
    def factory(name='lane', **kwargs):
        return LeaseLane(tmp_path / name, candidate, ('a', 'b'), expected_candidate=expected,
            lane=name, adapter=NATIVE, policy=local_session.policy, ledger=ledger,
            trusted_process=True, fixture=BACKEND, transport=transport, **kwargs)
    try:
        if disposition is None:
            await rotation((candidate, ledger, factory))
        else:
            await dissent((candidate, ledger, factory), disposition)
    finally:
        ledger.close()
        local_session.ledger.close()
        local_session.broker.close()


async def test_programmatic_private_preflight(tmp_path, transport, monkeypatch):
    configuration = config(tmp_path)
    environment = _SessionOwner._environment
    def configured_home(owner, home):
        return {**environment(owner, home), 'CODEX_HOME': str(configuration.codex_home)}
    monkeypatch.setattr(_SessionOwner, '_environment', configured_home)
    result = await PROBE(tmp_path / 'probe', NATIVE, None, trusted_process=True,
        fixture=BACKEND, configuration=configuration, transport=transport)
    (tmp_path / 'startup-result.json').write_text(json.dumps(result, sort_keys=True))
    assert result['outcome'] == 'initialized', result
    assert result['owned_reaped'] and result['closed']
    assert result['effective_config_sha256']
    assert result['served_identity'] == {'model': 'gpt-6-astra', 'modelProvider': 'openai',
                                        'reasoningEffort': 'medium'}
    assert result['reservations'] == result['sends'] == result['provider_turns'] == 0
    assert not list((tmp_path / 'probe').rglob('trace.jsonl'))


async def test_single_c1_fixed_timing_protocol_witness(tmp_path, transport, monkeypatch):
    observations, owners = [], []
    complete, finish, seal, start = TurnBroker.complete, PilotLedger.finish, Custody.seal, _SessionOwner.start
    def record(stage, completion):
        identity = completion.identity
        observations.append({'stage': stage, 'lane': identity.lane, 'role': identity.role,
            'ordinal': identity.ordinal, 'candidate': completion.sealed_candidate,
            'at': time.monotonic()})
    def receipt(broker, *args, **kwargs):
        result = complete(broker, *args, **kwargs)
        record('broker_receipt', result)
        return result
    def acknowledged(ledger, ticket, **kwargs):
        owner = ledger._operation_owner
        assert owner.last_completion is not None
        result = finish(ledger, ticket, **kwargs)
        assert ledger._turns[ticket][1] == 'acked'
        record('ledger_ack', owner.last_completion)
        return result
    def sealed(custody, broker, completion):
        result = seal(custody, broker, completion)
        assert custody.record.exists()
        record('sealed_ready', completion)
        return result
    async def started(owner, *args, **kwargs):
        owners.append(owner)
        return await start(owner, *args, **kwargs)
    monkeypatch.setattr(TurnBroker, 'complete', receipt)
    monkeypatch.setattr(PilotLedger, 'finish', acknowledged)
    monkeypatch.setattr(Custody, 'seal', sealed)
    monkeypatch.setattr(_SessionOwner, 'start', started)
    # One witness with original timing; failures must remain for parent attention.
    root = tmp_path / 'campaign'
    result = await campaign(root, trusted_process=True, adapter=NATIVE, fixture=BACKEND,
                            package=None, episodes=('C1',), transport=transport)
    (tmp_path / 'protocol-stages.json').write_text(json.dumps(observations, sort_keys=True))
    assert result['episodes']['C1']['outcome'] == 'passed'
    data = json.loads((root / 'C1/state.json').read_text())
    check_scheduling_events(data, streaming=True)
    events = data['events']
    def stamp(event, lane, phase):
        return next(row['monotonic_seconds'] for row in events
                    if row['event'] == event and row['lane'] == lane and row.get('phase') == phase)
    assert stamp('provider_completed', 'z-first', 'work') < stamp('completion', 'z-first', 'work')
    assert stamp('completion', 'z-first', 'work') < stamp('dispatch', 'z-first', 'validate')
    assert stamp('prompt_sent', 'z-first', 'validate') < stamp('provider_completed', 'a-second', 'work')
    for lane in ('z-first', 'a-second'):
        def stage(name):
            return next(row['at'] for row in observations if row['stage'] == name
                        and row['lane'] == lane and row['role'] == 'worker')
        assert stage('broker_receipt') < stage('ledger_ack') < stage('sealed_ready')
        assert stage('sealed_ready') < stamp('completion', lane, 'work')
        assert stage('sealed_ready') < stamp('dispatch', lane, 'validate')
    assert len(owners) == 5  # retained first lane, fresh second roles, fresh final pair
    assert all(owner.transport is transport for owner in owners)
    assert all(process.returncode is not None for owner in owners for process in (
        *(r.process for r in owner.roles.values()), *(b.process for b in owner.backends.values())))
    assert len(data['completions']) == 4 and len(data['final']) == 2
    early = {row['identity']['process_generation'] for row in data['completions']}
    final = {row['identity']['process_generation'] for row in data['final']}
    assert not early & final and len(final) == 2
    assert all(row['verdicts'] for row in data['final'])
    assert (root / 'C1/integration/lane_a.txt').read_bytes() == b'A\n'
    assert (root / 'C1/integration/lane_b.txt').read_bytes() == b'B\n'


@pytest.mark.parametrize('which', ['fixture', 'interpreter'])
async def test_selected_pin_rechecked_before_any_registration(local_session, tmp_path, transport, which):
    original = LOCAL if which == 'fixture' else Path(sys.executable)
    copied = tmp_path / which
    copied.write_bytes(original.read_bytes())
    selected = ControlledTransport(copied if which == 'fixture' else LOCAL,
                                   copied if which == 'interpreter' else Path(sys.executable))
    local_session.transport = selected
    copied.write_bytes(b'mutated after selection')
    await local_session.start()
    with pytest.raises(LeaseRefused):
        await local_session.turn('worker')
    assert not local_session.roles and not local_session.backends
    assert not (local_session.root / 'worker').exists()
    assert local_session.last_completion is None


@pytest.mark.parametrize('boundary', ['write', 'fsync'])
@pytest.mark.parametrize('corrective_failure', [False, True])
async def test_actual_receipt_then_journal_io_failure(local_session, monkeypatch,
                                                     boundary, corrective_failure):
    import os
    # Coordinator owners preserve the primary error while retaining cleanup faults.
    local_session.drain_after_halt = True
    ledger = local_session.ledger
    append, write, fsync = ledger._append, os.write, os.fsync
    current = [None]
    observed = []
    def appending(event, fields):
        current[0] = event
        try:
            return append(event, fields)
        finally:
            current[0] = None
    def inject(stage, fd):
        if fd != ledger._fd:
            return
        if (current[0] == 'ack' and stage == boundary
                or current[0] == 'uncertain' and corrective_failure and stage == boundary):
            completion = local_session.last_completion
            assert completion is not None
            assert local_session.broker.completion(completion.identity) == completion
            assert not local_session._acknowledged
            observed.append(current[0])
            raise OSError('controlled journal I/O failure')
    def writing(fd, data):
        inject('write', fd)
        return write(fd, data)
    def syncing(fd):
        inject('fsync', fd)
        return fsync(fd)
    monkeypatch.setattr(ledger, '_append', appending)
    monkeypatch.setattr(os, 'write', writing)
    monkeypatch.setattr(os, 'fsync', syncing)
    await local_session.start()
    with pytest.raises(LeaseRefused, match='journal_unavailable') as failure:
        await local_session.turn('worker')
    assert local_session.failure is failure.value
    assert local_session.last_completion is not None and not local_session._acknowledged
    assert local_session.stopped and local_session.quarantined
    assert observed == ['ack', 'uncertain'] if corrective_failure else observed == ['ack']
    assert len(ledger._turns) == 1 and ledger.accounting()['campaign'] == 1
    assert next(iter(ledger._turns.values()))[1] == ('sent' if corrective_failure else 'uncertain')
    assert (local_session.root / 'quarantine').exists()
    assert all(child.returncode is not None for child in (
        *(r.process for r in local_session.roles.values()),
        *(b.process for b in local_session.backends.values())))
