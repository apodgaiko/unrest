"""Explicit disposable trusted-process coordinator; ordinary dispatch is unchanged.

Run with ``python -m unrest_harness.experimental_cohort``. One invocation owns
one event loop and one durable campaign ledger for all selected episodes.
Disabled by default. Genuine native approval, ACP live reuse and final-candidate
timing are UNVERIFIED; controlled local results prove bounded local behavior.
"""
from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
from typing import Literal

from . import experimental_model as model
from .capability_policy import (
    ResolvedRoleCapability, SAFE_PROFILE, load_capability_policy, resolve_role_capability,
)
from .experimental_candidate import CandidateManifest, observe_candidate_inputs, verify_candidate_inputs
from .experimental_custody import Custody, flat_digest, git, integrate, recover_sealed, write_record
from .experimental_lease import Completion, LeaseRefused, PilotLedger, REAL_PROVIDER
from .experimental_provider import check_package
from .experimental_provider_config import ProviderConfig
from .experimental_resources import Access, Resource, ResourceAdmission
from .experimental_diagnostics import StartupDiagnostics, category
from .experimental_session import ControlledTransport, verify_transport, _SessionOwner, check_pin, FIXTURE_SHA256
from .providers import PROVIDERS


LIMITATIONS = {
    'trusted_process': True, 'os_write_isolation': 'unverified',
    'unknown_descendant_cleanup': 'unverified', 'transient_write_detection': 'unverified',
    'broker_authority': 'turn_bound', 'cleanup': 'owned_handles_only',
    'live_acceptance': 'unverified', 'benefit': 'unmeasured',
    'native_approval': 'unverified', 'final_candidate_timing': 'unverified',
    'enabled_by_default': False,
}


async def controller_io[T](operation: Callable[..., T], *arguments: object) -> T:
    """Retain filesystem work through cancellation; thread cancellation cannot stop Git."""
    task = asyncio.create_task(asyncio.to_thread(operation, *arguments))
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result


@dataclass(frozen=True)
class ProviderSetup:
    adapter: Path
    backend: Path
    policy: ResolvedRoleCapability
    controlled: bool
    package: Path | None = None
    configuration: ProviderConfig | None = None
    transport: ControlledTransport | None = None

    def __post_init__(self) -> None:
        if self.transport is not None:
            verify_transport(self.transport, controlled=self.controlled,
                             package=self.package, adapter=self.adapter)


class Coordinator:
    """Drive the passed model using real retained ACP/MCP completion records.

    Model reservations persist before transport work. Real identities are kept
    separately from symbolic model identities; neither substitutes for the other.
    A new process may inspect or invalidate state, but never resume old sessions.
    """

    def __init__(self, root: Path, lanes: tuple[tuple[str, Custody], ...], *,
                 destination: Path, base: CandidateManifest, resources: ResourceAdmission,
                 ledger: PilotLedger, provider: ProviderSetup, trusted_process: bool = False,
                 config: model.Config = model.Config()):
        if not trusted_process:
            raise LeaseRefused('trusted_process_opt_in_required')
        if not provider.controlled and (provider.configuration is None
                or resources.common is not provider.configuration.inputs):
            raise LeaseRefused('provider_common_inputs_required')
        if not 1 <= len(lanes) <= 2 or tuple(resources.lanes) != tuple(name for name, _ in lanes):
            raise LeaseRefused('resource_lane_binding')
        for name, custody in lanes:
            bound = {a.purpose: a.resource.identity for a in resources.lanes[name]
                     if a.purpose in ('candidate', 'broker', 'owned')}
            if (bound['candidate'] != str(custody.root) or bound['broker'] != str(custody.broker_root)
                    or bound['owned'] != str(root / name)):
                raise LeaseRefused('resource_custody_binding')
            custody.verify()
            custody.bind_resources(resources.digest)
        verify_candidate_inputs(destination, base)
        admission = model.admit(tuple(model.LaneSpec(id=name, writes=c.writes,
                                                    targets=c.manifest.targets)
                                      for name, c in lanes),
                                base=base.candidate_commit_oid, clean=True,
                                isolated_dispatch=True, config=config)
        if admission.state is None:
            raise LeaseRefused('model_admission_' + str(admission.reason))
        self.root, self.lanes = root, dict(lanes)
        self.destination, self.base = destination, base
        self.resources, self.ledger, self.provider = resources, ledger, provider
        self.state = admission.state
        self.owners: dict[str, _SessionOwner] = {}
        self.all_owners: list[_SessionOwner] = []
        self.events: list[dict[str, object]] = []
        self.completions: list[Completion] = []
        self.final: list[Completion] = []
        self.integrated: CandidateManifest | None = None
        self.started = time.monotonic()
        self.outcome = 'running'
        self.reason: str | None = None
        self.failure_diagnostics = StartupDiagnostics()
        self.cleanup_errors: list[dict[str, str]] = []
        self.persistence_failed = False
        self.observation_locks = {name: asyncio.Lock() for name in self.lanes}
        self._persist()

    def _persist(self) -> None:
        try:
            self._write_state()
        except Exception:
            self.persistence_failed = True
            raise

    def _write_state(self) -> None:
        write_record(self.root / 'state.json', {
            'schema': 'experimental-cohort.v1', 'model': self.state.model_dump(mode='json'),
            'outcome': self.outcome, 'reason': self.reason, 'limits': LIMITATIONS,
            'cleanup_errors': self.cleanup_errors, 'persistence_failed': self.persistence_failed,
            'diagnostics': self._diagnostics(),
            'unconsumed_completions': [asdict(owner.last_completion) for owner in self.all_owners
                if owner.last_completion is not None and owner.last_completion not in self.completions],
            'candidates': {name: c.manifest.digest for name, c in self.lanes.items()},
            'authority_seals': {name: c.authority_digest for name, c in self.lanes.items()},
            'events': self.events,
            'completions': [asdict(c) for c in self.completions],
            'final': [asdict(c) for c in self.final],
            'integrated': None if self.integrated is None else self.integrated.digest,
            'capacity': min(self.state.config.capacity, 4),
            'active': self.state.active_count, 'parked': self.state.parked_count,
            **self._accounting(), 'turn_limit': self.state.config.turn_budget,
            'controlled': self.provider.controlled,
            'provider_configuration': [
                {**owner.provider_config.evidence(owner.root / role),
                 'effective_config_sha256': owner.provider_config.effective_digests.get(str(owner.root / role)),
                 'served_identity': (owner.thread_observations[role].served
                                     if role in owner.thread_observations else None)}
                for owner in self.all_owners if owner.provider_config is not None
                for role in sorted(owner.roles)],
        })

    def _accounting(self) -> dict[str, int]:
        usage = self.ledger.accounting()
        # A model reservation may precede process construction and the journal's
        # turn reservation. Neither that gap nor failed finals grants a refund.
        consumed = max(self.state.turn_count + usage['final'], usage['episode'])
        return {'turns_consumed': consumed, 'final_turns_consumed': usage['final'],
                'campaign_turns_consumed': usage['campaign'] + consumed - usage['episode']}

    def _sending_final(self) -> None:
        self._assert_send_allowed()
        self._persist()  # Reservation accounting only; this is not send evidence.

    def _event(self, name: str, lane: str, **fields: object) -> None:
        self.events.append({'event': name, 'lane': lane,
                            'monotonic_seconds': time.monotonic(),
                            'active': self.state.active_count, 'parked': self.state.parked_count,
                            'parking_reserved': sum(item.parking_reserved for item in self.state.lanes),
                            **fields})
        self._persist()

    def _verify(self) -> None:
        self.resources.verify()
        for name in self.lanes:
            self._verify_lane(name)
        verify_candidate_inputs(self.destination, self.base if self.integrated is None else self.integrated)

    def _verify_resources(self, name: str) -> None:
        self.resources.verify()
        if self.lanes[name].resource_digest != self.resources.digest:
            raise LeaseRefused('candidate_resource_seal_changed')

    def _verify_lane(self, name: str) -> None:
        self._verify_resources(name)
        custody = self.lanes[name]
        custody.verify()
        lane = next(item for item in self.state.lanes if item.spec.id == name)
        if lane.active is None and flat_digest(custody.broker_root, custody.writes) != custody.expected:
            raise LeaseRefused('parked_candidate_changed')

    def _new_owner(self, root: Path, candidate: Path, scope: tuple[str, ...],
                   expected: str, lane: str) -> _SessionOwner:
        owner = _SessionOwner(root, candidate, scope, adapter=self.provider.adapter,
                              fixture=self.provider.backend, policy=self.provider.policy,
                              controlled=self.provider.controlled, ledger=self.ledger,
                              lane=lane, provider_package=self.provider.package,
                              drain_after_halt=True, provider_config=self.provider.configuration,
                              transport=self.provider.transport)
        self.all_owners.append(owner)
        owner.on_failure = lambda error: self._owner_failed(error, owner=owner)
        owner.broker.seal(scope, expected)
        return owner

    def _assert_send_allowed(self) -> None:
        if (self.root / 'stop-request').exists() and not self.state.halted:
            self.state = model.stop(self.state)
            self._halt_owners()
            self._cleanup_call('persist', self._persist)
        if self.state.halted:
            raise LeaseRefused('cohort_dispatch_stopped')

    def _cleanup_error(self, stage: str, error: BaseException) -> None:
        self.outcome = 'attention'
        # Error text from arbitrary I/O may contain private paths or bodies.
        item = {'stage': stage, 'error': category(error)}
        if item not in self.cleanup_errors and len(self.cleanup_errors) < 32:
            self.cleanup_errors.append(item)

    def _cleanup_call(self, stage: str, operation: Callable[[], None]) -> None:
        try:
            operation()
        except Exception as error:
            self._cleanup_error(stage, error)

    def _owner_failed(self, error: BaseException | None, *, owner: _SessionOwner) -> None:
        # Owned cleanup can outlive the run loop's next scan. Preserve its cause
        # before an early halt observation produces generic cohort attention.
        self.outcome = 'attention'
        if error is not None:
            self.failure_diagnostics.phase('coordinator_run')
            self.failure_diagnostics.fail(error)
            self.reason = self.reason or (category(error) if isinstance(error, LeaseRefused)
                else 'cohort_cancelled' if isinstance(error, asyncio.CancelledError)
                else 'cohort_failed')
        if self.ledger.halted_by(owner):
            self._authorize_drain(cause=owner)
        self._halt_owners()

    def _authorize_drain(self, *, cause: _SessionOwner | None = None) -> None:
        # The first halt can occur inside an owned journal operation before its
        # failure callback. Only that operation's retained owner establishes the
        # causal exception; expired lifetimes and closed storage still refuse.
        try:
            self.ledger.lifetime_remaining(drain=(cause is not None
                and cause in self.all_owners and self.ledger.halted_by(cause)))
        except LeaseRefused:
            pass
        else:
            for owner in self.all_owners:
                owner.request_drain()

    def _halt_owners(self) -> None:
        # Revocation and the in-memory stop must not depend on writable storage.
        if not self.state.halted:
            self.state = model.stop(self.state)
        self._authorize_drain()
        for owner in self.all_owners:
            if not owner.sent_active:
                self._cleanup_call('revoke', lambda: owner._revoke(quarantine=False))
        self._cleanup_call('journal_stop', self.ledger.stop)

    async def _drain(self, active: dict[str, asyncio.Task[Completion]]) -> None:
        for name, task in active.items():
            owner = self.owners.get(name)
            if not task.done() and (owner is None or not owner.sent_active):
                task.cancel()
        # Shield the retained gather, not each retry. Repeated cancellation cannot
        # cancel siblings or reset the deadline already owned by their turn.
        pending = asyncio.gather(*active.values(), return_exceptions=True)
        while not pending.done():
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError as error:
                self._cleanup_error('drain', error)
        for name, task in active.items():
            if not task.cancelled() and task.exception() is None:
                self._cleanup_call('consume', lambda: self._consume(name, task.result()))
            elif not task.cancelled():
                failure = task.exception()
                assert failure is not None
                self._cleanup_error('turn', failure)

    def _consume(self, name: str, result: Completion) -> None:
        lane = next(item for item in self.state.lanes if item.spec.id == name)
        ordinal = lane.turns[-1].ordinal
        self.state = model.transmission(self.state, name, ordinal, 'acked')
        outcome: Literal['sealed', 'pass', 'defect', 'other'] = (
            'defect' if result.disposition == 'reproducible_product_defect'
            else 'sealed' if result.disposition == 'sealed'
            else 'pass' if result.disposition == 'pass' else 'other')
        self.state = model.complete(self.state, name, ordinal, outcome)
        if self.state.halted:
            self._halt_owners()
        self._event('consumed', name, ordinal=ordinal, outcome=outcome)

    def _sending(self, lane: str, ordinal: int, phase: str) -> None:
        self._assert_send_allowed()
        self.resources.verify()

    def _sent(self, lane: str, ordinal: int, phase: str) -> None:
        self.state = model.transmission(self.state, lane, ordinal, 'sent')
        self._event('prompt_sent', lane, ordinal=ordinal, phase=phase)

    async def _observe(self, name: str | None = None) -> None:
        # Git object inspection must not block ACP startup/deadline/cleanup tasks.
        # Only the observed candidate's custody is serialized. Observing unrelated
        # Git stores behind one lock would itself erase streaming readiness.
        if name is None:
            await controller_io(self._verify)
        else:
            async with self.observation_locks[name]:
                await controller_io(self._verify_lane, name)

    async def _turn(self, lane: model.Lane, instruction: str) -> Completion:
        try:
            result = await self._run_turn(lane, instruction)
            self.owners[lane.spec.id].complete_turn()
            return result
        except BaseException as error:
            owner = self.owners.get(lane.spec.id)
            if owner is not None:
                owner.failure = owner.failure or error
                owner._revoke(quarantine=True)
            raise
        finally:
            owner = self.owners.get(lane.spec.id)
            if owner is not None:
                owner.sent_active = False

    async def _run_turn(self, lane: model.Lane, instruction: str) -> Completion:
        custody = self.lanes[lane.spec.id]
        turn = lane.turns[-1]
        role: Literal['worker', 'validator'] = (
            'worker' if turn.phase in ('work', 'correction') else 'validator')
        owner = self.owners.get(lane.spec.id)
        if owner is None:
            owner = self._new_owner(
                self.root / lane.spec.id / f'turn-{turn.ordinal}', custody.broker_root,
                custody.writes, custody.expected, lane.spec.id)
            self.owners[lane.spec.id] = owner
            await owner.start()
        await self._observe(lane.spec.id)
        owner.broker.verify(custody.writes)
        self._event('dispatch', lane.spec.id, ordinal=turn.ordinal, phase=turn.phase,
                    candidate=custody.manifest.digest)
        if not self.provider.controlled:
            instruction += '\nDeclared read-only inputs and targets: ' + await controller_io(custody.context)
        result = await owner.turn(role, instruction=instruction, targets=lane.spec.targets,
            on_send=lambda: self._sending(lane.spec.id, turn.ordinal, turn.phase),
            after_send=lambda: self._sent(lane.spec.id, turn.ordinal, turn.phase))
        self._event('provider_completed', lane.spec.id, ordinal=turn.ordinal, phase=turn.phase,
                    candidate=result.sealed_candidate)
        async with self.observation_locks[lane.spec.id]:
            if role == 'worker':
                await controller_io(self._verify_resources, lane.spec.id)
                # seal performs the complete expected-candidate check immediately
                # before mutation; repeating it here delays independent readiness.
                await controller_io(custody.seal, owner.broker, result)
            else:
                await controller_io(self._verify_lane, lane.spec.id)
                if (result.sealed_candidate != custody.expected
                        or set(dict(result.verdicts)) != set(lane.spec.targets)):
                    raise LeaseRefused('validation_identity_changed')
        self.completions.append(result)
        self._event('completion', lane.spec.id, ordinal=turn.ordinal, phase=turn.phase,
                    candidate=custody.manifest.digest,
                    process_generation=result.identity.process_generation,
                    session_digest=hashlib.sha256(result.identity.session.encode()).hexdigest(),
                    verdicts=result.verdicts, disposition=result.disposition)
        return result

    async def run(self, instructions: dict[str, tuple[str, ...]],
                  final_instruction: str) -> dict[str, object]:
        active: dict[str, asyncio.Task[Completion]] = {}
        try:
            while not self.state.halted and not all(item.phase == 'passed' for item in self.state.lanes):
                self._assert_send_allowed()
                self.state = model.advance(self.state, int(time.monotonic() - self.started))
                await controller_io(self.resources.verify)
                while not self.state.halted:
                    reserved = model.reserve_next(self.state)
                    if reserved == self.state:
                        break
                    self.state = reserved
                    self._persist()
                    if self.state.halted:
                        self._halt_owners()
                        break
                    newly = next(item for item in self.state.lanes if item.active is not None
                                 and item.spec.id not in active)
                    ordinal = newly.turns[-1].ordinal
                    self._event('reservation', newly.spec.id, ordinal=ordinal,
                                phase=newly.phase, candidate=self.lanes[newly.spec.id].manifest.digest)
                    values = instructions[newly.spec.id]
                    if ordinal >= len(values) or not values[ordinal].strip():
                        raise LeaseRefused('missing_turn_instruction')
                    active[newly.spec.id] = asyncio.create_task(self._turn(newly, values[ordinal]))
                if not active:
                    if self.state.halted:
                        raise LeaseRefused('cohort_' + str(self.state.halt or 'attention'))
                    raise LeaseRefused('cohort_no_progress')
                await asyncio.wait(active.values(), timeout=.05, return_when=asyncio.FIRST_COMPLETED)
                # Completion ties follow authored order. Waiting tasks are never preempted.
                for name in tuple(self.lanes):
                    task = active.get(name)
                    if task is None or not task.done():
                        continue
                    del active[name]
                    result = task.result()
                    lane = next(item for item in self.state.lanes if item.spec.id == name)
                    self._consume(name, result)
                    after = next(item for item in self.state.lanes if item.spec.id == name)
                    if (not after.reuse_owner or after.generation != lane.generation
                            or after.phase in ('passed', 'attention') or after.generation == 1):
                        await self.owners.pop(name).close()
                    self._persist()
            if self.state.halted:
                raise LeaseRefused('cohort_attention')
            self._assert_send_allowed()
            await self._observe()
            self.integrated = await controller_io(
                integrate, self.destination, self.base, tuple(self.lanes.values()))
            self._event('integrated', '', candidate=self.integrated.digest)
            await self._finalize(final_instruction)
            self.outcome = 'passed'
        except (Exception, asyncio.CancelledError) as exc:
            self.outcome = 'attention'
            self.failure_diagnostics.phase('coordinator_run')
            self.failure_diagnostics.fail(exc)
            self.reason = self.reason or (category(exc) if isinstance(exc, LeaseRefused)
                                          else 'cohort_cancelled' if isinstance(exc, asyncio.CancelledError)
                                          else 'cohort_failed')
            self._halt_owners()
            self._cleanup_call('persist', self._persist)
            await self._drain(active)
            self.state = model.restart(self.state)
        finally:
            for owner in self.all_owners:
                try:
                    await owner.close()
                except (Exception, asyncio.CancelledError) as error:
                    self._cleanup_error('close', error)
                    self.reason = self.reason or 'owned_cleanup_unverified'
            self._cleanup_call('persist', self._persist)
            if self.persistence_failed:
                self.outcome = 'attention'
                self.reason = self.reason or 'cohort_persistence_failed'
        return self.status()

    async def _finalize(self, instruction: str) -> None:
        assert self.integrated is not None
        targets = tuple(sorted({t for c in self.lanes.values() for t in c.manifest.targets}))
        scope = tuple(sorted(f.path for f in (*self.integrated.tracked_inputs,
                                             *self.integrated.extra_inputs)))
        sessions = {c.identity.session for c in self.completions}
        generations = {c.identity.process_generation for c in self.completions}
        for index in range(2):
            await self._observe()
            candidate = self.root / f'final-input-{index}'
            candidate.mkdir(mode=0o700)
            for name in scope:
                (candidate / name).write_bytes((self.destination / name).read_bytes())
            expected = flat_digest(candidate, scope)
            owner = self._new_owner(self.root / f'final-owner-{index}', candidate, scope,
                                    expected, f'final-{index}')
            await owner.start()
            result = await owner.turn('validator', instruction=instruction, targets=targets, final=True,
                                      on_send=self._sending_final)
            self.final.append(result)
            await self._observe()
            if (result.identity.session in sessions
                    or result.identity.process_generation in generations
                    or result.sealed_candidate != expected
                    or result.disposition != 'pass' or dict(result.verdicts) != dict.fromkeys(targets, True)):
                raise LeaseRefused('fresh_final_gate_failed')
            sessions.add(result.identity.session)
            generations.add(result.identity.process_generation)
            await owner.close()
            self._event('final', f'final-{index}', candidate=self.integrated.digest,
                        verdicts=result.verdicts, process_generation=result.identity.process_generation)

    def _diagnostics(self) -> dict[str, object]:
        return {'coordinator': self.failure_diagnostics.snapshot(),
                'owners': [owner.diagnostics() for owner in self.all_owners]}

    def status(self) -> dict[str, object]:
        return {'outcome': self.outcome, 'reason': self.reason, **LIMITATIONS,
                'diagnostics': self._diagnostics(),
                'cleanup_errors': self.cleanup_errors, 'persistence_failed': self.persistence_failed,
                'candidate': None if self.integrated is None else self.integrated.digest,
                'active': self.state.active_count, 'parked': self.state.parked_count,
                **self._accounting(),
                'capacity': min(self.state.config.capacity, 4),
                'lanes': [{'id': item.spec.id, 'generation': item.generation, 'phase': item.phase,
                           'reuse_eligible': (not self.state.halted and item.reuse_owner
                                              and item.generation == 0),
                           'reuse_refusal': item.blocking, 'candidate': self.lanes[item.spec.id].manifest.digest}
                          for item in self.state.lanes]}


def recovered_status(path: Path) -> dict[str, object]:
    """Read-only recovery projection consumes reservations, never resurrects owners."""
    data = json.loads(path.read_text())
    state = model.load_state(json.dumps(data['model']))
    return {'outcome': data['outcome'] if data['outcome'] != 'running' else 'attention',
            'resumable': False, 'model': json.loads(model.projection(state)),
            'accounting': 'last_persisted_snapshot',
            **{key: data.get(key) for key in (
                'turns_consumed', 'final_turns_consumed', 'campaign_turns_consumed')}, **LIMITATIONS}


async def campaign(root: Path, *, trusted_process: bool, adapter: Path,
                   fixture: Path | None, package: Path | None,
                   episodes: tuple[str, ...] = ('P1', 'P2', 'P3', 'C1'),
                   streaming: bool = True, reuse: bool = True,
                   controlled_timing: tuple[tuple[int, int], tuple[int, int]] | None = None,
                   controlled_rounds: int | None = None,
                   controlled_terminal_defect: bool = False,
                   transport: ControlledTransport | None = None) -> dict[str, object]:
    if not trusted_process:
        raise LeaseRefused('trusted_process_opt_in_required')
    if (fixture is None) == (package is None):
        raise LeaseRefused('explicit_provider_selection_required')
    if (controlled_timing is not None or controlled_rounds is not None
            or controlled_terminal_defect) and fixture is None:
        raise LeaseRefused('controlled_override_on_real_provider')
    if controlled_rounds is not None and controlled_rounds not in (1, 2, 3):
        raise LeaseRefused('controlled_rounds_invalid')
    backend = check_package(package) if fixture is None else fixture
    configuration = None
    if fixture is None:
        user_home = Path(os.environ.get('HOME', str(Path.home())))
        configuration = ProviderConfig(
            codex_home=Path(os.environ.get('CODEX_HOME', str(user_home / '.codex'))),
            user_home=user_home, cwd=root,
            ambient=json.loads(os.environ.get('CODEX_CONFIG', '{}')))
    if fixture is not None:
        check_pin(fixture, FIXTURE_SHA256)
    verify_transport(transport, controlled=fixture is not None, package=package, adapter=adapter)
    if not episodes or len(set(episodes)) != len(episodes) or not set(episodes) <= set(PilotLedger.maxima):
        raise LeaseRefused('invalid_episodes')
    root.mkdir(mode=0o700)
    ledger = PilotLedger(root / 'campaign.jsonl', provider=(
        'local-controlled-only' if fixture is not None else REAL_PROVIDER))
    results: dict[str, object] = {}
    try:
        for episode in episodes:
            ledger.admit(episode)
            directory = root / episode
            directory.mkdir()
            original = directory / 'base'
            original.mkdir()
            git(original, 'init', '--initial-branch=main', '--object-format=sha1')
            for name in ('lane_a.txt', 'lane_b.txt'):
                (original / name).write_text('base\n')
            git(original, 'add', '.')
            git(original, 'commit', '-m', 'base')
            base_oid = git(original, 'rev-parse', 'HEAD')
            destination = directory / 'integration'
            shutil.copytree(original, destination)
            count = 2 if episode == 'C1' else 1
            targets = tuple('VAL-' + letter for letter in ('A', 'B')[:count])
            base = observe_candidate_inputs(destination, base_oid, base_oid, (), (), targets)
            lanes = []
            resources: dict[str, tuple[Access, ...]] = {}
            instructions = {}
            expected_final = {'lane_a.txt': 'A\n', 'lane_b.txt': 'B\n' if count == 2 else 'base\n'}
            rounds = controlled_rounds or {'P1': 1, 'P2': 2, 'P3': 3, 'C1': 1}[episode]
            for index, lane_name in enumerate(('z-first', 'a-second')[:count]):
                letter = ('a', 'b')[index]
                name, correct = f'lane_{letter}.txt', letter.upper() + '\n'
                candidate, broker_root = directory / f'candidate-{index}', directory / f'broker-{index}'
                shutil.copytree(original, candidate)
                owned = directory / lane_name
                owned.mkdir()
                custody = Custody(candidate, broker_root, directory / f'seal-{index}.json',
                                  base=base_oid, commit=base_oid, writes=(name,),
                                  targets=(targets[index],))
                lanes.append((lane_name, custody))
                resources[lane_name] = (Access(Resource.path(candidate), 'write', 'candidate'),
                    Access(Resource.path(broker_root), 'write', 'broker'),
                    Access(Resource.path(owned), 'write', 'owned'))
                turns = []
                for number in range(rounds):
                    body = correct if number == rounds - 1 and not controlled_terminal_defect else 'defective\n'
                    if fixture is not None:
                        turns.append('fixture:' + json.dumps({'writes': {name: body},
                                      'delay': controlled_timing[0][index] if controlled_timing
                                      else 10 if index == 1 else 0}))
                        turns.append('fixture:' + json.dumps({'expected': {name: correct},
                                     'delay': controlled_timing[1][index] if controlled_timing else 0}))
                    else:
                        turns.append(f'Replace {name} with exactly {body!r}; this episode deliberately '
                                     'injects defects until the final generation. Complete the worker turn.')
                        turns.append(f'Check {name} equals exactly {correct!r}. Report a reproducible '
                                     'product defect if unequal, otherwise pass every declared target.')
                instructions[lane_name] = tuple(turns)
            policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
                policy=load_capability_policy(Path(__file__).parent / 'bundled'),
                profile=SAFE_PROFILE, workspace=directory, project_record=directory)
            provider = ProviderSetup(adapter, backend, policy, fixture is not None, package, configuration, transport)
            coordinator = Coordinator(directory, tuple(lanes), destination=destination, base=base,
                resources=ResourceAdmission(resources, common=None if configuration is None
                                             else configuration.inputs), ledger=ledger, provider=provider,
                trusted_process=True, config=model.Config(enabled=True, capacity=2,
                    turn_budget=PilotLedger.maxima[episode], streaming=streaming, reuse=reuse))
            final_instruction = ('fixture:' + json.dumps({'expected': expected_final})
                                 if fixture is not None else
                                 'Check every original target against these exact expected contents: '
                                 + json.dumps(expected_final) + '. Report every target verdict.')
            result = await coordinator.run(instructions, final_instruction)
            results[episode] = result
            if result['outcome'] != 'passed':
                break
            ledger.close_episode()
    finally:
        ledger.close()
    result = {'episodes': results, 'controlled': fixture is not None, **LIMITATIONS}
    try:
        write_record(root / 'campaign-status.json', result)
    except OSError:
        # Reporting failure occurs after owned teardown. Preserve an existing
        # episode cause and never present an unrecorded campaign as success.
        result['persistence_failed'] = True
        last = results[episodes[len(results) - 1]]
        assert isinstance(last, dict)
        last['outcome'] = 'attention'
        last['reason'] = last.get('reason') or 'campaign_status_unavailable'
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    status = commands.add_parser('status', help='read-only; never resumes sessions')
    status.add_argument('--state', type=Path, required=True)
    stop = commands.add_parser('stop', help='stop new dispatch/integration; bounded active turns drain')
    stop.add_argument('--state', type=Path, required=True)
    recover = commands.add_parser('recover', help='copy last seal to a new root; never resumes sessions')
    recover.add_argument('--seal', type=Path, required=True)
    recover.add_argument('--destination', type=Path, required=True)
    run = commands.add_parser('run', help='disposable trusted processes; OS isolation unverified')
    run.add_argument('--root', type=Path, required=True, help='new absolute disposable campaign directory')
    run.add_argument('--trusted-process', action='store_true')
    run.add_argument('--adapter', type=Path, required=True, help='explicit pinned codex-acp entrypoint')
    selection = run.add_mutually_exclusive_group(required=True)
    selection.add_argument('--controlled-fixture', type=Path)
    selection.add_argument('--live-provider-package', type=Path, help='explicit frozen complete Codex package')
    run.add_argument('--episode', choices=tuple(PilotLedger.maxima), action='append')
    run.add_argument('--barrier', action='store_true')
    run.add_argument('--fresh', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'status':
            print(json.dumps(recovered_status(args.state), sort_keys=True))
            return 0
        if args.command == 'stop':
            recovered_status(args.state)
            fd = os.open(args.state.parent / 'stop-request', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.fsync(fd)
            os.close(fd)
            print(json.dumps({'stop_requested': True, 'preemption': False}))
            return 0
        if args.command == 'recover':
            manifest = recover_sealed(args.seal, args.destination)
            print(json.dumps({'candidate': manifest.digest, 'resumable': False}))
            return 0
        result = asyncio.run(campaign(args.root, trusted_process=args.trusted_process,
            adapter=args.adapter, fixture=args.controlled_fixture, package=args.live_provider_package,
            episodes=tuple(args.episode or PilotLedger.maxima), streaming=not args.barrier,
            reuse=not args.fresh))
        print(json.dumps(result, sort_keys=True))
        episodes_result = result['episodes']
        assert isinstance(episodes_result, dict)
        return 0 if all(r['outcome'] == 'passed' for r in episodes_result.values()) else 2
    except (OSError, ValueError) as error:
        reason = str(error) if isinstance(error, LeaseRefused) else 'setup_refused'
        print(json.dumps({'outcome': 'refused', 'reason': reason, **LIMITATIONS}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
