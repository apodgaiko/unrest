"""Controlled retained-session and real construction readiness CLI; no model calls.

Strong OS isolation is unverified. Requires explicit trusted-process opt-in.
Real Codex construction is exposed by experimental_session.LeaseLane for the
independent pilot owner; this probe never substitutes for live acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import sys

from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_lease import LeaseRefused, PilotLedger, REAL_PROVIDER, require_provider
from unrest_harness.experimental_session import LeaseLane
from unrest_harness.providers import PROVIDERS


async def run(root: Path, episode: str, *, trusted_process: bool,
              disposition: str = 'reproducible_product_defect') -> dict[str, object]:
    if not trusted_process:
        require_provider('codex')
    root.mkdir(mode=0o700)
    candidate = root / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    (candidate / 'b').write_text('unchanged\n')
    expected = hashlib.sha256(json.dumps([
        (p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(candidate.iterdir())
    ], separators=(',', ':')).encode()).hexdigest()
    source = Path(__file__).resolve().parents[1]
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
                                    policy=load_capability_policy(source / 'src/unrest_harness/bundled'),
                                    profile=SAFE_PROFILE, workspace=candidate, project_record=root)
    adapter = Path(shutil.which('codex-acp') or '/missing-codex-acp').resolve()
    fixture = source / 'tests/fixtures/experimental_session_app_server.py'
    ledger = PilotLedger(root / 'campaign.jsonl')
    lanes: list[LeaseLane] = []
    results = []
    outcome = 'passed'
    try:
        ledger.admit(episode)
        lane = LeaseLane(root / 'lane', candidate, ('a', 'b'), expected_candidate=expected,
                         lane='a', adapter=adapter, policy=policy, ledger=ledger,
                         trusted_process=trusted_process, fixture=fixture)
        lanes.append(lane)
        rounds = {'P1': 1, 'P2': 2, 'P3': 3}[episode]
        for index in range(rounds):
            for role in ('worker', 'validator'):
                result = await lane.turn(role, 'produce_corrected' if index == rounds - 1 else 'fixture',
                    controlled_disposition=('sealed' if role == 'worker' else
                                            'pass' if index == rounds - 1 else disposition))
                results.append(asdict(result))
        for index in range(2):
            final = LeaseLane(root / f'final-{index}', candidate, ('a', 'b'),
                              expected_candidate=lane.expected, lane=f'final-{index}',
                              adapter=adapter, policy=policy, ledger=ledger,
                              trusted_process=trusted_process, fixture=fixture, final=True)
            lanes.append(final)
            results.append(asdict(await final.turn('validator', 'Check every declared input.')))
        ledger.close_episode()
        assert (candidate / 'a').read_bytes() == b'corrected\n'
        assert (candidate / 'b').read_bytes() == b'unchanged\n'
    except LeaseRefused:
        outcome = 'attention'
    finally:
        for lane in lanes:
            try:
                await lane.close()
            except LeaseRefused:
                outcome = 'attention'
        ledger.close()
    return {'outcome': outcome, 'episode': episode, 'controlled': True, 'provider_turns': 0,
            'os_write_isolation': 'unverified', 'live_acceptance': 'unverified',
            'completions': results, 'lanes': [lane.status() for lane in lanes],
            'owned_reaped': all(
                process.returncode is not None for lane in lanes for owner in lane.owners
                for process in [*(r.process for r in owner.roles.values()),
                                *(b.process for b in owner.backends.values())]),
            'broker_registered': all(
                json.loads((owner.root / name / 'registered-broker.json').read_text())['registered']
                for lane in lanes for owner in lane.owners for name in owner.roles)}


async def readiness(root: Path, package: Path, adapter: Path) -> dict[str, object]:
    """Actual real lane construction only: no owner start, transport or turn."""
    launches: list[str] = []
    def audit(event: str, args: tuple[object, ...]) -> None:
        if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'):
            launches.append(event)
            raise RuntimeError('readiness_process_launch_forbidden')
    sys.addaudithook(audit)
    root.mkdir(mode=0o700)
    candidate = root / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_text('base\n')
    expected = hashlib.sha256(json.dumps([
        ('a', hashlib.sha256(b'base\n').hexdigest())], separators=(',', ':')).encode()).hexdigest()
    import unrest_harness
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(unrest_harness.__file__).parent / 'bundled'), profile=SAFE_PROFILE,
        workspace=candidate, project_record=root)
    journal = root / 'readiness-only.jsonl'
    ledger = PilotLedger(journal, provider=REAL_PROVIDER)
    lane = None
    try:
        ledger.admit('P1')
        lane = LeaseLane(root / 'lane', candidate, ('a',), expected_candidate=expected,
            lane='readiness', adapter=adapter, policy=policy, ledger=ledger,
            trusted_process=True, fixture=None, provider_package=package)
        await lane.close()
        assert lane.owner is None and not lane.owners
        assert not ledger._leases and not ledger._turns and ledger._counts == {'P1': 0}
    finally:
        if lane is not None:
            await lane.close()
        ledger.close()
    events = [json.loads(line)['event'] for line in journal.read_text().splitlines()]
    assert events == ['campaign', 'admit'] and not launches
    return {'outcome': 'passed', 'real_constructor_ready': True, 'controlled': False,
            'provider_package': str(package), 'campaign_provider': REAL_PROVIDER,
            'owner_started': False, 'launch_attempts': len(launches), 'reservations': 0,
            'sends': 0, 'provider_turns': 0, 'closed': True,
            'os_write_isolation': 'unverified', 'live_acceptance': 'unverified'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-process', action='store_true',
                        help='trusted disposable inputs only; OS isolation is unverified')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--controlled', action='store_true', help='fixed local backend only')
    mode.add_argument('--readiness', action='store_true', help='real construction and close; zero launches')
    parser.add_argument('--provider-package', type=Path, help='explicit full official package directory')
    parser.add_argument('--adapter', type=Path, help='explicit resolved pinned adapter for readiness')
    parser.add_argument('--episode', choices=['P1', 'P2', 'P3'], default='P2')
    parser.add_argument('--disposition', default='reproducible_product_defect',
                        choices=['reproducible_product_defect', 'conflict', 'missing_authority',
                                 'scope_expansion', 'unknown', 'malformed_handoff'])
    parser.add_argument('--root', type=Path, required=True, help='new disposable directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.trusted_process:
        parser.error('explicit --trusted-process required; OS isolation unverified')
    if args.readiness and (args.provider_package is None or args.adapter is None):
        parser.error('--readiness requires --provider-package and --adapter')
    if args.controlled and (args.provider_package is not None or args.adapter is not None):
        parser.error('real package/adapter selection requires --readiness')
    try:
        result = (asyncio.run(readiness(args.root, args.provider_package, args.adapter))
                  if args.readiness else asyncio.run(run(
                      args.root, args.episode, trusted_process=args.trusted_process,
                      disposition=args.disposition)))
    except (LeaseRefused, OSError, ValueError):
        result = {'outcome': 'setup_refused', 'os_write_isolation': 'unverified', 'provider_turns': 0}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('outcome', 'os_write_isolation', 'provider_turns')}))
    return 0 if result['outcome'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
