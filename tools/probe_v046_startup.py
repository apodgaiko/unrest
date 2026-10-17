"""One independently authorized initialization attempt; never a model prompt.

Uses supported provider configuration, pinned owner/bridge and owned close.
Existing roots refuse. This does not run, resume or reset a campaign.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

import unrest_harness
from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
from unrest_harness.experimental_diagnostics import (
    StartupDiagnostics, startup_timeout_at,
)
from unrest_harness.experimental_lease import PilotLedger, REAL_PROVIDER, require_provider
from unrest_harness.experimental_provider import check_package
from unrest_harness.experimental_provider_config import ProviderConfig
from unrest_harness.experimental_session import ControlledTransport, _SessionOwner
from unrest_harness.providers import PROVIDERS


async def probe(root: Path, adapter: Path, package: Path | None, *,
                trusted_process: bool, fixture: Path | None = None,
                configuration: ProviderConfig | None = None,
                transport: ControlledTransport | None = None) -> dict[str, object]:
    """Fixture/config injection is for controlled tests, never real CLI overrides."""
    started = time.monotonic()
    setup_deadline = started + 300
    diagnostics = StartupDiagnostics()
    owner = None
    ledger = None
    result: dict[str, object] = {
        'outcome': 'attention', 'provider_turns': 0, 'reservations': 0, 'sends': 0,
        'attempt_limit': 1, 'controlled': fixture is not None,
        'diagnostic_format': 'initialization-boundaries-v4',
        'os_write_isolation': 'unverified', 'live_acceptance': 'unverified',
        'deadlines_seconds': {'setup_total': 300, 'broker_start': 3,
                             'lifetime_connect': 1, 'bridge_connect': 1},
        'effective_config_sha256': None, 'served_identity': None,
        'owned_reaped': False, 'closed': False,
    }
    try:
        if trusted_process is not True or (fixture is None) == (package is None):
            raise ValueError('explicit_selection_required')
        # Exclusive directory is the one-attempt marker, retained on all outcomes.
        root.mkdir(mode=0o700)
        backend = check_package(package) if fixture is None else fixture
        if configuration is None:
            user_home = Path(os.environ.get('HOME', str(Path.home())))
            configuration = ProviderConfig(
                codex_home=Path(os.environ.get('CODEX_HOME', str(user_home / '.codex'))),
                user_home=user_home, cwd=root,
                ambient=json.loads(os.environ.get('CODEX_CONFIG', '{}')))
        candidate = root / 'candidate'
        candidate.mkdir()
        (candidate / 'a').write_bytes(b'base\n')
        expected = hashlib.sha256(json.dumps([
            ('a', hashlib.sha256(b'base\n').hexdigest())], separators=(',', ':')).encode()).hexdigest()
        policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
            policy=load_capability_policy(Path(unrest_harness.__file__).parent / 'bundled'),
            profile=SAFE_PROFILE, workspace=candidate, project_record=root)
        ledger = PilotLedger(root / 'initialization-only.jsonl',
            provider='local-controlled-only' if fixture is not None else REAL_PROVIDER)
        ledger.admit('P1')
        require_provider('codex', trusted_process=trusted_process, controls=True, ledger=ledger)
        owner = _SessionOwner(root / 'owner', candidate, ('a',), adapter=adapter,
            fixture=backend, policy=policy, controlled=fixture is not None, ledger=ledger,
            lane='initialization-only', provider_package=package, provider_config=configuration,
            transport=transport)
        owner.broker.seal(('a',), expected)
        ledger.remaining_until(setup_deadline)
        async with startup_timeout_at(setup_deadline, 'owner_launch'):
            await owner.start()
            await owner.initialize_only(deadline=setup_deadline)
        ledger.remaining_until(setup_deadline)
        role_root = owner.root / 'worker'
        result['effective_config_sha256'] = configuration.effective_digests.get(str(role_root))
        result['served_identity'] = owner.thread_observations['worker'].served
        if result['effective_config_sha256'] is None or result['served_identity'] is None:
            raise ValueError('verification_missing')
        result['outcome'] = 'initialized'
    except (Exception, asyncio.CancelledError) as error:
        diagnostics.fail(error)
    finally:
        setup_finished = time.monotonic()
        result['setup_elapsed_seconds'] = setup_finished - started
        if owner is not None:
            try:
                await owner.close()
                result['closed'] = True
            except (Exception, asyncio.CancelledError) as error:
                diagnostics.phase('owner_cleanup')
                diagnostics.fail(error, cleanup=True)
                result['outcome'] = 'attention'
            result['owner_diagnostics'] = owner.diagnostics()
            result['owned_reaped'] = all(p.returncode is not None for p in (
                *(r.process for r in owner.roles.values()),
                *(b.process for b in owner.backends.values())))
            if configuration is not None:
                result['effective_config_sha256'] = configuration.effective_digests.get(
                    str(owner.root / 'worker'))
                observation = owner.thread_observations.get('worker')
                result['served_identity'] = None if observation is None else observation.served
        if ledger is not None:
            # This dedicated journal can record admission/ownership/stop, but no turn.
            result['reservations'] = len(ledger._turns)
            try:
                ledger.close()
            except Exception as error:
                diagnostics.phase('owner_cleanup')
                diagnostics.fail(error, cleanup=True)
                result['outcome'] = 'attention'
        result['cleanup_elapsed_seconds'] = time.monotonic() - setup_finished
        result['diagnostics'] = diagnostics.snapshot()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-process', action='store_true', required=True)
    parser.add_argument('--one-initialization-attempt', action='store_true', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--provider-package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Refuse an existing result before any provider work, as well as an existing root.
    with args.output.open('x') as output:
        result = asyncio.run(probe(args.root, args.adapter, args.provider_package,
                                   trusted_process=args.trusted_process))
        output.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'outcome': result['outcome'], 'provider_turns': 0}))
    return 0 if result['outcome'] == 'initialized' else 2


if __name__ == '__main__':
    raise SystemExit(main())
