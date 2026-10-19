"""Supplementary canaries through the production phase executor and capsules."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from phase_catalog import catalog, ORDER
from preflight_policy import context, SCRIPT
from structured_evidence import canonical, require

SUPPORT = Path(__file__).resolve().parent


def sha(body):
    return hashlib.sha256(body).hexdigest()


def main():
    context()
    from full_bootstrap import produce, semantic_manifest
    temporary = Path(os.environ['RUNNER_TEMP'])
    retained = temporary / 'preflight-retained'
    retained.mkdir(mode=0o700)
    identity = {'head_sha': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID'],
                'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
                'candidate_sha256': sha(canonical(semantic_manifest())),
                'eligible_certificate': False, 'source_checkpoint_ready': False}
    rows = []

    def execute(name, runner, flag, command, expected, physical=None):
        script = runner / (name + '-script.sh')
        script.write_bytes(command)
        arguments = [sys.executable, '-B', str(SUPPORT / 'ci_shell.py'), flag]
        if flag == '--producer':
            arguments = [sys.executable, '-B', str(SUPPORT / 'full_bootstrap.py'), 'PREFLIGHT']
        if flag == '--preflight':
            arguments.append('TEST-poison' if name == 'poison' else 'TEST-positive')
        if flag != '--producer':
            arguments.append(str(script))
        with (runner / (name + '-private.log')).open('xb') as output:
            result = subprocess.run(arguments, env={**os.environ, 'RUNNER_TEMP': str(runner)},
                                    stdout=output, stderr=subprocess.STDOUT, check=False)
        rows.append({'scenario': name, 'exit_code': result.returncode, 'expected_exit_code': expected,
                     'script_sha256': sha(command), 'members': {}, 'physical': physical})
        # Every available encrypted pair is selected by the execution catalog.
        roots = (['primary-preparation'] if flag == '--producer' else ['primary-source-poison' if name == 'poison' else 'primary-source-positive']
                 if flag == '--preflight' else [phase.output for phase in catalog().values()
                     if command in {phase.command.encode(), phase.command.rstrip('\n').encode()}])
        for root_name in roots:
            source = runner / root_name
            if not source.exists():
                continue
            destination = retained / name / root_name
            destination.mkdir(mode=0o700, parents=True)
            for member in ('evidence.cms', 'safe-provenance.json'):
                body = (source / member).read_bytes()
                require(len(body) <= 64 * 1024 * 1024, 'preflight_retention_bound')
                (destination / member).write_bytes(body)
                rows[-1]['members'][name + '/' + root_name + '/' + member] = sha(body)
        (retained / 'index.json').write_bytes(canonical({**identity, 'scenarios': rows}))
        require(result.returncode == expected and rows[-1]['members'], 'preflight_scenario_failed')

    def runner(name):
        root = temporary / ('preflight-' + name)
        root.mkdir(mode=0o700)
        shutil.copytree(temporary / 'source-readiness', root / 'source-readiness')
        saved = os.environ['RUNNER_TEMP']
        os.environ['RUNNER_TEMP'] = str(root)
        try:
            produce('PREFLIGHT')
        finally:
            os.environ['RUNNER_TEMP'] = saved
        return root

    from full_input_controls import PREFLIGHT_HOST_CASES, preflight_mutation, preflight_snapshot
    for case in PREFLIGHT_HOST_CASES:
        physical = runner('host-' + case)
        before = preflight_snapshot(physical)
        preflight_mutation(case, physical)
        after = preflight_snapshot(physical)
        execute('host-' + case, physical, '--preflight', SCRIPT, 125,
                {'case': case, 'before': before, 'after': after})
    producer = temporary / 'preflight-producer-acquisition'
    producer.mkdir(mode=0o700)
    (producer / 'primary-input-custody').mkdir(mode=0o755)
    execute('producer-acquisition', producer, '--producer', __import__('full_bootstrap').SCRIPT, 125)

    # Each failure has a distinct physical envelope and evidence directory.
    early = runner('early')
    prerequisite = early / 'source-readiness/safe-provenance.json'
    value = json.loads(prerequisite.read_bytes())
    value['head_sha'] = '0' * 40
    prerequisite.write_bytes(canonical(value))
    import_command = catalog()['Import package'].command.rstrip('\n').encode()
    execute('early', early, '--preflight-phase', import_command, 125)

    production = runner('production')
    execute('positive', production, '--preflight', SCRIPT, 0)
    execute('poison', production, '--preflight', SCRIPT, 0)
    for duty in ORDER:
        command = catalog()[duty].command
        wire = command.encode() if '\n' in command.rstrip('\n') else command.rstrip('\n').encode()
        execute(catalog()[duty].output, production, '--preflight-package', wire, 0)

    late = runner('late')
    # A genuine terminal custody refusal after a successful actual capsule.
    from checkpoint_decision import expected_identity
    from primary_custody import Binding, Custody
    custody = Custody(late / 'primary-custody', Binding(expected_identity(),
                      int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])), create=True)
    from primary_custody import exclusive
    exclusive(custody.root / (sha(b'Import package') + '.json'), b'controlled late collision')
    execute('late', late, '--preflight-phase', import_command, 125)
    return 0


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        result = 125
    print(json.dumps({'schema': 'unrest.v046.supplementary-preflight-status.v1',
                      'exit_code': result, 'eligible_certificate': False}))
    raise SystemExit(result)
