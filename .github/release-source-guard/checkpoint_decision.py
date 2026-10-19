"""Resolve same-SHA reuse on the control plane before any payload execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from checkpoint_lookup import ActionsReader, lookup
from checkpoint_receipt import COMMAND, ReceiptRefused, artifact_members, require
from checkpoint_packages import materialize
from ci_commands import REGISTRY
from environment import BASE

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent


def sha(body):
    return hashlib.sha256(body).hexdigest()


def expected_identity(repository=REPOSITORY, support=SUPPORT):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=repository, stderr=subprocess.DEVNULL).decode().strip()
    head = git('rev-parse', 'HEAD')
    if head != os.environ['GITHUB_SHA']:
        raise ReceiptRefused('checkout_head_differs')
    workflow = repository / '.github/workflows/ci.yml'
    if workflow.read_bytes() != subprocess.check_output(['git', 'show', 'HEAD:.github/workflows/ci.yml'], cwd=repository):
        raise ReceiptRefused('checkout_workflow_differs')
    pins = {str(path.relative_to(support)): sha(path.read_bytes())
            for path in sorted(support.rglob('*'))
            if path.is_file() and path.suffix in {'.py', '.json', '.pem', '.c'}}
    runtime_names = ['environment.py', 'primary_environment.py', 'primary_entry.c',
                     'primary_entry.py', 'primary_entry_build.py', 'native_entry.c',
                     'native_entry.py', 'native_entry_build.py', 'producer_inputs.py']
    runtime = {'base': BASE, 'inputs': {name: pins[name] for name in runtime_names}}
    return {'head_sha': head, 'source_tree': git('rev-parse', 'HEAD^{tree}'),
            'workflow_sha256': sha(workflow.read_bytes()),
            'guard_definition_sha256': sha(json.dumps(pins, sort_keys=True).encode()),
            'runtime_definition_sha256': sha(json.dumps(runtime, sort_keys=True).encode()),
            'source_command_sha256': sha(COMMAND.encode()),
            'package_command_sha256': sha(REGISTRY.read_bytes()),
            'lock_sha256': sha((repository / 'uv.lock').read_bytes())}


def decide(reader, expected, current_run):
    receipt = lookup(reader, expected, current_run)
    return {'schema': 'unrest.v046.primary-decision.v1', 'expected': expected,
            'decision': 'execute-first-full' if receipt is None else 'reuse-authentic-full',
            'receipt': receipt, 'source_checkpoint_ready': False, 'selected_carrier': None}


def main():
    destination = Path(os.environ['RUNNER_TEMP']) / 'primary-decision.json'
    if destination.exists() or destination.is_symlink():
        raise ReceiptRefused('decision_already_exists')
    reader = ActionsReader(os.environ['GH_TOKEN'])
    current = int(os.environ['GITHUB_RUN_ID'])
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    result = decide(reader, expected_identity(), current)
    jobs = reader.api(f'actions/runs/{current}/attempts/{attempt}/jobs?per_page=100')
    require(jobs['total_count'] <= 100, 'current_primary_job_inventory')
    from checkpoint_receipt import PRIMARY
    primary = [job for job in jobs['jobs'] if job['name'] == PRIMARY and job['run_id'] == current]
    require(len(primary) == 1, 'current_primary_job_identity')
    job_path = Path(os.environ['RUNNER_TEMP']) / 'primary-job.json'
    with job_path.open('x') as stream:
        json.dump({'id': primary[0]['id'], 'name': PRIMARY, 'run_id': current,
                   'run_attempt': attempt, 'expected': result['expected']}, stream, sort_keys=True)
    job_path.chmod(0o600)
    name = f'unrest-v046-primary-{current}-{attempt}'
    if result['receipt'] is not None:
        receipt = result['receipt']
        materialize(reader, receipt, REPOSITORY / 'dist')
        artifact = reader.api(f"actions/artifacts/{receipt['artifact_id']}")
        require(artifact['digest'] == receipt['artifact_digest'], 'original_artifact_changed')
        members = artifact_members(reader.archive(artifact), artifact)
        evidence = Path(os.environ['RUNNER_TEMP']) / 'primary-full'
        evidence.mkdir(mode=0o700)
        (evidence / 'evidence.cms').write_bytes(members['evidence.cms'])
        marker = {'schema': 'unrest.v046.primary-reuse.v1', 'execution_kind': 'verified-same-commit-reuse',
                  'run_id': current, 'run_attempt': attempt, 'expected': result['expected'],
                  'original': receipt, 'ciphertext_sha256': receipt['ciphertext_sha256']}
        (evidence / 'safe-provenance.json').write_text(json.dumps(marker, sort_keys=True))
        name = f'unrest-v046-reuse-{current}-{attempt}'
    if 'GITHUB_OUTPUT' in os.environ:
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write('evidence-name=' + name + '\n')
    with destination.open('x') as stream:
        json.dump(result, stream, sort_keys=True)
    destination.chmod(0o600)
    if result['receipt'] is None:
        from full_bootstrap import produce
        produce('FULL')
    print(json.dumps({'decision': result['decision'], 'eligible_prior_full': result['receipt'] is not None}))
    return 0


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        print(json.dumps({'decision': 'refused'}))
        status = 125
    diagnostic = {'schema': 'unrest.v046.primary-decision-status.v1', 'exit_code': status,
                  'decision': 'resolved' if status == 0 else 'refused'}
    (Path(os.environ['RUNNER_TEMP']) / 'primary-decision-status.json').write_text(json.dumps(diagnostic, sort_keys=True))
    raise SystemExit(status)
