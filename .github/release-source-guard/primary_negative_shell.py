"""Exercise actual custom-shell refusals without executing a payload command."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_commands import bind_generated

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent


def sha(body):
    return hashlib.sha256(body).hexdigest()


def main():
    case, filename = sys.argv[1:]
    if case not in {'substitution', 'identity'}:
        raise RuntimeError('negative_case')
    script = Path(filename)
    body = script.read_bytes()
    workflow_path = REPOSITORY / '.github/workflows/ci.yml'
    original = workflow_path.read_bytes()
    before = {path.name for path in Path(os.environ['RUNNER_TEMP']).glob('primary-*') if path.is_dir()}
    state = Path(os.environ['RUNNER_TEMP']) / ('refusal-state-' + case)
    state.mkdir(mode=0o700)
    if case == 'substitution':
        try:
            bind_generated(body, original.decode())
        except RuntimeError:
            pass
        else:
            raise RuntimeError('negative_script_is_registered')
    else:
        if bind_generated(body, original.decode())['name'] != 'Import package':
            raise RuntimeError('negative_identity_script')
    records = []
    mutations = [('substituted_script' if case == 'substitution' else 'different_head', None)]
    if case == 'identity':
        mutations += [('conditional_workflow_drift', original.replace(
            b'      - name: Type-check (mypy)\n',
            b'      - name: Type-check (mypy)\n        if: false\n', 1)),
            ('dead_workflow_drift', original.replace(b'run: uv run mypy src', b'run: echo uv run mypy src', 1))]
    try:
        for name, mutation in mutations:
            child_root = state / name
            child_root.mkdir(mode=0o700)
            environment = {**os.environ, 'RUNNER_TEMP': str(child_root)}
            if name == 'different_head':
                environment['GITHUB_SHA'] = '0' * 40
            if mutation is not None:
                if mutation == original:
                    raise RuntimeError('negative_mutation_missing')
                workflow_path.write_bytes(mutation)
            result = subprocess.run([sys.executable, str(SUPPORT / 'ci_shell.py'), str(script)],
                                    env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    check=False)
            try:
                diagnostic = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                raise RuntimeError('negative_diagnostic_invalid') from None
            expected_fields = {'schema', 'exit_code', 'stage', 'script_sha256', 'script_size'}
            if (set(diagnostic) != expected_fields or diagnostic['schema'] != 'primary-executor-status-v1'
                    or result.returncode != 125 or diagnostic['exit_code'] != 125
                    or diagnostic['stage'] != 'binding' or diagnostic['script_sha256'] != sha(body)
                    or diagnostic['script_size'] != len(body) or result.stderr
                    or any(path.is_dir() for path in child_root.iterdir())):
                raise RuntimeError('negative_not_refused_before_execution')
            records.append({'case_id': name, 'child_exit_code': result.returncode, 'stage': diagnostic['stage'],
                            'script_sha256': diagnostic['script_sha256'], 'unexpected_stderr': False})
            if mutation is not None:
                workflow_path.write_bytes(original)
    finally:
        if workflow_path.read_bytes() != original:
            workflow_path.write_bytes(original)
    after = {path.name for path in Path(os.environ['RUNNER_TEMP']).glob('primary-*') if path.is_dir()}
    if after != before:
        raise RuntimeError('negative_created_capsule_state')
    output = {'schema': 'unrest.v046.primary-script-refusals.v1', 'case_id': case,
              'head_sha': os.environ['GITHUB_SHA'], 'records': records,
              'workflow_restored': workflow_path.read_bytes() == original,
              'workflow_sha256': sha(original), 'capsules_created': 0,
              'source_checkpoint_ready': False, 'selected_carrier': None}
    (Path(os.environ['RUNNER_TEMP']) / ('primary-negative-' + case + '.json')).write_text(
        json.dumps(output, sort_keys=True))
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        print(json.dumps({'schema': 'primary-script-refusal-status-v1', 'exit_code': 125}))
        status = 125
    raise SystemExit(status)
