"""Controlled parser tests only; these fixtures are never actual CI receipts."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location(
    'checkpoint_receipt', Path(__file__).with_name('checkpoint_receipt.py')
)
assert spec is not None and spec.loader is not None
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


def fixture():
    expected = {key: 'a' * 64 for key in receipt.DEFINITION_FIELDS}
    expected['head_sha'] = 'b' * 40
    expected['source_command_sha256'] = hashlib.sha256(receipt.COMMAND.encode()).hexdigest()
    run = {'status': 'completed', 'conclusion': 'success', 'path': receipt.WORKFLOW,
           'head_repository': {'full_name': receipt.REPOSITORY}, 'event': 'push',
           'head_sha': expected['head_sha'], 'head_branch': 'codex/release-v046-unit-control',
           'id': 1, 'run_attempt': 1}
    job = {'name': receipt.PRIMARY, 'conclusion': 'success', 'run_id': 1, 'id': 2,
           'steps': [{'name': name, 'status': 'completed', 'conclusion': 'success'}
                     for name in receipt.REQUIRED_STEPS]}
    cipher = b'controlled parser bytes; not genuine encrypted execution evidence'
    data = {**expected, 'schema': 'unrest.v046.primary-checkpoint.v1',
            'execution_kind': 'executed-primary-full', 'repository': receipt.REPOSITORY,
            'workflow': receipt.WORKFLOW, 'run_id': 1, 'run_attempt': 1, 'job_id': 2,
            'source_command': receipt.COMMAND, 'ciphertext_sha256': hashlib.sha256(cipher).hexdigest(),
            'source': {'argv': ['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q'],
                       'collection_filters': [], 'item_mutations': [], 'deselected': 0,
                       'exit_code': 0, 'counts': {'collected': 2, 'passed': 2, 'failed': 0,
                                                 'errors': 0, 'skipped': 0},
                       'kernel_poison': [], 'guard_poison': [], 'unknown_execs': [],
                       'missing_original_parent_waits': []},
            'package': {'build_exit_code': 0, 'archive_exit_code': 0,
                        'installed_lifecycle_exit_code': 0,
                        'extracted_oracle': {'cases': 15, 'failures': 0, 'errors': 0, 'skipped': 0},
                        'unrelated_cwd': True, 'full_member_bytes_verified': True,
                        'archives': {'unrest_harness-0.4.6-py3-none-any.whl': 'c' * 64,
                                     'unrest_harness-0.4.6.tar.gz': 'd' * 64}}}
    return expected, run, [job], data, cipher


def seal(data, cipher):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('safe-provenance.json', json.dumps(data))
        archive.writestr('evidence.cms', cipher)
    body = buffer.getvalue()
    artifact = {'id': 3, 'name': 'unrest-v046-primary-1-1', 'expired': False,
                'workflow_run': {'id': 1, 'head_sha': data['head_sha']},
                'size_in_bytes': len(body), 'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}
    return body, artifact


def test_controlled_parser_closes_all_links():
    expected, run, jobs, data, cipher = fixture()
    body, artifact = seal(data, cipher)
    result = receipt.validate(body, artifact, run, jobs, expected)
    assert result['original_run_id'] == 1 and result['artifact_id'] == 3
    assert result['execution_kind'] == 'verified-same-commit-reuse'


@pytest.mark.parametrize('mutation', ['readiness', 'other_sha', 'failed_job', 'skipped_source',
                                    'filtered', 'count_gap', 'missing_wait', 'poison',
                                    'partial_package', 'wrong_oracle', 'reused_receipt',
                                    'guard_drift', 'cipher_drift', 'artifact_digest'])
def test_incomplete_or_different_execution_cannot_be_reused(mutation):
    expected, run, jobs, data, cipher = copy.deepcopy(fixture())
    if mutation == 'readiness':
        run['path'] = '.github/workflows/v046-source-readiness.yml'
    elif mutation == 'other_sha':
        run['head_sha'] = 'e' * 40
    elif mutation == 'failed_job':
        jobs[0]['conclusion'] = 'failure'
    elif mutation == 'skipped_source':
        next(step for step in jobs[0]['steps'] if step['name'] == 'v0.4.6 source suite')['conclusion'] = 'skipped'
    elif mutation == 'filtered':
        data['source']['collection_filters'] = ['-k partial']
    elif mutation == 'count_gap':
        data['source']['counts']['collected'] += 1
    elif mutation == 'missing_wait':
        data['source']['missing_original_parent_waits'] = [7]
    elif mutation == 'poison':
        data['source']['kernel_poison'] = ['caught unknown exec']
    elif mutation == 'partial_package':
        data['package']['archive_exit_code'] = 1
    elif mutation == 'wrong_oracle':
        data['package']['extracted_oracle']['cases'] = 14
    elif mutation == 'reused_receipt':
        data['execution_kind'] = 'verified-same-commit-reuse'
    elif mutation == 'guard_drift':
        data['guard_definition_sha256'] = 'f' * 64
    elif mutation == 'cipher_drift':
        data['ciphertext_sha256'] = 'f' * 64
    body, artifact = seal(data, cipher)
    if mutation == 'artifact_digest':
        artifact['digest'] = 'sha256:' + 'f' * 64
    with pytest.raises(receipt.ReceiptRefused):
        receipt.validate(body, artifact, run, jobs, expected)
