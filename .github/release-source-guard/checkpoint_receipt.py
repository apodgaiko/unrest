"""Reuse only an authenticated successful original primary full/package run.

A readiness result or a receipt file alone cannot authorize reuse. The caller
obtains run/job/artifact records from GitHub's read API and verifies the actual
artifact ZIP against its server-provided digest before this closed validation.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile

REPOSITORY = 'apodgaiko/unrest'
WORKFLOW = '.github/workflows/ci.yml'
PRIMARY = 'primary source and package gate (py3.13)'
COMMAND = 'env -u CODEX_PATH uv run pytest -q'
REQUIRED_STEPS = (
    'Install dependencies', 'Import package', 'Supported CLI surfaces', 'Lint (ruff)',
    'Type-check (mypy)', 'v0.4.7 source suite', 'Repository contract',
    'Build wheel and source distribution', 'Check distribution archives',
    'Smoke-test installed wheel', 'Generate and verify v0.4.7 build-local checksums',
    'Upload v0.4.7 archives and checksums', 'Upload encrypted primary evidence',
)
DEFINITION_FIELDS = ('head_sha', 'source_tree', 'workflow_sha256', 'guard_definition_sha256',
                     'runtime_definition_sha256', 'source_command_sha256', 'package_command_sha256', 'lock_sha256')


class ReceiptRefused(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise ReceiptRefused(reason)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_receipt_field')
        result[key] = value
    return result


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def artifact_members(archive, artifact):
    require(len(archive) == artifact['size_in_bytes'], 'artifact archive size differs from GitHub')
    require(artifact.get('digest') == 'sha256:' + sha256(archive), 'GitHub artifact digest mismatch')
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        members = source.infolist()
        names = [item.filename for item in members]
        require(set(names) == {'safe-provenance.json', 'evidence.cms'} and len(names) == 2,
                'primary evidence artifact member set differs')
        require(all(not item.is_dir() and item.file_size <= 128 * 1024 * 1024
                    and item.external_attr >> 16 & 0o170000 in (0, 0o100000)
                    for item in members), 'artifact has nonregular or unbounded members')
        return {item.filename: source.read(item) for item in members}


def validate(archive, artifact, run, jobs, expected):
    require(all(type(value) is int and value > 0 for value in
                (run['id'], run['run_attempt'], artifact['id'], artifact['workflow_run']['id'])),
            'execution_identity_types')
    require(set(expected) == set(DEFINITION_FIELDS), 'definition_fields')
    require(all(type(expected[key]) is str and re.fullmatch(
        '[0-9a-f]{40}' if key in {'head_sha', 'source_tree'} else '[0-9a-f]{64}', expected[key])
        for key in DEFINITION_FIELDS), 'definition_digest_types')
    require(run['status'] == 'completed' and run['conclusion'] == 'success',
            'original primary run did not complete successfully')
    require(run['path'] == WORKFLOW and run['head_repository']['full_name'] == REPOSITORY,
            'original run is not this repository primary workflow')
    require(run['event'] == 'push' and run['head_sha'] == expected['head_sha'],
            'original execution event or frozen SHA differs')
    require(run['head_branch'] == 'main' or run['head_branch'].startswith('codex/release-v047-'),
            'readiness or unrelated branch is not a primary checkpoint')
    require(artifact.get('expired') is False and artifact['workflow_run']['id'] == run['id']
            and artifact['workflow_run']['head_sha'] == run['head_sha'],
            'artifact execution identity differs')
    require(artifact['name'] == f"unrest-v046-primary-{run['id']}-{run['run_attempt']}",
            'artifact is not the original primary execution evidence')
    primary = [job for job in jobs if job['name'] == PRIMARY]
    require(len(primary) == 1 and primary[0]['conclusion'] == 'success'
            and primary[0]['run_id'] == run['id'], 'primary job identity or result differs')
    for name in REQUIRED_STEPS:
        steps = [step for step in primary[0]['steps'] if step['name'] == name]
        require(len(steps) == 1 and steps[0]['status'] == 'completed'
                and steps[0]['conclusion'] == 'success', 'required executable duty did not pass: ' + name)
    members = artifact_members(archive, artifact)
    receipt = json.loads(members['safe-provenance.json'], object_pairs_hook=unique_fields)
    require(type(receipt) is dict, 'receipt_type')
    require(all(type(receipt[key]) is int and receipt[key] > 0
                for key in ('run_id', 'run_attempt', 'job_id')), 'receipt_identity_types')
    require(set(receipt) == set(DEFINITION_FIELDS) | {'schema', 'execution_kind', 'repository',
            'workflow', 'run_id', 'run_attempt', 'job_id', 'source_command', 'ciphertext_sha256',
            'source', 'package'}, 'receipt_fields')
    require(receipt['schema'] == 'unrest.v046.primary-checkpoint.v1'
            and receipt['execution_kind'] == 'executed-primary-full',
            'reused, partial or readiness evidence is not original full execution')
    require(receipt['repository'] == REPOSITORY and receipt['workflow'] == WORKFLOW
            and receipt['run_id'] == run['id'] and receipt['run_attempt'] == run['run_attempt']
            and receipt['job_id'] == primary[0]['id'], 'receipt execution identity differs')
    require(all(receipt[field] == expected[field] for field in DEFINITION_FIELDS),
            'frozen source/workflow/guard/runtime definition drift')
    require(receipt['source_command'] == COMMAND
            and receipt['source_command_sha256'] == sha256(COMMAND.encode()),
            'original source command differs')
    require(receipt['ciphertext_sha256'] == sha256(members['evidence.cms']),
            'private evidence ciphertext digest differs')
    source = receipt['source']
    require(set(source) == {'argv', 'collection_filters', 'item_mutations', 'deselected', 'exit_code',
                            'counts', 'kernel_poison', 'guard_poison', 'missing_original_parent_waits',
                            'unknown_execs'} or set(source) == {'argv', 'collection_filters', 'item_mutations',
                'deselected', 'exit_code', 'counts', 'kernel_poison', 'guard_poison',
                'missing_original_parent_waits', 'actual_adoptive_parent_waits', 'unknown_execs'},
            'source_fields')
    require(source['argv'] == ['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']
            and source['collection_filters'] == [] and source['item_mutations'] == []
            and type(source['deselected']) is int and source['deselected'] == 0 and type(source['exit_code']) is int and source['exit_code'] == 0,
            'full source execution was filtered, mutated or unsuccessful')
    counts = source['counts']
    require(set(counts) == {'collected', 'passed', 'failed', 'errors', 'skipped'}, 'source_count_fields')
    require(all(type(counts[key]) is int and counts[key] >= 0
                for key in ('collected', 'passed', 'failed', 'errors', 'skipped')),
            'source counts are not complete nonnegative integers')
    require(counts['collected'] > 0 and counts['failed'] == counts['errors'] == 0
            and counts['collected'] == counts['passed'] + counts['skipped'],
            'source JUnit and collection counts do not close')
    adopted = source.get('actual_adoptive_parent_waits', [])
    require(type(adopted) is list and all(type(row) is dict
            and set(row) == {'pid', 'method', 'raw'} and type(row['pid']) is int
            and row['pid'] > 0 and type(row['raw']) is int
            and row['method'] in {'actual_adoptive_parent_wait4', 'adoptive_tracer_terminal_wait'}
            for row in adopted) and len({row['pid'] for row in adopted}) == len(adopted),
            'source_adoptive_wait_inventory')
    require(source['kernel_poison'] == source['guard_poison'] == []
            and source['missing_original_parent_waits'] == sorted(row['pid'] for row in adopted)
            and source['unknown_execs'] == [], 'source guard or wait obligations did not close')
    package = receipt['package']
    require(set(package) == {'build_exit_code', 'archive_exit_code', 'installed_lifecycle_exit_code',
                            'extracted_oracle', 'unrelated_cwd', 'full_member_bytes_verified', 'archives'},
            'package_fields')
    require(set(package['extracted_oracle']) == {'cases', 'failures', 'errors', 'skipped'}
            and all(type(value) is int for value in package['extracted_oracle'].values()), 'oracle_count_types')
    require(all(type(package[key]) is int for key in ('build_exit_code', 'archive_exit_code', 'installed_lifecycle_exit_code'))
            and package['build_exit_code'] == package['archive_exit_code']
            == package['installed_lifecycle_exit_code'] == 0,
            'package duties did not actually pass')
    require(package['extracted_oracle'] == {'cases': 15, 'failures': 0, 'errors': 0, 'skipped': 0}
            and package['unrelated_cwd'] is True and package['full_member_bytes_verified'] is True,
            'extracted or installed package evidence is incomplete')
    require(set(package['archives']) == {'unrest_harness-0.4.7-py3-none-any.whl',
                                         'unrest_harness-0.4.7.tar.gz'},
            'package archive set differs')
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in package['archives'].values()),
            'package archive digests are invalid')
    return {'execution_kind': 'verified-same-commit-reuse', 'head_sha': run['head_sha'],
            'original_run_id': run['id'], 'original_run_attempt': run['run_attempt'],
            'original_job_id': primary[0]['id'], 'artifact_id': artifact['id'],
            'artifact_digest': artifact['digest'],
            'ciphertext_sha256': receipt['ciphertext_sha256'],
            'source_counts': counts, 'package_archives': package['archives']}
