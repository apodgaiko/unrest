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
    'Type-check (mypy)', 'v0.4.6 source suite', 'Repository contract',
    'Build wheel and source distribution', 'Check distribution archives',
    'Smoke-test installed wheel', 'Generate and verify v0.4.6 build-local checksums',
    'Upload v0.4.6 archives and checksums', 'Upload encrypted primary evidence',
)
DEFINITION_FIELDS = ('head_sha', 'source_tree', 'workflow_sha256', 'guard_definition_sha256',
                     'runtime_definition_sha256', 'source_command_sha256')


class ReceiptRefused(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise ReceiptRefused(reason)


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
    require(run['status'] == 'completed' and run['conclusion'] == 'success',
            'original primary run did not complete successfully')
    require(run['path'] == WORKFLOW and run['head_repository']['full_name'] == REPOSITORY,
            'original run is not this repository primary workflow')
    require(run['event'] == 'push' and run['head_sha'] == expected['head_sha'],
            'original execution event or frozen SHA differs')
    require(run['head_branch'] == 'main' or run['head_branch'].startswith('codex/release-v046-'),
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
    receipt = json.loads(members['safe-provenance.json'])
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
    require(source['argv'] == ['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']
            and source['collection_filters'] == [] and source['item_mutations'] == []
            and source['deselected'] == 0 and source['exit_code'] == 0,
            'full source execution was filtered, mutated or unsuccessful')
    counts = source['counts']
    require(all(type(counts[key]) is int and counts[key] >= 0
                for key in ('collected', 'passed', 'failed', 'errors', 'skipped')),
            'source counts are not complete nonnegative integers')
    require(counts['collected'] > 0 and counts['failed'] == counts['errors'] == 0
            and counts['collected'] == counts['passed'] + counts['skipped'],
            'source JUnit and collection counts do not close')
    require(source['kernel_poison'] == source['guard_poison'] == []
            and source['missing_original_parent_waits'] == []
            and source['unknown_execs'] == [], 'source guard or wait obligations did not close')
    package = receipt['package']
    require(package['build_exit_code'] == package['archive_exit_code']
            == package['installed_lifecycle_exit_code'] == 0,
            'package duties did not actually pass')
    require(package['extracted_oracle'] == {'cases': 15, 'failures': 0, 'errors': 0, 'skipped': 0}
            and package['unrelated_cwd'] is True and package['full_member_bytes_verified'] is True,
            'extracted or installed package evidence is incomplete')
    require(set(package['archives']) == {'unrest_harness-0.4.6-py3-none-any.whl',
                                         'unrest_harness-0.4.6.tar.gz'},
            'package archive set differs')
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in package['archives'].values()),
            'package archive digests are invalid')
    return {'execution_kind': 'verified-same-commit-reuse', 'head_sha': run['head_sha'],
            'original_run_id': run['id'], 'original_run_attempt': run['run_attempt'],
            'original_job_id': primary[0]['id'], 'artifact_id': artifact['id'],
            'artifact_digest': artifact['digest'],
            'ciphertext_sha256': receipt['ciphertext_sha256'],
            'source_counts': counts, 'package_archives': package['archives']}
