"""Authenticate the exact CI artifact before privately reducing preflight bytes."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import zipfile

from phase_catalog import catalog, ORDER
from primary_source_probe import check as check_source
from structured_evidence import canonical, consume, loads, require

LIMIT = 64 * 1024 * 1024


def sha(body):
    return hashlib.sha256(body).hexdigest()


def api(route):
    result = subprocess.run(['gh', 'api', 'repos/apodgaiko/unrest/' + route],
                            capture_output=True, check=False)
    require(result.returncode == 0, 'preflight_download')
    return result.stdout


def members(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        rows = archive.getmembers()
        require(len(rows) <= 40 and len({row.name for row in rows}) == len(rows)
                and sum(row.size for row in rows) <= 2 * LIMIT, 'preflight_archive_bound')
        result = {}
        for row in rows:
            require(row.isfile() and not row.issparse() and row.size <= LIMIT
                    and PurePosixPath(row.name).name == row.name, 'preflight_archive_member')
            stream = archive.extractfile(row)
            require(stream is not None, 'preflight_missing_member')
            result[row.name] = stream.read(LIMIT + 1)
        return result


def verify(root, run_id, artifact_id, head, key, support):
    root.mkdir(mode=0o700)
    run_body = api(f'actions/runs/{run_id}')
    run = loads(run_body)
    require(run['head_sha'] == head and run['status'] == 'completed'
            and run['path'] == '.github/workflows/ci.yml' and run['event'] == 'push'
            and run['head_repository']['full_name'] == 'apodgaiko/unrest', 'preflight_run')
    artifact_body = api(f'actions/artifacts/{artifact_id}')
    artifact = loads(artifact_body)
    require(artifact['expired'] is False and artifact['workflow_run']['id'] == run_id
            and artifact['workflow_run']['head_sha'] == head
            and artifact['name'] == f"unrest-v046-preflight-{run_id}-{run['run_attempt']}", 'preflight_artifact')
    body = api(f'actions/artifacts/{artifact_id}/zip')
    require(len(body) <= LIMIT and len(body) == artifact['size_in_bytes']
            and artifact['digest'] == 'sha256:' + sha(body), 'preflight_server_digest')
    (root / 'run.json').write_bytes(run_body)
    (root / 'artifact.json').write_bytes(artifact_body)
    (root / 'artifact.zip').write_bytes(body)
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        rows = archive.infolist()
        require(len(rows) <= 100 and len({row.filename for row in rows}) == len(rows)
                and sum(row.file_size for row in rows) <= 2 * LIMIT, 'preflight_zip_bound')
        payload = {}
        for row in rows:
            name = PurePosixPath(row.filename)
            require(not row.is_dir() and not name.is_absolute() and '..' not in name.parts
                    and row.external_attr >> 16 & 0o170000 in {0, 0o100000}
                    and row.file_size <= LIMIT, 'preflight_zip_member')
            payload[str(name)] = archive.read(row)
    prerequisite = loads(payload['source-readiness/safe-provenance.json'])
    cipher = payload['source-readiness/evidence.cms']
    require(sha(cipher) == prerequisite['ciphertext_sha256'], 'preflight_controls_cipher')
    encrypted = root / 'controls.cms'
    encrypted.write_bytes(cipher)
    plaintext = root / 'controls.tar.gz'
    with (root / 'controls-decrypt.stderr').open('xb') as errors:
        result = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                 '-in', str(encrypted), '-inkey', str(key), '-out', str(plaintext)],
                                stdout=subprocess.DEVNULL, stderr=errors, check=False)
    require(result.returncode == 0 and plaintext.stat().st_size <= LIMIT
            and sha(plaintext.read_bytes()) == prerequisite['plaintext_archive_sha256'],
            'preflight_controls_plaintext')
    direct = prerequisite['direct_identity']
    require(direct['head_sha'] == head and direct['run_id'] == str(run_id)
            and direct['run_attempt'] == str(run['run_attempt'])
            and prerequisite['synthetic_exit_code'] == 0, 'preflight_controls_identity')
    scope, control_records = consume(plaintext.read_bytes(), direct,
                                    prerequisite['structured_envelope_sha256'])
    import xml.etree.ElementTree as ET
    cases = list(ET.fromstring(control_records['control-suite.xml']).iter('testcase'))
    observer = loads(control_records['observer.json'])
    require(scope == 'synthetic-controls' and len(cases) >= 1363
            and all(all(case.find(tag) is None for tag in ('failure', 'error', 'skipped'))
                    for case in cases)
            and observer['actual_wait_raw'] == observer['actual_wait_normalized'] == 0,
            'preflight_original_controls')
    index = loads(payload['preflight-retained/index.json'])
    require(index['head_sha'] == head and index['run_id'] == str(run_id)
            and index['run_attempt'] == str(run['run_attempt'])
            and index['eligible_certificate'] is False and index['source_checkpoint_ready'] is False,
            'preflight_index_identity')
    from full_bootstrap import scope as candidate_scope
    require(index['candidate_sha256'] == candidate_scope(support.parent.parent), 'preflight_candidate_scope')
    expected = {'early': 125, 'positive': 0, 'poison': 0, 'late': 125,
                **{catalog()[name].output: 0 for name in ORDER}}
    scenarios = index['scenarios']
    require(len(scenarios) == len(expected)
            and {row['scenario'] for row in scenarios} == set(expected), 'preflight_scenarios')
    support_pins = {str(path.relative_to(support)): sha(path.read_bytes())
                    for path in sorted(support.rglob('*'))
                    if path.is_file() and path.suffix in {'.py', '.json', '.c', '.pem'}}
    require(prerequisite['support'] == support_pins
            and direct['support_sha256'] == sha(canonical(support_pins)), 'preflight_controls_support')
    projections = []
    for row in scenarios:
        name = row['scenario']
        require(row['exit_code'] == row['expected_exit_code'] == expected[name]
                and len(row['members']) == 2, 'preflight_scenario_exit')
        files = {member: payload['preflight-retained/' + member] for member in row['members']}
        require(all(sha(files[member]) == pin for member, pin in row['members'].items()), 'preflight_member_digest')
        metadata = loads(next(value for member, value in files.items() if member.endswith('safe-provenance.json')))
        cipher = next(value for member, value in files.items() if member.endswith('evidence.cms'))
        require(sha(cipher) == metadata['ciphertext_sha256'], 'preflight_ciphertext')
        directory = root / name
        directory.mkdir(mode=0o700)
        encrypted = directory / 'evidence.cms'
        encrypted.write_bytes(cipher)
        plain = directory / 'archive.tar.gz'
        with (directory / 'decrypt.stderr').open('xb') as errors:
            result = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                     '-in', str(encrypted), '-inkey', str(key), '-out', str(plain)],
                                    stdout=subprocess.DEVNULL, stderr=errors, check=False)
        require(result.returncode == 0 and plain.stat().st_size <= LIMIT
                and sha(plain.read_bytes()) == metadata['plaintext_archive_sha256'], 'preflight_plaintext')
        if name == 'early':
            records = members(plain.read_bytes())
            failure = loads(records['preparation-status.json'])
            require(failure['exit_code'] == 125 and failure['stage'] == 'binding'
                    and failure['script_sha256'] == row['script_sha256'], 'preflight_early_refusal')
            projections.append({'scenario': name, 'retained_expected_refusal': True})
            continue
        identity = metadata['direct_identity']
        require(metadata['support'] == support_pins and identity['head_sha'] == head
                and identity['workflow_sha'] == head and identity['run_id'] == str(run_id)
                and identity['run_attempt'] == str(run['run_attempt'])
                and identity['support_sha256'] == sha(canonical(support_pins))
                and identity['workflow_ref'] == 'apodgaiko/unrest/.github/workflows/ci.yml@refs/heads/' + run['head_branch'],
                'preflight_phase_identity')
        scope, records = consume(plain.read_bytes(), identity, metadata['structured_envelope_sha256'])
        require(scope == 'primary-executor', 'preflight_phase_scope')
        if name in {'positive', 'poison'}:
            proof = check_source(records, 'TEST-poison' if name == 'poison' else 'TEST-positive')
        elif name == 'late':
            from primary_custody import kernel_success
            kernel_success(records, row['script_sha256'])
            require(metadata['stage'] == 'custody_refused' and metadata['source_exit_code'] == 125,
                    'preflight_late_refusal')
            proof = {'retained_expected_refusal': True}
        else:
            from primary_package_probe import check, check_archive, check_installed, check_checksum
            functions = dict(zip((catalog()[duty].output for duty in ORDER),
                                 (check, check_archive, check_installed, check_checksum)))
            proof = functions[name](records)
        projections.append({'scenario': name, 'proof': proof})
    return {'schema': 'unrest.v046.supplementary-preflight-reduction.v1', 'head_sha': head,
            'run_id': run_id, 'artifact_id': artifact_id, 'control_cases': len(cases), 'scenarios': projections,
            'eligible_certificate': False, 'source_checkpoint_ready': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('run', type=int)
    parser.add_argument('artifact', type=int)
    parser.add_argument('head')
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--support', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    proof = verify(args.root, args.run, args.artifact, args.head, args.key, args.support)
    (args.root / 'proof.json').write_bytes(canonical(proof))
    print(json.dumps({'verified': True, 'run_id': args.run, 'eligible_certificate': False}))


if __name__ == '__main__':
    main()
