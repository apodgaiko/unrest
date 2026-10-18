"""Download one exact artifact and consume direct records without opening logs.

All process diagnostics stay in the owned private root. Stdout is a closed
numeric/hash/enum projection; caught exceptions never contribute text.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

from checkpoint_receipt import artifact_members
from producer_controls import check as check_producer
from structured_evidence import canonical, consume, digest, loads, require


class PrivateFailure(RuntimeError):
    pass


def gh(path):
    result = subprocess.run(['gh', 'api', 'repos/apodgaiko/unrest/' + path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise PrivateFailure('metadata_download')
    return result.stdout


def download(root, run_id, artifact_id, head):
    run_body = gh(f'actions/runs/{run_id}')
    artifact_body = gh(f'actions/artifacts/{artifact_id}')
    run, artifact = loads(run_body), loads(artifact_body)
    require(run['id'] == run_id and run['head_sha'] == head
            and run['head_repository']['full_name'] == 'apodgaiko/unrest'
            and run['path'] == '.github/workflows/v046-source-readiness.yml'
            and run['event'] == 'push' and run['status'] == 'completed', 'run_identity')
    require(artifact['id'] == artifact_id and artifact['expired'] is False
            and artifact['workflow_run']['id'] == run_id
            and artifact['workflow_run']['head_sha'] == head, 'artifact_identity')
    archive = gh(f'actions/artifacts/{artifact_id}/zip')
    members = artifact_members(archive, artifact)
    for name, body in [('run.json', run_body), ('artifact.json', artifact_body),
                       ('artifact.zip', archive), *sorted(members.items())]:
        (root / name).write_bytes(body)
    return run, artifact, members


def verify(root, run, artifact, members, key, support):
    require(not root.is_symlink() and stat.S_IMODE(root.stat().st_mode) == 0o700
            and root.stat().st_uid == os.getuid(), 'private_root_permissions')
    metadata = loads(members['safe-provenance.json'])
    require(metadata['ciphertext_sha256'] == digest(members['evidence.cms']), 'ciphertext_digest')
    pins = {str(path.relative_to(support)): digest(path.read_bytes())
            for path in sorted(support.rglob('*'))
            if path.is_file() and path.suffix in {'.py', '.json', '.pem', '.c'}}
    require(metadata['support'] == pins, 'current_support_digest')
    direct = metadata['direct_identity']
    expected = {'repository': 'apodgaiko/unrest', 'head_sha': run['head_sha'],
                'workflow_sha': run['head_sha'], 'run_id': str(run['id']),
                'run_attempt': str(run['run_attempt']), 'artifact_name': artifact['name'],
                'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@refs/heads/' + run['head_branch'],
                'support_sha256': digest(canonical(pins))}
    require(direct == expected, 'direct_identity')
    require(metadata['source_checkpoint_ready'] is False and metadata['selected_carrier'] is None,
            'scope_escalation')
    require(not key.is_symlink() and stat.S_IMODE(key.stat().st_mode) == 0o600,
            'key_permissions')
    plaintext = root / 'private-archive.tar.gz'
    with (root / 'decrypt.stderr').open('wb') as errors:
        result = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                 '-in', str(root / 'evidence.cms'), '-inkey', str(key),
                                 '-out', str(plaintext)], stdout=subprocess.DEVNULL,
                                stderr=errors, check=False)
    require(result.returncode == 0, 'decryption_failed')
    body = plaintext.read_bytes()
    require(digest(body) == metadata['plaintext_archive_sha256'], 'plaintext_digest')
    scope, records = consume(body, expected, metadata['structured_envelope_sha256'])
    projection = {'schema': 'direct-record-verification-v1', 'run_id': run['id'],
                  'artifact_id': artifact['id'], 'head_sha': run['head_sha'],
                  'ciphertext_sha256': digest(members['evidence.cms']),
                  'archive_sha256': digest(body), 'scope': scope,
                  'structured_records': len(records), 'source_checkpoint_ready': False,
                  'negative_verified': False}
    if 'runner-stage.json' in records:
        stage = loads(records['runner-stage.json'])
        require(set(stage) == {'schema', 'stage', 'error_code', 'frames', 'original_pytest_exit_code'}
                and stage['schema'] == 'unrest.v046.runner-failure.v1'
                and stage['stage'] in {'startup', 'manifest', 'guard_load', 'guard_install', 'pytest', 'summary'}
                and stage['error_code'] in {'AssertionError', 'AttributeError', 'KeyError', 'RuntimeError',
                                             'TypeError', 'ValueError', 'other'}, 'runner_stage_schema')
        require(metadata['source_exit_code'] != 0 and type(stage['frames']) is list
                and len(stage['frames']) <= 8, 'runner_stage_outcome')
        import re
        require(all(type(frame) is dict and set(frame) == {'file_sha256', 'line'}
                    and type(frame['line']) is int and frame['line'] > 0
                    and type(frame['file_sha256']) is str
                    and re.fullmatch('[0-9a-f]{64}', frame['file_sha256'])
                    for frame in stage['frames']), 'runner_stage_frames')
        projection.update(error_code='source_runner_refused', runner_stage=stage['stage'],
                          runner_error=stage['error_code'], frames=stage['frames'])
        return projection
    if scope == 'primary-controls':
        kernel = loads(records['kernel-source.json'])
        require(kernel['schema'] == 'unrest.v046.primary-controls.v1', 'primary_controls_schema')
        controls = kernel['controls']
        expected = {'isolated_no_site': 0, 'private_path': 0, 'native_unknown_caught': 86,
                    'native_network': 86, 'foreign_fd': 86, 'kernel_unknown_caught': 0}
        require(len(controls) == len(expected) and {row['control_id'] for row in controls} == set(expected),
                'primary_controls_cases')
        import os as operating_system
        results = {}
        for row in controls:
            require(type(row['root_parent_wait_raw']) is int, 'primary_control_actual_wait')
            identity = row['source_identity']
            valid = (operating_system.waitstatus_to_exitcode(row['root_parent_wait_raw']) == expected[row['control_id']]
                     and identity['uids'] == [20000] * 4 and not any(identity['capabilities'].values())
                     and identity['no_new_privs'] == 1 and row['control_verified'] is True)
            require(row['poison'] == (['unknown_or_drifted_exec']
                    if row['control_id'] == 'kernel_unknown_caught' else []), 'primary_control_poison')
            results[row['control_id']] = valid
        if 'host_private_canary_sha256' in metadata:
            require(metadata['private_canary_outside_mounts'] is True
                    and isinstance(metadata['host_private_canary_sha256'], str)
                    and len(metadata['host_private_canary_sha256']) == 64, 'primary_canary_identity')
            projection['private_canary_outside_mounts'] = True
            projection['host_private_canary_sha256'] = metadata['host_private_canary_sha256']
        projection.update(primary_controls_verified=all(results.values()) and metadata['source_exit_code'] == 0,
                          controls=results, actual_root_parent_waits=len(controls))
        if not projection['primary_controls_verified']:
            projection['error_code'] = 'primary_controls_failed'
        return projection
    if scope == 'primary-executor':
        kernel = loads(records['kernel-source.json'])
        if kernel.get('failure_code') == 'bootstrap_failure':
            require(kernel['stage'] in {'bootstrap', 'dependencies', 'runtime', 'source_setup',
                                        'authority', 'trace'}, 'primary_stage')
            require(all(type(line) is int and 0 < line < 10000 for line in kernel['frame_lines']),
                    'primary_stage_lines')
            projection.update(error_code='primary_bootstrap_failed', primary_stage=kernel['stage'],
                              frame_lines=kernel['frame_lines'])
            return projection
        diagnostics = []
        for row in kernel.get('native_diagnostics', []):
            require((row['schema'] == 'primary-native-state-v1' and set(row) == {'schema', 'pid', 'source_path_present', 'venv_site_present', 'prefix_is_venv', 'body_failure'})
                    or (row['schema'] == 'primary-native-state-v2' and set(row) == {'schema', 'pid', 'source_path_present', 'venv_site_present', 'prefix_is_venv', 'body_failure', 'git_status', 'git_error_code'}), 'primary_diagnostic_schema')
            require(row.get('git_status') is None or type(row['git_status']) is int, 'primary_git_status')
            require(row.get('git_error_code') in {None, 'git_ownership', 'other'}, 'primary_git_error')
            require(all(type(row[key]) is bool for key in ('source_path_present', 'venv_site_present', 'prefix_is_venv')), 'primary_diagnostic_flags')
            failure = row['body_failure']
            if failure is not None:
                require(set(failure) in ({'error_code', 'missing_module', 'frames', 'detail_code', 'error_path_noexec'}, {'error_code', 'missing_module', 'frames'})
                        and failure.get('detail_code', 'other') in {'native_noexec', 'native_symbol', 'native_library', 'import_name', 'permission', 'glibc', 'other'}
                        and type(failure.get('error_path_noexec', False)) is bool
                        and type(failure['frames']) is list and len(failure['frames']) <= 8
                        and all(type(frame) is dict and set(frame) == {'file_sha256', 'line'}
                                and type(frame['line']) is int and 0 < frame['line'] < 10000
                                and type(frame['file_sha256']) is str and len(frame['file_sha256']) == 64
                                and all(char in '0123456789abcdef' for char in frame['file_sha256'])
                                for frame in failure['frames']), 'primary_diagnostic_frames')
                require(failure['error_code'] in {'ModuleNotFoundError', 'ImportError', 'PermissionError', 'FileNotFoundError', 'RuntimeError', 'AssertionError', 'ValueError', 'TypeError', 'AttributeError', 'other'}
                        and failure['missing_module'] in {'unrest_harness', 'pydantic', 'click', 'fastmcp', 'yaml', 'other'}, 'primary_diagnostic_error')
            diagnostics.append({'source_path_present': row['source_path_present'], 'venv_site_present': row['venv_site_present'], 'prefix_is_venv': row['prefix_is_venv'], 'error_code': failure['error_code'] if failure else None, 'missing_module': failure['missing_module'] if failure else None, 'frame_lines': [frame['line'] for frame in failure['frames']] if failure else [], 'detail_code': failure.get('detail_code') if failure else None, 'error_path_noexec': failure.get('error_path_noexec') if failure else None, 'git_status': row.get('git_status'), 'git_error_code': row.get('git_error_code')})
        projection['native_diagnostics'] = diagnostics
        denials = kernel['primary_denials']
        require(set(denials) <= {'environment_or_cwd', 'unknown_descendant', 'uv_parent_identity',
                                'query_renderer', 'unknown_body', 'original_body_argv',
                                'original_body_shape', 'duplicate_profile'}, 'primary_denial_enum')
        waits = [row for row in kernel['records'] if row['kind'] == 'original_parent_wait4']
        births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
                  and row['identity']['tgid'] == row['child']]
        missing = sum(len([wait for wait in waits if wait['child'] == row['child']
                           and wait['parent_tgid'] == row['identity']['ppid']]) != 1 for row in births)
        projection.update(primary_verified=False, root_raw=kernel['root_parent_wait_raw'],
                          parent_waits=len(births) - missing, missing_parent_waits=missing,
                          kernel_poison_count=len(kernel['poison']), denial_codes=sorted(set(denials)),
                          native_preinit_refusal=kernel['native_preinit_refusal'],
                          native_preinit_profiles=sum(row['kind'] == 'primary_native_preinit'
                                                      for row in kernel['primary_records']),
                          actual_script_sha256=kernel['actual_script_sha256'])
        if (metadata['source_exit_code'] != 0 or kernel['root_parent_wait_raw'] != 0
                or kernel['poison'] or denials or missing or kernel['native_preinit_refusal']
                or kernel['failure_code'] is not None or not kernel['all_commands_dispatched']):
            projection['error_code'] = 'primary_execution_failed'
        else:
            require(kernel['actual_script_sha256'] == metadata['primary_plan']['script_sha256'],
                    'primary_actual_script')
            projection['primary_verified'] = True
        return projection
    if scope == 'producer-controls':
        require(type(metadata['source_exit_code']) is int, 'source_status_type')
        try:
            proof = check_producer(records, metadata['source_exit_code'])
        except Exception as error:
            # A support line number is a typed stage locator, never exception text.
            trace = error.__traceback__
            while trace.tb_next is not None:
                trace = trace.tb_next
            projection.update(error_code='negative_predicate_refused', predicate_line=trace.tb_lineno)
        else:
            projection.update(negative_verified=True, source_exit=proof['original_source_exit_code'],
                              query_raw=proof['query_exit_raw'], query_status=proof['query_exit_normalized'],
                              parent_waits=proof['all_kernel_process_parent_waits'],
                              source_body_dispatched=False, sticky_poison=True)
    elif scope == 'synthetic-controls':
        observer = loads(records['observer.json'])
        projection.update(synthetic_raw=observer['actual_wait_raw'],
                          synthetic_status=observer['actual_wait_normalized'],
                          trace_controls=sum(name.startswith('trace-control-') for name in records))
        if 'control-suite.xml' in records:
            cases = ET.fromstring(records['control-suite.xml']).findall('.//testcase')
            failures = [case for case in cases if any(case.find(tag) is not None
                                                     for tag in ('failure', 'error'))]
            projection.update(control_cases=len(cases), control_failures=len(failures),
                              failed_case_hashes=[digest((case.get('classname', '') + '::'
                                                         + case.get('name', '')).encode())
                                                  for case in failures])
        if metadata['synthetic_exit_code'] != 0 or observer['actual_wait_raw'] != 0:
            projection.update(error_code='synthetic_suite_failed', synthetic_verified=False)
            return projection
        require(metadata['original_source_cases_executed'] == 0
                and observer['actual_wait_normalized'] == 0
                and projection.get('control_failures', 0) == 0, 'synthetic_actual_wait')
        projection.update(synthetic_verified=True, source_cases=0)
    elif scope in {'producer-contract', 'producer-distribution', 'ci-mutations'}:
        kernel = loads(records['kernel-source.json'])
        summary = loads(records['summary.json'])
        cases = ET.fromstring(records['source.xml']).findall('.//testcase')
        expected_cases = 17 if scope == 'ci-mutations' else 2 if scope == 'producer-contract' else 1
        expected_names = ({'test_installed_supported_provider_matrix[claude]',
                           'test_installed_supported_provider_matrix[codex]'}
                          if scope == 'producer-contract' else {
                              'test_checker_builds_and_executes_15_cases_with_extracted_provenance'})
        if scope == 'ci-mutations':
            expected_groups = {'test_ci_constant_dead_guards_fail_through_candidate_cli': 10,
                               'test_ci_literal_dead_shell_branches_fail_through_candidate_cli': 3,
                               'test_ci_live_or_dynamic_guards_remain_accepted_through_candidate_cli': 4}
            names = [case.get('name', '') for case in cases]
            require(len(names) == len(set(names)) == 17 and all(
                sum(name.startswith(prefix + '[') for name in names) == count
                for prefix, count in expected_groups.items()), 'ci_original_collection')
        else:
            require({case.get('name') for case in cases} == expected_names, 'positive_original_cases')
        require(len(cases) == expected_cases and all(
            all(case.find(tag) is None for tag in ('failure', 'error', 'skipped'))
            for case in cases), 'positive_original_junit')
        require(type(metadata['source_exit_code']) is int
                and type(summary['original_pytest_exit_code']) is int
                and type(kernel['root_parent_wait_raw']) is int
                and metadata['source_exit_code'] == 0 and summary['original_pytest_exit_code'] == 0
                and summary['ready'] is True and kernel['root_parent_wait_raw'] == 0
                and kernel['poison'] == [] and kernel['guard_poison'] is False
                and 'failure' not in kernel, 'positive_source_outcome')
        waits = [row for row in kernel['records'] if row['kind'] == 'original_parent_wait4']
        births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
                  and row['identity']['tgid'] == row['child']]
        require(all(len([wait for wait in waits if wait['child'] == birth['child']
                         and wait['parent_tgid'] == birth['identity']['ppid']]) == 1
                    for birth in births), 'positive_kernel_wait_closure')
        events = kernel['source_events']
        if scope != 'ci-mutations':
            require(any(row['kind'] == 'operation_settled' for row in events), 'positive_settlement')
        projection.update(positive_verified=True, junit_cases=len(cases),
                          parent_waits=len(births), source_exit=0, sticky_poison=False,
                          query_returns=sum(row['kind'] == 'query_actual_main_return' for row in events),
                          backend_calls=sum(row['kind'] == 'isolated_actual_backend_call' for row in events),
                          settlements=sum(row['kind'] == 'operation_settled' for row in events))
    return projection


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('run', type=int)
    parser.add_argument('artifact', type=int)
    parser.add_argument('head')
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--support', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    os.umask(0o077)
    args.root.mkdir(mode=0o700)
    output = {'schema': 'direct-record-verification-v1', 'error_code': 'verification_refused'}
    try:
        run, artifact, members = download(args.root, args.run, args.artifact, args.head)
        output = verify(args.root, run, artifact, members, args.key, args.support)
    except Exception:
        # No command, source, exception, stdout or stderr body reaches the operator.
        pass
    (args.root / 'verification.json').write_bytes(canonical(output))
    print(json.dumps(output, sort_keys=True))
    return 0 if 'error_code' not in output else 2


if __name__ == '__main__':
    sys.exit(main())
