"""Reduce actual PRIMARY TEST build records without release authority."""
from __future__ import annotations

from primary_custody import BUILD, WHEEL, SDIST, decode_outputs, kernel_success, loads, sha


def check(records):
    kernel = loads(records['kernel-source.json'])
    plan = kernel['primary_plan']
    if (plan['duty'] != BUILD or plan['package_mode'] != 'TEST'
            or plan['commands'] != [['uv', 'build']]
            or plan['script_sha256'] not in {sha(b'uv build'), sha(b'uv build\n')}):
        raise RuntimeError('primary_package_test_identity')
    kernel_success(records, plan['script_sha256'])
    if kernel['guard_poison'] or kernel['receipt_ledger_poison']:
        raise RuntimeError('primary_package_test_poison')
    native = [row for row in kernel['native_source_records'] if row['kind'] == 'native_source_child']
    if (len(native) != 5 or len({row['pid'] for row in native}) != 5
            or sorted(row['helper'] for row in native) != sorted([
                'main', 'get_requires_for_build_sdist', 'build_sdist',
                'get_requires_for_build_wheel', 'build_wheel'])):
        raise RuntimeError('primary_package_original_helpers')
    for child in native:
        starts = [row for row in kernel['primary_records']
                  if row['kind'] == 'primary_native_preinit' and row['pid'] == child['pid']
                  and row['identity'] == child['identity']]
        ready = [row for row in kernel['source_events']
                 if row['kind'] == 'ready' and row['owner_pid'] == child['pid']
                 and row['token'] == child['token']]
        dispatch = [row for row in kernel['source_events'] if row['owner_pid'] == child['pid']
                    and row['kind'] in {'query_original_dispatch', 'isolated_original_dispatch'}]
        if len(starts) != 1 or len(ready) != 1 or len(dispatch) != 1:
            raise RuntimeError('primary_package_native_ready_dispatch')
    cache = [row for row in kernel['native_source_records'] if row['kind'] == 'original_UV_cache_output']
    if len(cache) != 1 or cache[0]['operation'] != 'source-build' or cache[0]['kernel_exit_raw'] != 0:
        raise RuntimeError('primary_package_cache_closure')
    output = decode_outputs(records['package-output.json'], BUILD)
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']]
    return {'schema': 'unrest.v046.primary-package-build-test-proof.v1',
            'mode': 'TEST', 'original_backend_helpers': 4, 'native_query': 1,
            'actual_parent_waits': len(births), 'missing_waits': 0,
            'archives': {name: sha(output[name]) for name in (WHEEL, SDIST)},
            'eligible_certificate': False, 'source_checkpoint_ready': False,
            'selected_carrier': None}


def check_archive(records):
    from checkpoint_issuer import member_hashes, observed_return
    from primary_custody import ARCHIVE, canonical
    import base64
    kernel = loads(records['kernel-source.json'])
    plan = kernel['primary_plan']
    if (plan['duty'] != ARCHIVE or plan['package_mode'] != 'TEST'
            or plan['commands'] != [['uv', 'run', 'python', 'tools/check_distribution.py', 'dist']]):
        raise RuntimeError('primary_package_archive_test_identity')
    kernel_success(records, plan['script_sha256'])
    if kernel['guard_poison'] or kernel['receipt_ledger_poison']:
        raise RuntimeError('primary_package_archive_test_poison')
    proof = loads(records['package-proof.json'])
    observed_return({'records': {name: base64.b64encode(body).decode()
                                for name, body in records.items()}}, proof)
    output = decode_outputs(records['package-output.json'], ARCHIVE)
    if (proof['schema'] != 'unrest.v046.primary-archive-observation.v1'
            or proof['result']['restart_oracle']['cases'] != 15
            or proof['member_bytes_sha256'] != member_hashes(output)):
        raise RuntimeError('primary_package_archive_original_result')
    imports = [row for row in kernel['primary_records'] if row['kind'] == 'primary_package_input_consumption']
    if (len(imports) != 1 or imports[0]['members'] != {
            name: {'size': len(body), 'sha256': sha(body)} for name, body in output.items()}):
        raise RuntimeError('primary_package_archive_actual_input')
    return {'schema': 'unrest.v046.primary-package-archive-test-proof.v1', 'mode': 'TEST',
            'extracted_cases': 15, 'member_bytes_sha256': proof['member_bytes_sha256'],
            'input_descriptor_sha256': imports[0]['descriptor_sha256'],
            'original_return_sha256': sha(canonical(proof)), 'eligible_certificate': False,
            'source_checkpoint_ready': False, 'selected_carrier': None}


def check_installed(records):
    from checkpoint_issuer import observed_return
    from primary_custody import INSTALLED
    import base64
    kernel = loads(records['kernel-source.json'])
    if kernel['primary_plan'].get('package_mode') != 'TEST' or kernel['primary_plan']['duty'] != INSTALLED:
        raise RuntimeError('primary_package_installed_test_identity')
    kernel_success(records, kernel['actual_script_sha256'])
    from primary_package_trace import verify_retirements
    verify_retirements(kernel['records'])
    proof = loads(records['package-proof.json'])
    observed_return({'records': {name: base64.b64encode(body).decode() for name, body in records.items()}}, proof)
    corruption = [row for row in kernel['native_source_records']
                  if row['kind'] == 'primary_package_installed_corruption']
    if (kernel['guard_poison'] or kernel['receipt_ledger_poison'] or len(corruption) != 1
            or not corruption[0]['corrupt_state_refused'] or not corruption[0]['original_bytes_restored']):
        raise RuntimeError('primary_package_installed_corruption')
    effects = proof['result']
    if (type(effects) is not dict or set(effects) != {'attempts', 'mission_id', 'project_id',
            'restart_resume', 'state', 'terminal_reviews'}
            or type(effects['attempts']) is not int or effects['attempts'] != 2
            or type(effects['terminal_reviews']) is not int or effects['terminal_reviews'] != 1
            or effects['restart_resume'] is not True or effects['state'] != 'done'
            or any(type(effects[key]) is not str or not effects[key] for key in ('mission_id', 'project_id'))):
        raise RuntimeError('primary_package_installed_original_effects')
    decode_outputs(records['package-output.json'], INSTALLED)
    from primary_custody import canonical
    return {'schema': 'unrest.v046.primary-installed-test-proof.v1', 'mode': 'TEST',
            'original_return_sha256': sha(canonical(proof)), 'corruption_refused': True, 'eligible_certificate': False,
            'source_checkpoint_ready': False, 'selected_carrier': None}


def check_checksum(records):
    from primary_custody import CHECKSUM
    kernel = loads(records['kernel-source.json'])
    if kernel['primary_plan'].get('package_mode') != 'TEST' or kernel['primary_plan']['duty'] != CHECKSUM:
        raise RuntimeError('primary_package_checksum_test_identity')
    kernel_success(records, kernel['actual_script_sha256'])
    if kernel['guard_poison'] or kernel['receipt_ledger_poison']:
        raise RuntimeError('primary_package_checksum_poison')
    output = decode_outputs(records['package-output.json'], CHECKSUM)
    return {'schema': 'unrest.v046.primary-checksum-test-proof.v1', 'mode': 'TEST',
            'checksum_sha256': sha(output['SHA256SUMS']), 'eligible_certificate': False,
            'source_checkpoint_ready': False, 'selected_carrier': None}
