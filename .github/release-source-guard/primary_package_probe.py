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
