"""Finite metadata is bound to the original query and canonical Unix ctime."""
import copy
from types import SimpleNamespace

import pytest

from primary_package_cache import admit, expected, identical
from structured_evidence import identity_check, EvidenceRefused
from test_primary_package_entry import execution


def query():
    return {'result': 'success', 'platform': {'os': {'name': 'manylinux', 'major': 2, 'minor': 40},
            'arch': 'x86_64'}, 'markers': {'python_full_version': '3.13.12'},
            'scheme': {'purelib': 'pure', 'platlib': 'plat', 'scripts': 'bin', 'data': 'root', 'include': 'h'},
            'virtualenv': {'purelib': 'vpure', 'platlib': 'vplat', 'scripts': 'vbin', 'data': 'vroot', 'include': 'vh'},
            'manylinux_compatible': True, 'sys_prefix': 'prefix', 'sys_base_exec_prefix': 'exec-prefix',
            'sys_base_prefix': 'base-prefix', 'sys_base_executable': None, 'sys_executable': 'image',
            'sys_path': ['one', 'two'], 'site_packages': ['site'], 'stdlib': 'standard',
            'standalone': False, 'pointer_size': '64', 'gil_disabled': False, 'debug_enabled': True}


def test_complete_rust_field_order_and_unix_ctime_nanoseconds():
    assert expected(query(), 123000000456) == [[123, 456], [
        [['manylinux', 2, 40], 'x86_64'], {'python_full_version': '3.13.12'},
        ['pure', 'plat', 'bin', 'root', 'h'], ['vpure', 'vplat', 'vbin', 'vroot', 'vh'],
        True, 'prefix', 'exec-prefix', 'base-prefix', None, 'image', ['one', 'two'], ['site'],
        'standard', False, '64', False, True]]


@pytest.mark.parametrize('mutation', ['timestamp', 'nanoseconds', 'field', 'field_order',
                                    'extra', 'missing', 'bool_as_int', 'int_as_bool',
                                    'mapping_extra', 'tuple_as_array'])
def test_every_field_and_type_remains_required(mutation):
    wanted = expected(query(), 123000000456)
    actual = copy.deepcopy(wanted)
    if mutation == 'timestamp':
        actual[0][0] += 1
    elif mutation == 'nanoseconds':
        actual[0][1] += 1
    elif mutation == 'field':
        actual[1][9] = 'foreign image'
    elif mutation == 'field_order':
        actual[1][2][0], actual[1][2][1] = actual[1][2][1], actual[1][2][0]
    elif mutation == 'extra':
        actual[1].append('foreign')
    elif mutation == 'missing':
        actual[1].pop()
    elif mutation == 'bool_as_int':
        actual[1][4] = 1
    elif mutation == 'int_as_bool':
        actual[0][1] = True
    elif mutation == 'mapping_extra':
        actual[1][1]['extra'] = 'foreign'
    else:
        actual[1][10] = tuple(actual[1][10])
    assert not identical(actual, wanted)


@pytest.mark.parametrize('context', [{}, {'operation': 'source-build'},
                                    {'operation': 'source-install', 'package_origin': {}},
                                    {'operation': 'source-build', 'package_origin': {'path': 'foreign'}}])
def test_original_and_foreign_origins_never_gain_cache_authority(context):
    assert admit(object(), context, 'key', {}, {}, {}, object()) is False


@pytest.mark.parametrize('mutation', ['python_file', 'other_bucket', 'extra_depth', 'duplicate', 'poison', 'supervisor_poison'])
def test_metadata_layout_never_becomes_a_generic_cache_allowlist(mutation):
    context = {'operation': 'source-build', 'package_origin': {'path': 'bound', 'sha256': 'a' * 64}}
    relative = 'interpreter-v4/shard/exact.msgpack'
    if mutation == 'python_file':
        relative = 'interpreter-v4/shard/python.py'
    elif mutation == 'other_bucket':
        relative = 'built-wheels-v5/shard/exact.msgpack'
    elif mutation == 'extra_depth':
        relative = 'interpreter-v4/a/b/exact.msgpack'
    current = {'key': {'type': 'file'}}
    names = {'key': relative}
    if mutation == 'duplicate':
        current['other'] = {'type': 'file'}
        names['other'] = 'interpreter-v4/shard/foreign.msgpack'
    producers = SimpleNamespace(cache_current={}, supervisor=SimpleNamespace(poisoned=mutation == 'supervisor_poison'))
    trace = SimpleNamespace(poison=['refused'] if mutation == 'poison' else [])
    assert admit(producers, context, 'key', current['key'], current, names, trace) is False


@pytest.mark.parametrize('epoch', ['01', '02'])
def test_exact_new_cache_record_epochs(epoch):
    identity_check(execution('cache-record-' + epoch))


@pytest.mark.parametrize('epoch', ['00', '03', '1', '001', '01-extra', '../01'])
def test_cache_record_epoch_prefix_is_not_authority(epoch):
    with pytest.raises(EvidenceRefused):
        identity_check(execution('cache-record-' + epoch))
