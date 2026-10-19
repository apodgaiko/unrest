"""Frozen public wheel input selection cannot become a generic download route."""
import copy

import pytest
from packaging.tags import Tag

from primary_package_wheels import select, LIMIT, TOTAL


def row():
    return {'package': [{'name': 'example', 'version': '1.0', 'wheels': [
        {'url': 'https://files.pythonhosted.org/packages/00/example-1.0-py3-none-any.whl',
         'hash': 'sha256:' + 'a' * 64, 'size': 123}]}]}


def test_exact_current_platform_selection_ignores_incompatible_wheels():
    lock = row()
    incompatible = copy.deepcopy(lock['package'][0]['wheels'][0])
    incompatible['url'] = incompatible['url'].replace('py3-none-any', 'cp313-cp313-win_amd64')
    lock['package'][0]['wheels'].append(incompatible)
    actual = select(lock, [Tag('py3', 'none', 'any')])
    assert len(actual) == 1 and actual[0]['name'] == 'example-1.0-py3-none-any.whl'


@pytest.mark.parametrize('mutation', ['host', 'http', 'query', 'fragment', 'path', 'name',
                                     'version', 'hash', 'hash-hex', 'size', 'bool-size', 'oversize'])
def test_foreign_or_unpinned_input_refused(mutation):
    lock = row()
    wheel = lock['package'][0]['wheels'][0]
    if mutation == 'host':
        wheel['url'] = wheel['url'].replace('files.pythonhosted.org', 'foreign.invalid')
    elif mutation == 'http':
        wheel['url'] = wheel['url'].replace('https:', 'http:')
    elif mutation == 'query':
        wheel['url'] += '?foreign=1'
    elif mutation == 'fragment':
        wheel['url'] += '#foreign'
    elif mutation == 'path':
        wheel['url'] = wheel['url'].replace('/packages/', '/foreign/')
    elif mutation == 'name':
        lock['package'][0]['name'] = 'foreign'
    elif mutation == 'version':
        lock['package'][0]['version'] = '2.0'
    elif mutation == 'hash':
        wheel['hash'] = 'unbound'
    elif mutation == 'hash-hex':
        wheel['hash'] = 'sha256:' + 'g' * 64
    elif mutation == 'bool-size':
        wheel['size'] = True
    elif mutation == 'size':
        wheel['size'] = 0
    else:
        wheel['size'] = LIMIT + 1
    with pytest.raises(RuntimeError, match='package_wheel_'):
        select(lock, [Tag('py3', 'none', 'any')])


def test_empty_or_total_oversize_input_refused():
    with pytest.raises(RuntimeError, match='input_bound'):
        select(row(), [])
    lock = row()
    lock['package'][0]['wheels'][0]['size'] = LIMIT
    for name in ('second', 'third'):
        item = copy.deepcopy(lock['package'][0])
        item['name'] = name
        item['wheels'][0]['url'] = item['wheels'][0]['url'].replace('example-', name + '-')
        lock['package'].append(item)
    assert sum(package['wheels'][0]['size'] for package in lock['package']) > TOTAL
    with pytest.raises(RuntimeError, match='input_bound'):
        select(lock, [Tag('py3', 'none', 'any')])
