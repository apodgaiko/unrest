"""Bounded hashes and counts from current producer-owned failure records only."""
from collections import Counter
import hashlib
import json
import re

GROUPS = ('primary_denials', 'kernel_poison', 'receipt_poison', 'forbidden_reasons',
          'receipt_reasons', 'dependency_refusals', 'runtime_member_stages',
          'junit_error_cases', 'junit_failed_cases', 'last_native_predicate',
          'runtime_member_names', 'cache_member_names')
MAX_CODES = 2


def digest(value):
    return hashlib.sha256(value).hexdigest()


def histogram(values, already_hashed=False):
    values = [value for value in values if type(value) is str]
    if already_hashed and any(re.fullmatch('[0-9a-f]{64}', value) is None for value in values):
        raise ValueError('failure_diagnostic_digest')
    counts = Counter(values if already_hashed else (digest(value.encode()) for value in values))
    rows = sorted(counts.items())
    return {'total': sum(counts.values()), 'distinct': len(rows),
            'complete_sha256': digest(json.dumps(rows, separators=(',', ':')).encode()),
            'codes': [{'sha256': code, 'count': count} for code, count in rows[:MAX_CODES]]}


def build(kernel, cases=()):
    groups = {
        'primary_denials': kernel.get('primary_denials', []),
        'kernel_poison': kernel.get('poison', []),
        'receipt_poison': kernel.get('receipt_ledger_poison', []),
        'forbidden_reasons': [row.get('reason') for row in kernel.get('source_events', [])
                              if row.get('kind') == 'forbidden'],
        'receipt_reasons': [row.get('reason') for row in kernel.get('receipts', []) if row.get('ok') is not True],
        'dependency_refusals': [row.get('code_sha256') for row in kernel.get('source_events', [])
                                if row.get('kind') == 'primary_dependency_refusal'],
        'runtime_member_stages': [row.get('stage') for row in kernel.get('native_source_records', [])
                                  if row.get('kind') == 'primary_runtime_member_refusal'],
    }
    native = kernel.get('native_source_records', [])
    predicates = [row for row in native if row.get('kind') == 'native_producer_predicate']
    groups['last_native_predicate'] = [row['stage'] + ':' + str(row['value']) for row in predicates[-1:]
                                      if type(row.get('stage')) is str and type(row.get('value')) is bool]
    groups['runtime_member_names'] = [row.get('member_sha256') for row in native
                                      if row.get('kind') == 'primary_runtime_member_refusal']
    groups['cache_member_names'] = [row.get('member_sha256') for row in native
                                    if row.get('kind') in {'primary_cache_output_unbound', 'primary_cache_unbound_member'}]
    for category, outcome in (('junit_error_cases', 'error'), ('junit_failed_cases', 'failure')):
        groups[category] = [case.attrib.get('classname', '') + '\0' + case.attrib.get('name', '')
                            for case in cases if case.findall(outcome)]
    return {name: histogram(groups[name], name in {'dependency_refusals', 'runtime_member_names',
                                                  'cache_member_names'}) for name in GROUPS}


def validate(value):
    def number(value):
        return type(value) is int and 0 <= value <= (1 << 64) - 1
    def pin(value):
        return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    if type(value) is not dict or set(value) != set(GROUPS):
        return False
    for row in value.values():
        if (type(row) is not dict or set(row) != {'total', 'distinct', 'complete_sha256', 'codes'}
                or not number(row['total']) or not number(row['distinct'])
                or row['distinct'] > row['total'] or not pin(row['complete_sha256'])
                or type(row['codes']) is not list or len(row['codes']) != min(MAX_CODES, row['distinct'])):
            return False
        previous = ''
        subtotal = 0
        for code in row['codes']:
            if (type(code) is not dict or set(code) != {'sha256', 'count'} or not pin(code['sha256'])
                    or code['sha256'] <= previous or not number(code['count']) or code['count'] == 0):
                return False
            previous = code['sha256']
            subtotal += code['count']
        if subtotal > row['total'] or row['distinct'] <= MAX_CODES and subtotal != row['total']:
            return False
    return True
