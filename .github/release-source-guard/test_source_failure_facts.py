"""Failure diagnostics remain finite, private and non-authoritative."""
import copy
import json
import pytest
import source_failure_facts as facts
import structured_evidence as evidence
from test_source_transport import identity, INVOCATION


def test_current_failure_codes_are_only_bounded_hashes_and_counts():
    private = 'SYNTHETIC_PRIVATE_CANARY_failure_body'
    kernel = {'primary_denials': [private, private], 'poison': ['kernel_code'],
              'receipt_ledger_poison': ['receipt_code'],
              'source_events': [{'kind': 'forbidden', 'reason': 'reason_code'},
                                {'kind': 'primary_dependency_refusal', 'code_sha256': 'a' * 64}],
              'receipts': [{'ok': False, 'reason': 'receipt_reason'}, {'ok': True, 'reason': private}],
              'native_source_records': [{'kind': 'primary_runtime_member_refusal', 'stage': 'stage_code', 'member_sha256': 'b' * 64}]}
    value = facts.build(kernel)
    assert facts.validate(value)
    assert private not in json.dumps(value)
    assert value['primary_denials']['total'] == 2
    assert value['primary_denials']['codes'] == [{'sha256': facts.digest(private.encode()), 'count': 2}]
    assert all(row['total'] == 1 for name, row in value.items() if name not in {'primary_denials', 'junit_error_cases', 'junit_failed_cases', 'last_native_predicate', 'cache_member_names'})
    body = evidence.source_header({'kernel-source.json': evidence.canonical(kernel)}, kernel,
                                  identity(), INVOCATION, 2)
    assert len(body) < evidence.HEADER_LIMIT
    header = evidence.loads(body[len(evidence.HEADER_PREFIX):-1])
    assert header['failure_facts'] == value
    assert header['source_checkpoint_ready'] is False and header['selected_carrier'] is None
    assert private.encode() not in body


def test_many_codes_keep_complete_digest_without_expanding_the_header():
    kernel = {'primary_denials': ['code_' + str(i) for i in range(1000)]}
    value = facts.build(kernel)
    row = value['primary_denials']
    assert row['total'] == row['distinct'] == 1000 and len(row['codes']) == 2
    assert facts.validate(value)
    changed = facts.build({'primary_denials': [*kernel['primary_denials'], 'other']})
    assert changed['primary_denials']['complete_sha256'] != row['complete_sha256']
    for name in facts.GROUPS:
        value[name] = copy.deepcopy(row)
    assert len(evidence.canonical(value)) < 4500
    assert facts.validate(value)


@pytest.mark.parametrize('mutation', ['category', 'body', 'extra', 'count', 'order', 'digest', 'too_many'])
def test_unknown_or_malformed_failure_facts_refuse(mutation):
    value = facts.build({'primary_denials': ['a', 'b']})
    row = value['primary_denials']
    if mutation == 'category':
        value['unknown'] = value.pop('kernel_poison')
    elif mutation == 'body':
        row['message'] = 'forbidden body'
    elif mutation == 'extra':
        row['codes'][0]['body'] = 'forbidden body'
    elif mutation == 'count':
        row['total'] = True
    elif mutation == 'order':
        row['codes'].reverse()
    elif mutation == 'digest':
        row['codes'][0]['sha256'] = 'unknown'
    elif mutation == 'too_many':
        row['codes'].append(copy.deepcopy(row['codes'][0]))
    assert not facts.validate(value)
    header = evidence.loads(evidence.source_header({'kernel-source.json': b'{}'}, {}, identity(),
                                                   INVOCATION, 2)[len(evidence.HEADER_PREFIX):-1])
    header['failure_facts'] = value
    with pytest.raises(evidence.EvidenceRefused, match='header_failure_facts'):
        evidence.validate_header(header, identity(), INVOCATION)


def test_junit_categories_hash_case_identity_without_reading_message_bodies():
    import xml.etree.ElementTree as ET
    case = ET.fromstring('<testcase classname="public_case" name="original"><error>PRIVATE_BODY</error></testcase>')
    value = facts.build({}, [case])
    row = value['junit_error_cases']
    assert row['total'] == 1 and row['codes'][0]['sha256'] == facts.digest(b'public_case\0original')
    assert value['junit_failed_cases']['total'] == 0
    assert 'PRIVATE_BODY' not in json.dumps(value) and 'public_case' not in json.dumps(value)
