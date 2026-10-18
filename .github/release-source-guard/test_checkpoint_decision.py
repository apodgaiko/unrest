"""Decision controls exercise lookup; synthetic objects never certify CI."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_decision import decide
from checkpoint_receipt import ReceiptRefused
from test_checkpoint_lookup import Reader


def test_authentic_chain_is_required_before_reuse_decision():
    reader = Reader()
    decision = decide(reader, reader.expected, 99)
    assert decision['decision'] == 'reuse-authentic-full'
    assert decision['receipt']['original_job_id'] == 2
    assert decision['source_checkpoint_ready'] is False


def test_no_previous_execution_requires_first_execution():
    reader = Reader()
    reader.runs = []
    result = decide(reader, reader.expected, 99)
    assert result['decision'] == 'execute-first-full' and result['receipt'] is None


def test_prior_failed_source_cannot_be_silently_reexecuted_at_same_sha():
    reader = Reader()
    reader.run['conclusion'] = 'failure'
    reader.jobs[0]['steps'][5]['conclusion'] = 'failure'
    with pytest.raises(ReceiptRefused):
        decide(reader, reader.expected, 99)


def test_scratch_workflow_does_not_become_a_full_certificate():
    reader = Reader()
    reader.run['head_branch'] = 'codex/source-guard-structured-20261018-primary-unit'
    assert decide(reader, reader.expected, 99)['decision'] == 'execute-first-full'


@pytest.mark.parametrize('key', ['exit_code', 'build_exit_code'])
def test_boolean_does_not_count_as_numeric_exit_status(key):
    reader = Reader()
    if key == 'exit_code':
        reader.receipt['source'][key] = False
    else:
        reader.receipt['package'][key] = False
    from test_checkpoint_receipt import seal
    reader.archive_bytes, reader.artifact = seal(reader.receipt, reader.cipher)
    with pytest.raises(ReceiptRefused):
        decide(reader, reader.expected, 99)
