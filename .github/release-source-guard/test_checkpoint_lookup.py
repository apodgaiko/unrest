"""Controlled Actions metadata only; no fabricated object is an execution proof."""
import importlib.util
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_receipt import ReceiptRefused
from test_checkpoint_receipt import fixture, seal

spec = importlib.util.spec_from_file_location(
    'checkpoint_lookup', Path(__file__).with_name('checkpoint_lookup.py'))
assert spec is not None and spec.loader is not None
lookup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lookup)


class Reader:
    def __init__(self):
        self.expected, self.run, self.jobs, self.receipt, self.cipher = fixture()
        self.archive_bytes, self.artifact = seal(self.receipt, self.cipher)
        self.runs = [self.run]
        self.paths = []

    def api(self, path):
        self.paths.append(path)
        if path.startswith('actions/workflows/'):
            return {'total_count': len(self.runs), 'workflow_runs': self.runs}
        if '/jobs?' in path:
            return {'total_count': len(self.jobs), 'jobs': self.jobs}
        if '/artifacts?' in path:
            return {'total_count': 1, 'artifacts': [self.artifact]}
        raise AssertionError(path)

    def archive(self, artifact):
        assert artifact is self.artifact
        return self.archive_bytes


def test_lookup_requires_actual_run_job_artifact_chain():
    reader = Reader()
    result = lookup.lookup(reader, reader.expected, 99)
    assert result['original_run_id'] == 1
    assert len(reader.paths) == 3


def test_new_commit_with_no_execution_returns_no_reuse():
    reader = Reader()
    reader.runs = []
    assert lookup.lookup(reader, reader.expected, 99) is None


def test_current_run_cannot_authorize_its_own_reuse():
    reader = Reader()
    assert lookup.lookup(reader, reader.expected, 1) is None
    assert len(reader.paths) == 1


@pytest.mark.parametrize('condition', ['pending', 'partial_package', 'no_evidence', 'wrong_commit'])
def test_unsettled_or_incomplete_prior_execution_fails_closed(condition):
    reader = Reader()
    if condition == 'pending':
        reader.run['status'] = 'in_progress'
    elif condition == 'partial_package':
        reader.run['conclusion'] = 'failure'
    elif condition == 'no_evidence':
        reader.artifact['name'] = 'readiness'
    elif condition == 'wrong_commit':
        reader.run['head_sha'] = 'e' * 40
    with pytest.raises(ReceiptRefused):
        lookup.lookup(reader, reader.expected, 99)


def test_read_credential_is_not_a_public_value():
    for value in ('', 'invalid\nheader', 'invalid\rheader'):
        with pytest.raises(ReceiptRefused):
            lookup.ActionsReader(value)
    with pytest.raises(ReceiptRefused):
        lookup.ActionsReader('controlled').api('../unrelated-repository')


def test_signed_artifact_redirect_does_not_receive_api_authorization(monkeypatch):
    import io
    import urllib.error
    from email.message import Message
    requests = []
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 60
            if len(requests) == 1:
                headers = Message()
                headers['Location'] = 'https://controlled.blob.core.windows.net/immutable?sig=controlled'
                raise urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())
            return io.BytesIO(b'controlled archive bytes')
    monkeypatch.setattr(lookup.urllib.request, 'build_opener', lambda *args: Opener())
    assert lookup.ActionsReader('controlled-read-token').archive({'id': 3}) == b'controlled archive bytes'
    assert requests[0].get_header('Authorization') == 'Bearer controlled-read-token'
    assert requests[1].get_header('Authorization') is None
    assert requests[0].full_url == lookup.API + 'actions/artifacts/3/zip'


@pytest.mark.parametrize('origin', ['http://controlled.blob.core.windows.net/a',
                                   'https://foreign.example/a',
                                   'https://user:password@controlled.blob.core.windows.net/a',
                                   'https://controlled.blob.core.windows.net:444/a'])
def test_artifact_redirect_cannot_select_foreign_or_credentialed_origin(monkeypatch, origin):
    import io
    import urllib.error
    from email.message import Message
    requests = []
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            headers = Message()
            headers['Location'] = origin
            raise urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())
    monkeypatch.setattr(lookup.urllib.request, 'build_opener', lambda *args: Opener())
    with pytest.raises(ReceiptRefused):
        lookup.ActionsReader('controlled').archive({'id': 3})
    assert len(requests) == 1


def promotion_reader(mutate=False):
    import copy
    original = Reader()
    verified = lookup.lookup(original, original.expected, 99)
    promoted_run = {**original.run, 'id': 4}
    promoted_job = copy.deepcopy(original.jobs[0])
    promoted_job.update(id=6, run_id=4)
    marker = {'schema': 'unrest.v046.primary-reuse.v1', 'execution_kind': 'verified-same-commit-reuse',
              'run_id': 4, 'run_attempt': 1, 'expected': original.expected,
              'original': copy.deepcopy(verified),
              'ciphertext_sha256': verified['ciphertext_sha256']}
    if mutate:
        marker['original']['original_run_id'] = 999
    import io
    import json
    import zipfile
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('safe-provenance.json', json.dumps(marker))
        archive.writestr('evidence.cms', original.cipher)
    promoted_bytes = stream.getvalue()
    promoted_artifact = {**original.artifact, 'id': 5, 'name': 'unrest-v046-reuse-4-1',
                         'workflow_run': {'id': 4, 'head_sha': original.expected['head_sha']},
                         'size_in_bytes': len(promoted_bytes),
                         'digest': 'sha256:' + lookup.sha256(promoted_bytes)}
    class Promoted(Reader):
        def api(self, path):
            if path.startswith('actions/runs/4/'):
                if '/jobs?' in path:
                    return {'total_count': 1, 'jobs': [promoted_job]}
                return {'total_count': 1, 'artifacts': [promoted_artifact]}
            return super().api(path)
        def archive(self, artifact):
            return promoted_bytes if artifact['id'] == 5 else super().archive(artifact)
    reader = Promoted()
    # Keep the exact original instance used by the inherited archive identity
    # assertion while adding a separate successful promotion.
    reader.expected, reader.run, reader.jobs = original.expected, original.run, original.jobs
    reader.artifact, reader.archive_bytes = original.artifact, original.archive_bytes
    reader.runs = [reader.run, promoted_run]
    return reader


def test_same_sha_promotion_resolves_back_to_original_full_certificate():
    reader = promotion_reader()
    result = lookup.lookup(reader, reader.expected, 99)
    assert result['original_run_id'] == 1 and result['artifact_id'] == 3


@pytest.mark.parametrize('mutation', ['changed_reference', 'original_missing'])
def test_promotion_never_substitutes_for_original_full_certificate(mutation):
    reader = promotion_reader(mutation == 'changed_reference')
    if mutation == 'original_missing':
        reader.runs = reader.runs[1:]
    with pytest.raises(ReceiptRefused):
        lookup.lookup(reader, reader.expected, 99)
