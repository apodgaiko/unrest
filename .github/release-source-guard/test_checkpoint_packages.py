"""Package replay byte checks; synthetic ZIPs never prove actual CI execution."""
import copy
import io
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_packages import SDIST, WHEEL, verified_members, materialize
from checkpoint_receipt import ReceiptRefused, sha256


def fixture(mutation=None):
    members = {WHEEL: b'controlled wheel', SDIST: b'controlled sdist'}
    hashes = {name: sha256(body) for name, body in members.items()}
    members['SHA256SUMS'] = ''.join(hashes[name] + '  ' + name + '\n' for name in (WHEEL, SDIST)).encode()
    reuse = {'execution_kind': 'verified-same-commit-reuse', 'head_sha': 'a' * 40,
             'original_run_id': 1, 'package_archives': hashes}
    if mutation == 'changed_bytes':
        members[WHEEL] += b'drift'
    if mutation == 'checksum':
        members['SHA256SUMS'] = b'not the original checksums'
    if mutation == 'foreign_member':
        members['../foreign'] = b'forbidden'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, body in members.items():
            info = zipfile.ZipInfo(name)
            if mutation == 'symlink' and name == WHEEL:
                info.external_attr = 0o120777 << 16
            archive.writestr(info, body)
    body = buffer.getvalue()
    artifact = {'id': 7, 'name': 'unrest-v0.4.6-python313', 'expired': False,
                'size_in_bytes': len(body), 'digest': 'sha256:' + sha256(body),
                'workflow_run': {'id': 1, 'head_sha': 'a' * 40}}
    return body, artifact, reuse, members


def test_original_package_bytes_and_checksums_close():
    body, artifact, reuse, members = fixture()
    assert verified_members(body, artifact, reuse) == members


@pytest.mark.parametrize('mutation', ['changed_bytes', 'checksum', 'foreign_member', 'symlink',
                                     'expired', 'other_head', 'other_run', 'zip_digest'])
def test_no_partial_foreign_or_changed_package_replay(mutation):
    body, artifact, reuse, _ = fixture(mutation)
    if mutation == 'expired':
        artifact['expired'] = True
    elif mutation == 'other_head':
        artifact['workflow_run']['head_sha'] = 'b' * 40
    elif mutation == 'other_run':
        artifact['workflow_run']['id'] = 2
    elif mutation == 'zip_digest':
        artifact['digest'] = 'sha256:' + '0' * 64
    with pytest.raises(ReceiptRefused):
        verified_members(body, artifact, reuse)


def test_read_api_materializes_only_verified_bytes_and_never_overwrites(tmp_path):
    body, artifact, reuse, members = fixture()
    class Reader:
        def api(self, path):
            assert path == 'actions/runs/1/artifacts?per_page=100'
            return {'total_count': 1, 'artifacts': [copy.deepcopy(artifact)]}
        def archive(self, item):
            assert item == artifact
            return body
    target = tmp_path / 'dist'
    proof = materialize(Reader(), reuse, target)
    assert proof['package_artifact_id'] == 7
    assert {path.name: path.read_bytes() for path in target.iterdir()} == members
    with pytest.raises(ReceiptRefused):
        materialize(Reader(), reuse, target)
