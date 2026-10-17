"""Privacy and identity controls exercise direct archives, never log consumers."""
import base64
import copy
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import structured_evidence as evidence

CANARY = 'SYNTHETIC_PRIVATE_CANARY_must_stay_encrypted'


def identity():
    return {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'run_id': '12',
            'run_attempt': '1', 'workflow_sha': 'a' * 40, 'support_sha256': 'b' * 64,
            'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@refs/heads/codex/source-guard-structured-20261018-test',
            'artifact_name': 'v046-source-producer-controls-12-1'}


def transport(records=None):
    records = records or {'kernel-source.json': json.dumps({'private': CANARY}).encode(),
                          'source-output.log': CANARY.encode(), 'custodian.stderr': CANARY.encode()}
    return b'PRIVATE-EVIDENCE:' + json.dumps({name: base64.b64encode(body).decode()
                                            for name, body in records.items()}).encode() + b'\n'


def archive(root, mutate=None):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as target:
        for path in sorted(root.iterdir()):
            target.add(path, arcname=path.name, recursive=False)
        if mutate:
            name, body, kind = mutate
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.type = kind
            target.addfile(member, io.BytesIO(body))
    return data.getvalue()


def exported(tmp_path):
    evidence.export(transport(), tmp_path, identity(), 'producer-controls')
    return evidence.digest((tmp_path / evidence.MEMBER).read_bytes())


def test_private_canaries_never_print_and_consumer_never_opens_logs(tmp_path, capsys, monkeypatch):
    pin = exported(tmp_path)
    original = tarfile.TarFile.extractfile
    opened = []
    def checked(source, member, *args, **kwargs):
        name = member if isinstance(member, str) else member.name
        assert name in {evidence.MEMBER, 'structured-kernel-source.json'}
        opened.append(name)
        return original(source, member, *args, **kwargs)
    monkeypatch.setattr(tarfile.TarFile, 'extractfile', checked)
    scope, records = evidence.consume(archive(tmp_path), identity(), pin)
    assert scope == 'producer-controls' and CANARY.encode() in records['kernel-source.json']
    assert set(opened) == {evidence.MEMBER, 'structured-kernel-source.json'}
    assert capsys.readouterr() == ('', '')
    envelope = json.loads((tmp_path / evidence.MEMBER).read_bytes())
    assert CANARY not in json.dumps(envelope)


@pytest.mark.parametrize('field', sorted(evidence.IDENTITY))
def test_each_execution_identity_is_bound(tmp_path, field):
    pin = exported(tmp_path)
    expected = identity()
    expected[field] = 'different'
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path), expected, pin)


@pytest.mark.parametrize('name,kind', [('../escape', tarfile.REGTYPE),
                                      ('link', tarfile.SYMTYPE),
                                      (evidence.MEMBER, tarfile.REGTYPE)])
def test_archive_paths_types_duplicates_refuse(tmp_path, name, kind):
    pin = exported(tmp_path)
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path, (name, b'', kind)), identity(), pin)


@pytest.mark.parametrize('mutation', ['unknown', 'full', 'ready', 'hash', 'private_member', 'extra'])
def test_malformed_unknown_or_escalated_envelope_refuses(tmp_path, mutation):
    exported(tmp_path)
    path = tmp_path / evidence.MEMBER
    envelope = json.loads(path.read_bytes())
    if mutation == 'unknown':
        envelope['records']['unknown.json'] = copy.deepcopy(envelope['records']['kernel-source.json'])
    elif mutation == 'full':
        envelope['scope'] = 'executed-primary-full'
    elif mutation == 'ready':
        envelope['source_checkpoint_ready'] = True
    elif mutation == 'hash':
        envelope['records']['kernel-source.json']['sha256'] = '0' * 64
    elif mutation == 'private_member':
        envelope['records']['kernel-source.json']['member'] = 'private-source-output.log'
    else:
        envelope['secret'] = CANARY
    path.write_bytes(evidence.canonical(envelope))
    with pytest.raises(evidence.EvidenceRefused):
        evidence.consume(archive(tmp_path), identity(), evidence.digest(path.read_bytes()))


def test_unknown_transport_record_and_duplicate_fields_refuse(tmp_path):
    for body in (transport({'unknown.log': CANARY.encode()}),
                 b'PRIVATE-EVIDENCE:{"x":"a","x":"b"}\n',
                 b'PRIVATE-EVIDENCE:{broken}\n'):
        with pytest.raises(evidence.EvidenceRefused):
            evidence.export(body, tmp_path, identity(), 'producer-controls')


def test_real_owned_process_capture_is_direct_and_silent(tmp_path, capsys):
    body = transport()
    result, records = evidence.capture(
        [sys.executable, '-I', '-c', 'import os; os.write(1, ' + repr(body) + ')'],
        tmp_path, identity(), 'producer-controls')
    assert result.returncode == 0 and 'kernel-source.json' in records
    assert (tmp_path / evidence.MEMBER).is_file()
    assert capsys.readouterr() == ('', '')


def test_cms_roundtrip_and_operator_projection_keep_private_canaries(tmp_path, capsys):
    import os
    import subprocess
    from consume_evidence import verify
    raw = tmp_path / 'raw'
    raw.mkdir(mode=0o700)
    exported(raw)
    support = tmp_path / 'support'
    support.mkdir()
    (support / 'test.py').write_text('# synthetic support\n')
    pins = {'test.py': evidence.digest((support / 'test.py').read_bytes())}
    direct = identity()
    direct['support_sha256'] = evidence.digest(evidence.canonical(pins))
    evidence.export(transport(), raw, direct, 'producer-controls')
    plaintext = archive(raw)
    key, cert = tmp_path / 'key.pem', tmp_path / 'cert.pem'
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                             '-subj', '/CN=synthetic-private-control', '-days', '1',
                             '-keyout', str(key), '-out', str(cert)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0
    os.chmod(key, 0o600)
    key_pin = evidence.digest(key.read_bytes())
    original = tmp_path / 'original.tar.gz'
    original.write_bytes(plaintext)
    cipher = tmp_path / 'evidence.cms'
    result = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc',
                             '-outform', 'DER', '-in', str(original), '-out', str(cipher), str(cert)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0
    metadata = {'support': pins, 'direct_identity': direct, 'source_checkpoint_ready': False,
                'selected_carrier': None, 'source_exit_code': 2,
                'structured_envelope_sha256': evidence.digest((raw / evidence.MEMBER).read_bytes()),
                'ciphertext_sha256': evidence.digest(cipher.read_bytes()),
                'plaintext_archive_sha256': evidence.digest(plaintext)}
    members = {'safe-provenance.json': evidence.canonical(metadata), 'evidence.cms': cipher.read_bytes()}
    run = {'id': 12, 'run_attempt': 1, 'head_sha': 'a' * 40,
           'head_branch': 'codex/source-guard-structured-20261018-test'}
    artifact = {'id': 7, 'name': direct['artifact_name']}
    projected = verify(tmp_path, run, artifact, members, key, support)
    assert projected['error_code'] == 'negative_predicate_refused'
    assert CANARY not in json.dumps(projected) and CANARY not in json.dumps(metadata)
    assert CANARY.encode() not in cipher.read_bytes()
    assert evidence.digest(key.read_bytes()) == key_pin
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('kind', ['readiness', 'producer-controls', 'producer-contract',
                                 'producer-distribution', 'ci-mutations'])
def test_artifact_scope_identity_is_finite(kind):
    current = identity()
    current['artifact_name'] = 'v046-source-' + kind + '-12-1'
    evidence.identity_check(current)


def test_runner_failure_record_excludes_exception_text_and_code_bodies(tmp_path, capsys, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location('private_runner_control',
                                                  Path(__file__).with_name('source_runner.py'))
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    def failed_main():
        runner.STAGE = 'pytest'
        raise RuntimeError(CANARY)
    real_open, real_rename = runner.os.open, runner.os.rename
    def owned_open(path, flags, mode):
        assert path == '/work/.runner-stage.part'
        return real_open(tmp_path / '.runner-stage.part', flags, mode)
    def owned_rename(origin, target):
        assert origin == '/work/.runner-stage.part' and target == '/work/runner-stage.json'
        return real_rename(tmp_path / '.runner-stage.part', tmp_path / 'runner-stage.json')
    monkeypatch.setattr(runner, 'main', failed_main)
    monkeypatch.setattr(runner.os, 'open', owned_open)
    monkeypatch.setattr(runner.os, 'rename', owned_rename)
    assert runner.entry() == 125
    body = (tmp_path / 'runner-stage.json').read_bytes()
    record = json.loads(body)
    assert CANARY.encode() not in body
    assert record['stage'] == 'pytest' and record['error_code'] == 'RuntimeError'
    assert record['original_pytest_exit_code'] is None
    assert all(set(frame) == {'file_sha256', 'line'} for frame in record['frames'])
    assert capsys.readouterr() == ('', '')
