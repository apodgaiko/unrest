"""Synthetic custody controls; no release result is produced by these tests."""
import base64
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_custody import (ARCHIVE, BUILD, CHECKSUM, INSTALLED, Binding, Custody,
                             SDIST, WHEEL, canonical, sha)
from checkpoint_receipt import DEFINITION_FIELDS


def binding():
    return Binding({key: 'a' * (40 if key in {'head_sha', 'source_tree'} else 64)
                    for key in DEFINITION_FIELDS}, 12, 1)


def records(duty, outputs=None):
    kernel = {'root_parent_wait_raw': 0, 'poison': [], 'primary_denials': [],
              'failure_code': None, 'native_preinit_refusal': False,
              'all_commands_dispatched': True, 'actual_script_sha256': 'b' * 64,
              'unregistered_processes': [], 'missing_parent_waits': [],
              'primary_plan': {'duty': duty, 'workflow_sha256': 'a' * 64},
              'source_preexec_identity': {'uids': [20000] * 4, 'capabilities': {'CapEff': 0},
                                          'no_new_privs': 1},
              'records': [{'kind': 'kernel_child', 'child': 5,
                           'identity': {'tgid': 5, 'ppid': 4}},
                          {'kind': 'original_parent_wait4', 'child': 5,
                           'parent_tgid': 4, 'raw': 0}]}
    result = {'kernel-source.json': canonical(kernel)}
    if outputs is not None:
        result['package-output.json'] = canonical({
            'schema': 'unrest.v046.primary-package-output.v1',
            'members': {name: {'size': len(body), 'sha256': sha(body),
                               'bytes': base64.b64encode(body).decode()}
                        for name, body in outputs.items()}})
    return result


def test_four_phase_outputs_retain_exact_bytes_and_mac_chain(tmp_path):
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    outputs = {WHEEL: b'controlled wheel bytes', SDIST: b'controlled sdist bytes'}
    previous = None
    for duty in (BUILD, ARCHIVE, INSTALLED, CHECKSUM):
        if duty != BUILD:
            root = custody.package_inputs(duty)
            assert {p.name: p.read_bytes() for p in root.iterdir()} == outputs
        current = dict(outputs)
        if duty == CHECKSUM:
            current['SHA256SUMS'] = b''.join((sha(outputs[name]) + '  ' + name + '\n').encode()
                                           for name in (WHEEL, SDIST))
        value = custody.record(duty, 'b' * 64, records(duty, current))
        assert value['previous_sha256'] == (sha(canonical(previous)) if previous else None)
        assert custody.phase(duty) == value
        previous = value
    assert Custody(custody.root, binding()).phase(CHECKSUM) == previous


@pytest.mark.parametrize('drift', ['mac', 'run', 'attempt', 'head', 'bytes', 'symlink'])
def test_foreign_or_modified_phase_never_crosses_compartments(tmp_path, drift):
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    custody.record(BUILD, 'b' * 64, records(BUILD, {WHEEL: b'wheel', SDIST: b'sdist'}))
    if drift == 'mac':
        path = custody.root / (sha(BUILD.encode()) + '.json')
        value = json.loads(path.read_bytes())
        value['payload']['outputs'][WHEEL] = 'f' * 64
        path.write_bytes(canonical(value))
    elif drift in {'run', 'attempt', 'head'}:
        changed = copy.deepcopy(binding())
        changed = Binding({**changed.definition, **({'head_sha': 'f' * 40} if drift == 'head' else {})},
                          13 if drift == 'run' else 12, 2 if drift == 'attempt' else 1)
        with pytest.raises(RuntimeError):
            Custody(custody.root, changed)
        return
    else:
        path = custody.root / sha(BUILD.encode()) / WHEEL
        if drift == 'bytes':
            path.write_bytes(b'foreign wheel')
        else:
            path.unlink()
            path.symlink_to(tmp_path / 'foreign')
    with pytest.raises((RuntimeError, OSError)):
        custody.package_inputs(ARCHIVE)


@pytest.mark.parametrize('drift', ['poison', 'missing_wait', 'wrong_parent', 'cached_wait',
                                  'caught_refusal', 'wrong_script', 'wrong_duty', 'credential'])
def test_refused_or_unwaited_execution_cannot_issue_custody(tmp_path, drift):
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    data = records(BUILD, {WHEEL: b'wheel', SDIST: b'sdist'})
    kernel = json.loads(data['kernel-source.json'])
    if drift == 'poison':
        kernel['poison'] = ['unknown_or_drifted_exec']
    elif drift == 'caught_refusal':
        kernel['primary_denials'] = ['unknown_descendant']
    elif drift == 'missing_wait':
        kernel['records'].pop()
    elif drift == 'wrong_parent':
        kernel['records'][-1]['parent_tgid'] = 999
    elif drift == 'cached_wait':
        kernel['records'][-1]['kind'] = 'handle_wait'
    elif drift == 'wrong_script':
        kernel['actual_script_sha256'] = 'c' * 64
    elif drift == 'wrong_duty':
        kernel['primary_plan']['duty'] = ARCHIVE
    elif drift == 'credential':
        kernel['source_preexec_identity']['uids'][0] = 0
    data['kernel-source.json'] = canonical(kernel)
    with pytest.raises(RuntimeError):
        custody.record(BUILD, 'b' * 64, data)
    assert not (custody.root / (sha(BUILD.encode()) + '.json')).exists()


@pytest.mark.parametrize('drift', ['new_archive', 'extra_file', 'missing_archive', 'checksums'])
def test_only_original_build_can_introduce_archive_bytes(tmp_path, drift):
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    outputs = {WHEEL: b'wheel', SDIST: b'sdist'}
    custody.record(BUILD, 'b' * 64, records(BUILD, outputs))
    changed = dict(outputs)
    if drift == 'new_archive':
        changed[WHEEL] = b'foreign'
    elif drift == 'extra_file':
        changed['python'] = b'foreign'
    elif drift == 'missing_archive':
        del changed[SDIST]
    else:
        changed['SHA256SUMS'] = b'foreign'
    with pytest.raises(RuntimeError):
        custody.record(ARCHIVE, 'b' * 64, records(ARCHIVE, changed))


def test_custody_refusal_returns_to_evidence_encryption_without_disclosing_exception(tmp_path):
    from ci_shell import retain_phase
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    data = records('Import package')
    spec = {'duty': 'Import package', 'script_sha256': 'b' * 64}
    status, digest = retain_phase(custody, spec, data, {})
    assert status == 0 and len(digest) == 64
    # Duplicate issuance is refused; the caller must retain and encrypt its
    # current capture rather than throw away the failure evidence.
    status, digest = retain_phase(custody, spec, data, {})
    assert status == 125 and digest is None
