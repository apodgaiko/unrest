"""TEST transfer and refusal controls; these cannot certify a release."""
from __future__ import annotations

import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_package_inputs import prepare, consume, plan
from primary_custody import ARCHIVE, BUILD, WHEEL, SDIST, Custody, canonical, sha
from test_primary_custody import binding, records
from ci_commands import REGISTRY
from structured_evidence import loads
from test_ci_commands import workflow


def setup(tmp_path):
    custody = Custody(tmp_path / 'custody', binding(), create=True)
    members = {WHEEL: b'controlled wheel', SDIST: b'controlled sdist'}
    custody.record(BUILD, 'b' * 64, records(BUILD, members))
    descriptor = prepare(custody, ARCHIVE, tmp_path / 'mount')
    return custody, members, descriptor


def test_actual_custody_transfer_only_exports_exact_two_archives(tmp_path):
    custody, members, descriptor = setup(tmp_path)
    root = tmp_path / 'mount'
    assert {p.name for p in root.iterdir()} == {WHEEL, SDIST, 'input.json'}
    assert not (root / 'key').exists()
    assert all(p.stat().st_mode & 0o777 == 0o444 for p in root.iterdir())
    proof = consume(descriptor, tmp_path / 'dist', root)
    assert {p.name: p.read_bytes() for p in (tmp_path / 'dist').iterdir()} == members
    assert proof['descriptor_sha256'] == sha(canonical(descriptor))
    assert custody.phase(BUILD)['outputs'] == {name: sha(body) for name, body in members.items()}


@pytest.mark.parametrize('mutation', ['foreign_head', 'foreign_run', 'foreign_attempt',
                                    'foreign_duty', 'changed', 'symlink', 'hardlink',
                                    'extra', 'missing', 'mode', 'descriptor', 'output_exists'])
def test_mount_never_inherits_generic_file_or_cached_authentication(tmp_path, mutation):
    import os
    _, _, descriptor = setup(tmp_path)
    root = tmp_path / 'mount'
    root.chmod(0o755)
    path = root / WHEEL
    if mutation in {'foreign_head', 'foreign_run', 'foreign_attempt', 'foreign_duty'}:
        descriptor = copy.deepcopy(descriptor)
        if mutation == 'foreign_head':
            descriptor['binding']['definition']['head_sha'] = 'f' * 40
        elif mutation == 'foreign_run':
            descriptor['binding']['run_id'] += 1
        elif mutation == 'foreign_attempt':
            descriptor['binding']['run_attempt'] += 1
        else:
            descriptor['duty'] = BUILD
    elif mutation == 'changed':
        path.chmod(0o644)
        path.write_bytes(b'foreign bytes')
        path.chmod(0o444)
    elif mutation == 'symlink':
        path.unlink()
        path.symlink_to(root / SDIST)
    elif mutation == 'hardlink':
        os.link(path, tmp_path / 'alias')
    elif mutation == 'extra':
        (root / 'python').write_bytes(b'foreign interpreter')
    elif mutation == 'missing':
        path.unlink()
    elif mutation == 'mode':
        path.chmod(0o644)
    elif mutation == 'descriptor':
        (root / 'input.json').chmod(0o644)
        (root / 'input.json').write_bytes(b'{}')
        (root / 'input.json').chmod(0o444)
    else:
        (tmp_path / 'dist').mkdir()
    with pytest.raises((RuntimeError, OSError)):
        consume(descriptor, tmp_path / 'dist', root)
    assert not (tmp_path / 'dist' / WHEEL).exists()


def test_each_transfer_rechecks_custody_bytes_after_prior_admission(tmp_path):
    custody, _, _ = setup(tmp_path)
    source = custody.package_inputs(ARCHIVE) / WHEEL
    source.write_bytes(b'late foreign bytes')
    with pytest.raises(RuntimeError):
        prepare(custody, ARCHIVE, tmp_path / 'second')
    assert not (tmp_path / 'second').exists()


@pytest.mark.parametrize('duty', loads(REGISTRY.read_bytes()))
def test_original_package_scripts_are_test_only_until_full_readiness(duty):
    registry = loads(REGISTRY.read_bytes())
    if duty not in (BUILD, ARCHIVE, 'Smoke-test installed wheel',
                     'Generate and verify v0.4.7 build-local checksums'):
        return
    script = registry[duty].encode()
    script = script.rstrip(b'\n') if b'\n' not in script.rstrip(b'\n') else script
    wire = workflow(registry)
    result = plan(script, wire, None, test=True)
    assert result['package_mode'] == 'TEST' and result['source_checkpoint_ready'] is False
    with pytest.raises(RuntimeError, match='primary_source_readiness_closure_missing'):
        plan(script, wire, None)
