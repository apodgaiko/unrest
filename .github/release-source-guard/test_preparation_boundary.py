"""Preparation composition and private closed-error preservation controls."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import preparation_diagnostics
import prepare_source

SUPPORT = Path(__file__).parent
ROOT = SUPPORT.parent.parent


def test_exact_ownership_document_composes_with_original_engine_pins(monkeypatch):
    manifest = json.loads((SUPPORT / 'finite/source-template.json').read_bytes())
    before = copy.deepcopy(manifest)
    monkeypatch.setattr(prepare_source, 'ROOT', ROOT)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER', lambda root, name: (root / name).read_bytes(), raising=False)
    name = 'docs/architecture/experimental-lease.md'
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != before['product_pins'][name]
    prepare_source.admit_ownership_document(manifest)
    before['product_pins'][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert manifest == before


@pytest.mark.parametrize('mutation', ['baseline', 'document', 'lease', 'session', 'engine-pin'])
def test_ownership_document_never_admits_other_inputs(monkeypatch, mutation):
    manifest = json.loads((SUPPORT / 'finite/source-template.json').read_bytes())
    if mutation == 'baseline':
        manifest['product_pins']['docs/architecture/experimental-lease.md'] = '0' * 64
    if mutation == 'engine-pin':
        manifest['product_pins']['src/unrest_harness/experimental_lease.py'] = '0' * 64
    changed = {'document': 'docs/architecture/experimental-lease.md',
               'lease': 'src/unrest_harness/experimental_lease.py',
               'session': 'src/unrest_harness/experimental_session.py'}.get(mutation)
    monkeypatch.setattr(prepare_source, 'ROOT', ROOT)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER',
                        lambda root, name: (root / name).read_bytes() + (b'changed' if name == changed else b''),
                        raising=False)
    before = copy.deepcopy(manifest)
    with pytest.raises(RuntimeError, match='ownership_document_'):
        prepare_source.admit_ownership_document(manifest)
    assert manifest == before


@pytest.mark.parametrize('error,code', [
    (RuntimeError('primary_source_prepare'), 'primary_source_prepare'),
    (RuntimeError('original source baseline drift: private/source'), 'source_baseline_drift'),
    (RuntimeError('private/source body key'), 'unknown'),
    (PermissionError(13, 'private/path'), 'unknown'),
])
def test_closed_diagnostic_never_serializes_exception_body(error, code):
    try:
        raise error
    except BaseException as caught:
        value = preparation_diagnostics.failure(caught)
    assert value['code'] == code
    assert len(value['location_sha256']) == 64
    assert b'private/' not in json.dumps(value).encode()
    assert value['errno'] == (13 if isinstance(error, PermissionError) else None)


@pytest.mark.parametrize('prevent_bytecode', [False, True])
def test_host_control_import_cannot_poison_readonly_source_support(tmp_path, prevent_bytecode):
    import os
    import shutil
    import subprocess
    import sys

    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    assert '\nenv:\n  PYTHONDONTWRITEBYTECODE: "1"\n' in workflow
    support = tmp_path / 'support'
    shutil.copytree(SUPPORT, support, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}}
    if prevent_bytecode:
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
    result = subprocess.run(
        [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); '
         'import primary_dependency_authority', str(support)],
        env=environment, capture_output=True, check=False, timeout=30)
    assert result.returncode == 0, result.stderr
    caches = list((support / 'finite/__pycache__').glob('linux_identity.*.pyc'))
    assert bool(caches) is not prevent_bytecode


@pytest.mark.parametrize('kind,name,pin', [
    ('canonical-backend', 'experimental_session_app_server.py',
     'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'),
    ('controlled-acp', 'controlled_python_acp.py',
     'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'),
])
def test_controlled_postinit_locale_keeps_exact_fixture_and_exec_environment(kind, name, pin):
    from primary_source_inputs import python_environment
    registration = {'class': kind, 'source_binding': {
        'path': '/source/tests/fixtures/' + name, 'line': 1, 'sha256': pin}}
    original = {'HOME': '/owned/home', 'PATH': '/usr/bin:/bin'}
    before = dict(original)
    assert python_environment(original, registration, [0, 0, 0]) == {
        **original, 'LC_CTYPE': 'C.UTF-8'}
    assert original == before
    for key in ('LC_CTYPE', 'LC_ALL', 'LANG'):
        environment = {**original, key: 'C'}
        assert python_environment(environment, registration, [0, 0, 0]) == environment
    for key, value in [('class', 'unknown'), ('path', '/foreign/copy.py'),
                       ('line', 2), ('sha256', '0' * 64)]:
        changed = copy.deepcopy(registration)
        if key == 'class':
            changed[key] = value
        else:
            changed['source_binding'][key] = value
        assert python_environment(original, changed, [0, 0, 0]) == original
    for flags in ([1, 0, 0], [0, 1, 0], [0, 0, 1]):
        assert python_environment(original, registration, flags) == original


@pytest.mark.parametrize('tracker_owner', [26, 99, None])
def test_preflight_ready_uses_durable_owner_schema_and_refuses_missing_or_wrong_owner(tracker_owner):
    from preflight_policy import CASES
    from primary_source_probe import check
    ready = {'kind': 'ready', 'owner_pid': tracker_owner, 'token': 'tracker'}
    # A legacy pid field must not substitute for the durable owner identity.
    if tracker_owner is None:
        ready = {'kind': 'ready', 'pid': 26, 'token': 'tracker'}
    events = [{'kind': 'ready', 'owner_pid': 20, 'token': 'root'}, ready,
              {'kind': 'registered', 'class': 'source-multiprocess-tracker',
               'python': True, 'pid': 26},
              {'kind': 'endpoint_install_complete', 'owner_pid': 26, 'nonce': 'bound-nonce'},
              {'kind': 'raw_actual_parent_waitpid', 'pid': 26, 'raw_status': 0}]
    birth = {'pid': 26, 'uid': 20000}
    kernel = {'primary_plan': {'duty': 'TEST-source-positive'},
              'root_parent_wait_raw': 0, 'poison': [], 'primary_denials': [],
              'native_preinit_refusal': False, 'unregistered_processes': [],
              'receipt_ledger_poison': [], 'missing_parent_waits': [],
              'all_commands_dispatched': True, 'guard_poison': False, 'failure_code': None,
              'records': [{'kind': 'kernel_child', 'child': 26,
                           'identity': {'tgid': 26, 'ppid': 20}},
                          {'kind': 'original_parent_wait4', 'child': 26, 'parent_tgid': 20}],
              'primary_records': [{'kind': 'primary_native_preinit',
                                   'role': 'source-bootstrap', 'pid': 26}],
              'receipts': [{'request': {'kind': 'ready', 'pid': 26, 'nonce': 'bound-nonce'},
                            'ok': True, 'identity': birth,
                            'kernel_peer': {'birth': birth, 'uid': 20000}}]}
    provenance = {'collection_before': list(CASES), 'collection_after': list(CASES),
                  'deselected': 0, 'exitstatus': 0, 'invocation_args': ['-q', *CASES]}
    records = {name: json.dumps(value).encode() for name, value in {
        'kernel-source.json': kernel, 'summary.json': {'events': events, 'ready': True, 'failures': []},
        'collection.json': list(CASES), 'source-provenance.json': provenance}.items()}
    records['source.xml'] = b'<testsuite><testcase/><testcase/></testsuite>'
    if tracker_owner == 26:
        assert check(records, 'TEST-positive')['original_cases'] == 2
    else:
        with pytest.raises(RuntimeError, match='preflight_tracker_ready_missing'):
            check(records, 'TEST-positive')
