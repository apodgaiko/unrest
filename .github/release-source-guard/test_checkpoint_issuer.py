"""Controlled issuer tests only; their synthetic records never certify CI."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_issuer import issue, member_hashes, package_result, source_result
from checkpoint_receipt import COMMAND, DEFINITION_FIELDS, PRIMARY
from primary_custody import (ARCHIVE, CHECKSUM, INSTALLED, ORDER, SOURCE,
                             WHEEL, SDIST, Binding, Custody, canonical, sha)
from ci_commands import REGISTRY, bind_generated
from test_ci_commands import workflow
from test_primary_custody import records as kernel_records


def archives():
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, 'w') as target:
        target.writestr('unrest_harness/__init__.py', b'# synthetic package\n')
    sdist = io.BytesIO()
    with gzip.GzipFile(fileobj=sdist, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as target:
            row = tarfile.TarInfo('unrest_harness-0.4.7/src/unrest_harness/__init__.py')
            data = b'# synthetic package\n'
            row.size = len(data)
            target.addfile(row, io.BytesIO(data))
    return {WHEEL: wheel.getvalue(), SDIST: sdist.getvalue()}


def source_data():
    root = {'kind': 'ready', 'token': 'root', 'owner_pid': 5}
    collection = ['tests/test_synthetic.py::test_one', 'tests/test_synthetic.py::test_two']
    return {'collection.json': canonical(collection),
            'summary.json': canonical({'ready': True, 'failures': [], 'events': [root],
                                       'descendants': []}),
            'source-provenance.json': canonical({
                'schema': 'unrest.v046.primary-source-provenance.v1', 'invocation_args': ['-q'],
                'collection_before': collection, 'collection_after': collection, 'deselected': 0,
                'exitstatus': 0, 'root_ready_sha256': sha(canonical(root))}),
            'source.xml': b'<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0">'
                b'<testcase classname="tests.test_synthetic" name="test_one"/>'
                b'<testcase classname="tests.test_synthetic" name="test_two"/>'
                b'</testsuite></testsuites>'}


def setup(tmp_path):
    registry = json.loads(REGISTRY.read_bytes())
    wire_workflow = workflow(registry)
    definition = {key: 'a' * (40 if key in {'head_sha', 'source_tree'} else 64)
                  for key in DEFINITION_FIELDS}
    definition['workflow_sha256'] = sha(wire_workflow.encode())
    definition['source_command_sha256'] = sha(COMMAND.encode())
    custody = Custody(tmp_path / 'custody', Binding(definition, 12, 1), create=True)
    outputs = archives()
    pins = {'tools/check_distribution.py': 'c' * 64,
            'src/unrest_harness/installed_wheel_check.py': 'd' * 64}
    for duty in [name for name in registry if name not in ORDER] + list(ORDER):
        script = registry[duty]
        script = script if '\n' in script.rstrip('\n') else script.removesuffix('\n')
        bound = bind_generated(script.encode(), wire_workflow)
        current = dict(outputs) if duty in ORDER else None
        if duty == CHECKSUM:
            current['SHA256SUMS'] = b''.join((sha(outputs[name]) + '  ' + name + '\n').encode()
                                            for name in (WHEEL, SDIST))
        data = kernel_records(duty, current)
        kernel = json.loads(data['kernel-source.json'])
        kernel.update(actual_script_sha256=bound['script_sha256'], guard_poison=False,
                      receipt_ledger_poison=[], primary_records=[])
        kernel['primary_plan']['workflow_sha256'] = definition['workflow_sha256']
        if duty == SOURCE:
            data.update(source_data())
        if duty == ARCHIVE:
            proof = {'schema': 'unrest.v046.primary-archive-observation.v1',
                     'source_sha256': pins['tools/check_distribution.py'], 'function': 'check_distribution',
                     'member_bytes_sha256': member_hashes(outputs),
                     'result': {'package_files': 1, 'wheel': WHEEL, 'sdist': SDIST,
                                'restart_oracle': {'cases': 15, 'cwd': '/work/extracted',
                                    'module': '/work/extracted/src/unrest_harness/__init__.py',
                                    'source_path': '/work/extracted/src',
                                    'test': '/work/extracted/tests/test_persistence_schema_v1.py'}}}
        elif duty == INSTALLED:
            proof = {'schema': 'unrest.v046.primary-installed-observation.v1',
                     'source_sha256': pins['src/unrest_harness/installed_wheel_check.py'],
                     'function': 'run_installed_wheel_check', 'cwd': '/work/unrelated',
                     'module': '/source/.wheel-venv/lib/python3.13/site-packages/unrest_harness/installed_wheel_check.py',
                     'result': {'attempts': 2, 'mission_id': 'controlled-mission',
                                'project_id': 'controlled-project', 'restart_resume': True,
                                'state': 'done', 'terminal_reviews': 1}}
        if duty in (ARCHIVE, INSTALLED):
            data['package-proof.json'] = canonical(proof)
            kernel['primary_records'] = [
                {'kind': 'primary_native_preinit', 'pid': 5, 'identity': {'controlled': 1}},
                {'kind': 'primary_function_return', 'proof_sha256': sha(canonical(proof)),
                 'source_sha256': proof['source_sha256'], 'function': proof['function'],
                 'pid': 5, 'identity': {'controlled': 1}}]
        data['kernel-source.json'] = canonical(kernel)
        custody.record(duty, bound['script_sha256'], data, input_pins=pins)
    return custody, wire_workflow, pins, {'name': PRIMARY, 'id': 13, 'run_id': 12}


def test_controlled_original_complete_reduction(tmp_path):
    custody, wire_workflow, pins, job = setup(tmp_path)
    result = issue(custody, wire_workflow, pins, job, b'controlled ciphertext')
    assert result['execution_kind'] == 'executed-primary-full'
    assert result['source']['counts'] == {'collected': 2, 'passed': 2, 'failed': 0, 'errors': 0, 'skipped': 0}
    assert result['package']['extracted_oracle'] == {'cases': 15, 'failures': 0, 'errors': 0, 'skipped': 0}
    assert result['package']['archives'] == {name: sha(body) for name, body in archives().items()}


def test_actual_encryption_export_and_consumer_schema_are_compatible(tmp_path):
    from checkpoint_finalize import export, materialize
    from checkpoint_receipt import REQUIRED_STEPS, validate
    from test_checkpoint_receipt import seal
    custody, wire_workflow, pins, job = setup(tmp_path)
    root = tmp_path / 'synthetic-certificate'
    result = export(custody, wire_workflow, pins, job, root,
                    Path(__file__).with_name('evidence-recipient.pem'))
    assert result['ciphertext_sha256'] == sha((root / 'evidence.cms').read_bytes())
    assert not (root / 'private-current-phases.tar.gz').exists()
    assert not (root / 'key').exists()
    materialize(custody, tmp_path / 'dist')
    assert set(path.name for path in (tmp_path / 'dist').iterdir()) == {WHEEL, SDIST, 'SHA256SUMS'}
    # External Actions records here are explicitly synthetic parser fixtures.
    archive, artifact = seal(result, (root / 'evidence.cms').read_bytes())
    run = {'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/ci.yml',
           'head_repository': {'full_name': 'apodgaiko/unrest'}, 'event': 'push',
           'head_sha': result['head_sha'], 'head_branch': 'codex/release-v047-controlled',
           'id': 12, 'run_attempt': 1}
    artifact.update(name='unrest-v046-primary-12-1', workflow_run={'id': 12, 'head_sha': result['head_sha']})
    jobs = [{**job, 'conclusion': 'success', 'steps': [
        {'name': name, 'status': 'completed', 'conclusion': 'success'} for name in REQUIRED_STEPS]}]
    assert validate(archive, artifact, run, jobs, custody.binding['definition'])['original_run_id'] == 12


def test_incomplete_export_cannot_leave_full_certificate_or_packages(tmp_path):
    from checkpoint_finalize import export
    custody, wire_workflow, pins, job = setup(tmp_path)
    (custody.root / (sha(SOURCE.encode()) + '.json')).unlink()
    root = tmp_path / 'refused'
    with pytest.raises(OSError):
        export(custody, wire_workflow, pins, job, root,
               Path(__file__).with_name('evidence-recipient.pem'))
    assert not root.exists()


@pytest.mark.parametrize('drift', ['partial', 'foreign_head', 'workflow', 'source_pin', 'readiness_job'])
def test_incomplete_readiness_or_foreign_results_cannot_issue(tmp_path, drift):
    custody, wire_workflow, pins, job = setup(tmp_path)
    if drift == 'partial':
        (custody.root / (sha(SOURCE.encode()) + '.json')).unlink()
    elif drift == 'foreign_head':
        custody.binding['definition']['head_sha'] = 'f' * 40
    elif drift == 'workflow':
        wire_workflow += '# changed workflow\n'
    elif drift == 'source_pin':
        pins['tools/check_distribution.py'] = 'f' * 64
    else:
        job['name'] = 'Linux compartment controls (not a source checkpoint)'
    with pytest.raises((OSError, RuntimeError)):
        issue(custody, wire_workflow, pins, job, b'controlled ciphertext')


@pytest.mark.parametrize('drift', ['filter', 'items', 'deselected', 'failed', 'missing_ready',
                                  'missing_case', 'junit_failure', 'poison', 'cached_wait'])
def test_original_full_source_cannot_shrink_to_a_partial_success(drift):
    data = source_data()
    provenance = json.loads(data['source-provenance.json'])
    summary = json.loads(data['summary.json'])
    kernel = {'guard_poison': False, 'receipt_ledger_poison': []}
    if drift == 'filter':
        provenance['invocation_args'] += ['-k', 'partial']
    elif drift == 'items':
        provenance['collection_after'].pop()
    elif drift == 'deselected':
        provenance['deselected'] = 1
    elif drift == 'failed':
        provenance['exitstatus'] = 1
    elif drift == 'missing_ready':
        summary['events'] = []
    elif drift == 'missing_case':
        data['source.xml'] = data['source.xml'].replace(
            b'<testcase classname="tests.test_synthetic" name="test_two"/>', b'')
    elif drift == 'junit_failure':
        data['source.xml'] = data['source.xml'].replace(b'name="test_two"/>',
                                                     b'name="test_two"><failure/></testcase>')
    elif drift == 'poison':
        kernel['guard_poison'] = True
    else:
        summary['descendants'] = [{'wait_status': 'cached_wait'}]
    data['source-provenance.json'] = canonical(provenance)
    data['summary.json'] = canonical(summary)
    with pytest.raises(RuntimeError):
        source_result(data, kernel)


@pytest.mark.parametrize('drift', ['no_return_observation', 'wrong_code', 'no_startup', 'members', 'oracle',
                                  'checkout_module', 'installed_effects', 'installed_cwd', 'archive_drift'])
def test_package_evidence_requires_original_body_effects_and_actual_custody(tmp_path, drift):
    custody, _, pins, _ = setup(tmp_path)
    phases = {duty: custody.phase(duty) for duty in ORDER}
    duty = INSTALLED if drift.startswith('installed') else ARCHIVE
    data = {name: base64.b64decode(body) for name, body in phases[duty]['records'].items()}
    proof = json.loads(data['package-proof.json'])
    kernel = json.loads(data['kernel-source.json'])
    if drift == 'no_return_observation':
        kernel['primary_records'].pop()
    elif drift == 'wrong_code':
        proof['source_sha256'] = 'f' * 64
    elif drift == 'no_startup':
        kernel['primary_records'].pop(0)
    elif drift == 'members':
        proof['member_bytes_sha256'][WHEEL] = 'f' * 64
    elif drift == 'oracle':
        proof['result']['restart_oracle']['cases'] = 14
    elif drift == 'checkout_module':
        proof['result']['restart_oracle']['module'] = '/source/src/unrest_harness/__init__.py'
    elif drift == 'installed_effects':
        proof['result']['restart_resume'] = False
    elif drift == 'installed_cwd':
        proof['cwd'] = '/source'
    else:
        phases[CHECKSUM]['outputs'][WHEEL] = 'f' * 64
    # Changing a linked phase also requires changing the chain. These controls
    # deliberately bypass MAC verification to exercise the reducer's own floor.
    data.update({'package-proof.json': canonical(proof), 'kernel-source.json': canonical(kernel)})
    phases[duty]['records'] = {name: base64.b64encode(body).decode() for name, body in data.items()}
    for previous, current in zip(ORDER, ORDER[1:]):
        phases[current]['previous_sha256'] = sha(canonical(phases[previous]))
    with pytest.raises(RuntimeError):
        package_result(phases, copy.deepcopy(pins))


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'same'])
def test_member_verification_rejects_unsafe_or_duplicate_archive_paths(name):
    outputs = archives()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        target.writestr(name, b'one')
        if name == 'same':
            with pytest.warns(UserWarning):
                target.writestr(name, b'two')
    outputs[WHEEL] = buffer.getvalue()
    with pytest.raises(RuntimeError):
        member_hashes(outputs)
