"""Reduce authenticated original capsule records into an original full receipt.

This reducer accepts the control-plane custody journal, never a caller's pass
booleans, readiness metadata, a reuse marker, or an older artifact. Publication
authenticity still comes from the original successful Actions job/artifact;
the existing receipt consumer checks that external execution chain.
"""
from __future__ import annotations

from approval_wait_evidence import adopted_waits, original_missing, summary_closed

import base64
import io
from pathlib import PurePosixPath
import tarfile
import xml.etree.ElementTree as ET
import zipfile

from checkpoint_receipt import COMMAND, PRIMARY, REPOSITORY, WORKFLOW
from primary_custody import (ARCHIVE, CHECKSUM, INSTALLED, ORDER, SOURCE,
                             WHEEL, SDIST, canonical, kernel_success, sha)
from primary_custody import decode_outputs
from checkpoint_packages import LIMIT
from structured_evidence import loads, require


def records(phase):
    return {name: base64.b64decode(body, validate=True) for name, body in phase['records'].items()}


def source_result(data, kernel):
    collection = loads(data['collection.json'])
    provenance = loads(data['source-provenance.json'])
    summary = loads(data['summary.json'])
    require(type(collection) is list and collection and all(type(node) is str for node in collection)
            and len(collection) == len(set(collection)), 'issuer_complete_collection')
    require(set(provenance) == {'schema', 'invocation_args', 'collection_before', 'collection_after',
                               'deselected', 'exitstatus', 'root_ready_sha256'}
            and provenance['schema'] == 'unrest.v046.primary-source-provenance.v1'
            and provenance['invocation_args'] == ['-q']
            and provenance['collection_before'] == provenance['collection_after'] == collection
            and type(provenance['deselected']) is int and provenance['deselected'] == 0
            and type(provenance['exitstatus']) is int and provenance['exitstatus'] == 0,
            'issuer_unexcluded_source')
    require(summary_closed(summary, kernel)
            and kernel['guard_poison'] is False and kernel['receipt_ledger_poison'] == [],
            'issuer_source_guard')
    roots = [event for event in summary['events'] if event['kind'] == 'ready' and event['token'] == 'root']
    require(len(roots) == 1 and sha(canonical(roots[0])) == provenance['root_ready_sha256'],
            'issuer_source_ready_binding')
    require(all(row['wait_status'] == 'actually_waited' or row.get('pid') is not None and row['pid'] in adopted_waits(kernel)
                for row in summary['descendants']),
            'issuer_guard_parent_waits')
    document = ET.fromstring(data['source.xml'])
    cases = list(document.iter('testcase'))
    expected = set()
    for node in collection:
        path, *owners, name = node.split('::')
        require(path.endswith('.py'), 'issuer_collection_node')
        expected.add(('.'.join([path[:-3].replace('/', '.'), *owners]), name))
    actual = [(case.attrib.get('classname'), case.attrib.get('name')) for case in cases]
    require(len(actual) == len(set(actual)) == len(collection) and set(actual) == expected,
            'issuer_junit_collection_identity')
    counts = {'collected': len(collection), 'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
    for case in cases:
        if case.find('failure') is not None:
            counts['failed'] += 1
        elif case.find('error') is not None:
            counts['errors'] += 1
        elif case.find('skipped') is not None:
            counts['skipped'] += 1
        else:
            counts['passed'] += 1
    require(counts['failed'] == counts['errors'] == 0, 'issuer_source_junit_failure')
    suites = list(document.iter('testsuite'))
    require(suites and sum(int(suite.attrib['tests']) for suite in suites) == len(cases)
            and all(int(suite.attrib.get('failures', '-1')) == 0
                    and int(suite.attrib.get('errors', '-1')) == 0 for suite in suites),
            'issuer_junit_totals')
    return {'argv': COMMAND.split(), 'collection_filters': [], 'item_mutations': [],
            'deselected': provenance['deselected'], 'exit_code': provenance['exitstatus'],
            'counts': counts, 'kernel_poison': [], 'guard_poison': [],
            'missing_original_parent_waits': original_missing(kernel),
            'actual_adoptive_parent_waits': list(adopted_waits(kernel).values()), 'unknown_execs': []}


def package_result(phases, source_pins):
    for previous, current in zip(ORDER, ORDER[1:]):
        require(phases[current]['previous_sha256'] == sha(canonical(phases[previous])),
                'issuer_package_phase_chain')
    output = phases[CHECKSUM]['outputs']
    require(set(output) == {WHEEL, SDIST, 'SHA256SUMS'}
            and all(set(phases[duty]['outputs']) == {WHEEL, SDIST} for duty in ORDER[:-1])
            and all(phases[duty]['outputs'][name] == output[name]
                    for duty in ORDER for name in (WHEEL, SDIST)), 'issuer_package_archive_custody')
    archive = loads(records(phases[ARCHIVE])['package-proof.json'])
    observed_return(phases[ARCHIVE], archive)
    require(set(archive) == {'schema', 'source_sha256', 'function', 'result', 'member_bytes_sha256'}
            and archive['schema'] == 'unrest.v046.primary-archive-observation.v1'
            and archive['source_sha256'] == source_pins['tools/check_distribution.py']
            and archive['function'] == 'check_distribution', 'issuer_original_archive_observation')
    result = archive['result']
    require(set(result) == {'package_files', 'restart_oracle', 'sdist', 'wheel'}
            and type(result['package_files']) is int and result['package_files'] > 0
            and result['wheel'] == WHEEL and result['sdist'] == SDIST,
            'issuer_archive_result')
    require(set(archive['member_bytes_sha256']) == {WHEEL, SDIST}
            and all(type(value) is str and len(value) == 64
                    and all(c in '0123456789abcdef' for c in value)
                    for value in archive['member_bytes_sha256'].values()), 'issuer_complete_member_bytes')
    archive_outputs = decode_outputs(records(phases[ARCHIVE])['package-output.json'], ARCHIVE)
    require(archive['member_bytes_sha256'] == member_hashes(archive_outputs),
            'issuer_member_byte_digest')
    oracle = result['restart_oracle']
    require(set(oracle) == {'cases', 'cwd', 'module', 'source_path', 'test'}
            and type(oracle['cases']) is int and oracle['cases'] == 15,
            'issuer_extracted_fifteen')
    cwd = PurePosixPath(oracle['cwd'])
    require(cwd.is_absolute() and not cwd.is_relative_to('/source')
            and PurePosixPath(oracle['module']).is_relative_to(cwd / 'src/unrest_harness')
            and oracle['source_path'] == str(cwd / 'src')
            and oracle['test'] == str(cwd / 'tests/test_persistence_schema_v1.py')
            and '..' not in cwd.parts, 'issuer_extracted_provenance')
    installed = loads(records(phases[INSTALLED])['package-proof.json'])
    observed_return(phases[INSTALLED], installed)
    require(set(installed) == {'schema', 'source_sha256', 'function', 'cwd', 'module', 'result'}
            and installed['schema'] == 'unrest.v046.primary-installed-observation.v1'
            and installed['source_sha256'] == source_pins['src/unrest_harness/installed_wheel_check.py']
            and installed['function'] == 'run_installed_wheel_check'
            and PurePosixPath(installed['cwd']).is_absolute()
            and not PurePosixPath(installed['cwd']).is_relative_to('/source')
            and '..' not in PurePosixPath(installed['cwd']).parts
            and PurePosixPath(installed['module']).is_relative_to(
                '/source/.wheel-venv/lib/python3.13/site-packages/unrest_harness'),
            'issuer_original_installed_observation')
    # The original lifecycle returns a finite effect summary, not a supplied pass.
    effects = installed['result']
    require(set(effects) == {'attempts', 'mission_id', 'project_id', 'restart_resume', 'state',
                             'terminal_reviews'}
            and type(effects['attempts']) is int and effects['attempts'] == 2
            and type(effects['terminal_reviews']) is int and effects['terminal_reviews'] == 1
            and effects['restart_resume'] is True and effects['state'] == 'done'
            and all(type(effects[key]) is str and effects[key] for key in ('project_id', 'mission_id')),
            'issuer_installed_lifecycle_effects')
    return {'build_exit_code': 0, 'archive_exit_code': 0, 'installed_lifecycle_exit_code': 0,
            'extracted_oracle': {'cases': 15, 'failures': 0, 'errors': 0, 'skipped': 0},
            'unrelated_cwd': True, 'full_member_bytes_verified': True,
            'archives': {name: output[name] for name in (WHEEL, SDIST)}}


def observed_return(phase, proof):
    kernel = loads(records(phase)['kernel-source.json'])
    matches = [row for row in kernel['primary_records']
               if row['kind'] == 'primary_function_return'
               and row['proof_sha256'] == sha(canonical(proof))
               and row['source_sha256'] == proof['source_sha256']
               and row['function'] == proof['function']]
    require(len(matches) == 1, 'issuer_observer_owned_return_missing')
    event = matches[0]
    starts = [row for row in kernel['primary_records']
              if row['kind'] == 'primary_native_preinit' and row['pid'] == event['pid']
              and row['identity'] == event['identity']]
    require(len(starts) == 1, 'issuer_original_body_startup_missing')


def member_hashes(outputs):
    result = {}
    for name in (WHEEL, SDIST):
        members = {}
        seen = set()
        total = 0
        def check_path(path):
            target = PurePosixPath(path)
            require(path and not target.is_absolute() and '..' not in target.parts
                    and target.as_posix() == path and path not in seen and len(seen) < 16384,
                    'issuer_unsafe_archive_member')
            seen.add(path)
        def add(path, size, read):
            nonlocal total
            target = PurePosixPath(path)
            require(path and not target.is_absolute() and '..' not in target.parts
                    and target.as_posix() == path and path not in members
                    and 0 <= size <= LIMIT, 'issuer_unsafe_archive_member')
            total += size
            require(total <= LIMIT, 'issuer_archive_member_bound')
            body = read()
            require(len(body) == size, 'issuer_archive_member_size')
            members[path] = {'size': size, 'sha256': sha(body)}
        if name == WHEEL:
            with zipfile.ZipFile(io.BytesIO(outputs[name])) as source:
                for row in source.infolist():
                    check_path(row.filename.rstrip('/') if row.is_dir() else row.filename)
                    if row.is_dir():
                        require(row.external_attr >> 16 & 0o170000 in (0, 0o040000),
                                'issuer_nonregular_archive_member')
                        continue
                    require(row.external_attr >> 16 & 0o170000 in (0, 0o100000),
                            'issuer_nonregular_archive_member')
                    add(row.filename, row.file_size, lambda: source.read(row))
        else:
            with tarfile.open(fileobj=io.BytesIO(outputs[name]), mode='r:gz') as source:
                for row in source:
                    check_path(row.name)
                    if row.isdir():
                        require(not PurePosixPath(row.name).is_absolute()
                                and '..' not in PurePosixPath(row.name).parts, 'issuer_unsafe_archive_member')
                        continue
                    require(row.isfile() and not row.issparse(), 'issuer_nonregular_archive_member')
                    def read():
                        stream = source.extractfile(row)
                        require(stream is not None, 'issuer_missing_archive_member')
                        return stream.read(LIMIT + 1)
                    add(row.name, row.size, read)
        require(members, 'issuer_empty_archive')
        result[name] = sha(canonical(members))
    return result


def issue(custody, workflow, source_pins, job, ciphertext):
    """Pure reduction after current-run capture and private evidence encryption."""
    from ci_commands import REGISTRY, bind_generated
    registry = loads(REGISTRY.read_bytes())
    require(job['name'] == PRIMARY and type(job['id']) is int and job['id'] > 0
            and job['run_id'] == custody.binding['run_id'], 'issuer_primary_job')
    phases = {duty: custody.phase(duty) for duty in registry}
    kernels = {}
    for duty, phase in phases.items():
        logical = registry[duty]
        script = logical.encode() if '\n' in logical.rstrip('\n') else logical.removesuffix('\n').encode()
        bound = bind_generated(script, workflow)
        require(phase['input_pins'] == source_pins and phase['script_sha256'] == bound['script_sha256'],
                'issuer_frozen_phase_inputs')
        kernels[duty] = kernel_success(records(phase), phase['script_sha256'])
        require(kernels[duty]['primary_plan'].get('package_mode') != 'TEST',
                'issuer_package_test_ineligible')
    require(sha(workflow.encode()) == custody.binding['definition']['workflow_sha256'],
            'issuer_workflow_definition')
    source = source_result(records(phases[SOURCE]), kernels[SOURCE])
    package = package_result(phases, source_pins)
    return {**custody.binding['definition'], 'schema': 'unrest.v046.primary-checkpoint.v1',
            'execution_kind': 'executed-primary-full', 'repository': REPOSITORY, 'workflow': WORKFLOW,
            'run_id': custody.binding['run_id'], 'run_attempt': custody.binding['run_attempt'],
            'job_id': job['id'], 'source_command': COMMAND, 'ciphertext_sha256': sha(ciphertext),
            'source': source, 'package': package}
