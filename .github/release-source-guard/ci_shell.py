"""GitHub custom shell: bind and execute the runner's actual temporary script."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import secrets

from primary_policy import plan, public_plan
from ci_commands import bind_generated
from checkpoint_decision import expected_identity
from primary_environment import build
from source_controller import source_bindings
import source_root
from structured_evidence import EvidenceRefused, execution_identity
from primary_custody import Binding, Custody, ORDER, ARCHIVE, INSTALLED, CHECKSUM
from primary_source_inputs import test_plan
from structured_evidence import canonical
from phase_catalog import catalog, require_retention

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
TMPFS = {'/work': 'rw,nosuid,nodev,size=512m,uid=20000,gid=20000,mode=0711',
         '/tmp': 'rw,nosuid,nodev,noexec,size=64m,mode=1777',
         **source_root.OVERLAYS,
         '/receipts': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0755'}


def resources(spec=None):
    """Bind workspace capacity and the full-sized diagnostic memory cap exactly."""
    mounts, memory = dict(TMPFS), 1073741824
    if spec is not None and (spec.get('duty') == 'v0.4.7 source suite'
                             or spec.get('source_mode') == 'SOURCE'):
        if (spec.get('duty') != 'v0.4.7 source suite' or spec.get('source_mode') != 'SOURCE'
                or spec.get('commands') != [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']]):
            raise RuntimeError('primary_source_resource_scope')
        mounts['/work'] = 'rw,exec,nosuid,nodev,size=2g,uid=20000,gid=20000,mode=0711'
        mounts['/receipts'] = TMPFS['/receipts'].replace('size=32m,', 'size=128m,', 1)
        memory = 3221225472
    if spec is not None and spec.get('source_mode') == 'TEST-positive':
        from primary_policy import TEST_SELECTIONS
        commands = [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q', *cases]
                    for cases in TEST_SELECTIONS]
        if spec.get('duty') != 'TEST-source-positive' or spec.get('commands') not in [[c] for c in commands]:
            raise RuntimeError('primary_source_fixture_mount_scope')
        mounts['/work'] = mounts['/work'].replace('rw,', 'rw,exec,', 1)
        from startup_journal_control import selected
        from primary_policy import TEST_RELEASE_STORAGE_PREFLIGHT_CASES
        if selected(spec) and spec.get('commands') == [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q', *TEST_RELEASE_STORAGE_PREFLIGHT_CASES]]:
            mounts['/receipts'] = TMPFS['/receipts'].replace('size=32m,', 'size=128m,', 1)
        from primary_policy import TEST_INITIALIZATION_CASES
        initialization = ['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q', *TEST_INITIALIZATION_CASES]
        if selected(spec) or (spec.get('commands') == [initialization]
                and spec.get('script_sha256') == hashlib.sha256(' '.join(initialization).encode()).hexdigest()
                and spec.get('source_checkpoint_ready') is False and spec.get('selected_carrier') is None):
            # The full-sized journal reproduction uses the existing full-source
            # memory cap, while retaining its smaller workspace and time budget.
            memory = 3221225472
    return mounts, memory

KINDS = {name: phase.output for name, phase in catalog().items()}
KINDS.update({'TEST-source-positive': 'primary-source-positive',
              'TEST-source-poison': 'primary-source-poison'})


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, log):
    if argv[:3] == ['docker', 'rm', '--force']:
        initiating = sys.exception()
        try:
            source_root.stop_capsule(argv[3])
        except BaseException as cleanup:
            if initiating is not None:
                raise BaseExceptionGroup('capsule operation and stop failed', [initiating, cleanup]) from None
            raise
        return subprocess.CompletedProcess(argv, 0)
    with log.open('ab') as stream:
        return subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=False)


def retain_phase(custody, spec, records, source_pins):
    """A custody refusal must still reach the private-evidence encryption path."""
    from structured_evidence import canonical
    try:
        phase = custody.record(spec['duty'], spec['script_sha256'], records, input_pins=source_pins)
    except Exception:
        return 125, None
    return 0, hashlib.sha256(canonical(phase)).hexdigest()


def validate(config, image, mounts, spec=None):
    tmpfs, memory = resources(spec)
    host = config['HostConfig']
    expected = {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                'PidsLimit': 128, 'Memory': memory, 'Tmpfs': tmpfs,
                'SecurityOpt': ['no-new-privileges'], 'CapDrop': ['ALL']}
    caps = host['CapAdd']
    if (any(host.get(key) != value for key, value in expected.items()) or len(caps) != 5
            or {item.removeprefix('CAP_') for item in caps} != {
                'SETUID', 'SETGID', 'SETPCAP', 'SYS_PTRACE', 'DAC_READ_SEARCH'}):
        raise RuntimeError('primary_container_configuration')
    actual = config['Mounts']
    if (len(actual) != len(mounts) or {row['Destination'] for row in actual} != set(mounts)
            or any(row['Type'] != 'bind' or row['RW'] or row['Propagation'] != 'rprivate'
                   or row['Source'] != mounts[row['Destination']] for row in actual)):
        raise RuntimeError('primary_mount_inventory')
    if (config['Image'] != image or config['Config']['OpenStdin']
            or config['Config']['Entrypoint'] != ['/usr/local/bin/python']
            or config['Config']['Cmd'] != ['-B', '/guard/primary_compartment.py']):
        raise RuntimeError('primary_container_entry')


STAGE = 'startup'
SCRIPT_PIN = None
SCRIPT_SIZE = None
ACTIVE_ROOT = None
CHILD_PREPARATION_FAILURE = None


def acquire_retention(kind):
    global ACTIVE_ROOT
    if ACTIVE_ROOT is None:
        from preparation_retention import acquire
        ACTIVE_ROOT = acquire(Path(os.environ['RUNNER_TEMP']), kind)
    else:
        if ACTIVE_ROOT.name != kind:
            raise RuntimeError('primary_retention_duty_changed')
        from preparation_retention import check
        check(ACTIVE_ROOT)
    return ACTIVE_ROOT


def prepare_capsule(spec, script, expected, source_input, test_mode, package_test):
    global STAGE, ACTIVE_ROOT, CHILD_PREPARATION_FAILURE
    kind = KINDS[spec['duty']]
    root = acquire_retention(kind)
    raw = root / 'raw'
    log = raw / 'coordinator.log'
    control = json.loads((Path(os.environ['RUNNER_TEMP']) / 'source-readiness/safe-provenance.json').read_bytes())
    if control['head_sha'] != os.environ['GITHUB_SHA'] or control['synthetic_exit_code'] != 0:
        raise RuntimeError('primary_same_head_controls')
    if any(digest(SUPPORT / name) != pin for name, pin in control['support'].items()):
        raise RuntimeError('primary_support_drift')
    custody_root = Path(os.environ['RUNNER_TEMP']) / 'primary-custody'
    custody = Custody(custody_root, Binding(expected, int(os.environ['GITHUB_RUN_ID']),
                                          int(os.environ['GITHUB_RUN_ATTEMPT'])),
                      create=not custody_root.exists())
    STAGE = 'image'
    if spec['duty'] == INSTALLED:
        image = build(root / 'image', control['synthetic_dependencies']['image_id'], SUPPORT, log, package_wheels=True)
    else:
        image = build(root / 'image', control['synthetic_dependencies']['image_id'], SUPPORT, log)
    STAGE = 'snapshot'
    source = root / 'source'
    source.mkdir()
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=REPOSITORY).decode().split('\0')
    source_pins = {}
    for name in sorted(filter(None, names)):
        path = REPOSITORY / name
        body = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=REPOSITORY)
        if path.is_symlink() or not path.is_file() or path.read_bytes() != body:
            raise RuntimeError('primary_source_snapshot_drift')
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(path.stat().st_mode & 0o777)
        source_pins[name] = hashlib.sha256(body).hexdigest()
    source_root.layout(source)
    # Preserve required public Git semantics without copying runner metadata.
    from public_git_snapshot import prepare as prepare_public_git
    prepare_public_git(REPOSITORY, source, os.environ['GITHUB_SHA'])
    git_root = source / '.git'
    # The readonly bind must have the real source UID, rather than bypassing
    # Git's repository-ownership safety check with configuration overrides.
    if run(['sudo', '-n', 'chown', '--no-dereference', '-R', '20000:20000', str(git_root)], log).returncode:
        raise RuntimeError('primary_git_metadata_owner')
    source = source_root.seal(source, log)
    inputs = root / 'inputs'
    inputs.mkdir()
    source_custody = canonical(source_root.inventory(source))
    (inputs / 'source-custody.json').write_bytes(source_custody)
    (raw / 'source-pins.json').write_bytes(source_custody)
    (inputs / 'github-script.sh').write_bytes(script)
    (inputs / 'plan.json').write_text(json.dumps(spec, sort_keys=True))
    (inputs / 'uv.toml').write_bytes(b'')
    (inputs / 'identity.json').write_text(json.dumps(expected, sort_keys=True))
    if package_test:
        (inputs / 'package-test').write_bytes(b'TEST')
    if test_mode:
        (inputs / 'test-mode').write_text(test_mode)
    if source_input is not None:
        (inputs / 'source-input.json').write_bytes(canonical(source_input))
        (inputs / 'source-input.json').chmod(0o600)
    if spec.get('source_mode') or spec.get('package_mode'):
        STAGE = 'source-input-preparation'
        prepare = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--user=20001:20001',
                   '--mount=type=bind,src=' + str(SUPPORT) + ',dst=/guard,readonly',
                   '--mount=type=bind,src=' + str(source) + ',dst=/source,readonly',
                   '--entrypoint=/usr/local/bin/python', image, '-B',
                   '/guard/primary_source_setup.py', secrets.token_hex(32)]
        prepared = source_root.run_preparer(prepare, source, log)
        if prepared.returncode:
            # Retain the named bounded child record before the parent refuses.
            if len(prepared.stdout) <= 8192:
                (raw / 'source-preparation-error.json').write_bytes(prepared.stdout)
                CHILD_PREPARATION_FAILURE = hashlib.sha256(prepared.stdout).hexdigest()
            raise RuntimeError('primary_source_prepare')
        value = json.loads(prepared.stdout)
        (inputs / 'source.json').write_bytes(canonical(value['manifest']))
        (inputs / 'registry.py').write_text(value['registry'])
    mounts = {'/guard': str(SUPPORT), '/inputs': str(inputs),
              **source_bindings(source, 'producer-primary')}
    if spec.get('package_input_required'):
        from primary_package_inputs import prepare as prepare_package_input
        descriptor = prepare_package_input(custody, spec['duty'], root / 'package-input')
        if descriptor['binding'] != custody.binding or descriptor['duty'] != spec['duty']:
            raise RuntimeError('primary_package_current_input')
        (inputs / 'package-input.json').write_bytes(canonical(descriptor))
        mounts['/package-input'] = str(root / 'package-input')
    tmpfs, memory = resources(spec)
    container = 'primary-script-' + spec['script_sha256'][:24]
    argv = ['docker', 'create', '--name', container, '--read-only', '--network=none',
            '--ipc=private', '--cgroupns=private', '--cap-drop=ALL', '--cap-add=SETUID',
            '--cap-add=SETGID', '--cap-add=SETPCAP', '--cap-add=SYS_PTRACE', '--cap-add=DAC_READ_SEARCH',
            '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=' + str(memory),
            *['--tmpfs=' + path + ':' + options for path, options in tmpfs.items()],
            *['--mount=type=bind,src=' + origin + ',dst=' + target + ',readonly' for target, origin in mounts.items()],
            '--entrypoint=/usr/local/bin/python', image, '-B', '/guard/primary_compartment.py']
    STAGE = 'identity'
    identity = execution_identity(SUPPORT, kind)
    source_invocation = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    (inputs / 'transport-identity.json').write_bytes(canonical({
        'identity': identity, 'invocation_sha256': source_invocation}))
    return {'root': root, 'raw': raw, 'log': log, 'control': control,
            'custody': custody, 'image': image, 'source_pins': source_pins,
            'container': container, 'identity': identity,
            'source_invocation': source_invocation, 'inputs': inputs, 'argv': argv, 'mounts': mounts, 'spec': spec}


def create_capsule(prepared):
    """Common inspected capsule creation; callers own the original error sink."""
    if run(source_root.plan_capsule(prepared['argv'], Path(prepared['mounts']['/source'])), prepared['log']).returncode:
        raise RuntimeError('primary_create_failed')
    inspected = subprocess.check_output(['docker', 'inspect', prepared['container']])
    (prepared['raw'] / 'container-inspect.json').write_bytes(inspected)
    config = json.loads(inspected)[0]
    source_root.bind_capsule(config)
    validate(config, prepared['image'], prepared['mounts'], prepared.get('spec'))
    source_root.verify(Path(prepared['mounts']['/source']),
                       json.loads((prepared['inputs'] / 'source-custody.json').read_bytes()))


def main(*, own_constructor_fault=None):
    global STAGE, SCRIPT_PIN, SCRIPT_SIZE
    from full_bootstrap import consume, context, reserved
    prepare_only = len(sys.argv) == 3 and sys.argv[1] == '--prepare-full'
    if reserved(os.environ.get('GITHUB_REF', '')):
        if not prepare_only:
            raise RuntimeError('primary_prepare_only_ref')
        context('PREPAREONLY')
    elif prepare_only:
        raise RuntimeError('primary_prepare_only_context')
    preflight = len(sys.argv) in {3, 4} and sys.argv[1] in {'--preflight', '--preflight-package', '--preflight-phase'}
    if preflight:
        from preflight_policy import context as preflight_context
        preflight_context()
    test_mode = None
    package_test = len(sys.argv) == 3 and sys.argv[1] in {'--package-test', '--preflight-package'}
    if package_test and not preflight and (os.environ.get('GITHUB_WORKFLOW') != 'v0.4.6 source guard readiness'
            or os.environ.get('GITHUB_REF') not in {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-' + epoch
                for epoch in ('01', '02', '03', '04')} | {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-cache-record-' + epoch
                for epoch in ('01', '02')} | {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-cache-lineage-' + epoch
                for epoch in ('01', '02', '03', '04', '05', '06')} | {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-control-input-' + epoch
                for epoch in ('01', '02', '03', '04', '05', '06')}):
        raise RuntimeError('primary_package_test_workflow_identity')
    if len(sys.argv) == 4 and sys.argv[1] in {'--source-test', '--preflight'}:
        test_mode = sys.argv[2]
        if not preflight:
            if (os.environ.get('GITHUB_WORKFLOW') != 'v0.4.6 source guard readiness'
                    or not (os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-root-allocation-' + epoch
                        for epoch in ('01', '02', '03')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-producer-startup-' + epoch
                        for epoch in ('01', '02', '03')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-cache-snapshot-' + epoch
                        for epoch in ('01', '02', '03', '04', '05', '06')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-source-return-' + epoch
                        for epoch in ('01', '02', '03', '04', '05', '06')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-primary-dependency-' + epoch
                        for epoch in ('01', '02', '03', '04', '05', '06')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-raw-record-transport-' + epoch
                        for epoch in ('01', '02', '03', '04')}
                        or os.environ.get('GITHUB_REF') in {
                        'refs/heads/codex/source-guard-structured-20261018-native-uv-mode-' + epoch
                        for epoch in ('01', '02', '03', '04')}
                        or os.environ.get('GITHUB_REF', '').startswith((
                        'refs/heads/codex/source-guard-structured-20261018-source-entry-',
                        'refs/heads/codex/source-guard-structured-20261018-source-composition-',
                        'refs/heads/codex/source-guard-structured-20261018-exact-pipe-',
                        'refs/heads/codex/source-guard-structured-20261018-source-receipt-',
                        'refs/heads/codex/source-guard-structured-20261018-layered-source-',
                        'refs/heads/codex/source-guard-structured-20261018-pinned-policy-',
                        'refs/heads/codex/source-guard-structured-20261018-source-seams-')))):
                raise RuntimeError('primary_test_workflow_identity')
    elif len(sys.argv) != 2 and not package_test and not prepare_only and not preflight:
        raise RuntimeError('primary_shell_argv')
    script_path = Path(sys.argv[-1])
    if script_path.is_symlink() or not script_path.is_file() or script_path.stat().st_size > 16384:
        raise RuntimeError('primary_script_carrier')
    script = script_path.read_bytes()
    SCRIPT_PIN, SCRIPT_SIZE = hashlib.sha256(script).hexdigest(), len(script)
    STAGE = 'binding'
    expected = expected_identity()
    workflow = (REPOSITORY / '.github/workflows/ci.yml').read_text()
    require_retention(workflow)
    bound = None if test_mode else bind_generated(script, workflow)
    decision_path = Path(os.environ['RUNNER_TEMP']) / 'primary-decision.json'
    if os.environ.get('GITHUB_WORKFLOW') == 'CI' and not preflight:
        if decision_path.is_symlink():
            raise RuntimeError('primary_decision_carrier')
        decision = json.loads(decision_path.read_bytes())
        if (decision['schema'] != 'unrest.v046.primary-decision.v1'
                or decision['expected'] != expected):
            raise RuntimeError('primary_decision_identity')
        if decision['decision'] == 'reuse-authentic-full':
            if not decision['receipt'] or decision['receipt']['head_sha'] != os.environ['GITHUB_SHA']:
                raise RuntimeError('primary_reuse_identity')
            return 0
        if decision['decision'] != 'execute-first-full' or decision['receipt'] is not None:
            raise RuntimeError('primary_decision_kind')
    # Admit the literal duty before acquiring an output; physical input failures
    # thereafter belong to this phase, including the initial consumer read.
    if preflight:
        context('PREFLIGHT')
    if test_mode:
        admitted = test_plan(script, workflow, test_mode)['duty']
    else:
        admitted = bound['name']
    acquire_retention(KINDS[admitted])
    source_input = consume('PREFLIGHT', script) if preflight else None
    if not preflight and not test_mode and not package_test and (bound['name'] == 'v0.4.7 source suite'
            or bound['name'] in ORDER):
        source_input = consume('PREPAREONLY' if prepare_only else 'FULL', script)
        if source_input['definition'] != expected:
            raise RuntimeError('primary_source_current_definition')
    if package_test:
        from primary_package_inputs import plan as package_plan
        spec = package_plan(bound['script'], workflow, None, test=True)
    else:
        spec = test_plan(script, workflow, test_mode) if test_mode else plan(bound['script'], workflow, source_input)
    prepared = prepare_capsule(spec, script, expected, source_input, test_mode, package_test)
    if own_constructor_fault is not None:
        from child_relative_host import MODES
        wrapper = sys._getframe(1)
        caller = sys._getframe(2)
        host = sys.modules.get(caller.f_globals.get('__name__'))
        if (own_constructor_fault not in MODES or host is None
                or wrapper.f_code is not retained_main.__code__ or wrapper.f_globals is not globals()
                or caller.f_code is not host.main.__code__
                or caller.f_globals is not vars(host) or host.main.__code__.co_filename != str(SUPPORT / 'child_relative_host.py')
                or not preflight or test_mode != 'TEST-positive'):
            raise RuntimeError('own_constructor_host_caller')
        own_pin = prepared['source_pins']['.github/release-source-guard/child_relative_methods.py']
        (prepared['inputs'] / 'own-constructor-fault.json').write_bytes(canonical(
            {'mode': own_constructor_fault, 'source_sha256': own_pin}))
    elif preflight and test_mode == 'TEST-positive':
        from child_relative_host import run as constructor_faults
        constructor_faults(prepared)
    root, raw, log, control, custody, image, source_pins, container, identity, source_invocation = (
        prepared[key] for key in ('root', 'raw', 'log', 'control', 'custody', 'image',
                                 'source_pins', 'container', 'identity', 'source_invocation'))
    if prepare_only:
        try:
            STAGE = 'capsule'
            consume('PREPAREONLY', script)
            create_capsule(prepared)
            # No docker start and no payload entry point. The same create and
            # inspect predicates above precede every eventual FULL dispatch.
            inputs = prepared['inputs']
            proof = {'schema': 'unrest.v046.full-preparation.v1',
                     'identity': identity, 'definition': expected,
                     'operation': 'PREPAREONLY', 'source_testcase_executed': False,
                     'eligible_certificate': False, 'source_checkpoint_ready': False,
                     'selected_carrier': None, 'primary_plan': public_plan(spec),
                     'image_id': image, 'script_sha256': digest(inputs / 'github-script.sh'),
                     'manifest_sha256': digest(inputs / 'source.json'),
                     'registry_sha256': digest(inputs / 'registry.py'),
                     'input_sha256': digest(inputs / 'source-input.json'),
                     'kernel': {'system': os.uname().sysname, 'release_sha256': hashlib.sha256(os.uname().release.encode()).hexdigest(),
                                'machine': os.uname().machine}}
            (root / 'preparation.json').write_bytes(canonical(proof))
        finally:
            if run(['docker', 'rm', '--force', container], log).returncode == 0:
                source_root.settle(sys.exception())
        return 0
    status = 125
    records = {}
    capture_failure = None
    container_state = None
    stage = 'create'
    STAGE = 'capsule'
    try:
        if source_input is not None:
            consume('PREFLIGHT' if preflight else 'FULL', script)
        create_capsule(prepared)
        stage = 'capture'
        from source_raw_transport import capture_packed as capture_raw_source
        _, records = capture_raw_source(['docker', 'start', '--attach', container], raw, identity, 'primary-executor', source_invocation=source_invocation)
        stage = 'settled'
        state = json.loads(subprocess.check_output(['docker', 'inspect', '--format={{json .State}}', container]))
        if state['Running'] or state['OOMKilled']:
            raise RuntimeError('primary_unsettled')
        status = state['ExitCode']
    except BaseException as error:
        # Only typed stage data enters public metadata; private exceptions are
        # unnecessary for this closed executor protocol.
        status = 125
        if stage == 'capture':
            capture_failure = (str(error) if isinstance(error, EvidenceRefused)
                               and str(error) in {'transport_bound', 'direct_transport_count',
                                                  'invalid_json', 'unknown_record', 'missing_record',
                                                  'record_bound', 'record_encoding'} else 'capture_failed')
            observed = subprocess.run(
                ['docker', 'inspect', '--format={{json .State}}', container],
                capture_output=True, check=False)
            if observed.returncode == 0:
                state = json.loads(observed.stdout)
                container_state = {'running': state['Running'], 'oom_killed': state['OOMKilled'],
                                   'exit_code': state['ExitCode']}
    finally:
        if run(['docker', 'rm', '--force', container], log).returncode == 0:
            source_root.settle(sys.exception())
    phase_sha256 = None
    if status == 0 and not test_mode:
        status, phase_sha256 = retain_phase(custody, spec, records, source_pins)
        if status:
            stage = 'custody_refused'
    negative_verified = False
    test_proof = None
    own_fault_proof = None
    if own_constructor_fault is not None:
        from child_relative_host import reduce_fault
        own_fault_proof = reduce_fault(records, own_constructor_fault)
    if test_mode and own_constructor_fault is None:
        from primary_source_probe import check
        expected_status = 2 if test_mode == 'TEST-poison' else 0
        if status == expected_status:
            try:
                test_proof = check(records, test_mode, require_faults=preflight)
                negative_verified = test_mode == 'TEST-poison'
            except Exception:
                status, stage = 125, 'source_test_refused'
    package_test_proof = None
    if package_test and status == 0:
        from primary_package_probe import check as check_build, check_archive, check_installed, check_checksum
        check_package = {ARCHIVE: check_archive, INSTALLED: check_installed, CHECKSUM: check_checksum}.get(spec['duty'], check_build)
        try:
            package_test_proof = check_package(records)
            if spec['duty'] == CHECKSUM:
                from checkpoint_issuer import package_result
                package_test_proof['original_issuer_package_chain'] = package_result(
                    {duty: custody.phase(duty) for duty in ORDER}, source_pins)
        except Exception:
            status, stage = 125, 'package_test_refused'
    metadata = {'own_constructor_fault': own_fault_proof, 'direct_identity': identity, 'source_checkpoint_ready': False, 'selected_carrier': None,
                'source_exit_code': status, 'stage': stage, 'primary_plan': public_plan(spec),
                'head_sha': os.environ['GITHUB_SHA'], 'source_tree': expected['source_tree'], 'image_id': image,
                'source_pins_sha256': hashlib.sha256(json.dumps(source_pins, sort_keys=True).encode()).hexdigest(),
                'support': control['support'],
                'custody_phase_sha256': phase_sha256,
                'package_test_identity': 'TEST' if package_test else None,
                'package_test_proof': package_test_proof,
                'source_test_identity': test_mode, 'negative_verified': negative_verified,
                'source_test_proof': test_proof,
                'transport_provenance_sha256': digest(raw / 'transport-provenance.json') if (raw / 'transport-provenance.json').is_file() else None,
                'capture_failure': capture_failure, 'container_state': container_state,
                'source_host_custody_sha256': digest(raw / 'source-pins.json') if (raw / 'source-pins.json').is_file() else None,
                'container_inspect_sha256': digest(raw / 'container-inspect.json') if (raw / 'container-inspect.json').is_file() else None,
                'structured_envelope_sha256': digest(raw / 'structured-envelope.json') if records else None}
    archive = root / 'raw.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        for path in sorted(raw.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError('primary_evidence_member')
            stream.add(path, arcname=path.name, recursive=False)
    if run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
            '-in', str(archive), '-out', str(root / 'evidence.cms'),
            str(SUPPORT / 'evidence-recipient.pem')], root / 'encryption.log').returncode:
        raise RuntimeError('primary_encryption_failed')
    metadata.update(ciphertext_sha256=digest(root / 'evidence.cms'), plaintext_archive_sha256=digest(archive))
    (root / 'safe-provenance.json').write_text(json.dumps(metadata, sort_keys=True))
    shutil.rmtree(raw)
    archive.unlink()
    return 0 if negative_verified else status


def retained_main(*, own_constructor_fault=None):
    """The acquiring host retains preparation failures before returning.

    ACTIVE_ROOT is assigned only after exclusive directory acquisition. A
    stale directory is never adopted as this invocation's private evidence.
    """
    try:
        options = {} if own_constructor_fault is None else {'own_constructor_fault': own_constructor_fault}
        result = main(**options)
        from preparation_retention import release, OWNED
        if ACTIVE_ROOT in OWNED:
            release(ACTIVE_ROOT)
        return result
    except BaseException as error:
        retained_error = error
        try:
            source_root.settle(error)
        except BaseException as combined:
            retained_error = combined
        root = ACTIVE_ROOT
        if root is None:
            raise
        if (root / 'evidence.cms').exists():
            raise
        from preparation_retention import retain
        record = {'schema': 'unrest.v046.primary-preparation-failure.v1',
                  'stage': STAGE, 'exit_code': 125, 'script_sha256': SCRIPT_PIN,
                  'script_size': SCRIPT_SIZE, 'source_checkpoint_ready': False,
                  'selected_carrier': None}
        retain(root, record, retained_error, CHILD_PREPARATION_FAILURE)
        if not (root / 'evidence.cms').is_file():
            raise RuntimeError('primary_encryption_failed')
        return 125


if __name__ == '__main__':
    try:
        status = retained_main()
    except BaseException:
        status = 125
    diagnostic = {'schema': 'primary-executor-status-v1', 'exit_code': status, 'stage': STAGE,
                  'script_sha256': SCRIPT_PIN, 'script_size': SCRIPT_SIZE}
    (Path(os.environ['RUNNER_TEMP']) / 'primary-host-stage.json').write_text(json.dumps(diagnostic, sort_keys=True))
    print(json.dumps(diagnostic))
    raise SystemExit(status)
