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
from structured_evidence import EvidenceRefused, execution_identity
from primary_custody import Binding, Custody, read_regular
from primary_source_inputs import test_plan, decode
from structured_evidence import canonical

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
TMPFS = {'/work': 'rw,nosuid,nodev,size=512m,uid=20000,gid=20000,mode=0711',
         '/tmp': 'rw,nosuid,nodev,noexec,size=64m,mode=1777',
         '/source': 'rw,exec,nosuid,nodev,size=256m,uid=20000,gid=20000,mode=0755',
         '/source/src/unrest_harness.egg-info': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
         '/receipts': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0755'}
KINDS = {'Install dependencies': 'primary-install', 'Import package': 'primary-import',
         'Supported CLI surfaces': 'primary-help', 'Repository contract': 'primary-repository',
         'Lint (ruff)': 'primary-lint', 'Type-check (mypy)': 'primary-types',
         'v0.4.6 source suite': 'primary-source',
         'Build wheel and source distribution': 'primary-package-build',
         'TEST-source-positive': 'primary-source-positive', 'TEST-source-poison': 'primary-source-poison'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, log):
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


def validate(config, image, mounts):
    host = config['HostConfig']
    expected = {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                'PidsLimit': 128, 'Memory': 1073741824, 'Tmpfs': TMPFS,
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


def main():
    global STAGE, SCRIPT_PIN, SCRIPT_SIZE
    test_mode = None
    package_test = len(sys.argv) == 3 and sys.argv[1] == '--package-test'
    if package_test and (os.environ.get('GITHUB_WORKFLOW') != 'v0.4.6 source guard readiness'
            or os.environ.get('GITHUB_REF') not in {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-' + epoch
                for epoch in ('01', '02', '03', '04')} | {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-cache-record-' + epoch
                for epoch in ('01', '02')} | {
                'refs/heads/codex/source-guard-structured-20261018-package-entry-cache-lineage-' + epoch
                for epoch in ('01', '02', '03', '04', '05', '06')}):
        raise RuntimeError('primary_package_test_workflow_identity')
    if len(sys.argv) == 4 and sys.argv[1] == '--source-test':
        test_mode = sys.argv[2]
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
    elif len(sys.argv) != 2 and not package_test:
        raise RuntimeError('primary_shell_argv')
    script_path = Path(sys.argv[-1])
    if script_path.is_symlink() or not script_path.is_file() or script_path.stat().st_size > 16384:
        raise RuntimeError('primary_script_carrier')
    script = script_path.read_bytes()
    SCRIPT_PIN, SCRIPT_SIZE = hashlib.sha256(script).hexdigest(), len(script)
    STAGE = 'binding'
    expected = expected_identity()
    workflow = (REPOSITORY / '.github/workflows/ci.yml').read_text()
    bound = None if test_mode else bind_generated(script, workflow)
    decision_path = Path(os.environ['RUNNER_TEMP']) / 'primary-decision.json'
    if os.environ.get('GITHUB_WORKFLOW') == 'CI':
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
    source_input = None
    if not test_mode and not package_test and (bound['name'] == 'v0.4.6 source suite'
            or bound['name'] == 'Build wheel and source distribution'):
        source_input = decode(read_regular(Path(os.environ['RUNNER_TEMP']) / 'primary-source-input.json', 65536, 0o600))
        if source_input['definition'] != expected:
            raise RuntimeError('primary_source_current_definition')
    if package_test:
        from primary_package_inputs import plan as package_plan
        spec = package_plan(bound['script'], workflow, None, test=True)
    else:
        spec = test_plan(script, workflow, test_mode) if test_mode else plan(bound['script'], workflow, source_input)
    kind = KINDS[spec['duty']]
    root = Path(os.environ['RUNNER_TEMP']) / kind
    root.mkdir(mode=0o700)
    raw = root / 'raw'
    raw.mkdir(mode=0o700)
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
        source_pins[name] = hashlib.sha256(body).hexdigest()
    (source / 'src/unrest_harness.egg-info').mkdir(exist_ok=True)
    # Minimal public read-only discovery metadata, with no runner Git config,
    # hooks, credentials, alternate object path or private history.
    git_root = source / '.git'
    git_root.mkdir()
    (git_root / 'objects').mkdir()
    (git_root / 'refs').mkdir()
    (git_root / 'HEAD').write_text(os.environ['GITHUB_SHA'] + '\n')
    (git_root / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\n')
    # The readonly bind must have the real source UID, rather than bypassing
    # Git's repository-ownership safety check with configuration overrides.
    if run(['sudo', '-n', 'chown', '--no-dereference', '-R', '20000:20000', str(git_root)], log).returncode:
        raise RuntimeError('primary_git_metadata_owner')
    inputs = root / 'inputs'
    inputs.mkdir()
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
        prepare = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--user=20001:20001',
                   '--mount=type=bind,src=' + str(SUPPORT) + ',dst=/guard,readonly',
                   '--mount=type=bind,src=' + str(source) + ',dst=/source,readonly',
                   '--entrypoint=/usr/local/bin/python', image, '-B',
                   '/guard/primary_source_setup.py', secrets.token_hex(32)]
        with log.open('ab') as errors:
            prepared = subprocess.run(prepare, stdout=subprocess.PIPE, stderr=errors, check=False)
        if prepared.returncode:
            raise RuntimeError('primary_source_prepare')
        value = json.loads(prepared.stdout)
        (inputs / 'source.json').write_bytes(canonical(value['manifest']))
        (inputs / 'registry.py').write_text(value['registry'])
    mounts = {'/guard': str(SUPPORT), '/inputs': str(inputs),
              **source_bindings(source, 'producer-primary')}
    container = 'primary-script-' + spec['script_sha256'][:24]
    argv = ['docker', 'create', '--name', container, '--read-only', '--network=none',
            '--ipc=private', '--cgroupns=private', '--cap-drop=ALL', '--cap-add=SETUID',
            '--cap-add=SETGID', '--cap-add=SETPCAP', '--cap-add=SYS_PTRACE', '--cap-add=DAC_READ_SEARCH',
            '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g',
            *['--tmpfs=' + path + ':' + options for path, options in TMPFS.items()],
            *['--mount=type=bind,src=' + origin + ',dst=' + target + ',readonly' for target, origin in mounts.items()],
            '--entrypoint=/usr/local/bin/python', image, '-B', '/guard/primary_compartment.py']
    STAGE = 'identity'
    identity = execution_identity(SUPPORT, kind)
    source_invocation = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    (inputs / 'transport-identity.json').write_bytes(canonical({
        'identity': identity, 'invocation_sha256': source_invocation}))
    status = 125
    records = {}
    capture_failure = None
    container_state = None
    stage = 'create'
    STAGE = 'capsule'
    try:
        if run(argv, log).returncode:
            raise RuntimeError('primary_create_failed')
        config = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]
        validate(config, image, mounts)
        stage = 'capture'
        from source_raw_transport import capture as capture_raw_source
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
        run(['docker', 'rm', '--force', container], log)
    phase_sha256 = None
    if status == 0 and not test_mode:
        status, phase_sha256 = retain_phase(custody, spec, records, source_pins)
        if status:
            stage = 'custody_refused'
    negative_verified = False
    test_proof = None
    if test_mode:
        from primary_source_probe import check
        expected_status = 2 if test_mode == 'TEST-poison' else 0
        if status == expected_status:
            try:
                test_proof = check(records, test_mode)
                negative_verified = test_mode == 'TEST-poison'
            except Exception:
                status, stage = 125, 'source_test_refused'
    package_test_proof = None
    if package_test and status == 0:
        from primary_package_probe import check as check_package
        try:
            package_test_proof = check_package(records)
        except Exception:
            status, stage = 125, 'package_test_refused'
    metadata = {'direct_identity': identity, 'source_checkpoint_ready': False, 'selected_carrier': None,
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


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        status = 125
    diagnostic = {'schema': 'primary-executor-status-v1', 'exit_code': status, 'stage': STAGE,
                  'script_sha256': SCRIPT_PIN, 'script_size': SCRIPT_SIZE}
    (Path(os.environ['RUNNER_TEMP']) / 'primary-host-stage.json').write_text(json.dumps(diagnostic, sort_keys=True))
    print(json.dumps(diagnostic))
    raise SystemExit(status)
