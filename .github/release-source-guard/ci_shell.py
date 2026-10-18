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

from primary_policy import plan
from ci_commands import bind_generated
from checkpoint_decision import expected_identity
from primary_environment import build
from source_controller import source_bindings
from structured_evidence import capture, execution_identity

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
TMPFS = {'/work': 'rw,nosuid,nodev,size=512m,uid=20000,gid=20000,mode=0711',
         '/tmp': 'rw,nosuid,nodev,noexec,size=64m,mode=1777',
         '/source': 'rw,nosuid,nodev,size=256m,uid=20000,gid=20000,mode=0755',
         '/source/src/unrest_harness.egg-info': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
         '/receipts': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0755'}
KINDS = {'Install dependencies': 'primary-install', 'Import package': 'primary-import',
         'Supported CLI surfaces': 'primary-help', 'Repository contract': 'primary-repository',
         'Lint (ruff)': 'primary-lint', 'Type-check (mypy)': 'primary-types'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, log):
    with log.open('ab') as stream:
        return subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=False)


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
    if len(sys.argv) != 2:
        raise RuntimeError('primary_shell_argv')
    script_path = Path(sys.argv[1])
    if script_path.is_symlink() or not script_path.is_file() or script_path.stat().st_size > 16384:
        raise RuntimeError('primary_script_carrier')
    script = script_path.read_bytes()
    SCRIPT_PIN, SCRIPT_SIZE = hashlib.sha256(script).hexdigest(), len(script)
    STAGE = 'binding'
    workflow = (REPOSITORY / '.github/workflows/ci.yml').read_text()
    bound = bind_generated(script, workflow)
    decision_path = Path(os.environ['RUNNER_TEMP']) / 'primary-decision.json'
    if os.environ.get('GITHUB_WORKFLOW') == 'CI':
        if decision_path.is_symlink():
            raise RuntimeError('primary_decision_carrier')
        decision = json.loads(decision_path.read_bytes())
        if (decision['schema'] != 'unrest.v046.primary-decision.v1'
                or decision['expected'] != expected_identity()):
            raise RuntimeError('primary_decision_identity')
        if decision['decision'] == 'reuse-authentic-full':
            if not decision['receipt'] or decision['receipt']['head_sha'] != os.environ['GITHUB_SHA']:
                raise RuntimeError('primary_reuse_identity')
            return 0
        if decision['decision'] != 'execute-first-full' or decision['receipt'] is not None:
            raise RuntimeError('primary_decision_kind')
    spec = plan(bound['script'], workflow)
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
    inputs = root / 'inputs'
    inputs.mkdir()
    (inputs / 'github-script.sh').write_bytes(script)
    (inputs / 'plan.json').write_text(json.dumps(spec, sort_keys=True))
    (inputs / 'uv.toml').write_bytes(b'')
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
    status = 125
    records = {}
    stage = 'create'
    STAGE = 'capsule'
    try:
        if run(argv, log).returncode:
            raise RuntimeError('primary_create_failed')
        config = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]
        validate(config, image, mounts)
        stage = 'capture'
        _, records = capture(['docker', 'start', '--attach', container], raw, identity, 'primary-executor')
        stage = 'settled'
        state = json.loads(subprocess.check_output(['docker', 'inspect', '--format={{json .State}}', container]))
        if state['Running'] or state['OOMKilled']:
            raise RuntimeError('primary_unsettled')
        status = state['ExitCode']
    except BaseException:
        # Only typed stage data enters public metadata; private exceptions are
        # unnecessary for this closed executor protocol.
        status = 125
    finally:
        run(['docker', 'rm', '--force', container], log)
    metadata = {'direct_identity': identity, 'source_checkpoint_ready': False, 'selected_carrier': None,
                'source_exit_code': status, 'stage': stage, 'primary_plan': spec,
                'head_sha': os.environ['GITHUB_SHA'], 'image_id': image,
                'source_pins_sha256': hashlib.sha256(json.dumps(source_pins, sort_keys=True).encode()).hexdigest(),
                'support': control['support'],
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
    return status


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
