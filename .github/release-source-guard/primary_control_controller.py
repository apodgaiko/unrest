"""Run only primary source-free controls against their exact built runtime."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from probe_controller import TMPFS
from structured_evidence import capture, execution_identity

SUPPORT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, log):
    with log.open('ab') as output:
        return subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=False)


def main():
    from full_bootstrap import reserved
    if reserved(os.environ.get('GITHUB_REF', '')):
        raise RuntimeError('full_prepare_only_ref')

    root, prerequisite = map(Path, sys.argv[1:])
    root.mkdir(mode=0o700)
    raw = root / 'raw'
    raw.mkdir(mode=0o700)
    log = raw / 'coordinator.log'
    private = root / 'host-private'
    private.mkdir(mode=0o700)
    canary = private / 'canary.bin'
    canary.write_bytes(os.urandom(32))
    canary.chmod(0o600)
    inputs = root / 'inputs'
    inputs.mkdir(mode=0o755)
    (inputs / 'controls.json').write_text(json.dumps({'private_host_path': str(canary.resolve())}))
    (inputs / 'controls.json').chmod(0o444)
    previous = json.loads(prerequisite.read_bytes())
    image = previous['image_id']
    if (previous['head_sha'] != os.environ['GITHUB_SHA'] or previous['source_exit_code'] != 0
            or not image.startswith('sha256:') or len(image) != 71
            or any(digest(SUPPORT / name) != pin for name, pin in previous['support'].items())):
        raise RuntimeError('primary_control_prerequisite')
    mounts = {**TMPFS, '/receipts': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0755'}
    container = 'primary-native-controls-' + os.environ['GITHUB_RUN_ID']
    argv = ['docker', 'create', '--name', container, '--read-only', '--network=none',
            '--ipc=private', '--cgroupns=private', '--cap-drop=ALL', '--cap-add=SETUID',
            '--cap-add=SETGID', '--cap-add=SETPCAP', '--cap-add=SYS_PTRACE', '--cap-add=DAC_READ_SEARCH',
            '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g',
            *['--tmpfs=' + path + ':' + value for path, value in mounts.items()],
            '--mount=type=bind,src=' + str(SUPPORT) + ',dst=/guard,readonly',
            '--mount=type=bind,src=' + str(inputs) + ',dst=/inputs,readonly',
            '--entrypoint=/usr/local/bin/python', image, '-B', '/guard/primary_controls.py']
    direct = execution_identity(SUPPORT, 'primary-controls')
    status = 125
    try:
        if run(argv, log).returncode:
            raise RuntimeError('primary_controls_create')
        config = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]
        host = config['HostConfig']
        expected = {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                    'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                    'PidsLimit': 128, 'Memory': 1073741824, 'Tmpfs': mounts,
                    'SecurityOpt': ['no-new-privileges'], 'CapDrop': ['ALL']}
        caps = host['CapAdd']
        if (any(host.get(key) != value for key, value in expected.items()) or len(caps) != 5
                or {item.removeprefix('CAP_') for item in caps} != {
                    'SETUID', 'SETGID', 'SETPCAP', 'SYS_PTRACE', 'DAC_READ_SEARCH'}):
            raise RuntimeError('primary_controls_privileges')
        bound = config['Mounts']
        wanted = {'/guard': str(SUPPORT), '/inputs': str(inputs)}
        if (len(bound) != 2 or {row['Destination'] for row in bound} != set(wanted)
                or any(row['Type'] != 'bind' or row['RW'] or row['Propagation'] != 'rprivate'
                       or row['Source'] != wanted[row['Destination']] for row in bound)):
            raise RuntimeError('primary_controls_mounts')
        if (config['Image'] != image or config['Config']['OpenStdin']
                or config['Config']['Entrypoint'] != ['/usr/local/bin/python']
                or config['Config']['Cmd'] != ['-B', '/guard/primary_controls.py']):
            raise RuntimeError('primary_controls_definition')
        capture(['docker', 'start', '--attach', container], raw, direct, 'primary-controls')
        state = json.loads(subprocess.check_output(['docker', 'inspect', '--format={{json .State}}', container]))
        if state['Running'] or state['OOMKilled']:
            raise RuntimeError('primary_controls_unsettled')
        status = state['ExitCode']
    finally:
        run(['docker', 'rm', '--force', container], log)
    archive = root / 'raw.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        for path in sorted(raw.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError('primary_controls_member')
            output.add(path, arcname=path.name, recursive=False)
    if run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
            '-in', str(archive), '-out', str(root / 'evidence.cms'),
            str(SUPPORT / 'evidence-recipient.pem')], root / 'encryption.log').returncode:
        raise RuntimeError('primary_controls_encrypt')
    metadata = {'direct_identity': direct, 'head_sha': os.environ['GITHUB_SHA'],
                'source_exit_code': status, 'image_id': image, 'support': previous['support'],
                'source_checkpoint_ready': False, 'selected_carrier': None,
                'host_private_canary_sha256': digest(canary),
                'private_canary_outside_mounts': True,
                'structured_envelope_sha256': digest(raw / 'structured-envelope.json'),
                'plaintext_archive_sha256': digest(archive), 'ciphertext_sha256': digest(root / 'evidence.cms')}
    (root / 'safe-provenance.json').write_text(json.dumps(metadata, sort_keys=True))
    shutil.rmtree(raw)
    archive.unlink()
    return status


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        status = 125
    print(json.dumps({'schema': 'primary-control-status-v1', 'exit_code': status}))
    raise SystemExit(status)
