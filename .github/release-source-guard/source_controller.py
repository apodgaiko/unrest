"""Trusted focused-source coordination; source receives no host authority."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import traceback

from drain_controls import check as check_drain_controls

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
TMPFS = {
    '/work': 'rw,nosuid,nodev,size=128m,uid=20000,gid=20000,mode=0711',
    '/tmp': 'rw,nosuid,nodev,noexec,size=64m,mode=1777',
    '/records': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0700',
    '/receipts': 'rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0755',
}

def validate(config, image, source, inputs):
    host = config['HostConfig']
    expected = {'Privileged':False, 'ReadonlyRootfs':True, 'NetworkMode':'none',
                'PidMode':'', 'IpcMode':'private', 'CgroupnsMode':'private',
                'PidsLimit':128, 'Memory':1073741824}
    capabilities = host['CapAdd']
    if (any(host.get(k) != v for k,v in expected.items())
            or host['CapDrop'] != ['ALL'] or len(capabilities) != 5
            or {c.removeprefix('CAP_') for c in capabilities} != {
                'SETUID','SETGID','SETPCAP','SYS_PTRACE','DAC_READ_SEARCH'}
            or host['SecurityOpt'] != ['no-new-privileges'] or host['Tmpfs'] != TMPFS):
        raise RuntimeError('focused source privilege/namespace definition drift')
    mounts = config['Mounts']
    wanted = {'/guard':str(SUPPORT), '/source':str(source), '/inputs':str(inputs)}
    if len(mounts) != 3 or {m['Destination'] for m in mounts} != set(wanted):
        raise RuntimeError('focused source mount inventory drift')
    if any(m['Type'] != 'bind' or m['RW'] or m['Source'] != wanted[m['Destination']]
           or m['Propagation'] != 'rprivate' for m in mounts):
        raise RuntimeError('focused source read-only mount binding drift')
    if (config['Image'] != image or config['Config']['OpenStdin']
            or config['Config']['Entrypoint'] != ['/usr/local/bin/python']
            or config['Config']['Cmd'] != ['-B','/guard/source_compartment.py']):
        raise RuntimeError('focused source finite entry definition drift')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(argv, log, **kwargs):
    with log.open('ab') as output:
        return subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=False, **kwargs)

def main():
    root, controls = map(lambda s: Path(s).resolve(), sys.argv[1:3])
    selection = sys.argv[3] if len(sys.argv) == 4 else 'inprocess'
    if selection not in {'inprocess', 'composed', 'backend', 'drain-controls'}:
        raise RuntimeError('unknown focused source selection')
    root.mkdir(mode=0o700)
    raw = root / 'raw'
    raw.mkdir(mode=0o700)
    log = raw / 'coordinator.log'
    control = json.loads((controls / 'safe-provenance.json').read_text())
    if (control['head_sha'] != os.environ['GITHUB_SHA'] or control['synthetic_exit_code'] != 0
            or control['source_checkpoint_ready'] is not False):
        raise RuntimeError('same-snapshot prerequisite controls missing')
    for name, pin in control['support'].items():
        if sha(SUPPORT / name) != pin:
            raise RuntimeError('support drift after prerequisite controls')
    image = control['synthetic_dependencies']['image_id']
    if not image.startswith('sha256:') or len(image) != 71:
        raise RuntimeError('immutable environment image identity required')
    source = root / 'source'
    source.mkdir()
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=REPOSITORY).decode().split('\0')
    pins = {}
    for name in sorted(filter(None, names)):
        path = REPOSITORY / name
        if path.is_symlink() or not path.is_file() or '..' in Path(name).parts:
            raise RuntimeError('nonregular public source snapshot member')
        expected = subprocess.check_output(['git','show','HEAD:' + name], cwd=REPOSITORY)
        if path.read_bytes() != expected:
            raise RuntimeError('public checkout source drift')
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(expected)
        pins[name] = sha(destination)
    (raw / 'source-pins.json').write_text(json.dumps(pins, sort_keys=True))
    inputs = root / 'inputs'
    inputs.mkdir()
    nonce = secrets.token_hex(32)
    mounts = ['--mount=type=bind,src=' + str(SUPPORT) + ',dst=/guard,readonly',
              '--mount=type=bind,src=' + str(source) + ',dst=/source,readonly']
    prepare = ['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL',
               '--security-opt=no-new-privileges','--user=20001:20001',*mounts,
               '--entrypoint=/usr/local/bin/python',image,'-I','/guard/prepare_source.py',nonce,selection]
    with log.open('ab') as errors:
        prepared = subprocess.run(prepare, stdout=subprocess.PIPE, stderr=errors, check=False)
    (raw / 'prepared.stdout').write_bytes(prepared.stdout)
    exit_code = prepared.returncode
    container = 'focused-source-' + secrets.token_hex(12)
    if exit_code == 0:
        value = json.loads(prepared.stdout)
        (inputs / 'source.json').write_text(json.dumps(value['manifest'], sort_keys=True, indent=2) + '\n')
        (inputs / 'registry.py').write_text(value['registry'])
        argv = ['docker','create','--name',container,'--read-only','--network=none',
                '--ipc=private','--cgroupns=private','--cap-drop=ALL','--cap-add=SETUID',
                '--cap-add=SETGID','--cap-add=SETPCAP','--cap-add=SYS_PTRACE',
                '--cap-add=DAC_READ_SEARCH','--security-opt=no-new-privileges',
                '--pids-limit=128','--memory=1g',
                *['--tmpfs=' + path + ':' + options for path,options in TMPFS.items()],
                *mounts, '--mount=type=bind,src=' + str(inputs) + ',dst=/inputs,readonly',
                '--entrypoint=/usr/local/bin/python',image,'-B','/guard/source_compartment.py']
        try:
            if run(argv, log).returncode:
                raise RuntimeError('focused source container creation failed')
            inspected = subprocess.check_output(['docker','inspect',container])
            (raw / 'container-inspect.json').write_bytes(inspected)
            config = json.loads(inspected)[0]
            validate(config, image, source, inputs)
            run(['docker','start','--attach',container], log)
            state = json.loads(subprocess.check_output(['docker','inspect','--format={{json .State}}',container]))
            (raw / 'container-state.json').write_text(json.dumps(state, sort_keys=True))
            if state['Running'] or state['OOMKilled']:
                raise RuntimeError('focused source did not settle normally')
            exit_code = state['ExitCode']
        except Exception:
            with log.open('a') as output:
                traceback.print_exc(file=output)
            exit_code = 125
        finally:
            run(['docker','rm','--force',container], log)
    control_exit = exit_code
    negative_proof = None
    if selection == 'drain-controls':
        try:
            negative_proof = check_drain_controls(log, exit_code)
            (raw / 'negative-control-proof.json').write_text(json.dumps(negative_proof, sort_keys=True))
            control_exit = 0
        except Exception:
            with log.open('a') as output:
                traceback.print_exc(file=output)
            control_exit = 125
    identity = {key: os.environ.get(name) for key,name in {
        'repository':'GITHUB_REPOSITORY','head_sha':'GITHUB_SHA','run_id':'GITHUB_RUN_ID',
        'run_attempt':'GITHUB_RUN_ATTEMPT','workflow_ref':'GITHUB_WORKFLOW_REF',
        'workflow_sha':'GITHUB_WORKFLOW_SHA'}.items()}
    identity.update({'scope':'focused-original-' + selection, 'source_exit_code':exit_code,
                     'source_checkpoint_ready':False,'selected_carrier':None,
                     'source_pins_sha256':sha(raw / 'source-pins.json'), 'image_id':image,
                     'negative_control_proof':negative_proof, 'control_exit_code':control_exit,
                     'support':{str(p.relative_to(SUPPORT)):sha(p) for p in sorted(SUPPORT.rglob('*'))
                                if p.is_file() and p.suffix in {'.py','.json','.pem','.c'}}})
    (raw / 'provenance.json').write_text(json.dumps(identity, sort_keys=True, indent=2))
    archive = root / 'raw.tar.gz'
    with tarfile.open(archive,'w:gz') as output:
        for path in sorted(raw.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError('nonregular source evidence member')
            output.add(path,arcname=path.name,recursive=False)
    encrypted = root / 'evidence.cms'
    encrypted_result = run(['openssl','cms','-encrypt','-binary','-aes-256-cbc','-outform','DER',
                            '-in',str(archive),'-out',str(encrypted),
                            str(SUPPORT / 'evidence-recipient.pem')],root / 'encryption.log')
    if encrypted_result.returncode:
        raise RuntimeError('source evidence encryption failed')
    identity.update(ciphertext_sha256=sha(encrypted),plaintext_archive_sha256=sha(archive))
    (root / 'safe-provenance.json').write_text(json.dumps(identity,sort_keys=True,indent=2) + '\n')
    shutil.rmtree(raw)
    archive.unlink()
    return control_exit

if __name__ == '__main__':
    raise SystemExit(main())
