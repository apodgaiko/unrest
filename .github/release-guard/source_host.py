"""Run selected original cases in a private, measured Linux generation.

This is a bounded integration checkpoint, not full source certification. The
root driver only prepares inputs and settles its own children. Admission and
original-parent wait joins run in the separate reduced-credential observer.
"""
from __future__ import annotations

import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import traceback


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def selection(arguments,checkout):
    if arguments==[]:
        return []
    require(len(arguments)<=32 and all(type(value) is str for value in arguments)
            and sum(len(value.encode()) for value in arguments)<=16384,'bounded source selection')
    for value in arguments:
        file=value.split('::',1)[0]
        relative=Path(file)
        require(file.startswith('tests/') and relative.suffix=='.py' and str(relative)==file
                and '..' not in relative.parts and '\0' not in value
                and (checkout/relative).resolve()==checkout/relative and (checkout/relative).is_file(),
                'source selector must name a canonical original test file')
    return list(arguments)


def unexcluded(metadata,binding):
    return type(metadata['cases']) is dict and metadata.get('selection')==[] and not binding.get('collection_only')


def production_binding(binding):
    require(Path(binding['bootstrap']['path']) == Path(binding['support'])/'native_entry.py'
            and Path(binding['entry']['path']) == Path(binding['runtime']['path']).parent/'python-unrest-guard-control',
            'source host requires production native binding')


def inventory(root):
    """Measure private runtime/dependency copies, including large extension DSOs."""
    rows, total = [], 0
    members = sorted(root.rglob('*'))
    require(len(members) <= 20000, 'input inventory bound')
    for path in members:
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode), 'input member custody')
        require(not stat.S_IMODE(before.st_mode) & 0o6022, 'mutable or privileged input')
        if stat.S_ISDIR(before.st_mode):
            continue
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= 64 * 1024 * 1024, 'input member custody')
        total += before.st_size
        require(total <= 512 * 1024 * 1024, 'input total byte bound')
        from content_manifest import read_regular, _key
        _,after,pin=read_regular(path,64*1024*1024,forbidden=0o6022,retain=False)
        require(_key(before)==_key(after),'input measurement race')
        rows.append([str(path.relative_to(root)), stat.S_IMODE(before.st_mode), before.st_size, pin])
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def prepare(binding, checkout, root, git=False, public=False, native=False, extracted=None, distribution=False):
    from content_manifest import capture, encode
    require(subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=checkout).decode().strip()
            == binding['head'], 'source revision binding')
    require(not subprocess.check_output(['/usr/bin/git', 'diff', '--name-only', 'HEAD'], cwd=checkout),
            'source tracked drift')
    names = subprocess.check_output(['/usr/bin/git', 'ls-files', '-z'], cwd=checkout).decode().split('\0')[:-1]
    source = extracted if extracted is not None else root / 'source'
    if extracted is not None:
        names=sorted(str(path.relative_to(source)) for path in source.rglob('*') if path.is_file())
        source.parent.chmod(0o755)
    else:
        source.mkdir(mode=0o755)
    manifest = capture(source if extracted is not None else checkout, sorted(names))
    for row in (() if extracted is not None else manifest['files']):
        target = source / row['path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(checkout / row['path'], target)
        target.chmod(row['mode'])
    require(capture(source, sorted(names)) == manifest, 'private source copy changed')
    if public:
        probe=source/'src/unrest_harness.egg-info/PKG-INFO'
        probe.parent.mkdir(parents=True)
        probe.write_bytes(b'Ignored generated metadata exclusion probe\n')
        from public_git import prepare as public_git
        from content_manifest import _capture
        public_git(checkout, source, binding['head'])
        metadata_names = sorted(path.relative_to(source).as_posix() for path in (source / '.git').rglob('*') if path.is_file())
        metadata_files = _capture(source, metadata_names, None, 64 * 1024 * 1024)
        metadata = {'schema':'unrest.git-inputs.v1','file_bound':64 * 1024 * 1024,'files':metadata_files['files']}
    dependencies = root / 'dependencies'
    original = checkout / '.venv/lib/python3.13/site-packages'
    # Dereference only contained regular file aliases. Never carry host links
    # or hardlink aliases into the read-only generation.
    for member in sorted(original.rglob('*')):
        target = member.resolve(strict=True)
        require(target.is_relative_to(original) and (target.is_file() or target.is_dir())
                and not (member.is_symlink() and target.is_dir()), 'dependency alias refused')
    shutil.copytree(original, dependencies, symlinks=False, ignore=shutil.ignore_patterns('__pycache__'))
    for member in [dependencies, *sorted(dependencies.rglob('*'))]:
        member.chmod(0o755 if member.is_dir() or member.stat().st_mode & 0o111 else 0o644)
    if extracted is not None:
        shutil.copyfile(checkout/'tools/check_distribution.py',dependencies/'release_distribution_oracle.py')
    if distribution:
        from prepared_distribution import prepare as prepare_distribution
        prepare_distribution(binding,source,manifest,dependencies)
    owned = root / 'owned'
    owned.mkdir(mode=0o700)
    os.chown(owned, 20000, 20000)
    for name in ('home', 'tmp'):
        directory = owned / name
        directory.mkdir(mode=0o700)
        os.chown(directory, 20000, 20000)
    if git:
        from git_observer import HOME_CONFIG
        os.chown(owned, 20001, 20000)
        owned.chmod(0o1770)
        home = owned / 'home'
        config = home / '.gitconfig'
        config.write_bytes(HOME_CONFIG)
        os.chown(config, 20001, 20001)
        config.chmod(0o444)
        os.chown(home, 20001, 20001)
        home.chmod(0o555)
    profiles = Path(binding['profiles'])
    require(profiles.is_dir() and profiles.stat().st_uid == 20001, 'protected profiles missing')
    native_input = None
    if native:
        from native_metadata import prepare as prepare_native
        native_root = root/'native-metadata'
        native_input = {'root':str(native_root),'descriptor':prepare_native(native_root)}
        native_input['generation']=[native_root.stat().st_dev,native_root.stat().st_ino]
    raw = encode(manifest)
    if public or native:
        envelope = {'schema':'unrest.source-inputs.v1','source':manifest}
        if public:
            envelope['git'] = metadata
        if native_input is not None:
            envelope['native_metadata'] = native_input['descriptor']
        raw = json.dumps(envelope,sort_keys=True,separators=(',',':')).encode()
        require(len(raw) <= 16 * 1024 * 1024, 'source input manifest bound')
    target = profiles / 'source-manifest.json'
    if target.exists():
        target.rename(profiles/('source-manifest-'+hashlib.sha256(target.read_bytes()).hexdigest()+'.json'))
    with target.open('xb') as stream:
        stream.write(raw)
    target.chmod(0o444)
    os.chown(target, 20001, 20001)
    runtime = Path(binding['entry']['path']).parent.parent
    support = Path(binding['support'])
    return {'checkout': str(source), 'owned': str(owned), 'dependencies': str(dependencies),
            'runtime_root': str(runtime), 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'support_sha256': inventory(support), 'runtime_sha256': inventory(runtime),
            'dependency_sha256': inventory(dependencies),
            **({'_native_input':native_input} if native_input is not None else {})}


def isolate(metadata, support, output):
    libc = ctypes.CDLL(None, use_errno=True)
    # Private mount/network/IPC namespaces; no shared-host mount mutation.
    network_before=os.readlink('/proc/self/ns/net')
    require(libc.unshare(0x00020000 | 0x40000000 | 0x08000000) == 0, 'private namespace refused')
    if libc.mount(None, b'/', None, ctypes.c_ulong((1 << 18) | (1 << 14)), None):
        raise OSError(ctypes.get_errno(), 'private mount propagation refused')
    points={path:path for path in (metadata['checkout'],metadata['dependencies'],metadata['runtime_root'],support)}
    native_input=metadata.get('_native_input')
    if native_input is not None:
        points['/native']=native_input['root']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        request = struct.pack('16sH14x', b'lo', 0)
        current = fcntl.ioctl(stream.fileno(), 0x8913, request)
        flags = struct.unpack_from('H', current, 16)[0]
        fcntl.ioctl(stream.fileno(), 0x8914, struct.pack('16sH14x', b'lo', flags | 1))
    from network_scope import isolated
    metadata['network_namespace']=isolated(network_before)
    from filesystem_scope import enter
    return enter({**metadata, 'mounts': points}, support, output)


def settle(pid, terminate=False, deadline=None):
    try:
        actual, raw = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return None
    if actual:
        return raw
    if terminate:
        os.kill(pid, signal.SIGKILL)
    if deadline is None:
        deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        actual, raw = os.waitpid(pid, os.WNOHANG)
        if actual:
            return raw
        time.sleep(.001)
    raise RuntimeError('owned host cleanup actual wait missing')


def worker(binding, metadata, raw_directory):
    from compartment import credentials
    from linux_trace import OwnedTrace, install_observation_filter
    from source_observer import Observer
    metadata = isolate(metadata, binding['support'], raw_directory)
    full=type(metadata['cases']) is dict
    timeout=1200 if unexcluded(metadata,binding) else 60 if binding.get('collection_only') else 170 if full else 100
    start_read, start_write = os.pipe()
    ready_read, ready_write = os.pipe()
    output_read, output_write = os.pipe()
    if full:
        from full_source import environment as full_environment
        from source_profile import pytest_arguments as arguments
        environment=full_environment(metadata)
        vector=['/usr/bin/env','-u','CODEX_PATH','uv','run',*arguments(metadata,binding)]
    else:
        from console_entries import standalone_environment
        from postbuild_root import COMMAND
        environment=standalone_environment(metadata)
        vector=[binding['entry']['path'],'-I','-S','-c',COMMAND,binding['checkout']]
    child = os.fork()
    if child == 0:
        try:
            os.close(start_write)
            os.close(ready_read)
            with open('/dev/null', 'rb') as stream:
                os.dup2(stream.fileno(), 0)
            os.dup2(output_write, 1)
            os.dup2(output_write, 2)
            os.chdir(metadata['checkout'])
            credentials(20000)
            os.setsid()
            install_observation_filter()
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                os._exit(125)
            os.closerange(3, 1 << 20)
            os.execve(vector[0], vector, environment)
        finally:
            os._exit(125)
    observer, trace, result, failure = None, None, None, None
    os.close(start_read)
    os.close(ready_write)
    os.close(output_write)
    try:
        credentials(20001)
        require(bool(select.select([ready_read], [], [], 5)[0]) and os.read(ready_read, 1) == b'R',
                'source held startup handshake')
        os.close(ready_read)
        observer = Observer(binding, metadata, child, output_read)
        allowed = [{'pid': child, 'path': vector[0], 'argv': vector, 'environment': environment,
                    'cwd': metadata['checkout'], 'sha256': hashlib.sha256(Path(vector[0]).read_bytes()).hexdigest()}]
        trace = OwnedTrace(child, allowed, timeout, start_write=start_write, selective=True, cleanup_seconds=5, full_source=unexcluded(metadata,binding),
                           on_attached=lambda: observer.consume(trace), on_tick=observer.tick,
                           resolve_exec=lambda *args: observer.resolve(trace, *args),
                           validate_wait=lambda *args: observer.validate_wait(trace, *args))
        result = trace.run()
        observer.tick(trace)
        if full:
            from full_launch import finished
            finished(observer)
        require(result['root_parent_wait_raw'] == 0 and not result['poison']
                and observer.finished and tuple(observer.completed) == (() if binding.get('collection_only') else observer.cases)
                and not observer.frames
                and all(intent['consumed'] for intent in observer.intents.values()), 'original source completion refused')
    except BaseException:
        failure = traceback.format_exc()
        if trace is None:
            os.close(start_write)  # Held subject receives EOF, never a synthetic reap.
            status = settle(child)
            (raw_directory / 'held-source-cleanup.json').write_text(json.dumps({'actual_parent_wait': status}))
        raise
    finally:
        try:
            record = {'schema': 'unrest.bootstrap-source-result.v5', 'wait_evidence': 'kernel-original-parent-terminal-wait4-and-explicit-namespace-init-wait', 'source_checkpoint_ready': bool(result is not None and result['root_parent_wait_raw']==0 and observer is not None and unexcluded(metadata,binding) and observer.finished and failure is None),
                      'git_value_provenance_proven':False, 'release_certified': False, 'completed': [] if observer is None else observer.completed,
                      'result': result, 'failure': failure, 'metadata': metadata,
                      'kernel': [] if trace is None else trace.records,
                      'controls': [] if observer is None else observer.controls,
                      'outcomes': [] if observer is None else observer.outcomes,
                      'network_observations': {'namespace':metadata.get('network_namespace'),
                          'tcp_peer_ownership_proven':False,'tcp_quotas_proven':False,
                          'reservation_causality_proven':False,'application_payload_proven':False,
                          'unix_pair_lineage_proven':False},
                      'cohort_observations': [] if observer is None else observer.cohort_observations,
                      'adoptions': [] if observer is None else observer.adoptions,
                      'plan_observations': [] if observer is None else observer.plan_records,
                      'trace_poison': None if trace is None else trace.poison,
                      'output_base64': '' if observer is None else base64.b64encode(observer.output).decode()}
            if observer is not None and observer.full:
                ref=observer.meta['cases']
                body=Path(ref['path']).read_bytes()
                require(len(body)<=8*1024*1024 and hashlib.sha256(body).hexdigest()==ref['sha256'],'source inventory evidence bytes')
                (raw_directory/'collected-cases.json').write_bytes(body)
            (raw_directory / 'source-result.json').write_text(json.dumps(record, sort_keys=True))
        finally:
            if observer is not None:
                observer.close()


def children():
    rows = Path('/proc/self/task/' + str(os.getpid()) + '/children').read_text().split()
    require(len(rows) <= 32 and all(row.isdecimal() for row in rows), 'host child census bound')
    return sorted(int(row) for row in rows)


def drain_owned(rows):
    deadline = time.monotonic() + 5
    while children():
        require(time.monotonic() < deadline and len(rows) < 32, 'bounded adopted cleanup')
        # Reaping this root may reparent its own children to the dedicated
        # driver. Re-census until empty under the same deadline.
        for child in children():
            require(len(rows) < 32, 'adopted population bound')
            rows.append({'pid': child, 'actual_wait': settle(child, terminate=True, deadline=deadline),
                         'original_parent_wait_proven': False})

def supervise(binding,metadata,raw_directory,archive):
    """PID1 owns observer waits and all adoption; host PIDs stay outside."""
    require(os.getpid()==1,'source supervisor must be namespace init')
    metadata={**metadata,'pid_namespace':os.readlink('/proc/self/ns/pid')}
    try:
        pid = os.fork()
        if pid == 0:
            try:
                worker(binding, metadata, raw_directory)
            except BaseException:
                (raw_directory / 'worker-failure.txt').write_text(traceback.format_exc())
                os._exit(125)
            os._exit(0)
        closeouts={}
        raw, deadline = None, time.monotonic() + (110 if archive else 1220 if unexcluded(metadata,binding) else 190)
        try:
            while raw is None:
                from cohort_controller import host_tick
                host_tick(binding['profiles'],closeouts)
                from composed_adoption import host_tick as adopted_tick
                adopted_tick(binding['profiles'])
                actual, status = os.waitpid(pid, os.WNOHANG)
                if actual:
                    raw = status
                elif time.monotonic() > deadline:
                    raise TimeoutError('source observer finite deadline')
                else:
                    time.sleep(.005)
        finally:
            if raw is None:
                raw = settle(pid, terminate=True)
            (raw_directory / 'observer-parent-wait.json').write_text(json.dumps({'actual_parent_wait': raw}))
        require(raw == 0, 'original source integration failed; encrypted diagnostics retained')
    finally:
        adopted=[]
        try:
            drain_owned(adopted)
        finally:
            (raw_directory/'namespace-fallback-cleanup.json').write_text(json.dumps(adopted))
        require(not adopted,'namespace emergency cleanup cannot certify source')


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    require(sys.platform=='linux' and os.getuid()==0 and len(sys.argv)>=2,'source host requires root Linux invocation')
    binding_file = Path(sys.argv[1]).resolve(strict=True)
    binding = json.loads(binding_file.read_bytes())
    root = binding_file.parent
    require(root.name == 'guard-native-control' and binding['profiles'] == str(root / 'profiles'), 'host output binding')
    for name in ('entry', 'bootstrap', 'source', 'library', 'compiler', 'runtime', 'recipient', 'uv'):
        row = binding[name]
        require(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest() == row['sha256'], 'native host input drift')
    production_binding(binding)
    binding['collection_only']=len(sys.argv)==3 and sys.argv[2]=='full-collect'
    profiles = Path(binding['profiles'])
    if not profiles.exists() and not profiles.is_symlink():
        profiles.mkdir(mode=0o755)
        os.chown(profiles, 20001, 20001)
    require(stat.S_ISDIR(profiles.lstat().st_mode) and profiles.lstat().st_uid == 20001, 'source protected profiles custody')
    require(not children(), 'source host must begin childless')
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'source host subreaper required')
    def interrupted(signum, frame):
        raise TimeoutError('source host outer deadline')
    signal.signal(signal.SIGTERM, interrupted)
    archive=len(sys.argv)==4 and sys.argv[2]=='archive15'
    raw_directory = root / ('archive-private' if archive else 'source-private')
    raw_directory.mkdir(mode=0o700)
    os.chown(raw_directory, 20001, 20001)
    success = False
    try:
        from postbuild_root import CASES as ARCHIVE_CASES
        from controlled_cases import ADMISSION,NOTIFICATION_STARTUP,NOTIFICATION_SIGNALS,ROOT_HTTP
        from fixed_inline import CONSOLE_CASE,UV_CASES
        from package_cases import CASES as PACKAGE_CASES
        checkout=Path.cwd().resolve(strict=True)
        chosen=[] if archive or binding['collection_only'] else selection(sys.argv[2:],checkout)
        modules={value.split('::',1)[0] for value in chosen}
        native_inputs=not chosen or bool(modules & {case.split('::',1)[0] for case in (*ADMISSION,*NOTIFICATION_STARTUP,*NOTIFICATION_SIGNALS,*ROOT_HTTP)})
        distribution=not chosen or bool(modules & {case.split('::',1)[0] for case in (CONSOLE_CASE,*UV_CASES,*PACKAGE_CASES)})
        phase_root=root/'archive' if archive else root
        if archive:
            phase_root.mkdir(mode=0o755)
        metadata={**prepare(binding,checkout,phase_root,
            extracted=Path(sys.argv[3]).resolve(strict=True) if archive else None,
            git=not archive,public=not archive,native=not archive and native_inputs,
            distribution=not archive and distribution),
            'cases':list(ARCHIVE_CASES) if archive else [],'selection':chosen}
        if not archive:
            from full_launch import prepare as prepare_full
            metadata=prepare_full(binding,metadata)
        from namespace_supervisor import run
        run(lambda:supervise(binding,metadata,raw_directory,archive),raw_directory/'namespace-failure.txt')
        success = True
    finally:
        adopted: list[dict] = []
        try:
            drain_owned(adopted)
            if adopted:
                success = False
        finally:
            (raw_directory / 'fallback-cleanup.json').write_text(json.dumps(adopted))
            packed = root / (raw_directory.name+'.tar')
            with tarfile.open(packed, 'w') as stream:
                stream.add(raw_directory, arcname='source-private', recursive=True)
            subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
                            '-in', str(packed), '-out', str(root / (raw_directory.name+'.cms')), binding['recipient']['path']], check=True)
            packed.unlink()
        require(not children(), 'source host cleanup residue')
    require(success, 'original source integration did not complete')
    print('Guarded source integration passed; release certification: false', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
