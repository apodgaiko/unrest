"""Execute the actual GitHub script under a separate finite primary authority."""
from __future__ import annotations

from approval_wait_evidence import unresolved, summary_closed

import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import stat

from linux_compartment import source_credentials, observer_credentials
from linux_observation import process_identity
from linux_trace import OwnedTrace, install_observation_filter
from primary_policy import environment, plan, sha, primary_root_allocation
from primary_authority import Authority
from primary_source_inputs import test_plan, decode
from owned_multiprocess_authority import DependencySourceAuthority as SourceAuthority
import producer_setup
import source_root
import dependency_closure
import primary_entry_build
from structured_evidence import source_binding, HEADER_LIMIT
from source_raw_transport import emit_source


STAGE = 'bootstrap'


def read_transport_binding():
    # This literal runner-owned input is not a caller-selected filesystem route.
    path = '/inputs/transport-identity.json'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > HEADER_LIMIT:
            raise RuntimeError('transport_binding_carrier')
        body = os.read(descriptor, HEADER_LIMIT + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    def identity(info):
        return tuple(getattr(info, key) for key in (
            'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    if identity(before) != identity(after) or identity(after) != identity(os.lstat(path)) or len(body) != before.st_size:
        raise RuntimeError('transport_binding_carrier')
    return source_binding(body)


def trace_failure_status(error):
    name = type(error).__name__
    closed = {'TimeoutError', 'RuntimeError', 'OSError', 'ProcessLookupError',
              'ValueError', 'KeyError', 'TypeError', 'EvidenceRefused'}
    frame = error.__traceback__
    while frame is not None and frame.tb_next is not None:
        frame = frame.tb_next
    location = None if frame is None else hashlib.sha256(json.dumps({
        'code_sha256': hashlib.sha256(frame.tb_frame.f_code.co_code).hexdigest(),
        'first_line': frame.tb_frame.f_code.co_firstlineno, 'line': frame.tb_lineno},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'exception_class': name if name in closed else 'other', 'location_sha256': location}


def status_guard_success(result):
    return (result['root_parent_wait_raw'] == 0 and not result['poison']
            and not result['primary_denials'] and result['failure_code'] is None
            and not unresolved(result) and not result['native_preinit_refusal']
            and result['all_commands_dispatched'] and not result.get('guard_poison', True)
            and not result.get('receipt_ledger_poison'))


def main():
    global STAGE
    if os.getpid() != 1 or os.getuid() != 0:
        raise RuntimeError('primary_bootstrap_identity')
    script = Path('/inputs/github-script.sh').read_bytes()
    workflow = Path('/source/.github/workflows/ci.yml').read_text()
    source_input = decode(Path('/inputs/source-input.json').read_bytes()) if Path('/inputs/source-input.json').is_file() else None
    test_mode = Path('/inputs/test-mode').read_text() if Path('/inputs/test-mode').is_file() else None
    package_test = Path('/inputs/package-test').is_file()
    if package_test:
        from primary_package_inputs import plan as package_plan
        spec = package_plan(script, workflow, None, test=True)
    else:
        spec = test_plan(script, workflow, test_mode) if test_mode else plan(script, workflow, source_input)
    package_build = spec.get('package_mode') is not None
    package_archive = package_build and spec['duty'] == 'Check distribution archives'
    package_installed = package_build and spec['duty'] == 'Smoke-test installed wheel'
    package_checksum = package_build and spec['duty'] == 'Generate and verify v0.4.7 build-local checksums'
    if spec != json.loads(Path('/inputs/plan.json').read_bytes()):
        raise RuntimeError('primary_script_plan_drift')
    expected = json.loads(Path('/inputs/identity.json').read_bytes())
    transport_identity = read_transport_binding()
    if transport_identity['identity']['head_sha'] != expected['head_sha']:
        raise RuntimeError('transport_head_identity')
    STAGE = 'dependencies'
    if (Path('/source/.git/HEAD').read_text() != expected['head_sha'] + '\n'
            or Path('/source/.git').stat().st_uid != 20000):
        raise RuntimeError('primary_git_metadata_identity')
    dependency_closure.verify_source_view(Path('/environment-closure.json').read_bytes())
    STAGE = 'runtime'
    runtime = primary_entry_build.verify()
    if spec.get('source_mode') or package_build:
        import native_entry_build
        import profile_gate_build
        import native_metadata
        import producer_inputs
        from linux_observation import require_linux_abi
        runtime = {'primary': runtime, 'source_abi': require_linux_abi(),
                   'source_native': native_entry_build.verify(),
                   'source_profile_gate': profile_gate_build.verify(),
                   'source_metadata': native_metadata.verify(),
                   'source_producer_inputs': producer_inputs.verify()}
    env = environment(source=bool(spec.get('source_mode')) or package_archive or package_installed)
    if package_installed:
        env = {**env, 'UV_FIND_LINKS': '/opt/primary-installed-wheels'}
    own_prebody_control = None
    if spec.get('source_mode') in {'TEST-positive', 'TEST-poison'}:
        from child_relative_control import run as own_prebody_probe
        own_prebody_control = own_prebody_probe(runtime['primary'], env)
        if own_prebody_control.get('verified') is not True:
            failure = {'failure_code': 'child_relative_control_refused',
                       'stage': 'child_relative_control', 'primary_records': [own_prebody_control],
                       'source_checkpoint_ready': False, 'selected_carrier': None}
            emit_source({'kernel-source.json': json.dumps(failure, sort_keys=True).encode()}, failure,
                        transport_identity['identity'], transport_identity['invocation_sha256'], 125)
            return 125
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    STAGE = 'source_setup'
    child = os.fork()
    if child == 0:
        try:
            os.dup2(write, 1)
            os.dup2(write, 2)
            os.close(ready_read)
            os.close(start_write)
            source_credentials()
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            if own_prebody_control is not None:
                from child_relative_control import source_cleanup
                source_cleanup(own_prebody_control)
            for name in ('home', 'tmp', 'events', 'owned'):
                (Path('/work') / name).mkdir(mode=0o700)
            if spec.get('source_mode') or package_build:
                producer_setup.source_child_setup(primary=True)
            shutil.copytree('/opt/primary-cache', '/work/cache', symlinks=True)
            # Relocate only native-produced internal archive links.
            for path in sorted(Path('/work/cache').rglob('*')):
                if path.is_symlink():
                    target = os.readlink(path)
                    if target.startswith('/opt/primary-cache/'):
                        path.unlink()
                        path.symlink_to('/work/cache/' + target.removeprefix('/opt/primary-cache/'))
            if spec.get('package_input_required'):
                from primary_package_inputs import consume as consume_package_input
                descriptor = json.loads(Path('/inputs/package-input.json').read_bytes())
                if descriptor['binding']['definition'] != expected or descriptor['duty'] != spec['duty']:
                    raise RuntimeError('primary_package_input_binding')
                consumption = consume_package_input(descriptor)
                Path('/work/package-input-consumption.json').write_text(json.dumps(consumption, sort_keys=True))
            install_observation_filter()
            os.setsid()
            os.chdir('/source')
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                os._exit(126)
            os.closerange(3, 1 << 20)
            os.execve(spec['shell_argv'][0], spec['shell_argv'], env)
        finally:
            os._exit(126)
    os.close(write)
    os.close(ready_write)
    os.close(start_read)
    observer_credentials()
    if os.read(ready_read, 1) != b'R':
        os.waitpid(child, 0)
        raise RuntimeError('primary_child_fence')
    os.close(ready_read)
    STAGE = 'authority'
    if package_installed or package_checksum:
        from primary_package_shell import PackageShellAuthority
        authority = PackageShellAuthority(spec, child, env)
    elif package_archive:
        from primary_package_authority import PackageArchivePrimaryAuthority
        authority = PackageArchivePrimaryAuthority(spec, child, env)
    else:
        authority = Authority(spec, child, env)
    if own_prebody_control is not None:
        from child_relative_control import confirm_source_cleanup
        confirm_source_cleanup(own_prebody_control)
        authority.records.append(own_prebody_control)
    if spec.get('package_input_required'):
        descriptor = json.loads(Path('/inputs/package-input.json').read_bytes())
        consumption = json.loads(Path('/work/package-input-consumption.json').read_bytes())
        expected_consumption = {
            'schema': 'unrest.v046.primary-package-input-consumption.v1',
            'descriptor_sha256': sha(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()),
            'members': descriptor['members']}
        if consumption != expected_consumption or descriptor['binding']['definition'] != expected:
            raise RuntimeError('primary_package_actual_input_consumption')
        authority.records.append({'kind': 'primary_package_input_consumption', 'pid': child,
                                  'identity': process_identity(child), **consumption})
    source = None
    if spec.get('source_mode') or package_build and not package_checksum:
        initial_path = Path('/inputs/source.json')
        initial = json.loads(initial_path.read_bytes())
        manifest_path, pin, common = producer_setup.prepare(initial, sha(initial_path.read_bytes()))
        if package_installed:
            from primary_package_installed import InstalledSession
            source = InstalledSession(manifest_path, pin, common, authority.contexts)
        elif package_archive:
            from primary_package_archive import PackageArchiveAuthority
            source = PackageArchiveAuthority(manifest_path, pin, common, authority.contexts)
        elif package_build:
            from primary_package_build import PackageBuildAuthority
            source = PackageBuildAuthority(manifest_path, pin, common, authority.contexts)
        else:
            source = SourceAuthority(manifest_path, pin, common, authority.contexts)
        authority.source, authority.output_fd = source, read
        if package_build and spec['duty'] == 'Build wheel and source distribution':
            source.initialize(authority, child, read)
    os.set_blocking(read, False)
    output = bytearray()
    def tick(trace):
        if source is not None:
            source.tick(trace)
        while True:
            try:
                part = os.read(read, 65536)
            except BlockingIOError:
                break
            if not part:
                break
            output.extend(part)
            if len(output) > 16 * 1024 * 1024:
                raise RuntimeError('primary_output_bound')
    def attached():
        os.write(start_write, b'1')
        os.close(start_write)
    root_identity = process_identity(child)
    if (root_identity['uids'] != [20000] * 4 or any(root_identity['capabilities'].values())
            or root_identity['no_new_privs'] != 1):
        raise RuntimeError('primary_child_credentials')
    allowed = [{'pid': child, 'path': spec['shell_argv'][0], 'argv': spec['shell_argv'],
                'environment': env, 'cwd': '/source',
                'sha256': sha(Path(spec['shell_argv'][0]).read_bytes())}]
    trace = None
    def resolve(pid, path, argv, values, cwd):
        return authority.resolve(trace, pid, path, argv, values, cwd)
    allocation = primary_root_allocation() if spec['timeout_seconds'] > 180 else None
    if package_installed:
        from primary_package_trace import PackageInstalledTrace
        trace = PackageInstalledTrace(child, allowed, spec['timeout_seconds'], on_tick=tick,
                                      resolve_exec=resolve, seize=True, on_attached=attached,
                                      selective=True, primary_allocation=allocation,
                                      package_authority=authority)
    else:
        trace = OwnedTrace(child, allowed, spec['timeout_seconds'], on_tick=tick,
                           resolve_exec=resolve, seize=True, on_attached=attached, selective=True,
                           primary_allocation=allocation)
    failure = None
    trace_status = None
    STAGE = 'trace'
    try:
        result = trace.run()
        tick(trace)
    except BaseException as error:
        failure = 'trace_failure'
        trace_status = trace_failure_status(error)
        result = {'records': trace.records, 'poison': trace.poison,
                  'root_parent_wait_raw': trace.root_parent_wait,
                  'diagnostic_trace': trace.diagnostic_trace.export()}
    os.close(read)
    births = {row['child']: row for row in result['records'] if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']}
    waits = {pid for pid, birth in births.items() if len([
        row for row in result['records']
        if row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
        and (row['kind'] == 'original_parent_wait4' or row['reaps'])
        and row['child'] == pid and row['parent_tgid'] == birth['identity']['ppid']]) == 1}
    children = {row['child'] for row in result['records'] if row['kind'] == 'kernel_child'
                and row['identity']['tgid'] == row['child']}
    native_failure = any(row['kind'] == 'kernel_exit' and row['raw'] == 86 << 8
                         for row in result['records'])
    diagnostics = []
    for row in authority.records:
        if row['kind'] == 'primary_native_preinit':
            path = Path('/work') / ('primary-native-state-' + str(row['pid']) + '.json')
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192:
                diagnostics.append(json.loads(path.read_bytes()))
    unregistered = children - set(authority.contexts)
    if unregistered:
        result['poison'].append('unregistered_process_birth')
    result.update({'trace_failure_status': trace_status, 'unregistered_processes': sorted(unregistered), 'native_diagnostics': diagnostics, 'primary_plan': spec, 'primary_records': authority.records,
                   'primary_denials': authority.denials, 'failure_code': failure,
                   'native_preinit_refusal': native_failure,
                   'missing_parent_waits': sorted(children - waits),
                   'source_preexec_identity': root_identity,
                   'runtime_binding_sha256': sha(json.dumps(runtime, sort_keys=True).encode()),
                   'actual_script_sha256': hashlib.sha256(script).hexdigest(),
                   'all_commands_dispatched': authority.next_command == len(spec['commands']),
                   'source_checkpoint_ready': False, 'selected_carrier': None})
    if source is not None:
        result.update(source.finish())
    if package_checksum:
        result.update(guard_poison=bool(result['poison'] or authority.denials), receipt_ledger_poison=[])
    records = {'source-output.log': bytes(output)}
    if package_build and spec['duty'] == 'Build wheel and source distribution' and getattr(source.producers, 'package_cache_refusal', None) is not None:
        records['package-proof.json'] = json.dumps(source.producers.package_cache_refusal, sort_keys=True, separators=(',', ':')).encode()
    if package_build and status_guard_success(result):
        try:
            if package_checksum:
                authority.require_complete(trace)
            else:
                source.require_complete(trace)
            if package_installed:
                authority.require_complete(trace)
            from primary_outputs import export
            if spec['duty'] == 'Build wheel and source distribution':
                from primary_package_exports import export as export_build
                records['package-output.json'] = export_build(source, trace, result)
            else:
                records['package-output.json'] = export(spec['duty'])
            if package_archive or package_installed:
                records['package-proof.json'] = json.dumps(source.package_proof, sort_keys=True, separators=(',', ':')).encode()
        except BaseException as error:
            failure = 'package_output_refused'
            result['failure_code'] = failure
            result['trace_failure_status'] = trace_failure_status(error)
    if source is not None and not package_build:
        for name in ('collection.json', 'summary.json', 'source.xml', 'source-provenance.json'):
            path = Path('/work') / name
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 32 * 1024 * 1024:
                records[name] = path.read_bytes()
        # A successful pytest return cannot erase a caught guard refusal.
        summary = json.loads(Path('/work/summary.json').read_bytes()) if Path('/work/summary.json').is_file() else None
        if (summary is None or not summary_closed(summary, result)
                or result['guard_poison'] or result['receipt_ledger_poison']):
            failure = 'source_guard_refused'
        result['failure_code'] = failure
    status = 0 if (result['root_parent_wait_raw'] == 0 and not result['poison']
                   and not authority.denials and not native_failure and not failure
                   and not unresolved(result) and result['all_commands_dispatched']) else 2
    source_root.retain_proof(result, root_identity, runtime)
    records['kernel-source.json'] = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    emit_source(records, result, transport_identity['identity'], transport_identity['invocation_sha256'], status)
    return status


if __name__ == '__main__':
    try:
        status = main()
    except BaseException as error:
        trace = error.__traceback__
        lines = []
        while trace is not None:
            lines.append(trace.tb_lineno)
            trace = trace.tb_next
        record = {'failure_code': 'bootstrap_failure', 'stage': STAGE, 'frame_lines': lines[-8:],
                  'source_checkpoint_ready': False, 'selected_carrier': None}
        transport_identity = read_transport_binding()
        emit_source({'kernel-source.json': json.dumps(record, sort_keys=True, separators=(',', ':')).encode()}, record,
                    transport_identity['identity'], transport_identity['invocation_sha256'], 125)
        status = 125
    raise SystemExit(status)
