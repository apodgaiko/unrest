"""Finite own constructor failures in separate, unchanged production capsules."""
from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

MODES = ('wrongcwd', 'nonsearchable')
SUPPORT = Path(__file__).resolve().parent


def sha(body):
    return hashlib.sha256(body).hexdigest()


def reduce_fault(records, mode):
    if mode not in MODES:
        raise RuntimeError('own_constructor_fault_mode')
    kernel = json.loads(records['kernel-source.json'])
    events = kernel['source_events']
    facts = [row for row in events if row['kind'] == 'own_constructor_fault']
    if len(facts) != 1:
        raise RuntimeError('own_constructor_fault_missing')
    fact = facts[0]
    token, pid, parent = fact['token'], fact['pid'], fact['owner_pid']
    constructors = [row for row in events if row['kind'] == 'child_relative_constructor'
                    and row['token'] == token and row['owner_pid'] == parent]
    admitted = [row for row in events if row['kind'] == 'admitted'
                and row['token'] == token and row['owner_pid'] == parent]
    launches = [row for row in events if row['kind'] == 'actual_launch_binding'
                and row['token'] == token and row['owner_pid'] == parent]
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['child'] == pid and row['identity']['ppid'] == parent]
    waits = [row for row in kernel['records'] if row['kind'] == 'original_parent_wait4'
             and row['child'] == pid and row['parent_tgid'] == parent and type(row['raw']) is int]
    if (fact['mode'] != mode or fact['calls'] != 1 or fact['outcome'] is None or fact['native_callback_error'] is not None
            or fact['before_fds'] != fact['after_fds']
            or fact['before_identity'] != fact['after_identity']
            or fact['profile_restored'] is not True or fact['cwd_restored'] is not True
            or fact['directory_absent'] is not True
            or len(constructors) != 1 or len(admitted) != 1 or len(launches) != 1
            or admitted[0]['class'] != 'source-child-relative-probe'
            or constructors[0]['constructor_cwd'] != '.'
            or constructors[0]['original_cwd'] is not None
            or len(births) != 1 or len(waits) != 1
            or len(fact['fork_returns']) != 1):
        raise RuntimeError('own_constructor_fault_composition')
    attempts = [row for row in kernel['records'] if row['kind'] == 'exec_attempt' and row['pid'] == pid]
    ready = [row for row in kernel['receipts'] if row['request']['kind'] == 'ready'
             and row['request']['pid'] == pid]
    custody = [row for row in kernel['source_pipe_records']
               if row['kind'] == 'child_relative_prebody_cwd' and row['identity']['pid'] == pid]
    if ready or custody:
        raise RuntimeError('own_constructor_fault_reached_later_boundary')
    if mode == 'wrongcwd':
        if (len(attempts) != 1 or attempts[0]['accepted'] is not False
                or attempts[0]['cwd'] != '/source/docs' or launches[0]['cwd'] != '/source'
                or sha(json.dumps(attempts[0]['argv']).encode()) != launches[0]['transformed_argv_sha256']
                or sha(json.dumps(attempts[0]['environment'], sort_keys=True).encode()) != launches[0]['environment_sha256']
                or 'unknown_or_drifted_exec' not in kernel['poison']
                or not any(row['kind'] == 'exec_syscall_return' and row['pid'] == pid
                           and row.get('denied') is True and row['return'] == -1
                           for row in kernel['records'])
                or 'source_descendant' not in kernel['primary_denials']):
            raise RuntimeError('own_constructor_resolver_denial_missing')
    elif (attempts or fact['outcome'] != {'class': 'PermissionError', 'errno': 13, 'filename': '.'}):
        raise RuntimeError('own_constructor_search_error_missing')
    # Every unrelated birth still requires its actual original parent's wait.
    for birth in kernel['records']:
        if birth['kind'] != 'kernel_child' or birth['identity']['tgid'] != birth['child']:
            continue
        joined = [row for row in kernel['records'] if row['kind'] in {
            'original_parent_wait4', 'original_parent_waitid'}
            and row['child'] == birth['child'] and row['parent_tgid'] == birth['identity']['ppid']
            and (row['kind'] == 'original_parent_wait4' or row['reaps'])]
        if len(joined) != 1:
            raise RuntimeError('own_constructor_unrelated_wait_missing')
    return {'mode': mode, 'verified': True, 'pid': pid, 'parent': parent, 'token': token,
            'constructor_outcome': fact['outcome'], 'actual_wait_raw': waits[0]['raw'],
            'exec_attempts': len(attempts), 'ready': False, 'later_custody': False,
            'poison': kernel['poison'], 'eligible_certificate': False}


def run(prepared):
    from preflight_policy import SCRIPT
    parent = Path(os.environ['RUNNER_TEMP'])
    retained = {}
    proof_path = prepared['raw'] / 'negative-control-proof.json'
    for mode in MODES:
        runner = parent / ('own-constructor-' + mode)
        runner.mkdir(mode=0o700)
        shutil.copytree(parent / 'source-readiness', runner / 'source-readiness')
        script = runner / 'script.sh'
        script.write_bytes(SCRIPT)
        command = [sys.executable, '-B', str(SUPPORT / 'child_relative_host.py'), mode, str(script)]
        host_log = runner / 'host.log'
        with host_log.open('xb') as output:
            result = subprocess.run(command, env={**os.environ, 'RUNNER_TEMP': str(runner)},
                                    stdout=output, stderr=subprocess.STDOUT, check=False)
        root = runner / 'primary-source-positive'
        # Retain the original failed capsule, even when our finite reducer fails.
        retained[mode] = {'command': command, 'exit_code': result.returncode,
                          'host_log': base64.b64encode(host_log.read_bytes()).decode(), 'members': {}}
        for name in ('evidence.cms', 'safe-provenance.json'):
            source = root / name
            if source.is_file() and not source.is_symlink():
                body = source.read_bytes()
                retained[mode]['members'][name] = {'sha256': sha(body),
                    'base64': base64.b64encode(body).decode()}
        proof_path.write_text(json.dumps({'schema': 'unrest.v047.own-constructor-capsules.v1',
                                        'capsules': retained}, sort_keys=True))
        if proof_path.stat().st_size > 64 * 1024 * 1024:
            raise RuntimeError('own_constructor_retention_bound')
        metadata = json.loads((root / 'safe-provenance.json').read_bytes())
        if (result.returncode != 2 or metadata['source_exit_code'] != 2
                or metadata.get('own_constructor_fault', {}).get('verified') is not True
                or metadata['own_constructor_fault']['mode'] != mode
                or metadata['head_sha'] != os.environ['GITHUB_SHA']):
            raise RuntimeError('own_constructor_host_fault_unproved')


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in MODES:
        raise RuntimeError('own_constructor_host_argv')
    mode, script = sys.argv[1:]
    from preflight_policy import SCRIPT, context
    context()
    if Path(script).read_bytes() != SCRIPT:
        raise RuntimeError('own_constructor_host_script')
    from full_bootstrap import produce
    produce('PREFLIGHT')
    import ci_shell
    sys.argv = [str(SUPPORT / 'ci_shell.py'), '--preflight', 'TEST-positive', script]
    try:
        return ci_shell.retained_main(own_constructor_fault=mode)
    finally:
        from preparation_retention import release, OWNED
        if ci_shell.ACTIVE_ROOT in OWNED:
            release(ci_shell.ACTIVE_ROOT)


if __name__ == '__main__':
    raise SystemExit(main())
