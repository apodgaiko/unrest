"""Actual Git-parent and Python-parent kernel waits; no stdout provenance claim."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from git_observer import Git
from git_operands import digest
from types import SimpleNamespace
from process_ledger import Birth, Ledger
from test_process_ledger_native import trace

pytestmark = pytest.mark.skipif(sys.platform != 'linux' or os.uname().machine != 'x86_64',
    reason='requires actual Linux Git parents and kernel waits')

BODY = '''
import json, os, subprocess, sys
fd, nonce, repository = int(sys.argv[1]), sys.argv[2], sys.argv[3]
fields = open('/proc/self/stat').read().rpartition(') ')[2].split()
pid = os.getpid()
identity = {'pid':pid, 'tgid':pid, 'ppid':int(fields[1]), 'start_ticks':int(fields[19]),
 'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),
 'uids':[int(v) for v in next(s for s in open('/proc/self/status') if s.startswith('Uid:')).split()[1:]],
 'pgid':os.getpgid(0), 'sid':os.getsid(0), 'clock_ticks_per_second':os.sysconf('SC_CLK_TCK')}
original_wait = os.waitpid
receipts = []
def wait(child, options):
    actual, raw = original_wait(child, options)
    if actual:
        receipts.append({'pid':actual, 'child_token':'child-' + str(actual), 'nonce':nonce,
          'owner_pid':pid, 'owner_identity':identity, 'owner_token':'root',
          'requested_pid':child, 'wait_event':'actual_os_waitpid_return', 'raw_status':raw,
          'numeric_returncode':os.waitstatus_to_exitcode(raw), 'options':options})
    return actual, raw
os.waitpid = wait
commit = subprocess.run(['/usr/bin/git', 'commit', '--allow-empty', '-m', 'base'], cwd=repository,
 check=True, capture_output=True, text=True)
head = subprocess.run(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=repository,
 check=True, capture_output=True, text=True)
body = json.dumps({'receipts':receipts, 'head':head.stdout}, sort_keys=True).encode()
assert len(body) < 4096 and os.write(fd, body) == len(body)
os.close(fd)
'''


def test_real_git_native_parent_wait_and_distinct_python_parent_numeric_join(tmp_path):
    repository = tmp_path / 'project'
    repository.mkdir()
    environment = {'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path), 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_AUTHOR_NAME': 'Workspace Test', 'GIT_AUTHOR_EMAIL': 'workspace@example.test',
        'GIT_AUTHOR_DATE': '@1700000000 +0000', 'GIT_COMMITTER_DATE': '@1700000000 +0000',
        'GIT_COMMITTER_NAME': 'Workspace Test', 'GIT_COMMITTER_EMAIL': 'workspace@example.test'}
    subprocess.run(['/usr/bin/git', 'init', '-b', 'main'], cwd=repository, env=environment,
        check=True, capture_output=True)
    # Keep this controlled native helper in the foreground: detachment cannot
    # provide its original parent's numeric wait and is not a reap exception.
    with (repository / '.git/config').open('a') as stream:
        stream.write('\n[maintenance]\n\tautoDetach = false\n')
    start_read, start_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    os.set_inheritable(receipt_write, True)
    nonce = uuid.uuid4().hex
    root_argv = [sys.executable, '-I', '-S', '-c', BODY, str(receipt_write), nonce, str(repository)]
    helper = '/usr/lib/git-core/git'
    helper_environment = {**environment, 'PATH': '/usr/lib/git-core:/usr/bin:/bin',
        'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': ''}
    allowed = [{'path': sys.executable, 'argv': root_argv, 'environment': environment, 'cwd': str(repository),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    for path, arguments, env in (('/usr/bin/git', ['commit', '--allow-empty', '-m', 'base'], environment),
        ('/usr/bin/git', ['rev-parse', 'HEAD'], environment),
        (helper, ['maintenance', 'run', '--auto', '--no-quiet', '--no-detach'], helper_environment)):
        allowed.append({'path': path, 'argv': [path, *arguments], 'environment': env, 'cwd': str(repository),
                        'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()})
    child = os.fork()
    if child == 0:
        try:
            os.close(start_write)
            os.close(receipt_read)
            if os.read(start_read, 1) != b'1':
                os._exit(125)
            os.close(start_read)
            os.chdir(repository)
            trace.install_observation_filter()
            os.execve(sys.executable, root_argv, environment)
        finally:
            os._exit(127)
    os.close(start_read)
    os.close(receipt_write)
    try:
        observer = trace.OwnedTrace(child, allowed, timeout=15, start_write=start_write, selective=True)
    except BaseException:
        os.close(start_write)
        os.waitpid(child, 0)
        os.close(receipt_read)
        raise
    try:
        result = observer.run()
        data = os.read(receipt_read, 4096)
        assert os.read(receipt_read, 1) == b''
    finally:
        os.close(receipt_read)
    diagnostics = {'status': result['root_parent_wait_raw'], 'poison': result['poison'],
        'execs': [(r['path'], r['accepted'], r['environment'].get('LC_CTYPE'))
                  for r in result['records'] if r['kind'] == 'exec_attempt'],
        'refused_git': [{k: r[k] for k in ('path', 'argv', 'cwd', 'environment')}
            for r in result['records'] if r['kind'] == 'exec_attempt' and r['path'] == helper and not r['accepted']]}
    if diagnostics['refused_git']:
        refused = diagnostics['refused_git'][0]
        actual_env = refused['environment']
        difference = {key: [actual_env.get(key), helper_environment.get(key)]
            for key in sorted(set(actual_env) | set(helper_environment))
            if actual_env.get(key) != helper_environment.get(key)}
        pytest.fail(json.dumps({'argv': refused['argv'], 'environment_delta_actual_expected': difference}, sort_keys=True), pytrace=False)
    assert result['root_parent_wait_raw'] == 0 and not result['poison'] and data, diagnostics
    raw = json.loads(data)
    assert len(raw['receipts']) == 2
    git_pin = hashlib.sha256(Path('/usr/bin/git').read_bytes()).hexdigest()
    assert git_pin == hashlib.sha256(Path(helper).read_bytes()).hexdigest()

    def reduce(records):
        ledger = Ledger(nonce)
        root, producers, helpers = None, [], []
        for row in records:
            ledger.kernel(ledger.next_kernel, row)
            if row['kind'] in ('kernel_root', 'kernel_child'):
                birth = Birth.read(row['identity'])
                if row['kind'] == 'kernel_root':
                    root = birth
                target = producers if birth.parent == child else helpers
                command_class = 'root' if birth == root else 'native-git-command' if birth.parent == child else 'native-git-helper'
                ledger.register(birth, 'root' if birth == root else 'child-' + str(birth.pid),
                    (('native-fixture', git_pin),), case='native-git-control',
                    command_class=command_class, expected_generation=1)
                if birth != root:
                    target.append(birth)
        assert root is not None and len(producers) == 2 and len(helpers) == 1
        return ledger, producers, helpers

    ledger, producers, helpers = reduce(result['records'])
    git=Git(SimpleNamespace(ledger=ledger))
    assert ledger.reaped(producers[0], 'child-' + str(producers[0].pid))
    assert ledger.reaped(helpers[0], 'child-' + str(helpers[0].pid))
    assert git.native_child_reaped(producers[0], helpers[0], 'native-git-control', (('native-fixture', git_pin),))
    assert ledger.reaped(producers[1],'child-'+str(producers[1].pid))
    assert digest(raw['head'].rstrip('\n'))==raw['head'][:-1]
    missing, parents, children = reduce([row for row in result['records']
        if not (row['kind'] == 'original_parent_wait4' and row['parent_tgid'] == producers[0].tgid)])
    assert not Git(SimpleNamespace(ledger=missing)).native_child_reaped(parents[0], children[0], 'native-git-control', (('native-fixture', git_pin),))
