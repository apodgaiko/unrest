"""Actual kernel->parent-return-pipe->incremental ledger composition control."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

from process_ledger import Birth, Ledger, canonical

pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or os.uname().machine != 'x86_64',
    reason='requires actual Linux kernel observations, never synthetic certification')

spec = importlib.util.spec_from_file_location('ledger_trace', Path(__file__).with_name('linux_trace.py'))
assert spec is not None and spec.loader is not None
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)

BODY = '''
import json, os, sys
fd = int(sys.argv[1])
child = os.fork()
if child == 0:
    os.close(fd)
    os._exit(17)
actual, raw = os.waitpid(child, 0)
assert actual == child and raw == 17 << 8
pid = os.getpid()
fields = open('/proc/self/stat').read().rpartition(') ')[2].split()
uids = next(line for line in open('/proc/self/status') if line.startswith('Uid:')).split()[1:]
identity = {'pid':pid, 'tgid':pid, 'ppid':int(fields[1]), 'start_ticks':int(fields[19]),
            'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),
            'uids':[int(uid) for uid in uids], 'pgid':os.getpgid(0), 'sid':os.getsid(0),
            'clock_ticks_per_second':os.sysconf('SC_CLK_TCK')}
row = {'pid':child, 'child_token':'child-' + str(child), 'nonce':sys.argv[2],
       'owner_pid':pid, 'owner_identity':identity, 'owner_token':'root',
       'requested_pid':actual, 'wait_event':'actual_os_waitpid_return',
       'raw_status':raw, 'numeric_returncode':os.waitstatus_to_exitcode(raw), 'options':0}
body = json.dumps(row, sort_keys=True).encode()
assert len(body) < 4096
assert os.write(fd, body) == len(body)
os.close(fd)
'''


def test_real_original_parent_wait_joins_once_and_missing_wait_remains_incomplete():
    start_read, start_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    os.set_inheritable(receipt_write, True)
    nonce = uuid.uuid4().hex
    argv = [sys.executable, '-I', '-S', '-c', BODY, str(receipt_write), nonce]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    child = os.fork()
    if child == 0:
        try:
            os.close(start_write)
            os.close(receipt_read)
            if os.read(start_read, 1) != b'1':
                os._exit(125)
            os.close(start_read)
            trace.install_observation_filter()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    os.close(start_read)
    os.close(receipt_write)
    try:
        observer = trace.OwnedTrace(child, allowed, timeout=10, start_write=start_write,
                                   selective=True, cleanup_seconds=2)
    except BaseException:
        os.close(start_write)
        os.waitpid(child, 0)
        os.close(receipt_read)
        raise
    try:
        result = observer.run()
        data = os.read(receipt_read, 4096)
        assert data and os.read(receipt_read, 1) == b''
    finally:
        os.close(receipt_read)
    assert result['root_parent_wait_raw'] == 0 and not result['poison']
    raw_receipt = json.loads(data)

    def reduce(records):
        ledger = Ledger(nonce)
        root_birth, target_birth = None, None
        for row in records:
            ledger.kernel(ledger.next_kernel, row)
            if row['kind'] in ('kernel_root', 'kernel_child'):
                birth = Birth.read(row['identity'])
                token = 'root' if row['kind'] == 'kernel_root' else 'child-' + str(birth.pid)
                ledger.register(birth, token, (('runtime', allowed[0]['sha256']),), hashlib.sha256(BODY.encode()).hexdigest(),
                                case='native-ledger', command_class='source-free-control',
                                expected_generation=1 if row['kind'] == 'kernel_root' else 0)
                if row['kind'] == 'kernel_root':
                    root_birth = birth
                else:
                    target_birth = birth
        assert root_birth is not None and target_birth is not None
        assert raw_receipt['owner_identity'] == canonical(ledger.process(root_birth).identity)
        ledger.control(root_birth, 'root', 1, 0, 'parent-wait', deepcopy(raw_receipt))
        return ledger, target_birth

    complete, target = reduce(result['records'])
    assert complete.reaped(target, raw_receipt['child_token'])
    missing, same_target = reduce([row for row in result['records']
                                  if row['kind'] != 'original_parent_wait4'])
    assert same_target == target and not missing.reaped(target, raw_receipt['child_token'])
