"""Exact custody controls; the original composed SOURCE run is separate proof."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import linux_trace
from primary_source_authority import SourceAuthority
from finite.linux_identity import identity


def authority(pid, owner, device, inode):
    binding = {'path': '/source/src/unrest_harness/acp_runner.py', 'sha256': 'a' * 64}
    event = {'kind': 'concrete_owned_role_registration', 'owner_pid': owner, 'role': 'worker',
             'source_binding': binding, 'argv_sha256': 'b' * 64,
             'pipe_device': device, 'pipe_inode': inode}
    value = object.__new__(SourceAuthority)
    value.bound = {pid: {'registration': {'class': 'source-owned-role:worker',
                   'source_binding': binding, 'argv_sha256': event['argv_sha256']}}}
    value.supervisor = SimpleNamespace(events=lambda: [dict(event), dict(event)], poison=lambda code: None)
    value.pipe_records = []
    value.manifest = {'runtime': {'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}}
    return value


@pytest.mark.parametrize('flag', [False, True])
def test_strict_preexec_contract_never_exempts_foreign_descriptors(flag):
    value = authority(11, 10, 2, 3)
    value.pipe_binding = lambda pid: {'pipe_device': 2, 'pipe_inode': 3}
    import stat
    pipe = {'fd': 7, 'device': 2, 'inode': 3, 'mode': stat.S_IFIFO | 0o600,
            'uid': 20000, 'access': os.O_RDONLY, 'close_on_exec': False}
    foreign = {**pipe, 'fd': 8, 'inode': 4, 'access': os.O_WRONLY, 'close_on_exec': flag}
    value.census = lambda pid: [pipe, foreign]
    with pytest.raises(RuntimeError, match='primary_source_role_pipe_cardinality'):
        value.descriptors(11)


@pytest.mark.skipif(sys.platform != 'linux' or os.uname().machine != 'x86_64', reason='Linux ptrace ABI')
@pytest.mark.parametrize('case', ['closed-pipe', 'closed-socket', 'closed-file',
                                 'extra-pipe', 'extra-socket', 'extra-file',
                                 'inventory-cloexec', 'stale-inode', 'write-end', 'unknown', 'caught-unknown'])
def test_successful_exec_census_precedes_any_native_or_body_instruction(tmp_path, case):
    assert os.getuid() == 20000
    read, write = os.pipe()
    inventory = write if case == 'write-end' else read
    info = os.fstat(inventory)
    marker = tmp_path / 'body-started'
    argv = [sys.executable, '-I', '-S', '-c',
            'from pathlib import Path; Path(' + repr(str(marker)) + ').write_bytes(b"1")']
    child = os.fork()
    if child == 0:
        try:
            os.set_inheritable(inventory, case != 'inventory-cloexec')
            for name in os.listdir('/proc/self/fd'):
                descriptor = int(name)
                if descriptor >= 3 and descriptor != inventory:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            extra = None
            if case.endswith('-pipe'):
                extra, other = os.pipe()
                os.close(other)
            elif case.endswith('-socket'):
                stream = socket.socket(socket.AF_UNIX)
                extra = stream.fileno()
            elif case.endswith('-file'):
                extra = os.open(tmp_path / 'extra', os.O_RDONLY | os.O_CREAT, 0o600)
            if extra is not None:
                os.set_inheritable(extra, case.startswith('extra-'))
            linux_trace.trace_me()
            try:
                os.execve(sys.executable, argv, {})
            except PermissionError:
                if case == 'caught-unknown':
                    os._exit(0)
                raise
        finally:
            os._exit(127)
    os.close(read)
    os.close(write)
    value = authority(child, os.getpid(), info.st_dev,
                      info.st_ino + (1 if case == 'stale-inode' else 0))
    value.supervisor.registered = {os.getpid(): {'identity': identity(os.getpid())}}
    trace = None
    def resolve(pid, path, vector, environment, cwd):
        if case in {'unknown', 'caught-unknown'}:
            return False
        value.exec_descriptors(trace, pid, vector, environment, cwd)
        return True
    trace = linux_trace.OwnedTrace(child, [], timeout=15, resolve_exec=resolve)
    positive = case.startswith('closed-')
    if positive or case in {'unknown', 'caught-unknown'}:
        result = trace.run()
        assert result['root_parent_wait_raw'] == (127 << 8 if case == 'unknown' else 0)
        assert bool(result['poison']) is (case in {'unknown', 'caught-unknown'})
    else:
        with pytest.raises(RuntimeError, match='primary_source_role_pipe_'):
            trace.run()
    assert marker.exists() is positive
    assert not trace.active
    assert type(trace.root_parent_wait) is int
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)
    if positive:
        assert len(value.pipe_records) == 3
        pre, post, custody = value.pipe_records
        assert len(pre['descriptors']) == 2 and len(post['descriptors']) == 1
        assert pre['identity'] == post['identity'] == custody['identity']
        assert len(custody['closed_fds']) == 1
        assert len([row for row in trace.records if row['kind'] == 'kernel_exec']) == 1
        assert len([row for row in trace.records if row['kind'] == 'exec_syscall_return']) == 1
        assert trace.root_parent_wait == 0
    elif case.startswith('extra-') or case == 'inventory-cloexec':
        assert 'primary_source_role_pipe_custody' in trace.poison
        assert any(row['kind'] == 'kernel_exec' for row in trace.records)


@pytest.mark.skipif(sys.platform != 'linux', reason='proc descriptor inventory')
@pytest.mark.parametrize('case', ['empty', 'pipe', 'foreign-directory'])
def test_native_inventory_accounts_for_its_live_enumerator_and_rejects_aliases(case):
    import ast
    import stat
    source = Path(__file__).with_name('primary_entry.py')
    tree = ast.parse(source.read_bytes())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'descriptor_inventory')
    namespace = {'os': os, 'stat': stat}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
    child = os.fork()
    if child == 0:
        try:
            os.closerange(3, 1 << 20)
            extra = None
            if case == 'pipe':
                extra, other = os.pipe()
                os.close(other)
            elif case == 'foreign-directory':
                extra = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            observed = namespace['descriptor_inventory']()
            if case == 'empty':
                assert observed == []
            elif case == 'pipe':
                assert len(observed) == 1 and observed[0]['fd'] == extra
                assert stat.S_ISFIFO(observed[0]['mode']) and observed[0]['access'] == os.O_RDONLY
            else:
                os._exit(99)
            os._exit(0)
        finally:
            os._exit(127)
    waited, raw = os.waitpid(child, 0)
    assert waited == child and raw == ((86 if case == 'foreign-directory' else 0) << 8)
