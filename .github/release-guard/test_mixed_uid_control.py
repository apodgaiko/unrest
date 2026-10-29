"""Root-driven Linux control only; never imported by enforcement or a source case.

Run as a separate root process. Each short observer worker drops to UID 20001
with only DAC_READ_SEARCH and SYS_PTRACE; the source drops to UID 20000 with no
capabilities. The root driver supervises the exact worker with an actual wait.
"""
from __future__ import annotations

import ctypes
import importlib.util
import os
from pathlib import Path
import signal
import time
import traceback

spec = importlib.util.spec_from_file_location('mixed_trace', Path(__file__).with_name('linux_trace.py'))
assert spec is not None and spec.loader is not None
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def prctl(op, value):
    if trace.LIBC.prctl(op, value, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'controlled credential transition')


def credentials(uid, capabilities):
    prctl(8, 1)
    for cap in range(int(Path('/proc/sys/kernel/cap_last_cap').read_text()) + 1):
        if cap not in capabilities:
            prctl(24, cap)
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)

    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                   ('inheritable', ctypes.c_uint32)]

    header = Header(0x20080522, 0)
    bits = sum(1 << cap for cap in capabilities)
    data = (Data * 2)(Data(bits, bits, 0), Data())
    if trace.LIBC.capset(ctypes.byref(header), ctypes.byref(data)):
        raise OSError(ctypes.get_errno(), 'controlled capability reduction')
    prctl(38, 1)
    identity = trace._observation.process_identity(os.getpid())
    assert identity['uids'] == [uid] * 4
    assert identity['capabilities']['CapEff'] == bits
    assert identity['capabilities']['CapPrm'] == bits
    assert not identity['capabilities']['CapBnd'] & (1 << 5)  # CAP_KILL absent.
    assert identity['no_new_privs'] == 1


def snapshot_custody():
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import tempfile
    import shutil
    from archive_snapshot import acquire

    with tempfile.TemporaryDirectory(prefix='unrest-snapshot-custody-') as raw:
        root=Path(raw)
        root.chmod(0o755)
        reference=root/'reference'
        reference.mkdir(mode=0o755)
        (reference/'member').write_bytes(b'actual extracted bytes')
        (reference/'member').chmod(0o644)
        source=root/'source'
        shutil.copytree(reference,source)
        for path in (source,source/'member'):
            os.chown(path,20000,20000)
        profiles=root/'profiles'
        profiles.mkdir(mode=0o755)
        os.chown(profiles,20001,20001)
        target=profiles/'snapshot'
        observer=os.fork()
        if observer==0:
            try:
                credentials(20001,(2,19))
                acquire(source,reference,target,'normal')
            except BaseException:
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        assert os.waitpid(observer,0)==(observer,0)
        source_process=os.fork()
        if source_process==0:
            try:
                credentials(20000,())
                assert (target/'member').read_bytes()==b'actual extracted bytes'
                operations=(lambda:os.open(target/'member',os.O_RDWR),
                    lambda:os.chmod(target/'member',0o600),
                    lambda:target.rename(profiles/'replacement'),
                    lambda:os.replace(source/'member',target/'member'))
                for operation in operations:
                    try:
                        operation()
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError('source changed observer-owned snapshot')
                (source/'member').write_bytes(b'later original mutation')
                assert (target/'member').read_bytes()==b'actual extracted bytes'
            except BaseException:
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        assert os.waitpid(source_process,0)==(source_process,0)
        print('mixed UID snapshot: immutable acquired bytes; both actual waits zero',flush=True)


def worker(case):
    if case=='snapshot_custody':
        snapshot_custody()
        return
    start_read, start_write = os.pipe()
    ready_read, ready_write = os.pipe()
    unrelated = os.fork()
    if unrelated == 0:
        os.close(start_write)
        os.close(ready_write)
        os._exit(17)
    source = os.fork()
    if source == 0:
        os.close(start_write)
        os.close(ready_read)
        credentials(20000, ())
        os.write(ready_write, b'R')
        os.close(ready_write)
        if os.read(start_read, 1) != b'1':
            os._exit(125)
        os.close(start_read)
        if case in ('birth', 'pending_birth'):
            child = os.fork()
            if child == 0:
                while True:
                    signal.pause()
        elif case == 'group_stop':
            os.kill(os.getpid(), signal.SIGSTOP)
        while True:
            signal.pause()
    os.close(start_read)
    os.close(ready_write)
    assert os.read(ready_read, 1) == b'R'
    os.close(ready_read)
    credentials(20001, (2, 19))
    initiating = RuntimeError('controlled observation failure')
    observed_group_stop = False

    def attached():
        if case == 'attached':
            raise initiating

    def tick(observer):
        if case == 'birth':
            if observer.newborn:
                raise initiating  # Parent event consumed, newborn stop still pending.
        elif case == 'group_stop':
            if observed_group_stop:
                raise initiating
        elif case == 'running':
            raise initiating

    observer = trace.OwnedTrace(source, [], timeout=3, start_write=start_write,
                               on_attached=attached, on_tick=tick, cleanup_seconds=2)
    if case in ('pending_birth', 'group_stop'):
        original_stop = observer.diagnostic_trace.stop

        def stop(pid, sig, event):
            nonlocal observed_group_stop
            original_stop(pid, sig, event)
            if case == 'group_stop' and event == 128 and sig == signal.SIGSTOP:
                observed_group_stop = True
            if case == 'pending_birth' and event == 1:
                raise initiating  # Raw stop retained, birth not yet consumed.

        observer.diagnostic_trace.stop = stop
    try:
        observer.run()
    except RuntimeError as error:
        assert error is initiating
    else:
        raise AssertionError('controlled failure did not occur')
    assert not observer.active and not observer.pidfds and observer.start_write is None
    assert observer.root_parent_wait == signal.SIGKILL
    births = [row for row in observer.records if row['kind'] == 'kernel_child']
    waits = [row for row in observer.records if row['kind'] == 'failure_cleanup_tracer_wait']
    expected = {source, *(row['child'] for row in births)}
    assert {row['pid'] for row in waits} == expected
    assert all(row['normalized'] == -signal.SIGKILL for row in waits)
    if case in ('birth', 'pending_birth'):
        assert len(births) == 1
    assert not observer.poison
    if case == 'group_stop':
        assert observed_group_stop
    assert os.waitpid(unrelated, 0) == (unrelated, 17 << 8)
    print(f'mixed UID/no CAP_KILL {case}: actual waits {len(waits)}, unrelated wait 17', flush=True)


def main():
    assert os.getuid() == 0 and os.uname().machine == 'x86_64'
    for case in ('attached', 'running', 'birth', 'pending_birth', 'group_stop','snapshot_custody'):
        child = os.fork()
        if child == 0:
            try:
                worker(case)
            except BaseException:
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        fd = trace._observation.pidfd_open(child, 0)
        try:
            deadline = time.monotonic() + 10
            while True:
                actual, raw = os.waitpid(child, os.WNOHANG)
                if actual:
                    assert actual == child and raw == 0, (case, raw)
                    break
                if time.monotonic() > deadline:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    actual, raw = os.waitpid(child, 0)
                    raise AssertionError(('controlled worker deadline', case, actual, raw))
                time.sleep(.001)
        finally:
            os.close(fd)


if __name__ == '__main__':
    main()
