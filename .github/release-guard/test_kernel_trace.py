"""Real Linux ptrace seam controls; these do not run original source cases."""
from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.uname().machine != "x86_64",
    reason="actual Linux/x86-64 kernel proof required; never a local release certificate")

spec = importlib.util.spec_from_file_location("linux_trace", Path(__file__).with_name("linux_trace.py"))
assert spec is not None and spec.loader is not None
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)

def run_control(argv, allowed, selective, on_tick=None, resolve_exec=None, validate_wait=None):
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(write)
            if os.read(read, 1) != b'1':
                os._exit(125)
            os.close(read)
            if selective:
                trace.install_observation_filter()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    os.close(read)
    try:
        observer = trace.OwnedTrace(child, allowed, timeout=30, start_write=write,
                                   selective=selective, on_tick=on_tick, resolve_exec=resolve_exec, validate_wait=validate_wait)
    except BaseException:
        os.close(write)
        os.waitpid(child, 0)  # The controlled child exits on startup EOF.
        raise
    return child, observer.run()


BODY = """
import os, signal, sys
child = os.fork()
if child == 0:
    try:
        os.execve(sys.argv[1], [sys.argv[1]], {})
    except FileNotFoundError:
        os._exit(29)
    except PermissionError:
        os._exit(31)
    os._exit(99)
actual, raw = os.waitpid(child, 0)
assert actual == child
assert os.waitstatus_to_exitcode(raw) == int(sys.argv[2])
child = os.fork()
if child == 0:
    os.kill(os.getpid(), signal.SIGTERM)
    os._exit(99)
actual, raw = os.waitpid(child, 0)
assert actual == child and raw == signal.SIGTERM
"""


@pytest.mark.parametrize("selective", [False, True])
@pytest.mark.parametrize(("program", "status", "admit", "poison"), [
    ("/usr/bin/true", 0, True, False),
    ("/guard/finite-missing-exec", 29, True, False),
    ("/usr/bin/false", 31, False, True),
])
def test_native_failed_and_caught_exec_preserve_actual_parent_waits(program, status, admit, poison, selective, tmp_path):
    assert sys.platform == "linux" and os.uname().machine == "x86_64"
    argv = [sys.executable, "-I", "-S", "-c", BODY, program, str(status)]
    allowed = [{"path": sys.executable, "argv": argv,
                "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                "environment": {}, "cwd": os.getcwd()}]
    if admit:
        path = Path(program)
        allowed.append({"path": program, "argv": [program],
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()
                        if path.exists() else None, "expected_missing": not path.exists(),
                        "environment": {}, "cwd": os.getcwd()})
    child, result = run_control(argv, allowed, selective)
    (tmp_path / f"trace-control-{status}-{selective}.json").write_text(json.dumps(result, sort_keys=True))
    assert result["root_parent_wait_raw"] == 0, result
    assert bool(result["poison"]) == poison
    records = result["records"]
    attempts = [row for row in records if row["kind"] == "exec_attempt"]
    assert [row["path"] for row in attempts] == [sys.executable, program]
    assert attempts[0]["accepted"] and attempts[1]["accepted"] == admit
    births = [row for row in records if row["kind"] == "kernel_child"]
    assert len(births) == 2 and all(row["parent"] == child for row in births)
    assert all(row["identity"]["ppid"] == child and row["identity"]["start_ticks"] > 0
               for row in births)
    waits = [row for row in records if row["kind"] == "original_parent_wait4"]
    assert [(row["parent"], row["child"], row["raw"], row["normalized"]) for row in waits] == [
        (child, births[0]["child"], status << 8, status),
        (child, births[1]["child"], signal.SIGTERM, -signal.SIGTERM),
    ]
    assert len([row for row in records if row["kind"] == "tracer_terminal_wait"]) == 3
    if admit and status == 29:
        assert any(row["kind"] == "exec_syscall_return" and row["return"] == -2 for row in records)
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)


@pytest.mark.parametrize("selective", [False, True])
def test_seized_vfork_births_precede_native_effects_and_parent_waits(selective, tmp_path):
    body = "import subprocess\nfor _ in range(8): subprocess.run(['/usr/bin/true'], check=True, env={})"
    argv = [sys.executable, "-I", "-S", "-c", body]
    allowed = [
        {"path": sys.executable, "argv": argv, "environment": {}, "cwd": os.getcwd(),
         "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
        {"path": "/usr/bin/true", "argv": ["/usr/bin/true"], "environment": {},
         "cwd": os.getcwd(), "sha256": hashlib.sha256(Path('/usr/bin/true').read_bytes()).hexdigest()},
    ]
    child, result = run_control(argv, allowed, selective)
    (tmp_path / f"trace-control-vfork-{selective}.json").write_text(json.dumps(result, sort_keys=True))
    assert result['root_parent_wait_raw'] == 0 and not result['poison'], result
    records = result['records']
    births = [row['child'] for row in records if row['kind'] == 'kernel_child']
    waits = [row for row in records if row['kind'] == 'original_parent_wait4']
    assert len(births) == 8 and len(set(births)) == 8
    assert [(row['child'], row['raw']) for row in waits] == [(pid, 0) for pid in births]
    for pid in births:
        birth = next(i for i, row in enumerate(records)
                     if row['kind'] == 'kernel_child' and row['child'] == pid)
        effect = next(i for i, row in enumerate(records)
                      if row['kind'] == 'kernel_exec' and row['pid'] == pid)
        assert birth < effect


def test_selective_waitid_retains_original_siginfo_then_actual_reap(tmp_path):
    body = """
import os
child = os.fork()
if child == 0:
    os._exit(23)
result = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
assert result.si_pid == child and result.si_status == 23
actual, raw = os.waitpid(child, 0)
assert actual == child and raw == 23 << 8
"""
    argv = [sys.executable, '-I', '-S', '-c', body]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    child, result = run_control(argv, allowed, True)
    (tmp_path / 'trace-control-waitid.json').write_text(json.dumps(result, sort_keys=True))
    assert result['root_parent_wait_raw'] == 0 and not result['poison'], result
    observations = [row for row in result['records'] if row['kind'] == 'original_parent_waitid']
    assert len(observations) == 1
    observation = observations[0]
    assert observation['code'] == 1 and observation['status'] == 23 and not observation['reaps']
    assert len(bytes.fromhex(observation['siginfo_hex'])) == 128
    waits = [row for row in result['records'] if row['kind'] == 'original_parent_wait4']
    assert len(waits) == 1 and waits[0]['child'] == observation['child']
    assert waits[0]['raw'] == 23 << 8 and waits[0]['normalized'] == 23


def test_long_finite_original_exec_argument_is_observed_without_truncation():
    body = "assert len(__import__('sys').argv[1]) == 32768"
    argv = [sys.executable, "-I", "-S", "-c", body, "x" * 32768]
    allowed = [{"path": sys.executable, "argv": argv,
                "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                "environment": {}, "cwd": os.getcwd()}]
    child, result = run_control(argv, allowed, True)
    assert result["root_parent_wait_raw"] == 0 and not result["poison"]
    attempts = [row for row in result["records"] if row["kind"] == "exec_attempt"]
    assert len(attempts) == 1 and attempts[0]["argv"] == argv


@pytest.mark.parametrize("where", ["attached", "tick", "initial_stop"])
def test_actual_failed_setup_cleans_owned_root_and_preserves_unrelated_child(where):
    unrelated = os.fork()
    if unrelated == 0:
        os._exit(17)
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(write)
        if os.read(read, 1) != b'1':
            os._exit(125)
        os.close(read)
        while True:
            signal.pause()
    os.close(read)
    initiating = RuntimeError("controlled setup failure")

    def fail(*args):
        raise initiating

    observer = trace.OwnedTrace(child, [], timeout=.05 if where == "initial_stop" else 2,
                               cleanup_seconds=2, start_write=write,
                               on_attached=fail if where == "attached" else None,
                               on_tick=fail if where == "tick" else None)
    if where == 'initial_stop':
        # Expire the initial-stop allocation without changing product parameters.
        observer.deadline = 0
    try:
        with pytest.raises(TimeoutError if where == "initial_stop" else RuntimeError) as result:
            observer.run()
        if where != "initial_stop":
            assert result.value is initiating
        assert observer.root_parent_wait == signal.SIGKILL
        assert not observer.active and not observer.pidfds
        assert os.waitpid(unrelated, 0) == (unrelated, 17 << 8)
        unrelated = None
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        if unrelated is not None:
            os.waitpid(unrelated, 0)


@pytest.mark.parametrize('failure', ['seize_refused', 'constructor_refused'])
def test_pre_attach_refusal_closes_barrier_before_body_and_actual_parent_reaps(failure, monkeypatch):
    read, write = os.pipe()
    effect_read, effect_write = os.pipe()
    unrelated = os.fork()
    if unrelated == 0:
        os._exit(17)
    child = os.fork()
    if child == 0:
        os.close(write)
        os.close(effect_read)
        if os.read(read, 1) == b'1':
            os.write(effect_write, b'BODY')
            os._exit(99)
        os._exit(125)
    os.close(effect_write)
    observer = None
    try:
        if failure == 'constructor_refused':
            with pytest.raises(ValueError, match='write-only startup pipe'):
                trace.OwnedTrace(child, [], timeout=2, start_write=read)
            # Construction did not accept ownership; the caller cancels its pipe.
            os.close(write)
            assert os.waitpid(child, 0) == (child, 125 << 8)
        else:
            original = trace.ptrace

            def invalid_seize(request, pid, address=0, data=0):
                if request == 0x4206:
                    # Real kernel EIO for unsupported option bits, before attachment.
                    data = trace.ctypes.c_void_p(1 << 63)
                return original(request, pid, address, data)

            monkeypatch.setattr(trace, 'ptrace', invalid_seize)
            observer = trace.OwnedTrace(child, [], timeout=2, start_write=write,
                                       cleanup_seconds=2)
            with pytest.raises(OSError) as result:
                observer.run()
            assert result.value.errno == errno.EIO
            assert observer.root_parent_wait == 125 << 8
            assert not observer.active and not observer.attached and not observer.poison
            assert observer.start_write is None and not observer.pidfds
        assert os.read(effect_read, 4) == b''
        assert os.waitpid(unrelated, 0) == (unrelated, 17 << 8)
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        os.close(read)
        os.close(effect_read)


def test_declined_birth_stays_stopped_before_child_canary(tmp_path):
    canary = tmp_path / 'forbidden-fork-body'
    body = "import os,sys; child=os.fork();\nif child==0:\n open(sys.argv[1],'w').write('forbidden')\n os._exit(0)\nos.waitpid(child,0)"
    argv = [sys.executable, '-I', '-S', '-c', body, str(canary)]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    seen = []
    def decline(observer):
        if any(row['kind'] == 'kernel_child' for row in observer.records):
            seen.append(observer)
            raise RuntimeError('control child declined before resume')
    with pytest.raises(RuntimeError, match='child declined before resume'):
        run_control(argv, allowed, True, on_tick=decline)
    assert len(seen) == 1 and not seen[0].active and not canary.exists()
    assert any(row['kind'] == 'failure_cleanup_tracer_wait' for row in seen[0].records)


def test_vfork_exec_admission_error_reaps_both_without_effect(tmp_path):
    marker = tmp_path / 'forbidden-native-effect'
    body = 'import subprocess; subprocess.run(["/usr/bin/touch", ' + repr(str(marker)) + '], check=True)'
    argv = [sys.executable, '-I', '-S', '-c', body]
    seen = []
    def tick(observer):
        if not seen:
            seen.append(observer)
    def resolve(pid, path, vector, environment, cwd):
        if path == '/usr/bin/touch':
            raise RuntimeError('controlled exec admission failure')
        return False
    allowed = [{'path': sys.executable, 'argv': argv, 'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                'environment': {}, 'cwd': str(Path.cwd())}]
    with pytest.raises(RuntimeError, match='controlled exec admission failure'):
        run_control(argv, allowed, True, tick, resolve)
    observer = seen[0]
    assert not observer.active and not observer.poison and not marker.exists()
    births = [row for row in observer.records if row['kind'] == 'kernel_child']
    assert len(births) == 1 and births[0]['event'] == 2
    waits = [row for row in observer.records if row['kind'] == 'failure_cleanup_tracer_wait']
    assert len(waits) == 2 and all(row['normalized'] == -signal.SIGKILL for row in waits)
    assert observer.root_parent_wait == signal.SIGKILL


@pytest.mark.parametrize('requested', [-1, 0, 2147483647])
def test_wait_entry_stops_even_caught_nonblocking_or_echild_attempt(requested, tmp_path):
    marker = tmp_path / 'incorrectly-resumed'
    body = f"""import os
try:
    os.waitpid({requested}, os.WNOHANG)
except ChildProcessError:
    pass
open({str(marker)!r}, 'w').write('resumed')
"""
    argv = [sys.executable, '-I', '-S', '-c', body]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    seen = []
    def reject(pid, actual):
        seen.append((pid, actual))
        raise RuntimeError('wait-entry-rejected')
    with pytest.raises(RuntimeError, match='wait-entry-rejected'):
        run_control(argv, allowed, True, validate_wait=reject)
    assert len(seen) == 1 and seen[0][1] == requested
    assert not marker.exists()


def test_sequential_children_do_not_accumulate_terminal_pidfds():
    import resource

    body="import os\nfor _ in range(160):\n p=os.fork()\n if p==0: os._exit(0)\n actual,raw=os.waitpid(p,0)\n assert actual==p and raw==0\n"
    argv=[sys.executable,'-I','-S','-c',body]
    allowed=[{'path':sys.executable,'argv':argv,
        'sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        'environment':{},'cwd':os.getcwd()}]
    before=resource.getrlimit(resource.RLIMIT_NOFILE)
    peak=[]
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE,(min(96,before[1]),before[1]))
        child,result=run_control(argv,allowed,True,
            on_tick=lambda observer:peak.append(len(observer.pidfds)))
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE,before)
    assert result['root_parent_wait_raw']==0 and not result['poison']
    assert max(peak)<=3
    waits=[row for row in result['records'] if row['kind']=='original_parent_wait4']
    assert len(waits)==160 and all(row['parent']==child and row['raw']==0 for row in waits)
    terminals=[row for row in result['records'] if row['kind']=='tracer_terminal_wait']
    assert len(terminals)==161 and all(row['raw']==0 for row in terminals)
