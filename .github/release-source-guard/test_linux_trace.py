"""Real Linux ptrace seam controls; these do not run original source cases."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys

import pytest

spec = importlib.util.spec_from_file_location("linux_trace", Path(__file__).with_name("linux_trace.py"))
assert spec is not None and spec.loader is not None
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)

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


@pytest.mark.parametrize(("program", "status", "admit", "poison"), [
    ("/usr/bin/true", 0, True, False),
    ("/guard/finite-missing-exec", 29, True, False),
    ("/usr/bin/false", 31, False, True),
])
def test_native_failed_and_caught_exec_preserve_actual_parent_waits(program, status, admit, poison):
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
    child = os.fork()
    if child == 0:
        try:
            trace.trace_me()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    result = trace.OwnedTrace(child, allowed, timeout=30).run()
    Path(f"/work/trace-control-{status}.json").write_text(json.dumps(result, sort_keys=True))
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


def test_seized_vfork_births_precede_native_effects_and_parent_waits():
    body = "import subprocess\nfor _ in range(8): subprocess.run(['/usr/bin/true'], check=True)"
    argv = [sys.executable, "-I", "-S", "-c", body]
    allowed = [
        {"path": sys.executable, "argv": argv, "environment": {}, "cwd": os.getcwd(),
         "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
        {"path": "/usr/bin/true", "argv": ["/usr/bin/true"], "environment": {},
         "cwd": os.getcwd(), "sha256": hashlib.sha256(Path('/usr/bin/true').read_bytes()).hexdigest()},
    ]
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(write)
        os.read(read, 1)
        os.close(read)
        os.execve(sys.executable, argv, {})
        os._exit(127)
    os.close(read)

    def attached():
        os.write(write, b"1")
        os.close(write)

    result = trace.OwnedTrace(child, allowed, timeout=30, seize=True, on_attached=attached).run()
    assert result['root_parent_wait_raw'] == 0 and not result['poison']
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
