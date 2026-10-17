"""Synthetic Linux compartment controls; never invokes product source tests."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    "linux_observation", Path(__file__).with_name("linux_observation.py")
)
assert _spec is not None and _spec.loader is not None
_observation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_observation)
descriptors = _observation.descriptors
process_identity = _observation.process_identity
require_linux_abi = _observation.require_linux_abi

SOURCE_UID = 20000
OBSERVER_UID = 20001


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def no_new_privileges() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")


def source_controls() -> None:
    Path("/work/home").mkdir()
    Path("/work/tmp").mkdir()
    identity = process_identity(os.getpid())
    assert identity["uids"] == [SOURCE_UID] * 4
    assert not any(identity["capabilities"].values())
    assert identity["no_new_privs"] == 1 and identity["seccomp"] == 2
    assert set(os.environ) == {"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR"}
    assert [row["fd"] for row in descriptors(os.getpid())] == [0, 1, 2]
    denials = []
    for name in ("/records/controller-canary", "/root/.ssh/id_rsa",
                 "/var/run/docker.sock", "/source", f"/proc/{os.getppid()}/environ"):
        try:
            Path(name).read_bytes()
        except OSError as error:
            denials.append({"operation": "read", "path": name, "errno": error.errno})
        else:
            raise AssertionError("private or absent input exposed")
    try:
        Path("/guard/compartment_probe.py").write_bytes(b"mutation")
    except OSError as error:
        denials.append({"operation": "guard-write", "errno": error.errno})
    else:
        raise AssertionError("guard input mutable")
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            foreign.connect("/records/foreign-broker.sock")
        except OSError as error:
            denials.append({"operation": "foreign-broker", "errno": error.errno})
        else:
            raise AssertionError("foreign broker exposed")
    finally:
        foreign.close()
    external = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    external.settimeout(1)
    try:
        try:
            external.connect(("192.0.2.1", 443))
        except OSError as error:
            denials.append({"operation": "external-network", "errno": error.errno})
        else:
            raise AssertionError("external network exposed")
    finally:
        external.close()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(listener.getsockname())
    accepted, _ = listener.accept()
    try:
        client.sendall(b"owned-loopback")
        assert accepted.recv(64) == b"owned-loopback"
    finally:
        accepted.close()
        client.close()
        listener.close()
    native = subprocess.Popen(
        ["ps", "-axo", "pid=,ppid=,pgid="], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True,
    )
    native_identity = process_identity(native.pid)
    output, errors = native.communicate(timeout=5)
    assert native.returncode == 0 and errors == b""
    rows = [tuple(map(int, row.split())) for row in output.splitlines()]
    assert (os.getpid(), os.getppid(), os.getpgid(0)) in rows
    assert native_identity["ppid"] == os.getpid()
    # Preserve a genuine original-parent raw wait independently of Popen caches.
    pid = os.fork()
    if pid == 0:
        os.kill(os.getpid(), signal.SIGTERM)
        os._exit(99)
    waited_pid, raw_status = os.waitpid(pid, 0)
    assert waited_pid == pid and raw_status == signal.SIGTERM
    assert os.waitstatus_to_exitcode(raw_status) == -signal.SIGTERM
    write(Path("/work/source-controls.json"), {
        "synthetic_only": True, "source_checkpoint_ready": False,
        "identity": identity, "denials": denials,
        "native_ps_identity": native_identity,
        "native_ps_sha256": hashlib.sha256(Path("/bin/ps").read_bytes()).hexdigest(),
        "original_parent_wait": {"parent": os.getpid(), "child": pid,
                                 "raw": raw_status, "normalized": -signal.SIGTERM},
    })
    result = subprocess.run(
        ["/opt/deps/bin/python", "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--basetemp=/work/pytest", "/guard/test_linux_observation.py",
         "/guard/test_probe_controller.py", "/guard/test_linux_trace.py",
         "/guard/test_dependency_closure.py", "/guard/test_linux_native_custody.py"],
        cwd="/work", check=False,
    )
    raise SystemExit(result.returncode)


def observer() -> None:
    assert os.getuid() == 0
    no_new_privileges()
    abi = require_linux_abi()
    closure_spec = importlib.util.spec_from_file_location("dependency_closure", "/guard/dependency_closure.py")
    assert closure_spec is not None and closure_spec.loader is not None
    closure = importlib.util.module_from_spec(closure_spec)
    closure_spec.loader.exec_module(closure)
    expected_bytes = Path("/environment-closure.json").read_bytes()
    expected_closure = json.loads(expected_bytes)
    if closure.inventory(Path("/opt/deps")) != expected_closure:
        raise RuntimeError("installed dependency closure drift")
    abi["dependency_closure"] = {"sha256": hashlib.sha256(expected_bytes).hexdigest(),
                                 "members": len(expected_closure), "verified": True}

    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_write)
            if os.read(ready_read, 1) != b"1":
                raise RuntimeError("observer setup did not settle")
            os.dup2(write_fd, 1)
            os.dup2(write_fd, 2)
            # No descriptor from the observer survives except stdio pipes.
            os.closerange(3, 1 << 20)
            libc = ctypes.CDLL(None, use_errno=True)
            last_capability = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
            if last_capability != 40:
                raise RuntimeError("unknown Linux capability ABI")
            for capability in range(last_capability + 1):
                if libc.prctl(24, capability, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), "PR_CAPBSET_DROP")
            os.setgroups([])
            os.setgid(SOURCE_UID)
            os.setuid(SOURCE_UID)
            no_new_privileges()
            os.chdir("/work")
            os.execve(sys.executable, [sys.executable, "-I", "-B", __file__, "source"], {
                "HOME": "/work/home", "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": "/work/tmp",
            })
        finally:
            os._exit(126)
    os.close(write_fd)
    os.close(ready_read)
    os.setgroups([])
    os.setgid(OBSERVER_UID)
    os.setuid(OBSERVER_UID)
    no_new_privileges()
    canary = Path("/records/controller-canary")
    canary.write_bytes(os.urandom(32))
    canary.chmod(0o600)
    broker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    broker.bind("/records/foreign-broker.sock")
    broker.listen(1)
    os.write(ready_write, b"1")
    os.close(ready_write)
    log = bytearray()
    while block := os.read(read_fd, 65536):
        log.extend(block)
        if len(log) > 8 * 1024 * 1024:
            os.kill(pid, signal.SIGKILL)
            raise RuntimeError("bounded synthetic output exceeded")
    os.close(read_fd)
    actual_pid, raw = os.waitpid(pid, 0)
    Path("/records/source-output.log").write_bytes(log)
    assert actual_pid == pid
    write(Path("/records/observer.json"), {
        "synthetic_only": True, "source_checkpoint_ready": False,
        "selected_carrier": None, "abi": abi,
        "observer": process_identity(os.getpid()),
        "source_child": pid, "actual_wait_raw": raw,
        "actual_wait_normalized": os.waitstatus_to_exitcode(raw),
        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
    })
    source_result = Path("/work/source-controls.json")
    if source_result.is_file() and not source_result.is_symlink():
        Path("/records/source-controls.json").write_bytes(source_result.read_bytes())
    for status in (0, 29, 31):
        control = Path(f"/work/trace-control-{status}.json")
        if control.is_file() and not control.is_symlink():
            body = control.read_bytes()
            if len(body) > 131072:
                raise RuntimeError("trace control output exceeded its bound")
            Path("/records", control.name).write_bytes(body)
    broker.close()
    envelope = {
        path.name: base64.b64encode(path.read_bytes()).decode("ascii")
        for path in sorted(Path("/records").iterdir())
        if path.name in {"observer.json", "source-controls.json", "source-output.log",
                         "trace-control-0.json", "trace-control-29.json", "trace-control-31.json"}
    }
    print("PRIVATE-EVIDENCE:" + json.dumps(envelope, sort_keys=True), flush=True)
    raise SystemExit(os.waitstatus_to_exitcode(raw))


if __name__ == "__main__":
    if sys.argv[1:] == ["source"]:
        source_controls()
    elif not sys.argv[1:]:
        observer()
    else:
        raise SystemExit("unsupported synthetic control selection")
