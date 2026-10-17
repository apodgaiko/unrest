"""Owned Linux/x86-64 ptrace observations, separate from source admission.

The tracer observes exec boundaries and original-parent wait4 results, including
failed execs and children too brief for polling. It is not the finite Python
source guard. Callers must bind source, runtime, environment and launch plans
before allowing a source payload. Tracer waits never substitute for parent waits.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any

_spec = importlib.util.spec_from_file_location(
    "linux_observation", Path(__file__).with_name("linux_observation.py")
)
assert _spec is not None and _spec.loader is not None
_observation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_observation)

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
LIBC.ptrace.restype = ctypes.c_long

# Linux UAPI: sys/user.h, linux/ptrace.h, asm/unistd_64.h.
class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
    )]


def ptrace(request: int, pid: int, address: int = 0, data: Any = 0) -> int:
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address), data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, "owned ptrace operation refused")
    return result


def trace_me() -> None:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("unsupported trace ABI")
    ptrace(0, 0)
    os.kill(os.getpid(), signal.SIGSTOP)


def registers(pid: int) -> Registers:
    value = Registers()
    ptrace(12, pid, data=ctypes.byref(value))
    return value


def read_bytes(pid: int, address: int, count: int) -> bytes:
    if not address or not 0 <= count <= 65536:
        raise RuntimeError("invalid bounded tracee read")
    result = bytearray()
    for offset in range(0, count, 8):
        word = ptrace(2, pid, address + offset)
        result.extend((word & ((1 << 64) - 1)).to_bytes(8, "little"))
    return bytes(result[:count])


def read_string(pid: int, address: int) -> bytes:
    result = bytearray()
    base = address & ~7
    first = address - base
    for offset in range(0, 8200, 8):
        block = read_bytes(pid, base + offset, 8)
        if offset == 0:
            block = block[first:]
        end = block.find(b"\0")
        result.extend(block if end < 0 else block[:end])
        if end >= 0:
            if len(result) > 8192:
                raise RuntimeError("unbounded exec string")
            return bytes(result)
    raise RuntimeError("unbounded exec string")


def exec_vector(pid: int, argv_address: int) -> list[str]:
    result: list[str] = []
    for index in range(128):
        address = int.from_bytes(read_bytes(pid, argv_address + index * 8, 8), "little")
        if address == 0:
            return result
        result.append(os.fsdecode(read_string(pid, address)))
    raise RuntimeError("unbounded exec vector")


def signed(value: int) -> int:
    return ctypes.c_longlong(value).value


class OwnedTrace:
    """Consume a stopped, directly owned child once, with finite exec vectors.

    This low-level seam intentionally has no CLI and cannot receive payload
    requests to execute host commands. All records belong to its caller.
    """

    def __init__(self, child: int, allowed: list[dict[str, Any]], timeout: float,
                 on_tick: Any = None, resolve_exec: Any = None,
                 seize: bool = False, on_attached: Any = None):
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            raise RuntimeError("unsupported trace ABI")
        if child <= 0 or timeout <= 0 or timeout > 180:
            raise ValueError("bounded owned trace required")
        if Path(f"/proc/{child}/status").read_text().split("PPid:", 1)[1].split()[0] != str(
            os.getpid()
        ):
            raise RuntimeError("trace root is not a direct child")
        self.child = child
        self.allowed = allowed
        self.timeout = timeout
        self.on_tick = on_tick
        self.resolve_exec = resolve_exec
        self.seize = seize
        self.on_attached = on_attached
        self.root_parent_wait: int | None = None
        self.records: list[dict[str, Any]] = []
        self.poison: list[str] = []
        self.active = {child}
        self.pending: dict[int, dict[str, Any]] = {}
        self.denied: set[int] = set()
        self.newborn: set[int] = set()
        self.identities: dict[int, dict[str, Any]] = {}

    def admit_exec(self, pid: int, value: Registers) -> None:
        self.records.append({"kind": "exec_memory_boundary", "pid": pid,
                             "path_address": value.rdi, "argv_address": value.rsi,
                             "environment_address": value.rdx,
                             "observer_identity": _observation.process_identity(os.getpid()),
                             "tracee_identity": _observation.process_identity(pid)})
        path = os.fsdecode(read_string(pid, value.rdi))
        vector = exec_vector(pid, value.rsi)
        environment_rows = exec_vector(pid, value.rdx)
        environment = {}
        for row in environment_rows:
            key, separator, content = row.partition("=")
            if not separator or not key or key in environment:
                raise RuntimeError("invalid or duplicate exec environment entry")
            environment[key] = content
        cwd = os.readlink(f"/proc/{pid}/cwd")
        matches = [row for row in self.allowed if row["path"] == path and row["argv"] == vector
                   and row.get("pid", pid) == pid]
        accepted = len(matches) == 1
        image = Path(f"/proc/{pid}/root") / path.lstrip("/")
        if accepted:
            expected = matches[0]["sha256"]
            try:
                observed = hashlib.sha256(image.read_bytes()).hexdigest()
            except FileNotFoundError:
                observed = None
            accepted = (environment == matches[0]["environment"] and cwd == matches[0]["cwd"]
                        and observed == expected and (observed is not None or matches[0].get(
                "expected_missing"
            ) is True))
        if not accepted and self.resolve_exec is not None:
            accepted = self.resolve_exec(pid, path, vector, environment, cwd)
        self.records.append({"kind": "exec_attempt", "pid": pid, "path": path,
                             "argv": vector, "cwd": cwd, "environment": environment,
                             "accepted": accepted})
        if not accepted:
            self.poison.append("unknown_or_drifted_exec")
            self.denied.add(pid)
            value.orig_rax = (1 << 64) - 1
            ptrace(13, pid, data=ctypes.byref(value))

    def syscall(self, pid: int) -> None:
        # GET_SYSCALL_INFO identifies entry/exit even for a newborn task whose
        # first stop can be a clone return. Alternation guesses lose that edge.
        info = ctypes.create_string_buffer(88)
        size = ptrace(0x420E, pid, 88, ctypes.byref(info))
        operation = info.raw[0]
        architecture = int.from_bytes(info.raw[4:8], "little")
        if (architecture != 0xC000003E or operation not in (1, 2)
                or size < (80 if operation == 1 else 33)):
            raise RuntimeError("unknown syscall observation ABI")
        value = registers(pid)
        entering = operation == 1
        number = value.orig_rax
        if entering:
            self.pending[pid] = {"syscall": number, "status_address": value.rsi,
                                 "wait_options": value.rdx}
            if number == 59:  # execve
                self.admit_exec(pid, value)
            elif number == 322:  # execveat has a distinct ABI; never silently admit.
                self.poison.append("unsupported_execveat")
                self.denied.add(pid)
                value.orig_rax = (1 << 64) - 1
                ptrace(13, pid, data=ctypes.byref(value))
        else:
            pending = self.pending.pop(pid, None)
            if pid in self.denied:
                value.rax = ((1 << 64) - errno.EPERM)
                ptrace(13, pid, data=ctypes.byref(value))
                self.denied.remove(pid)
                self.records.append({"kind": "exec_syscall_return", "pid": pid,
                                     "return": -errno.EPERM, "denied": True})
            elif pending and pending["syscall"] == 61 and signed(value.rax) > 0:
                address = pending["status_address"]
                raw = int.from_bytes(read_bytes(pid, address, 4), "little") if address else None
                self.records.append({"kind": "original_parent_wait4", "parent": pid,
                                     "parent_tgid": self.identities[pid]["tgid"],
                                     "child": signed(value.rax), "raw": raw,
                                     "normalized": os.waitstatus_to_exitcode(raw)
                                     if raw is not None and (os.WIFEXITED(raw) or os.WIFSIGNALED(raw)) else None,
                                     "options": pending["wait_options"]})
            elif pending and pending["syscall"] in (59, 322):
                self.records.append({"kind": "exec_syscall_return", "pid": pid,
                                     "return": signed(value.rax)})

    def run(self) -> dict[str, Any]:
        options = 0x100000 | 0x7F
        if self.seize:
            # SEIZE records the observer's credentials for access to the
            # nondumpable source child; TRACEME records the child's credentials.
            ptrace(0x4206, self.child, data=ctypes.c_void_p(options))
            ptrace(0x4207, self.child)
            initial, status = os.waitpid(self.child, 0x40000000)
            if (initial != self.child or not os.WIFSTOPPED(status)
                    or status >> 16 != 128):
                raise RuntimeError("owned seize interrupt stop missing")
            if self.on_attached is not None:
                self.on_attached()
        else:
            initial, status = os.waitpid(self.child, 0)
            if (initial != self.child or not os.WIFSTOPPED(status)
                    or os.WSTOPSIG(status) != signal.SIGSTOP):
                raise RuntimeError("owned pre-exec stop missing")
            ptrace(0x4200, self.child, data=ctypes.c_void_p(options))
        self.identities[self.child] = _observation.process_identity(self.child)
        self.records.append({"kind": "kernel_root", "identity": self.identities[self.child]})
        # EXITKILL keeps tracer failure fail-closed; forks/clones are followed by
        # the kernel, not discovered by process-table polling.
        ptrace(24, self.child)
        started = time.monotonic()
        root_wait = None
        try:
            while self.active:
                if self.on_tick is not None:
                    self.on_tick(self)
                if time.monotonic() - started > self.timeout:
                    raise TimeoutError("owned trace deadline exceeded")
                pid, raw = os.waitpid(-1, os.WNOHANG | 0x40000000)
                if not pid:
                    time.sleep(0.0001)
                    continue
                if pid not in self.active:
                    raise RuntimeError("unregistered tracer wait")
                if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                    self.active.remove(pid)
                    self.records.append({"kind": "tracer_terminal_wait", "pid": pid,
                                         "raw": raw, "normalized": os.waitstatus_to_exitcode(raw),
                                         "identity": self.identities[pid]})
                    if pid == self.child:
                        root_wait = raw
                        self.root_parent_wait = raw
                    continue
                if not os.WIFSTOPPED(raw):
                    raise RuntimeError("unknown ptrace wait disposition")
                stop = os.WSTOPSIG(raw)
                event = raw >> 16
                deliver = 0
                if event in (1, 2, 3):
                    child = ctypes.c_ulong()
                    ptrace(0x4201, pid, data=ctypes.byref(child))
                    self.active.add(child.value)
                    self.newborn.add(child.value)
                    self.identities[child.value] = _observation.process_identity(child.value)
                    self.records.append({"kind": "kernel_child", "parent": pid,
                                         "child": child.value, "event": event,
                                         "identity": self.identities[child.value]})
                elif event == 4:
                    self.records.append({"kind": "kernel_exec", "pid": pid})
                elif event == 5:
                    self.records.append({"kind": "kernel_vfork_done", "pid": pid})
                elif event == 6:
                    terminal = ctypes.c_ulong()
                    ptrace(0x4201, pid, data=ctypes.byref(terminal))
                    self.records.append({"kind": "kernel_exit", "pid": pid,
                                         "raw": terminal.value})
                elif event == 128 and pid in self.newborn:
                    self.newborn.remove(pid)
                elif event == 128 and self.seize and stop in (
                    signal.SIGSTOP, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU
                ):
                    ptrace(0x4208, pid)  # LISTEN preserves the original group stop.
                    continue
                elif event:
                    raise RuntimeError("unknown ptrace event")
                elif stop == signal.SIGTRAP | 0x80:
                    self.syscall(pid)
                elif stop == signal.SIGSTOP and pid in self.newborn:
                    self.newborn.remove(pid)
                else:
                    deliver = stop
                ptrace(24, pid, data=ctypes.c_void_p(deliver))
        finally:
            for pid in sorted(self.active):
                try:
                    ptrace(8, pid)
                except ProcessLookupError:
                    pass
            while self.active:
                pid, raw = os.waitpid(-1, 0x40000000)
                if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                    self.active.discard(pid)
                    self.records.append({"kind": "failure_cleanup_tracer_wait", "pid": pid,
                                         "raw": raw, "normalized": os.waitstatus_to_exitcode(raw),
                                         "root_original_parent": pid == self.child})
                    if pid == self.child:
                        self.root_parent_wait = raw
                else:
                    ptrace(24, pid, data=ctypes.c_void_p(signal.SIGKILL))
        return {"root_parent_wait_raw": root_wait, "records": self.records,
                "poison": self.poison, "source_checkpoint_ready": False}
