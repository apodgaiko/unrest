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
    for offset in range(0, 8192, 8):
        block = read_bytes(pid, address + offset, 8)
        end = block.find(b"\0")
        result.extend(block if end < 0 else block[:end])
        if end >= 0:
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

    def __init__(self, child: int, allowed: list[dict[str, Any]], timeout: float):
        if child <= 0 or timeout <= 0 or timeout > 180:
            raise ValueError("bounded owned trace required")
        if Path(f"/proc/{child}/status").read_text().split("PPid:", 1)[1].split()[0] != str(
            os.getpid()
        ):
            raise RuntimeError("trace root is not a direct child")
        self.child = child
        self.allowed = allowed
        self.timeout = timeout
        self.records: list[dict[str, Any]] = []
        self.poison: list[str] = []
        self.active = {child}
        self.pending: dict[int, dict[str, Any]] = {}
        self.denied: set[int] = set()
        self.newborn: set[int] = set()
        self.identities: dict[int, dict[str, Any]] = {}

    def admit_exec(self, pid: int, value: Registers) -> None:
        path = os.fsdecode(read_string(pid, value.rdi))
        vector = exec_vector(pid, value.rsi)
        matches = [row for row in self.allowed if row["path"] == path and row["argv"] == vector]
        accepted = len(matches) == 1
        image = Path(f"/proc/{pid}/root") / path.lstrip("/")
        if accepted:
            expected = matches[0]["sha256"]
            try:
                observed = hashlib.sha256(image.read_bytes()).hexdigest()
            except FileNotFoundError:
                observed = None
            accepted = observed == expected and (observed is not None or matches[0].get(
                "expected_missing"
            ) is True)
        self.records.append({"kind": "exec_attempt", "pid": pid, "path": path,
                             "argv": vector, "accepted": accepted})
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
        if operation not in (1, 2) or size < (80 if operation == 1 else 33):
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
                                     "child": signed(value.rax), "raw": raw,
                                     "normalized": os.waitstatus_to_exitcode(raw)
                                     if raw is not None else None,
                                     "options": pending["wait_options"]})
            elif pending and pending["syscall"] in (59, 322):
                self.records.append({"kind": "exec_syscall_return", "pid": pid,
                                     "return": signed(value.rax)})

    def run(self) -> dict[str, Any]:
        initial, status = os.waitpid(self.child, 0)
        if initial != self.child or not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError("owned pre-exec stop missing")
        self.identities[self.child] = _observation.process_identity(self.child)
        self.records.append({"kind": "kernel_root", "identity": self.identities[self.child]})
        # EXITKILL keeps tracer failure fail-closed; forks/clones are followed by
        # the kernel, not discovered by process-table polling.
        ptrace(0x4200, self.child, data=ctypes.c_void_p(0x100000 | 0x7F))
        ptrace(24, self.child)
        started = time.monotonic()
        root_wait = None
        try:
            while self.active:
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
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while self.active:
                pid, raw = os.waitpid(-1, 0x40000000)
                if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                    self.active.discard(pid)
                else:
                    ptrace(24, pid, data=ctypes.c_void_p(signal.SIGKILL))
        return {"root_parent_wait_raw": root_wait, "records": self.records,
                "poison": self.poison, "source_checkpoint_ready": False}
