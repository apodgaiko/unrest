"""Owned Linux/x86-64 ptrace observations, separate from source admission.

The tracer observes exec boundaries and original-parent wait4 results, including
failed execs and children too brief for polling. It is not the finite Python
source guard. Callers must bind source, runtime, environment and launch plans
before allowing a source payload. Tracer waits never substitute for parent waits.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import stat
import hashlib
import importlib.util
import os
import math
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


class FilterInstruction(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class FilterProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort),
                ("instructions", ctypes.POINTER(FilterInstruction))]


def install_observation_filter() -> None:
    """Inherit unremovable exec/wait stops without stopping unrelated syscalls."""
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("unsupported observation filter ABI")
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
            (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for number in (59, 61, 247, 322):  # execve, wait4, waitid, execveat
        rows.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x7FF00000)])
    rows.append((0x06, 0, 0, 0x7FFF0000))
    instructions = (FilterInstruction * len(rows))(*(FilterInstruction(*row) for row in rows))
    program = FilterProgram(len(rows), instructions)
    if LIBC.prctl(38, 1, 0, 0, 0) != 0 or LIBC.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "inherited kernel observation filter refused")


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


MAX_EXEC_STRING = 131071
MAX_EXEC_VECTOR_BYTES = 2 * 1024 * 1024


def read_string(pid: int, address: int) -> bytes:
    result = bytearray()
    base = address & ~7
    first = address - base
    for offset in range(0, MAX_EXEC_STRING + 9, 8):
        block = read_bytes(pid, base + offset, 8)
        if offset == 0:
            block = block[first:]
        end = block.find(b"\0")
        result.extend(block if end < 0 else block[:end])
        if end >= 0:
            if len(result) > MAX_EXEC_STRING:
                raise RuntimeError("unbounded exec string")
            return bytes(result)
    raise RuntimeError("unbounded exec string")


def exec_vector(pid: int, argv_address: int) -> list[str]:
    result: list[str] = []
    total = 0
    for index in range(128):
        address = int.from_bytes(read_bytes(pid, argv_address + index * 8, 8), "little")
        if address == 0:
            return result
        body = read_string(pid, address)
        total += len(body) + 1
        if total > MAX_EXEC_VECTOR_BYTES:
            raise RuntimeError("unbounded exec vector bytes")
        result.append(os.fsdecode(body))
    raise RuntimeError("unbounded exec vector")


def signed(value: int) -> int:
    return ctypes.c_longlong(value).value


class DiagnosticTrace:
    """Fixed-width numeric rows per owned PID; no per-stop record growth.

    Column order is part of this diagnostic schema. Original records retain
    their independent order and complete identity/wait/security content.
    """

    COLUMNS = ('pid', 'stops', 'resumes', 'first_ns', 'last_ns', 'cpu_ns',
               'handling_ns', 'max_handling_ns', 'forks', 'execs', 'seccomp',
               'syscalls', 'other', 'continue', 'syscall_resume')

    def __init__(self) -> None:
        self.rows: dict[int, list[int]] = {}
        self.started: dict[int, tuple[int, int]] = {}

    def stop(self, pid: int, stop: int, event: int) -> None:
        now, cpu = time.monotonic_ns(), time.process_time_ns()
        row = self.rows.setdefault(pid, [pid, 0, 0, now, now, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        row[1] += 1
        row[4] = now
        row[8 if event in (1, 2, 3) else 9 if event == 4 else 10 if event == 7
            else 11 if stop == signal.SIGTRAP | 0x80 else 12] += 1
        self.started[pid] = (now, cpu)

    def resume(self, pid: int, request: int) -> None:
        now, cpu = time.monotonic_ns(), time.process_time_ns()
        begin, start_cpu = self.started.pop(pid)
        row = self.rows[pid]
        row[2] += 1
        row[4] = now
        row[5] += cpu - start_cpu
        row[6] += now - begin
        row[7] = max(row[7], now - begin)
        row[13 if request == 7 else 14] += 1

    def export(self) -> dict[str, Any]:
        return {'columns': self.COLUMNS, 'rows': [self.rows[pid] for pid in sorted(self.rows)]}


class OwnedTrace:
    """Consume a stopped, directly owned child once, with finite exec vectors.

    This low-level seam intentionally has no CLI and cannot receive payload
    requests to execute host commands. All records belong to its caller.
    """

    def __init__(self, child: int, allowed: list[dict[str, Any]], timeout: float,
                 *, on_tick: Any = None, resolve_exec: Any = None,
                 start_write: int, on_attached: Any = None, selective: bool = False,
                 cleanup_seconds: float = 60):
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            raise RuntimeError("unsupported trace ABI")
        if (child <= 0 or type(timeout) not in (int, float)
                or (type(timeout) is float and not math.isfinite(timeout)) or timeout <= 0):
            raise ValueError("bounded owned trace required")
        if (type(child) is not int or timeout > 180
                or type(cleanup_seconds) not in (int, float)
                or not math.isfinite(cleanup_seconds) or not 0 < cleanup_seconds <= 60):
            raise ValueError("bounded owned trace required")
        self.acquired_root = _observation.process_identity(child)
        if self.acquired_root['ppid'] != os.getpid():
            raise RuntimeError("trace root is not a direct child")
        if (type(start_write) is not int or start_write < 0
                or not stat.S_ISFIFO(os.fstat(start_write).st_mode)
                or fcntl.fcntl(start_write, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY):
            raise ValueError('owned write-only startup pipe required')
        self.start_write: int | None = start_write
        self.attached: set[int] = set()
        self.stopped: dict[int, int] = {}
        self.harvested: set[int] = set()
        self.child = child
        self.allowed = allowed
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.cleanup_seconds = cleanup_seconds
        self.pidfds: dict[int, int] = {}
        self.foreign: set[int] = set()
        self.on_tick = on_tick
        self.resolve_exec = resolve_exec
        self.selective = selective
        self.on_attached = on_attached
        self.defer_numeric_wait: Any = None
        self.before_numeric_wait: Any = None
        self.root_parent_wait: int | None = None
        self.records: list[dict[str, Any]] = []
        self.diagnostic_trace = DiagnosticTrace()
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
            if not separator or key in environment:
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
        if (architecture != 0xC000003E or operation not in (1, 2, 3)
                or size < (80 if operation in (1, 3) else 33)):
            raise RuntimeError("unknown syscall observation ABI")
        value = registers(pid)
        entering = operation in (1, 3)
        number = value.orig_rax
        if entering:
            self.pending[pid] = {"syscall": number, "status_address": value.rsi,
                                 "wait_options": value.rdx, "waitid_address": value.rdx,
                                 "waitid_options": value.r10}
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
                if raw is None:
                    self.poison.append("original_wait4_status_unobserved")
                self.records.append({"kind": "original_parent_wait4", "parent": pid,
                                     "parent_tgid": self.identities[pid]["tgid"],
                                     "child": signed(value.rax), "raw": raw,
                                     "normalized": os.waitstatus_to_exitcode(raw)
                                     if raw is not None and (os.WIFEXITED(raw) or os.WIFSIGNALED(raw)) else None,
                                     "options": pending["wait_options"]})
            elif pending and pending["syscall"] == 247 and signed(value.rax) == 0:
                address = pending["waitid_address"]
                wait_info = read_bytes(pid, address, 128) if address else None
                if wait_info is None:
                    self.poison.append("original_waitid_status_unobserved")
                self.records.append({"kind": "original_parent_waitid", "parent": pid,
                                     "parent_tgid": self.identities[pid]["tgid"],
                                     "siginfo_hex": wait_info.hex() if wait_info else None,
                                     "child": int.from_bytes(wait_info[16:20], "little") if wait_info else None,
                                     "code": int.from_bytes(wait_info[8:12], "little", signed=True) if wait_info else None,
                                     "status": int.from_bytes(wait_info[24:28], "little", signed=True) if wait_info else None,
                                     "options": pending["waitid_options"],
                                     "reaps": not bool(pending["waitid_options"] & 0x1000000)})
            elif pending and pending["syscall"] in (59, 322):
                self.records.append({"kind": "exec_syscall_return", "pid": pid,
                                     "return": signed(value.rax)})

    def _pin(self, pid: int) -> dict[str, Any]:
        before = _observation.process_identity(pid)
        fields = ('pid', 'tgid', 'ppid', 'start_ticks', 'boot_id')
        if pid == self.child and (before['ppid'] != os.getpid() or any(
                before[field] != self.acquired_root[field] for field in fields)):
            self.foreign.add(pid)
            raise RuntimeError('original root birth changed before acquisition')
        fd = os.pidfd_open(before['tgid'], 0)
        try:
            after = _observation.process_identity(pid)
            if any(before[field] != after[field] for field in fields):
                self.foreign.add(pid)
                raise RuntimeError('owned trace birth changed during pidfd acquisition')
        except BaseException:
            os.close(fd)
            raise
        self.pidfds[pid] = fd
        return after

    def _initial_wait(self, options: int) -> tuple[int, int]:
        while time.monotonic() <= self.deadline:
            pid, raw = os.waitpid(self.child, options | os.WNOHANG)
            if pid:
                return pid, raw
            time.sleep(0.0001)
        raise TimeoutError('owned initial stop deadline exceeded')

    def _close_start(self) -> None:
        if self.start_write is not None:
            fd, self.start_write = self.start_write, None
            os.close(fd)

    def _birth(self, pid: int, raw: int) -> None:
        if raw >> 16 not in (1, 2, 3) or pid in self.harvested:
            return
        child = ctypes.c_ulong()
        ptrace(0x4201, pid, data=ctypes.byref(child))
        if not child.value or child.value in self.active:
            raise RuntimeError('duplicate or invalid kernel birth')
        # The event grants ownership even if richer identity acquisition fails.
        self.active.add(child.value)
        self.attached.add(child.value)
        self.newborn.add(child.value)
        self.harvested.add(pid)
        self.identities[child.value] = self._pin(child.value)
        self.records.append({'kind': 'kernel_child', 'parent': pid,
                             'child': child.value, 'event': raw >> 16,
                             'identity': self.identities[child.value]})

    def _terminal(self, pid: int, raw: int, *, cleanup: bool) -> None:
        self.active.remove(pid)
        self.stopped.pop(pid, None)
        self.attached.discard(pid)
        self.records.append({'kind': 'failure_cleanup_tracer_wait' if cleanup
                             else 'tracer_terminal_wait', 'pid': pid, 'raw': raw,
                             'normalized': os.waitstatus_to_exitcode(raw),
                             'identity': self.identities.get(pid),
                             'root_original_parent': pid == self.child})
        if pid == self.child:
            self.root_parent_wait = raw

    def _cleanup(self) -> list[BaseException]:
        deadline = time.monotonic() + self.cleanup_seconds
        errors: list[BaseException] = []
        self._close_start()  # An unattached root must see EOF, never a release byte.
        interrupted: set[int] = set()
        unavailable = set(self.foreign)
        # Freeze every TID, recursively admitting only births from kernel events.
        # No body is resumed while a pending fork/clone can escape the census.
        while self.active - unavailable and time.monotonic() <= deadline:
            progressed = False
            for pid in sorted(self.active - unavailable):
                try:
                    if pid in self.stopped:
                        self._birth(pid, self.stopped[pid])
                        continue
                    if pid in self.attached and pid not in interrupted:
                        try:
                            ptrace(0x4207, pid)
                        except ProcessLookupError:
                            pass  # A terminal wait, not ESRCH, must settle it.
                        interrupted.add(pid)
                    actual, raw = os.waitpid(pid, os.WNOHANG | 0x40000000)
                    if not actual:
                        continue
                    progressed = True
                    if actual != pid:
                        raise RuntimeError('foreign numeric cleanup wait')
                    if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                        self._terminal(pid, raw, cleanup=True)
                    elif os.WIFSTOPPED(raw):
                        self.stopped[pid] = raw
                        self._birth(pid, raw)
                    else:
                        raise RuntimeError('unknown cleanup wait disposition')
                except BaseException as error:
                    errors.append(error)
                    unavailable.add(pid)
            if self.active - unavailable <= self.stopped.keys():
                break
            if not progressed:
                time.sleep(0.0001)
        frozen = self.active - unavailable <= self.stopped.keys()
        if not frozen or unavailable:
            self.poison.append('cleanup_freeze_incomplete')
            errors.append(RuntimeError('owned freeze census incomplete'))
        killed: set[int] = set()
        for pid in sorted(self.attached & self.active - self.foreign):
            try:
                # Linux's PTRACE_KILL sends SIGKILL through the existing tracer
                # relationship. CONT(signal) from arbitrary stops is not equivalent.
                ptrace(8, pid)
                killed.add(pid)
            except ProcessLookupError:
                self.stopped.pop(pid, None)  # Still require its actual wait below.
            except BaseException as error:
                errors.append(error)
        while self.active - unavailable and time.monotonic() <= deadline:
            progressed = False
            for pid in sorted(self.active - unavailable):
                try:
                    # EXIT events remain stops; resume only after the kill request.
                    if pid in self.stopped:
                        if pid not in killed:
                            unavailable.add(pid)
                            continue
                        try:
                            ptrace(7, pid)
                        except ProcessLookupError:
                            pass  # SIGKILL may already have advanced the saved stop.
                        self.stopped.pop(pid)
                        self.harvested.discard(pid)
                    actual, raw = os.waitpid(pid, os.WNOHANG | 0x40000000)
                    if not actual:
                        continue
                    progressed = True
                    if actual != pid:
                        raise RuntimeError('foreign numeric cleanup wait')
                    if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                        self._terminal(pid, raw, cleanup=True)
                    elif os.WIFSTOPPED(raw):
                        self.stopped[pid] = raw
                    else:
                        raise RuntimeError('unknown cleanup wait disposition')
                except BaseException as error:
                    errors.append(error)
                    unavailable.add(pid)
            if not progressed:
                time.sleep(0.0001)
        if self.active:
            self.poison.append('owned_cleanup_incomplete')
            self.records.append({'kind': 'cleanup_incomplete', 'pids': sorted(self.active),
                                 'numeric_waits_unverified': True})
            errors.append(TimeoutError('owned cleanup did not settle every tracked task'))
        return errors

    def run(self) -> dict[str, Any]:
        root_wait = None
        last_waited = 0
        failure: BaseException | None = None
        try:
            self.identities[self.child] = self._pin(self.child)
            options = 0x100000 | 0x7F | (0x80 if self.selective else 0)
            # One setup mechanism: held pipe, SEIZE with EXITKILL, interrupt,
            # exact initial stop, then release. EOF cancels pre-attach startup.
            ptrace(0x4206, self.child, data=ctypes.c_void_p(options))
            self.attached.add(self.child)
            ptrace(0x4207, self.child)
            initial, status = self._initial_wait(0x40000000)
            if initial == self.child and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                self._terminal(initial, status, cleanup=False)
            elif initial == self.child and os.WIFSTOPPED(status):
                self.stopped[initial] = status
            if (initial != self.child or not os.WIFSTOPPED(status)
                    or status >> 16 != 128):
                raise RuntimeError("owned seize interrupt stop missing")
            self.records.append({"kind": "kernel_root", "identity": self.identities[self.child]})
            if self.on_attached is not None:
                self.on_attached()
            assert self.start_write is not None
            if os.write(self.start_write, b'1') != 1:
                raise RuntimeError('owned startup release failed')
            self._close_start()
            # EXITKILL keeps tracer failure fail-closed; forks/clones are followed by
            # the kernel, not discovered by process-table polling.
            ptrace(7 if self.selective else 24, self.child)
            self.stopped.pop(self.child)
            while self.active:
                if self.on_tick is not None:
                    self.on_tick(self)
                if time.monotonic() > self.deadline:
                    raise TimeoutError("owned trace deadline exceeded")
                # A newborn stop may become waitable before its parent's
                # fork event. Do not harvest or resume it until that kernel
                # event supplies its identity; rotate known tasks fairly.
                known = sorted(self.active)
                pivot = next((index for index, value in enumerate(known)
                              if value > last_waited), 0)
                pid, raw = 0, 0
                for candidate in known[pivot:] + known[:pivot]:
                    if (getattr(self, 'defer_numeric_wait', None) is not None
                            and self.defer_numeric_wait(self, candidate)):
                        continue
                    if getattr(self, 'before_numeric_wait', None) is not None:
                        self.before_numeric_wait(self, candidate)
                    pid, raw = os.waitpid(candidate, os.WNOHANG | 0x40000000)
                    if pid:
                        last_waited = pid
                        break
                if not pid:
                    time.sleep(0.0001)
                    continue
                if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                    self._terminal(pid, raw, cleanup=False)
                    if pid == self.child:
                        root_wait = raw
                    continue
                if not os.WIFSTOPPED(raw):
                    raise RuntimeError("unknown ptrace wait disposition")
                self.stopped[pid] = raw
                self.diagnostic_trace.stop(pid, os.WSTOPSIG(raw), raw >> 16)
                stop = os.WSTOPSIG(raw)
                event = raw >> 16
                deliver = 0
                if event in (1, 2, 3):
                    self._birth(pid, raw)
                elif event == 4:
                    self.records.append({"kind": "kernel_exec", "pid": pid})
                elif event == 7 and self.selective:
                    self.syscall(pid)
                elif event == 5:
                    self.records.append({"kind": "kernel_vfork_done", "pid": pid})
                elif event == 6:
                    terminal = ctypes.c_ulong()
                    ptrace(0x4201, pid, data=ctypes.byref(terminal))
                    self.records.append({"kind": "kernel_exit", "pid": pid,
                                         "raw": terminal.value})
                elif event == 128 and pid in self.newborn:
                    self.newborn.remove(pid)
                elif event == 128 and stop in (
                    signal.SIGSTOP, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU
                ):
                    ptrace(0x4208, pid)  # LISTEN preserves the original group stop.
                    self.stopped.pop(pid)
                    self.harvested.discard(pid)
                    continue
                elif event:
                    raise RuntimeError("unknown ptrace event")
                elif stop == signal.SIGTRAP | 0x80:
                    self.syscall(pid)
                elif stop == signal.SIGSTOP and pid in self.newborn:
                    self.newborn.remove(pid)
                else:
                    deliver = stop
                request = 24 if not self.selective or pid in self.pending else 7
                self.diagnostic_trace.resume(pid, request)
                ptrace(request, pid, data=ctypes.c_void_p(deliver))
                self.stopped.pop(pid)
                self.harvested.discard(pid)
        except BaseException as error:
            failure = error
        errors: list[BaseException] = []
        try:
            errors.extend(self._cleanup())
        except BaseException as error:
            errors.append(error)
            if self.active:
                self.poison.append('owned_cleanup_interrupted')
                self.records.append({'kind': 'cleanup_incomplete', 'pids': sorted(self.active),
                                     'numeric_waits_unverified': True})
        finally:
            try:
                self._close_start()
            except BaseException as error:
                errors.append(error)
            for fd in self.pidfds.values():
                try:
                    os.close(fd)
                except BaseException as error:
                    errors.append(error)
            self.pidfds.clear()
        if failure is not None:
            if errors:
                raise BaseExceptionGroup('owned trace failed and cleanup failed', [failure, *errors])
            raise failure
        if errors:
            raise BaseExceptionGroup('owned trace cleanup failed', errors)
        return {"root_parent_wait_raw": root_wait, "records": self.records,
                "poison": self.poison, "source_checkpoint_ready": False,
                "diagnostic_trace": self.diagnostic_trace.export()}
