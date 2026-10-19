"""Package-install-only terminal thread retirement; original process waits stay mandatory.

Linux may retire a UV worker after its observed PTRACE_EVENT_EXIT but before
GETEVENTMSG or CONT. Keep it active and let the original owned wait loop collect
its genuine terminal status. Never invent an exit value or use cleanup waits.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import signal
import time
from typing import Any

from linux_trace import OwnedTrace, ptrace, _observation
from producer_inputs import SOURCE_UV_ELF_SHA256

COMMAND = ['uv', 'pip', 'install', '--python', '.wheel-venv/bin/python',
           'dist/unrest_harness-0.4.6-py3-none-any.whl']


def verify_retirements(records):
    deferred = [row for row in records if row['kind'] == 'primary_package_thread_exit_pending']
    if len({row['pid'] for row in deferred}) != len(deferred):
        raise RuntimeError('package_thread_exit_duplicate')
    for row in deferred:
        waits = [wait for wait in records if wait['kind'] == 'tracer_terminal_wait'
                 and wait['pid'] == row['pid'] and wait['identity'] == row['identity']]
        if len(waits) != 1 or type(waits[0]['raw']) is not int or waits[0]['raw'] != 0:
            raise RuntimeError('package_thread_actual_terminal_wait_missing')
    return len(deferred)


class PackageInstalledTrace(OwnedTrace):
    def __init__(self, *args, package_authority, **kwargs):
        self.package_authority = package_authority
        super().__init__(*args, **kwargs)

    def defer_thread_exit(self, pid, operation):
        authority = self.package_authority
        saved = self.identities[pid]
        group = saved['tgid']
        context = authority.contexts.get(group)
        birth = [row for row in self.records if row['kind'] == 'kernel_child'
                 and row['child'] == pid and row['identity'] == saved and row['event'] == 3]
        starts = [row for row in authority.records if row['kind'] == 'primary_package_shell_operation'
                  and row['pid'] == group and row['operation_index'] == 1]
        if (operation not in {'exit-message', 'exit-resume'} or pid == group or pid == self.child
                or pid not in self.active or self.poison or authority.denials
                or authority.root != self.child or authority.plan.get('package_mode') not in {'TEST', 'FULL'}
                or authority.plan['duty'] != 'Smoke-test installed wheel'
                or authority.operation_index != 2 or authority.operations[1] != COMMAND
                or context is None or context['role'] != 'uv' or context['command'] != COMMAND
                or len(birth) != 1 or len(starts) != 1
                or starts[0]['identity'] != context['identity']
                or starts[0]['image_sha256'] != SOURCE_UV_ELF_SHA256
                or any(context['identity'][key] != self.identities[group][key]
                       for key in ('pid', 'ppid', 'start_ticks', 'boot_id'))
                or saved['uids'] != [20000] * 4 or any(saved['capabilities'].values())
                or saved['no_new_privs'] != 1 or saved['boot_id'] != context['identity']['boot_id']
                or any(row['kind'] in {'tracer_terminal_wait', 'primary_package_thread_exit_pending'}
                       and row['pid'] == pid for row in self.records)):
            return False
        self.records.append({'kind': 'primary_package_thread_exit_pending', 'pid': pid,
                             'identity': saved, 'uv_identity': context['identity'],
                             'operation': operation, 'ptrace_event': 6,
                             'native_image_sha256': SOURCE_UV_ELF_SHA256,
                             'kernel_birth_sha256': hashlib.sha256(json.dumps(
                                 birth[0], sort_keys=True).encode()).hexdigest()})
        return True

    # SOURCE keeps the original OwnedTrace loop; the focused parity control
    # checks every statement outside these two terminal-stop boundaries.
    def run(self) -> dict[str, Any]:
        options = 0x100000 | 0x7F | (0x80 if self.selective else 0)
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
        ptrace(7 if self.selective else 24, self.child)
        started = time.monotonic()
        root_wait = None
        last_waited = 0
        try:
            while self.active:
                if self.on_tick is not None:
                    self.on_tick(self)
                if time.monotonic() - started > self.timeout:
                    raise TimeoutError("owned trace deadline exceeded")
                # A newborn stop may become waitable before its parent's
                # fork event. Do not harvest or resume it until that kernel
                # event supplies its identity; rotate known tasks fairly.
                known = sorted(self.active)
                pivot = next((index for index, value in enumerate(known)
                              if value > last_waited), 0)
                pid, raw = 0, 0
                for candidate in known[pivot:] + known[:pivot]:
                    pid, raw = os.waitpid(candidate, os.WNOHANG | 0x40000000)
                    if pid:
                        last_waited = pid
                        break
                if not pid:
                    time.sleep(0.0001)
                    continue
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
                self.diagnostic_trace.stop(pid, os.WSTOPSIG(raw), raw >> 16)
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
                elif event == 7 and self.selective:
                    self.syscall(pid)
                elif event == 5:
                    self.records.append({"kind": "kernel_vfork_done", "pid": pid})
                elif event == 6:
                    terminal = ctypes.c_ulong()
                    try:
                        ptrace(0x4201, pid, data=ctypes.byref(terminal))
                    except ProcessLookupError as error:
                        if error.errno != errno.ESRCH or not self.defer_thread_exit(pid, 'exit-message'):
                            raise
                        continue
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
                request = 24 if not self.selective or pid in self.pending else 7
                self.diagnostic_trace.resume(pid, request)
                try:
                    ptrace(request, pid, data=ctypes.c_void_p(deliver))
                except ProcessLookupError as error:
                    if (error.errno != errno.ESRCH or event != 6
                            or not self.defer_thread_exit(pid, 'exit-resume')):
                        raise
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
        verify_retirements(self.records)
        return {"root_parent_wait_raw": root_wait, "records": self.records,
                "poison": self.poison, "source_checkpoint_ready": False,
                "diagnostic_trace": self.diagnostic_trace.export()}
