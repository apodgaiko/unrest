"""Current successful-exec descriptor custody for two finite spawn operations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import time

import linux_trace
from linux_observation import process_identity
from finite.linux_identity import identity


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require_descriptors(rows, declared):
    wanted = [row for row in declared if row["fd"] >= 3]
    keys = ("fd", "device", "inode", "mode", "uid", "access")
    actual = [{key: row[key] for key in keys} for row in rows]
    expected = [{key: row[key] for key in keys} for row in wanted]
    if actual != expected:
        raise RuntimeError("multiprocess successful-exec descriptor inventory mismatch")
    if any(row["close_on_exec"] for row in rows):
        raise RuntimeError("multiprocess surviving descriptor retains CLOEXEC")
    return actual


def exec_custody(authority, trace, pid, vector, environment, cwd):
    selected = authority.bound[pid]
    if selected["registration"]["class"] not in {
        "source-multiprocess-tracker",
        "source-multiprocess-spawn",
    }:
        raise RuntimeError("multiprocess custody class mismatch")
    declared = selected["multiprocess_descriptors"]
    pair = selected["multiprocess_fifo_pair"]
    before = identity(pid)
    owner = identity(before["ppid"])
    credentials = process_identity(pid)
    expected_uid = authority.supervisor.root["uid"]
    if (
        authority.supervisor.registered.get(owner["pid"], {}).get("identity") != owner
        or credentials["uids"] != [expected_uid] * 4
        or any(credentials["capabilities"].values())
        or credentials["no_new_privs"] != 1
        or trace.pending.get(pid, {}).get("syscall") != 59
        or any(
            before[key] != trace.identities[pid][key]
            for key in ("pid", "ppid", "start_ticks", "boot_id")
        )
    ):
        raise RuntimeError("multiprocess actual parent/kernel birth mismatch")
    writer = pair[1]
    parent_fd = Path("/proc/" + str(owner["pid"]) + "/fd/" + str(writer["fd"]))
    live = parent_fd.stat()
    if (live.st_dev, live.st_ino, live.st_mode, live.st_uid) != tuple(
        writer[key] for key in ("device", "inode", "mode", "uid")
    ):
        raise RuntimeError("multiprocess live original-parent FIFO generation mismatch")
    pre = authority.census(pid)
    for declared_fd in declared:
        info = Path("/proc/" + str(pid) + "/fd/" + str(declared_fd["fd"])).stat()
        if (info.st_dev, info.st_ino, info.st_mode, info.st_uid) != tuple(
            declared_fd[key] for key in ("device", "inode", "mode", "uid")
        ):
            raise RuntimeError("multiprocess inherited descriptor generation mismatch")
    linux_trace.ptrace(24, pid)
    deadline = time.monotonic() + min(5, trace.timeout)
    while True:
        waited, raw = os.waitpid(pid, os.WNOHANG | 0x40000000)
        if waited:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("multiprocess successful-exec deadline")
        time.sleep(0.0001)
    if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
        trace.active.discard(pid)
        trace.records.append(
            {
                "kind": "failure_cleanup_tracer_wait",
                "pid": pid,
                "raw": raw,
                "normalized": os.waitstatus_to_exitcode(raw),
                "root_original_parent": pid == trace.child,
            }
        )
    if (
        waited != pid
        or not os.WIFSTOPPED(raw)
        or os.WSTOPSIG(raw) != signal.SIGTRAP
        or raw >> 16 != 4
    ):
        raise RuntimeError("multiprocess successful-exec stop mismatch")
    trace.records.append({"kind": "kernel_exec", "pid": pid})
    after = identity(pid)
    post = authority.census(pid)
    process_root = Path("/proc/" + str(pid))
    after_credentials = process_identity(pid)
    if (
        after != before
        or identity(owner["pid"]) != owner
        or after_credentials["uids"] != credentials["uids"]
        or after_credentials["capabilities"] != credentials["capabilities"]
        or after_credentials["no_new_privs"] != 1
        or (process_root / "cmdline").read_bytes().split(b"\0")
        != [os.fsencode(v) for v in vector] + [b""]
        or sorted((process_root / "environ").read_bytes().split(b"\0"))
        != sorted([os.fsencode(key + "=" + value) for key, value in environment.items()] + [b""])
        or os.readlink(process_root / "cwd") != cwd
        or sha(process_root / "exe") != authority.manifest["runtime"]["sha256"]
    ):
        raise RuntimeError("multiprocess successful-exec identity mismatch")
    surviving = require_descriptors(post, declared)
    authority.pipe_records.append(
        {
            "kind": "multiprocess_exec_custody",
            "pid": pid,
            "identity": after,
            "owner_identity": owner,
            "preexec": authority.safe_census(pre),
            "postexec": authority.safe_census(post),
            "original_parent_fifo": writer,
            "declaration_sha256": hashlib.sha256(
                json.dumps(selected, sort_keys=True).encode()
            ).hexdigest(),
        }
    )
    return surviving
