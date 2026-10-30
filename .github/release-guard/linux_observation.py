"""Linux kernel observations for the isolated source-checkpoint controller.

These observations identify processes; disappearance never establishes a wait.
This module does not admit launches or activate the finite source guard.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

NAMESPACES = ("ipc", "mnt", "net", "pid", "user", "uts", "cgroup")


def pidfd_open(pid: int, flags: int = 0) -> int:
    if type(pid) is not int or not 0<pid<=(1<<31)-1 or type(flags) is not int or flags!=0:
        raise ValueError('exact pidfd operands required')
    return os.pidfd_open(pid,flags)


def process_identity(pid: int) -> dict[str, Any]:
    """Full observer-only identity, including namespace custody."""
    return _identity(pid, namespaces=True)


def credential_identity(pid: int) -> dict[str, Any]:
    """Kernel peer birth/credentials without reading privileged namespace links.

    SO_PEERCRED authentication runs in both directions: an unprivileged source
    can inspect the observer's public stat/status, but cannot ptrace its namespace
    links. This entry never substitutes for full observer custody acquisition.
    """
    return _identity(pid, namespaces=False)


def _identity(pid: int, *, namespaces: bool) -> dict[str, Any]:
    """Read the birth discriminator twice to refuse a PID replacement race."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("positive integer PID required")
    root = Path("/proc") / str(pid)
    first = (root / "stat").read_text()
    # comm can contain both spaces and closing parentheses.
    prefix, separator, tail = first.rpartition(") ")
    if not separator or not prefix.startswith(str(pid) + " ("):
        raise RuntimeError("malformed proc stat")
    fields = tail.split()
    status = dict(
        line.split(":", 1) for line in (root / "status").read_text().splitlines()
    )
    result = {
        "pid": pid,
        "tgid": int(status["Tgid"]),
        "ppid": int(fields[1]),
        "pgid": int(fields[2]),
        "sid": int(fields[3]),
        "start_ticks": int(fields[19]),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "state": fields[0],
        "uids": [int(value) for value in status["Uid"].split()],
        "gids": [int(value) for value in status["Gid"].split()],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "capabilities": {
            name: int(status[name], 16)
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        },
        "no_new_privs": int(status["NoNewPrivs"]),
        "seccomp": int(status["Seccomp"]),
    }
    if namespaces:
        result["namespaces"] = {name: os.readlink(root / "ns" / name) for name in NAMESPACES}
    second = (root / "stat").read_text().rpartition(") ")[2].split()
    if int(second[19]) != result["start_ticks"]:
        raise RuntimeError("process birth changed during observation")
    return result
