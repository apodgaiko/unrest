"""Linux kernel observations for the isolated source-checkpoint controller.

These observations identify processes; disappearance never establishes a wait.
This module does not admit launches or activate the finite source guard.
"""
from __future__ import annotations

import os
import ctypes
import importlib.util
import hashlib
from pathlib import Path
import platform
import socket
import struct
from typing import Any

NAMESPACES = ("ipc", "mnt", "net", "pid", "user", "uts", "cgroup")


def pidfd_open(pid: int, flags: int = 0) -> int:
    if type(pid) is not int or not 0<pid<=(1<<31)-1 or type(flags) is not int or flags!=0:
        raise ValueError('exact pidfd operands required')
    if hasattr(os,'pidfd_open'):
        return os.pidfd_open(pid,flags)
    if platform.system()!='Linux' or platform.machine()!='x86_64':
        raise RuntimeError('unsupported pidfd ABI')
    fd=ctypes.CDLL(None,use_errno=True).syscall(434,pid,0)
    if fd<0:
        raise OSError(ctypes.get_errno(),'kernel pidfd acquisition refused')
    return fd


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


def descriptors(pid: int) -> list[dict[str, Any]]:
    """Inventory kernel descriptor objects without treating names as authority."""
    directory = Path("/proc") / str(pid) / "fd"
    observed = []
    for entry in sorted(directory.iterdir(), key=lambda item: int(item.name)):
        try:
            info = entry.stat()
            target = os.readlink(entry)
        except FileNotFoundError:
            # Iterating our own directory creates a transient directory FD.
            if pid == os.getpid():
                continue
            raise RuntimeError("foreign descriptor inventory raced") from None
        observed.append({
            "fd": int(entry.name), "device": info.st_dev, "inode": info.st_ino,
            "mode": info.st_mode, "target": target,
        })
    return observed


def peer_identity(stream: socket.socket) -> dict[str, int]:
    if stream.family != socket.AF_UNIX:
        raise ValueError("Unix peer credentials required")
    pid, uid, gid = struct.unpack(
        "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    return {"pid": pid, "uid": uid, "gid": gid}


def require_linux_abi() -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("unsupported observer ABI")
    identity = process_identity(os.getpid())
    fd = pidfd_open(os.getpid(), 0)
    try:
        if not os.readlink(f"/proc/self/fd/{fd}").startswith("anon_inode:[pidfd]"):
            raise RuntimeError("kernel pidfd identity unavailable")
    finally:
        os.close(fd)
    aliases = {}
    for name in ('git', 'ps', 'sleep'):
        canonical, alias = Path('/usr/bin') / name, Path('/bin') / name
        if canonical.resolve() != alias.resolve():
            raise RuntimeError('stock Linux native alias identity drift')
        aliases[name] = {'canonical': str(canonical), 'alias': str(alias),
                         'realpath': str(canonical.resolve()),
                         'sha256': hashlib.sha256(canonical.read_bytes()).hexdigest()}
    return {"system": "Linux", "machine": "x86_64",
            "kernel_release": platform.release(), "identity": identity,
            "pidfd": True, "stock_native_aliases": aliases}


def direct_child_inventory(pid: int) -> dict[str, Any]:
    parent = process_identity(pid)
    directory = Path('/proc') / str(pid) / 'task'
    tasks = sorted(int(path.name) for path in directory.iterdir())
    children = {}
    all_children: set[int] = set()
    for task in tasks:
        values = [int(value) for value in (directory / str(task) / 'children').read_text().split()]
        if len(values) != len(set(values)) or any(value <= 0 for value in values):
            raise RuntimeError('kernel children list ABI drift')
        children[str(task)] = values
        all_children.update(values)
    if len(all_children) >= 64:
        raise RuntimeError('kernel child inventory exceeds finite bound')
    spec = importlib.util.spec_from_file_location(
        'retained_linux_birth', Path(__file__).with_name('linux_identity.py'))
    assert spec is not None and spec.loader is not None
    retained = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(retained)
    births = {}
    for child in sorted(all_children):
        birth = retained.identity(child)
        fields = (Path('/proc') / str(child) / 'stat').read_text().rpartition(') ')[2].split()
        if int(fields[19]) != birth['start_ticks']:
            raise RuntimeError('retained child birth changed during inventory')
        # Zombie namespace links vanish before reaping. Birth/parent/state stay
        # genuine; namespace custody comes from the earlier ptrace birth record.
        births[str(child)] = {**birth, 'state': fields[0]}

    if any(value['ppid'] != pid for value in births.values()):
        raise RuntimeError('kernel child original parent drift')
    after = process_identity(pid)
    if (parent['start_ticks'] != after['start_ticks'] or parent['boot_id'] != after['boot_id']
            or tasks != sorted(int(path.name) for path in directory.iterdir())):
        raise RuntimeError('kernel parent/task birth changed during inventory')
    return {'parent': parent, 'thread_children': children, 'children': sorted(all_children),
            'child_identities': births, 'method': 'Linux proc per-thread children and retained birth'}
