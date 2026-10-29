"""Linux SOCK_DIAG cookies and inode/FD bindings in the private network scope.

UAPI layouts: Linux v6.12 include/uapi/linux/{inet_diag,unix_diag,netlink}.h.
Only the trusted observer uses netlink; this does not authorize payload sockets.
"""
from __future__ import annotations

import os
import ctypes
import fcntl
from pathlib import Path
import socket
import struct
from typing import Any

from linux_observation import pidfd_open


def duplicate_descriptor(pid: int, descriptor: int) -> int:
    if type(pid) is not int or pid <= 0 or type(descriptor) is not int or descriptor < 0:
        raise ValueError('finite process descriptor required')
    if pid == os.getpid():
        return os.dup(descriptor)
    pidfd = pidfd_open(pid, 0)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.syscall(438, pidfd, descriptor, 0)  # x86-64 pidfd_getfd
        if result < 0:
            raise OSError(ctypes.get_errno(), 'kernel descriptor duplication refused')
        return result
    finally:
        os.close(pidfd)


def dump(request: bytes) -> list[bytes]:
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as stream:
        stream.settimeout(1)
        stream.bind((0, 0))
        sequence = int.from_bytes(os.urandom(4), "little") or 1
        port = stream.getsockname()[0]
        header = struct.pack("=IHHII", 16 + len(request), 20, 0x301, sequence, port)
        stream.sendto(header + request, (0, 0))
        rows: list[bytes] = []
        for _ in range(128):
            packet, ancillary, flags, sender = stream.recvmsg(262144)
            if sender != (0, 0) or ancillary or flags:
                raise RuntimeError("socket diagnostic sender or datagram drift")
            offset = 0
            while offset < len(packet):
                if len(packet) - offset < 16:
                    raise RuntimeError("short socket diagnostic header")
                length, kind, options, seq, destination = struct.unpack_from("=IHHII", packet, offset)
                if (length < 16 or offset + length > len(packet) or seq != sequence
                        or destination != port or options & 0x10):
                    raise RuntimeError("socket diagnostic envelope drift")
                body = packet[offset + 16:offset + length]
                if kind == 3:
                    return rows
                if kind == 2:
                    raise RuntimeError("socket diagnostic kernel error: " + str(
                        struct.unpack_from("=i", body)[0]
                    ))
                if kind != 20 or len(rows) >= 4096:
                    raise RuntimeError("unknown or unbounded socket diagnostic response")
                rows.append(body)
                offset += (length + 3) & ~3
        raise RuntimeError("unbounded socket diagnostic dump")


def unix_table() -> dict[int, dict[str, int]]:
    request = struct.pack("=BBHIIIII", socket.AF_UNIX, 0, 0, 0xFFFFFFFF, 0, 0x44,
                          0xFFFFFFFF, 0xFFFFFFFF)
    rows = {}
    for raw in dump(request):
        if len(raw) < 16 or raw[0] != socket.AF_UNIX:
            raise RuntimeError("unknown unix_diag ABI")
        inode, cookie = struct.unpack_from("=IQ", raw, 4)
        value = {"inode": inode, "socket_cookie": cookie, "state": raw[2], "type": raw[1]}
        offset = 16
        while offset < len(raw):
            if len(raw) - offset < 4:
                raise RuntimeError("short Unix diagnostic attribute")
            length, kind = struct.unpack_from("=HH", raw, offset)
            if length < 4 or offset + length > len(raw):
                raise RuntimeError("Unix diagnostic attribute length drift")
            if kind in (2, 7):
                if length != 8:
                    raise RuntimeError("Unix diagnostic peer/UID ABI drift")
                value["peer_inode" if kind == 2 else "socket_uid"] = struct.unpack_from(
                    "=I", raw, offset + 4
                )[0]
            offset += (length + 3) & ~3
        if inode in rows or cookie == (1 << 64) - 1:
            raise RuntimeError("Unix diagnostic cookie/inode drift")
        rows[inode] = value
    return rows


def _socket_inode(pid: int, descriptor: int) -> int | None:
    try:
        target = os.readlink(Path('/proc') / str(pid) / 'fd' / str(descriptor))
    except FileNotFoundError:
        return None
    if not target.startswith('socket:[') or not target.endswith(']'):
        return None
    return int(target[8:-1])


def unix_pair(pid: int, fds: list[int]) -> list[dict[str, int]]:
    if (type(fds) is not list or len(fds) != 2
            or any(type(fd) is not int or fd < 0 for fd in fds) or len(set(fds)) != 2):
        raise ValueError("exactly two distinct Unix descriptors required")
    before: dict[int, int] = {}
    for fd in fds:
        inode = _socket_inode(pid, fd)
        if inode is None:
            raise RuntimeError('Unix pair no longer has two live kernel descriptors')
        before[fd] = inode
    table = unix_table()
    if any(before[fd] not in table for fd in fds):
        raise RuntimeError("Unix pair no longer has two live kernel descriptors")
    rows = [{"fd": fd, **table[before[fd]]} for fd in fds]
    if ({fd: _socket_inode(pid, fd) for fd in fds} != before or any(row["type"] != socket.SOCK_STREAM for row in rows)
            or rows[0]["inode"] != rows[1].get("peer_inode")
            or rows[1]["inode"] != rows[0].get("peer_inode")):
        raise RuntimeError("Unix pair kernel peer binding refused")
    return rows


def retained_tcp_descriptor(pid: int, descriptor: int, *, eof_only: bool = False) -> dict[str, Any] | None:
    """Query a retained file description even after TCP leaves the diag table."""
    if type(eof_only) is not bool:
        raise ValueError('exact EOF observation mode required')
    path = Path('/proc') / str(pid) / 'fd' / str(descriptor)
    try:
        target = os.readlink(path)
    except FileNotFoundError:
        return None
    if not target.startswith('socket:[') or not target.endswith(']'):
        return None
    before = int(target[8:-1])
    copied = duplicate_descriptor(pid, descriptor)
    try:
        stream = socket.socket(fileno=copied)
    except OSError:
        os.close(copied)
        raise RuntimeError('retained descriptor ceased to be a socket') from None
    with stream:
        if (stream.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_INET
                or stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or stream.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) != socket.IPPROTO_TCP):
            return None
        info = os.fstat(stream.fileno())
        cookie = struct.unpack('=Q', stream.getsockopt(socket.SOL_SOCKET, 57, 8))[0]
        state = stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)[0]
        local = stream.getsockname()
        try:
            remote = stream.getpeername()
        except OSError as error:
            import errno
            if error.errno != errno.ENOTCONN:
                raise
            remote = None
        if eof_only:
            # Query the same held file description, never a cached TCP row.
            pending = struct.unpack('=I', fcntl.ioctl(stream.fileno(), 0x541B, b'\0' * 4))[0]
            after = os.fstat(stream.fileno())
            if (state != 8 or pending != 0 or stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)[0] != 8
                    or struct.unpack('=Q', stream.getsockopt(socket.SOL_SOCKET, 57, 8))[0] != cookie
                    or (info.st_dev, info.st_ino, info.st_uid) != (after.st_dev, after.st_ino, after.st_uid)):
                raise RuntimeError('retained socket is not proven empty CLOSE_WAIT EOF')
        if (info.st_ino != before or os.readlink(path) != target
                or cookie == (1 << 64) - 1):
            raise RuntimeError('retained descriptor changed during kernel query')
        return {'pid': pid, 'fd': descriptor, 'inode': info.st_ino, 'socket_cookie': cookie,
                'state': state, 'socket_uid': info.st_uid, 'local_address': local, 'peer_address': remote,
                'observation': 'pidfd_getfd held file description; actual TCP_INFO and SO_COOKIE'}








def retained_unix_member(pid: int, descriptor: int,
                         pair: list[dict[str, int]]) -> dict[str, int] | None:
    saved = next((row for row in pair if row['fd'] == descriptor), None)
    if saved is None:
        return None
    before = _socket_inode(pid, descriptor)
    if before != saved['inode']:
        return None
    current = unix_table().get(saved['inode'])
    if _socket_inode(pid, descriptor) != saved['inode']:
        raise RuntimeError('retained Unix descriptor changed during observation')
    if (current is None or current['socket_cookie'] != saved['socket_cookie']
            or current.get('socket_uid') != saved['socket_uid']
            or current['type'] != socket.SOCK_STREAM
            or current.get('peer_inode', 0) not in (0, saved['peer_inode'])):
        return None
    return {'fd': descriptor, **current}


def acquire_tcp(birth, descriptor: int, *, eof_only: bool = False):
    """Return one birth-bound socket; no caller-supplied PID or cached row wins."""
    from endpoint_policy import Socket
    from process_ledger import Birth
    from linux_observation import process_identity

    if type(birth) is not Birth or type(eof_only) is not bool:
        raise ValueError('exact owned birth and observation mode required')
    if Birth.read(process_identity(birth.pid)) != birth:
        raise RuntimeError('stale_or_reused_ownership')
    row = retained_tcp_descriptor(birth.pid, descriptor, eof_only=eof_only)
    if row is not None:
        local, remote = row['local_address'], row['peer_address']
        row = {**row, 'local_host': local[0], 'local_port': local[1],
               'remote_host': remote[0] if remote else '0.0.0.0',
               'remote_port': remote[1] if remote else 0}
    if Birth.read(process_identity(birth.pid)) != birth:
        raise RuntimeError('stale_or_reused_ownership')
    return None if row is None else Socket.read(birth, row)


def acquire_unix_pair(birth, descriptors):
    from process_ledger import Birth
    from linux_observation import process_identity
    from unix_endpoints import Member

    if type(birth) is not Birth or Birth.read(process_identity(birth.pid)) != birth:
        raise RuntimeError('stale_or_reused_ownership')
    rows = unix_pair(birth.pid, descriptors)
    if Birth.read(process_identity(birth.pid)) != birth:
        raise RuntimeError('stale_or_reused_ownership')
    return tuple(Member.read(birth, row) for row in rows)


def acquire_unix_member(birth, descriptor, pair):
    from process_ledger import Birth
    from linux_observation import process_identity
    from unix_endpoints import Member, Pair

    if type(descriptor) is not int or descriptor < 0:
        raise ValueError('exact Unix descriptor required')
    if (type(birth) is not Birth or type(pair) is not Pair or pair.owner.birth != birth
            or Birth.read(process_identity(birth.pid)) != birth):
        raise RuntimeError('stale_or_reused_ownership')
    saved = [{'fd': member.fd, 'inode': member.inode, 'socket_cookie': member.cookie,
              'socket_uid': member.uid, 'peer_inode': member.peer} for member in pair.members]
    row = retained_unix_member(birth.pid, descriptor, saved)
    if Birth.read(process_identity(birth.pid)) != birth:
        raise RuntimeError('stale_or_reused_ownership')
    return Member.read(birth, row) if row is not None else None
