"""Observer-owned, one-shot receipt admission using actual Linux Unix peers.

No execution API is provided. The source supervisor supplies finite registered
birth identities and handles an admitted request through its existing policy.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import struct
from typing import Any, NoReturn

_spec = importlib.util.spec_from_file_location(
    "linux_identity", Path(__file__).with_name("finite") / "linux_identity.py"
)
assert _spec is not None and _spec.loader is not None
_identity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_identity)


class ReceiptRefused(RuntimeError):
    pass


class ReceiptLedger:
    # Same bounded failure-drain methods as the source supervisor. Admission
    # still requires a genuine registered peer; policy rechecks source ownership.
    DRAIN_METHODS = {"custody_close", "custody_signal", "drain_inventory",
                     "drain_child", "drain_complete"}
    def __init__(self, nonce: str, source_uid: int):
        if len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
            raise ValueError("exact epoch nonce required")
        self.nonce = nonce
        self.source_uid = source_uid
        self.registered: dict[int, tuple[str, dict[str, Any]]] = {}
        self.seen: set[str] = set()
        self.closed: set[int] = set()
        self.poison: list[str] = []

    def refuse(self, reason: str) -> NoReturn:
        self.poison.append(reason)
        raise ReceiptRefused(reason)

    def register(self, pid: int, token: str) -> None:
        if pid in self.registered or len(token) != 32:
            self.refuse("duplicate_or_invalid_registration")
        identity = _identity.identity(pid)
        if identity["uid"] != self.source_uid:
            self.refuse("registration_UID_refused")
        self.registered[pid] = (token, identity)

    def admit(self, stream: socket.socket, request: dict[str, Any]) -> dict[str, Any]:
        if stream.family != socket.AF_UNIX:
            self.refuse("non_Unix_receipt_peer")
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if peer_uid != self.source_uid or type(request.get("pid")) is not int or request[
            "pid"
        ] != peer_pid:
            self.refuse("kernel_receipt_peer_refused")
        pid = peer_pid
        if pid in self.closed:
            self.refuse("late_receipt_refused")
        saved = self.registered.get(pid)
        if saved is None:
            self.refuse("foreign_unregistered_receipt")
        assert saved is not None
        token, birth = saved
        if (_identity.identity(pid) != birth or request.get("identity") != birth
                or request.get("token") != token or request.get("nonce") != self.nonce):
            self.refuse("stale_or_foreign_receipt_binding")
        identifier = request.get("id")
        if (not isinstance(identifier, str) or len(identifier) != 32
                or any(c not in "0123456789abcdef" for c in identifier)
                or identifier in self.seen):
            self.refuse("receipt_replay_or_identifier_refused")
        if self.poison and request.get("kind") not in self.DRAIN_METHODS:
            self.refuse("receipt_poison_retained")
        self.seen.add(identifier)
        return {"pid": peer_pid, "uid": peer_uid, "gid": peer_gid, "birth": birth,
                "id": identifier}

    def close(self, pid: int) -> None:
        if pid not in self.registered:
            self.refuse("foreign_close_refused")
        self.closed.add(pid)


def own_identity() -> dict[str, Any]:
    return _identity.identity(os.getpid())
