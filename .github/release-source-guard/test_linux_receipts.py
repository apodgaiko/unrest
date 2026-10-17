"""Kernel-peer receipt controls refuse before a caller can publish an effect."""
import importlib.util
import json
import os
from pathlib import Path
import socket

import pytest

spec = importlib.util.spec_from_file_location(
    "linux_receipts", Path(__file__).with_name("linux_receipts.py")
)
assert spec is not None and spec.loader is not None
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)


def setup():
    ledger = receipts.ReceiptLedger("a" * 64, os.getuid())
    ledger.register(os.getpid(), "b" * 32)
    request = {"nonce": "a" * 64, "pid": os.getpid(), "token": "b" * 32,
               "identity": receipts.own_identity(), "id": "c" * 32}
    return ledger, request


def test_genuine_peer_one_shot_and_caught_replay_poison():
    ledger, request = setup()
    left, right = socket.socketpair()
    try:
        actual = ledger.admit(left, request)
        assert actual["pid"] == os.getpid() and actual["uid"] == os.getuid()
        with pytest.raises(receipts.ReceiptRefused, match="replay"):
            ledger.admit(left, request)
        with pytest.raises(receipts.ReceiptRefused, match="poison_retained"):
            ledger.admit(left, {**request, "id": "d" * 32})
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("attack", ["peer", "nonce", "token", "birth", "late", "unregistered"])
def test_foreign_stale_and_late_cannot_publish_effect(attack):
    ledger, request = setup()
    if attack == "peer":
        request["pid"] = os.getppid()
    elif attack == "birth":
        request["identity"] = {**request["identity"], "start_ticks": -1}
    elif attack == "late":
        ledger.close(os.getpid())
    elif attack == "unregistered":
        ledger.registered.clear()
    else:
        request[attack] = "0" * (64 if attack == "nonce" else 32)
    left, right = socket.socketpair()
    effects = []
    try:
        with pytest.raises(receipts.ReceiptRefused):
            ledger.admit(left, request)
            effects.append("published")
        assert effects == [] and ledger.poison
    finally:
        left.close()
        right.close()


def test_inherited_descriptor_cannot_claim_the_child_peer():
    ledger = receipts.ReceiptLedger("a" * 64, os.getuid())
    left, right = socket.socketpair()
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            left.close()
            os.close(write)
            request = {"nonce": "a" * 64, "pid": os.getpid(), "token": "b" * 32,
                       "identity": receipts.own_identity(), "id": "c" * 32}
            right.sendall(json.dumps(request).encode() + b"\n")
            os.read(read, 1)
        finally:
            os._exit(0)
    right.close()
    os.close(read)
    try:
        ledger.register(child, "b" * 32)
        body = bytearray()
        while not body.endswith(b"\n"):
            part = left.recv(4096)
            assert part and len(body) + len(part) <= 4096
            body.extend(part)
        request = json.loads(body)
        assert request["pid"] == child
        with pytest.raises(receipts.ReceiptRefused, match="kernel_receipt_peer"):
            ledger.admit(left, request)
    finally:
        os.write(write, b"1")
        os.close(write)
        left.close()
        actual, raw = os.waitpid(child, 0)
    assert actual == child and raw == 0
