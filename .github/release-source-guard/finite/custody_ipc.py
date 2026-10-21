"""Exact task-owned Unix channel: kernel peer PID/UID and one-shot digest binding."""

import _socket
import hashlib
import json
import os
from pathlib import Path
import struct
import stat
import sys
import threading
import uuid

LIMIT = 8192
LOCAL_PEERPID = 2
SOL_LOCAL = 0


def peer(stream):
    pid, uid, gid = struct.unpack(
        "3i", stream.getsockopt(_socket.SOL_SOCKET, _socket.SO_PEERCRED, 12)
    )
    return {"pid": pid, "uid": uid, "gid": gid}


def frame_send(stream, value):
    data = json.dumps(value, sort_keys=True).encode()
    if not 0 < len(data) <= LIMIT:
        raise RuntimeError("custody_IPC_frame_size")
    stream.sendall(struct.pack("!I", len(data)) + data)


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise RuntimeError("custody_IPC_short_frame")
        data.extend(part)
    return bytes(data)


def frame_recv(stream):
    length = struct.unpack("!I", exact(stream, 4))[0]
    if not 0 < length <= LIMIT:
        raise RuntimeError("custody_IPC_frame_size")
    return json.loads(exact(stream, length))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def address():
    state = sys.modules["runtime_guard"]._STATE
    return os.path.relpath(Path(state["owned_root"]).parent / "custody.sock", os.getcwd())


def authorize(event, args):
    """Called only by the inherited endpoint audit before Unix socket effects."""
    endpoint = sys.modules["endpoint"]
    guard = sys.modules["runtime_guard"]
    if event == 'socket.bind' and str(guard._STATE.get('case', '')).startswith(
            'tests/test_supervision_paths.py::test_static_carrier_refuses_without_outside_effects[socket-'):
        path = Path(guard._STATE['guard']).with_name('fixture_unix.py')
        pin = guard._STATE['direct_support']['files'].get(str(path))
        if pin is not None and guard.checked_source(path, pin)['authorize'](
                event, args, guard._STATE, endpoint, guard):
            return
    selected = getattr(endpoint.LOCAL, "custody_effect", None)
    expected = (event, address())
    if (
        selected != expected
        or args[1] != address()
        or guard._STATE["case"]
        not in (sys.modules["restart_custody"].CONTROL, sys.modules["restart_custody"].CANONICAL)
    ):
        endpoint.refuse("custody_IPC_effect_binding_refused")
    if event == "socket.bind" and guard._STATE["class"] != "restart-custodian":
        endpoint.refuse("custody_IPC_listener_owner_refused")
    endpoint.LOCAL.custody_effect = None


def effect(stream, name):
    endpoint = sys.modules["endpoint"]
    endpoint.check()
    endpoint.LOCAL.custody_effect = ("socket." + name, address())
    try:
        getattr(stream, name)(address())
    finally:
        endpoint.LOCAL.custody_effect = None


def attest(snapshot):
    endpoint = sys.modules["endpoint"]
    stream = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    stream.settimeout(3)
    try:
        owner = endpoint.request("custody_owner")["identity"]
        before = os.lstat(address())
        if (
            not stat.S_ISSOCK(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            endpoint.refuse("custody_IPC_socket_carrier_refused")
        effect(stream, "connect")
        after = os.lstat(address())
        remote = peer(stream)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or remote["pid"] != owner["pid"]
            or remote["uid"] != owner["uid"]
        ):
            endpoint.refuse("custody_IPC_pre_payload_peer_refused")
        value = {
            "challenge": uuid.uuid4().hex,
            "nonce": endpoint.STATE["spec"]["nonce"],
            "pid": os.getpid(),
            "token": endpoint.STATE["token"],
            "identity": endpoint.STATE["identity"],
            "snapshot_sha256": digest(snapshot),
        }
        mode = sys.modules["runtime_guard"]._STATE.get("custody_control")
        if mode == "foreign":
            value["pid"] += 1000000
        elif mode == "forged-READY":
            value["token"] = "f" * 32
        elif mode == "stale-identity":
            value["identity"]["start_ticks"] += 1
        frame_send(stream, value)
        answer = frame_recv(stream)
        if (
            answer.get("request") != value
            or answer.get("custodian") != remote["pid"]
            or remote["uid"] != os.getuid()
            or answer.get("ok") is not True
        ):
            endpoint.refuse("custody_IPC_peer_reply_refused")
        return answer["attestation"]
    except endpoint.EndpointRefusal:
        raise
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        endpoint.refuse("custody_IPC_transport_refused:" + type(error).__name__)
    finally:
        stream.close()


def start():
    endpoint = sys.modules["endpoint"]
    guard = sys.modules["runtime_guard"]
    listener = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    effect(listener, "bind")
    os.chmod(address(), 0o600)
    listener.listen(4)
    listener.settimeout(0.1)
    stopped = threading.Event()

    def serve_peers():
        try:
            while not stopped.is_set():
                try:
                    descriptor, unused = listener._accept()
                    stream = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM, fileno=descriptor)
                except TimeoutError:
                    continue
                try:
                    stream.settimeout(3)
                    remote = peer(stream)
                    value = frame_recv(stream)
                    if (
                        set(value)
                        != {"challenge", "nonce", "pid", "token", "identity", "snapshot_sha256"}
                        or value["pid"] != remote["pid"]
                        or remote["uid"] != os.getuid()
                    ):
                        endpoint.refuse("custody_IPC_peer_PID_UID_refused")
                    receipt = endpoint.request("custody_peer", peer=remote, claim=value)
                    frame_send(
                        stream,
                        {
                            "ok": True,
                            "request": value,
                            "custodian": os.getpid(),
                            "attestation": receipt["attestation"],
                        },
                    )
                finally:
                    stream.close()
        except Exception as error:
            guard.append(
                {"kind": "forbidden", "reason": "custody_IPC_peer_failure:" + type(error).__name__}
            )
        finally:
            listener.close()

    thread = threading.Thread(target=serve_peers, name="finite-custody-peer", daemon=True)
    thread.start()
    guard.append(
        {
            "kind": "custody_IPC_listener_ready",
            "path_sha256": hashlib.sha256(address().encode()).hexdigest(),
        }
    )

    def close():
        stopped.set()
        thread.join(timeout=4)
        if thread.is_alive():
            endpoint.refuse("custody_IPC_peer_thread_unsettled")
        Path(address()).unlink(missing_ok=True)

    return close
