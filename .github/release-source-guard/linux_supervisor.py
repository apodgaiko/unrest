"""Linux transport/kernel adapter for the existing finite source policy."""

from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import time
import types

ROOT = Path(__file__).parent / "finite"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observation = load("linux_observation", ROOT.parent / "linux_observation.py")
identities = load("linux_identity", ROOT / "linux_identity.py")
sockets = load("linux_sockets", ROOT.parent / "linux_sockets.py")
receipts = load("linux_receipts", ROOT.parent / "linux_receipts.py")
kernel = types.SimpleNamespace(
    identity=identities.identity, sockets=sockets.sockets, unix_pair=sockets.unix_pair,
    direct_child_inventory=observation.direct_child_inventory
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


class AwaitOwnedPeer(RuntimeError):
    pass


class PendingOwnedListener(RuntimeError):
    pass


class Supervisor:
    def poison(self, reason):
        self.poisoned = True
        if not (self.control / "POISON.json").exists():
            write(
                self.control / "POISON.json",
                {"reason": reason, "nonce": self.spec["endpoint"]["nonce"]},
            )

    def events(self):
        rows = []
        for path in sorted(Path(self.manifest["events"]).glob("*.jsonl")):
            for line in path.read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    def refresh(self):
        events = self.events()
        for event in events:
            if event["kind"] == "forbidden":
                self.poison("finite_guard:" + event["reason"])
            if (
                event["kind"] != "registered"
                or not event.get("python", True)
                or event["pid"] in self.registered
            ):
                continue
            parent = event["owner_pid"]
            if parent not in self.registered:
                continue
            try:
                current = kernel.identity(event["pid"])
                lifecycle = next(
                    (
                        e
                        for e in events
                        if e["kind"] == "launch_lifecycle_binding" and e["token"] == event["token"]
                    )
                )
                expected_group = (
                    current["pid"]
                    if lifecycle["start_new_session"]
                    else self.registered[parent]["identity"]["pgid"]
                )
                if (
                    current["ppid"] != parent
                    or current["uid"] != self.root["uid"]
                    or current["pgid"] != expected_group
                ):
                    raise RuntimeError("child_kernel_custody_refused")
                self.registered[event["pid"]] = {"identity": current, "token": event["token"]}
            except RuntimeError:
                self.poison("registered_child_identity_unavailable")
        return events

    def authenticate(self, request, events):
        if request["nonce"] != self.spec["endpoint"]["nonce"]:
            raise RuntimeError("nonce_refused")
        saved = self.registered.get(request["pid"])
        if saved is None or saved["token"] != request["token"]:
            raise RuntimeError("unregistered_PID_or_token")
        if request.get("identity") is not None and request["identity"] != saved["identity"]:
            raise RuntimeError("stale_or_reused_ownership_claim")
        if kernel.identity(request["pid"]) != saved["identity"]:
            raise RuntimeError("stale_or_reused_ownership")
        ready = next(
            (
                e
                for e in events
                if e["kind"] == "ready"
                and e["owner_pid"] == request["pid"]
                and (e["token"] == request["token"])
            ),
            None,
        )
        if ready is None or any(
            (
                ready[key] != expected
                for key, expected in (
                    ("manifest_sha256", self.manifest_pin),
                    ("guard_sha256", self.manifest["guard_sha256"]),
                    ("registry_sha256", self.manifest["registry"]["sha256"]),
                    ("runtime_sha256", self.manifest["runtime"]["sha256"]),
                )
            )
        ):
            raise RuntimeError("authenticated_READY_missing")
        return saved

    def observe(self, pid):
        saved = self.registered[pid]
        if kernel.identity(pid) != saved["identity"]:
            raise RuntimeError("stale_or_reused_ownership")
        return kernel.sockets(pid)

    def handle(self, request, events):
        if self.poisoned and request.get("kind") not in (
            "custody_close",
            "custody_signal",
            "drain_inventory",
            "drain_child",
            "drain_complete",
        ):
            raise RuntimeError("global_poison_retained")
        self.authenticate(request, events)
        kind = request["kind"]
        if kind.startswith("drain_"):
            events = self.refresh()
            path = ROOT / "drain_host.py"
            if sha(path) != self.spec["pins"][str(path)]:
                raise RuntimeError("drain_host_pin_refused")
            support = {}
            exec(compile(path.read_bytes(), str(path), "exec"), support)
            answer = support["handle"](self, request, events, kernel)
            if answer.pop("pending_actual_wait", False):
                raise AwaitOwnedPeer("actual_parent_wait_record_still_pending")
            return answer
        if kind.startswith("custody_"):
            support = {}
            path = ROOT / "custody_host.py"
            if sha(path) != self.spec["pins"][str(path)]:
                raise RuntimeError("custody_host_pin_refused")
            exec(compile(path.read_bytes(), str(path), "exec"), support)
            try:
                answer = support["handle"](self, request, events)
            except (OSError, ValueError, TypeError, AttributeError) as error:
                raise RuntimeError("custody_bound_input_error:" + type(error).__name__) from error
            if answer.pop("pending", False):
                raise AwaitOwnedPeer("finite_custody_pending")
            return answer
        if kind == "ready":
            return {"identity": self.registered[request["pid"]]["identity"]}
        if kind == "poison":
            raise RuntimeError(request["reason"])
        if kind == "plan":
            if request["host"] != "127.0.0.1" or not 0 < request["port"] < 65536:
                raise RuntimeError("invalid_finite_plan")
            self.plans[request["port"]] = request
            return {"plan_recorded": True, "network_admitted": False}
        if kind == "listen":
            entry = next(
                (s for s in self.observe(request["pid"]) if s["fd"] == request["fd"]), None
            )
            if (
                not entry
                or entry["state"] != 10
                or entry["local_host"] != "127.0.0.1"
                or (entry["local_port"] != request["port"])
                or (request["host"] != "127.0.0.1")
            ):
                raise RuntimeError("listener_kernel_binding_refused")
            self.listeners[entry["local_port"]] = entry
            return {"listener": entry}
        if kind == "connect":
            entry = self.listeners.get(request["port"])
            if request["host"] != "127.0.0.1":
                raise RuntimeError("foreign_or_unregistered_endpoint")
            if entry is None:
                plan = self.plans.get(request["port"])
                if plan is not None:
                    matching = next(
                        (
                            e
                            for e in events
                            if e["kind"] == "admitted"
                            and e["owner_pid"] == plan["pid"]
                            and (e["token"] == plan["child_token"])
                            and (e["argv_sha256"] == plan["argv_sha256"])
                        ),
                        None,
                    )
                    owner = next(
                        (
                            pid
                            for pid, item in self.registered.items()
                            if item["token"] == plan["child_token"]
                        ),
                        None,
                    )
                    if (
                        matching is not None
                        and owner is not None
                        and (kernel.identity(owner) == self.registered[owner]["identity"])
                    ):
                        raise PendingOwnedListener("registered_finite_child_not_listening")
                raise RuntimeError("foreign_or_unregistered_endpoint")
            current = next((s for s in self.observe(entry["pid"]) if s["fd"] == entry["fd"]), None)
            if current != entry:
                raise RuntimeError("listener_closed_or_changed_binding")
            self.connect_admissions[request["pid"], request["fd"]] = current
            return {"listener": current}
        if kind == "connected":
            listener = self.connect_admissions.get((request["pid"], request["fd"]))
            if listener is None:
                raise RuntimeError("connection_without_listener_admission")
            current = next(
                (s for s in self.observe(listener["pid"]) if s["fd"] == listener["fd"]), None
            )
            own = next((s for s in self.observe(request["pid"]) if s["fd"] == request["fd"]), None)
            if (
                current != listener
                or not own
                or own["remote_host"] != "127.0.0.1"
                or (own["remote_port"] != listener["local_port"])
                or (own["state"] not in (2, 3, 1, 8))
            ):
                raise RuntimeError("connected_binding_drift")
            own_key = (
                request["pid"],
                own["socket_cookie"],
                own["inode"],
                own["local_port"],
                own["remote_port"],
            )
            self.connections.add(own_key)
            for peer in self.observe(listener["pid"]):
                if (
                    peer["state"] in (1, 8)
                    and peer["local_host"] == own["remote_host"]
                    and (peer["remote_host"] == own["local_host"])
                    and (peer["local_port"] == own["remote_port"])
                    and (peer["remote_port"] == own["local_port"])
                ):
                    peer_key = (
                        listener["pid"],
                        peer["socket_cookie"],
                        peer["inode"],
                        peer["local_port"],
                        peer["remote_port"],
                    )
                    self.connections.add(peer_key)
                    return {"socket": own, "accepted_peer": peer}
            if listener["pid"] == request["pid"]:
                return {"socket": own, "same_process_listener": listener}
            raise AwaitOwnedPeer("accepted_peer_not_yet_observable")
        if kind == "socketpair":
            pair = kernel.unix_pair(request["pid"], request["fds"])
            self.pairs[request["pid"], tuple(request["fds"])] = pair
            return {"pair": pair}
        if kind == "payload":
            for (pid, descriptors), pair in self.pairs.items():
                if pid == request["pid"] and request["fd"] in descriptors:
                    try:
                        current_pair = kernel.unix_pair(pid, descriptors)
                    except RuntimeError:
                        continue
                    if current_pair == pair:
                        return {"pair": pair}
            retained = sockets.retained_tcp_descriptor(request['pid'], request['fd'])
            if retained is not None and retained['socket_uid'] != self.root['uid']:
                raise RuntimeError('retained_socket_UID_drift')
            binding = sockets.live_binding(retained, self.connections)
            if binding is not None:
                return {'retained_live_socket': retained, 'previous_authenticated_binding': binding}
            binding = sockets.closed_binding(retained, self.connections)
            if binding is not None:
                return {'retained_closed_socket': retained,
                        'previous_authenticated_binding': binding,
                        'closed_descriptor_has_no_peer': True}
            own = next((s for s in self.observe(request["pid"]) if s["fd"] == request["fd"]), None)
            if not own or own["local_host"] != "127.0.0.1" or own["remote_host"] != "127.0.0.1":
                raise RuntimeError("unregistered_payload_socket:" + json.dumps(own, sort_keys=True))
            key = (
                request["pid"],
                own["socket_cookie"],
                own["inode"],
                own["local_port"],
                own["remote_port"],
            )
            if key in self.connections:
                return {"socket": own, "previously_authenticated_connection": True}
            if own["state"] not in (1, 8):
                raise RuntimeError("new_connection_not_established")
            listener = self.listeners.get(own["remote_port"])
            if listener is not None:
                current = next(
                    (s for s in self.observe(listener["pid"]) if s["fd"] == listener["fd"]), None
                )
                if current == listener:
                    self.connections.add(key)
                    return {"socket": own, "listener": listener, "accepted_queue_allowed": True}
            for pid in self.registered:
                try:
                    peers = self.observe(pid)
                except RuntimeError:
                    continue
                for peer in peers:
                    if (
                        peer["state"] in (1, 8)
                        and peer["local_host"] == own["remote_host"]
                        and (peer["remote_host"] == own["local_host"])
                        and (peer["local_port"] == own["remote_port"])
                        and (peer["remote_port"] == own["local_port"])
                    ):
                        self.connections.add(key)
                        return {"socket": own, "peer": peer}
            raise RuntimeError("foreign_or_unregistered_payload_peer")
        raise RuntimeError("unknown_request_kind")

    def __init__(self, spec, child):
        self.spec = spec
        self.manifest_pin = spec["pins"][spec["manifest"]]
        self.child = child
        self.control = Path(spec["endpoint"]["responses"])
        self.manifest = json.loads(Path(spec["manifest"]).read_bytes())
        self.root = kernel.identity(child.pid)
        self.registered = {child.pid: {"identity": self.root, "token": "root"}}
        self.listeners, self.plans, self.pairs = {}, {}, {}
        self.connections = set()
        self.connect_admissions = {}
        self.receipts = []
        self.poisoned = False
        self.ledger = receipts.ReceiptLedger(spec["endpoint"]["nonce"], self.root["uid"], child.pid)
        self.ledger.register(child.pid, "root")
        self.channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.channel.bind(spec["endpoint"]["socket"])
        os.chmod(spec["endpoint"]["socket"], 0o666)
        self.channel.listen(128)
        self.channel.setblocking(False)
        self.clients = {}

    def tick(self):
        events = self.refresh()
        while len(self.clients) < 128:
            try:
                stream, _ = self.channel.accept()
            except BlockingIOError:
                break
            stream.setblocking(False)
            self.clients[stream] = {
                "buffer": bytearray(),
                "started": time.monotonic(),
                "request": None,
                "authenticated": False,
                "output": None,
            }
        for stream, state in list(self.clients.items()):
            try:
                if time.monotonic() - state["started"] > 4:
                    raise RuntimeError("bounded_receipt_channel_timeout")
                if state["request"] is None:
                    try:
                        block = stream.recv(8197 - len(state["buffer"]))
                    except BlockingIOError:
                        continue
                    if not block:
                        raise RuntimeError("receipt_channel_closed_before_request")
                    state["buffer"].extend(block)
                    if len(state["buffer"]) < 4:
                        continue
                    size = struct.unpack("!I", state["buffer"][:4])[0]
                    if not 0 < size <= 8192 or len(state["buffer"]) > size + 4:
                        raise RuntimeError("receipt_frame_size_refused")
                    if len(state["buffer"]) < size + 4:
                        continue

                    def unique(pairs):
                        result = {}
                        for key, value in pairs:
                            if key in result:
                                raise RuntimeError("duplicate_receipt_field")
                            result[key] = value
                        return result

                    state["request"] = json.loads(state["buffer"][4:], object_pairs_hook=unique)
                    if type(state["request"]) is not dict:
                        raise RuntimeError("receipt_object_required")
                request = state["request"]
                if not state["authenticated"]:
                    pid, uid, _ = struct.unpack(
                        "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    if uid != self.root["uid"] or request.get("pid") != pid:
                        raise RuntimeError("kernel_receipt_peer_refused")
                    registered = self.registered.get(pid)
                    if registered is None:
                        continue  # No effect while the parent's registration settles.
                    if pid not in self.ledger.registered:
                        self.ledger.register(pid, registered["token"])
                    state["peer"] = self.ledger.admit(stream, request)
                    state["authenticated"] = True
                if state["output"] is None:
                    try:
                        answer = self.handle(request, events)
                        result = {"ok": True, "request": request, **answer}
                    except AwaitOwnedPeer:
                        continue
                    except PendingOwnedListener as error:
                        result = {
                            "ok": False,
                            "pending_owned_listener": True,
                            "network_admitted": False,
                            "request": request,
                            "reason": str(error),
                        }
                    except (RuntimeError, KeyError, StopIteration) as error:
                        self.poison(str(error))
                        result = {"ok": False, "request": request, "reason": str(error)}
                    result["kernel_peer"] = state["peer"]
                    encoded = json.dumps(result, sort_keys=True).encode()
                    if len(encoded) > 16384:
                        raise RuntimeError("bounded_receipt_response_exceeded")
                    state["output"] = struct.pack("!I", len(encoded)) + encoded
                    self.receipts.append(result)
                try:
                    count = stream.send(state["output"])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise RuntimeError("receipt_channel_write_failed")
                state["output"] = state["output"][count:]
                if not state["output"]:
                    stream.close()
                    del self.clients[stream]
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self.poison(type(error).__name__ + ":" + str(error))
                stream.close()
                del self.clients[stream]

    def close(self):
        for stream in self.clients:
            stream.close()
        self.clients.clear()
        self.channel.close()
