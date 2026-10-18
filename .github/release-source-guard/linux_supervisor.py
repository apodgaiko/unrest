"""Linux transport/kernel adapter for the existing finite source policy."""

from __future__ import annotations
import __future__
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import stat
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
        diagnostic_refresh_wall = time.monotonic_ns()
        diagnostic_refresh_cpu = time.process_time_ns()
        events = self.events()
        for event in events:
            if event['kind'] in {'admitted', 'actual_launch_binding', 'ready', 'source_entry',
                                 'test_outcome', 'actual_parent_preexit_drain', 'custody_IPC_listener_ready', 'custodian_stage'}:
                marker = tuple(event.get(key) for key in ('owner_pid', 'kind', 'token', 'pid',
                                                          'phase', 'outcome', 'class'))
                if marker not in self.timed_events:
                    self.timed_events.add(marker)
                    self.event_timings.append({'event_sha256': hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest(), 'event': event,
                                               'observed_monotonic': time.monotonic()})
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
        self.diagnostic_schedule["refresh_wall_ns"] += time.monotonic_ns() - diagnostic_refresh_wall
        self.diagnostic_schedule["refresh_cpu_ns"] += time.process_time_ns() - diagnostic_refresh_cpu
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
        pins = saved.get('ready_pins', {
            'manifest_sha256': self.manifest_pin,
            'guard_sha256': self.manifest['guard_sha256'],
            'registry_sha256': self.manifest['registry']['sha256'],
            'runtime_sha256': self.manifest['runtime']['sha256'],
        })
        if ready is None or any(ready[key] != expected for key, expected in pins.items()):
            raise RuntimeError("authenticated_READY_missing")
        return saved

    def observe(self, pid):
        saved = self.registered[pid]
        if kernel.identity(pid) != saved["identity"]:
            raise RuntimeError("stale_or_reused_ownership")
        return kernel.sockets(pid)

    def custody_support(self):
        # Only the code object survives. Each request receives fresh policy globals.
        path = ROOT / "custody_host.py"
        started = time.monotonic()
        if not hasattr(self, 'pure_phases'):
            self.pure_phases = {key: 0 for key in (
                'support_reads', 'support_compiles', 'source_reads', 'source_derivations',
                'support_read_seconds', 'support_compile_seconds',
                'source_read_seconds', 'source_derivation_seconds',
                'support_exec_seconds', 'snapshot_durable_seconds', 'custody_handler_seconds')}
        phases = self.pure_phases
        phases['support_reads'] += 1
        if path.resolve() != path:
            raise RuntimeError('custody_host_path_refused')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                body = stream.read()
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        def identity(info):
            return tuple(getattr(info, key) for key in (
                'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        carrier = identity(before)
        pin = self.spec['pins'][str(path)]
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or carrier != identity(after) or carrier != identity(path.lstat())
                or len(body) != before.st_size or hashlib.sha256(body).hexdigest() != pin):
            raise RuntimeError('custody_host_pin_refused')
        phases['support_read_seconds'] += time.monotonic() - started
        flags = __future__.annotations.compiler_flag
        key = (str(path), pin, carrier, 'exec', flags, -1, 'custody-code-v1')
        saved = getattr(self, '_custody_code', None)
        if saved is not None and saved[0] != key:
            raise RuntimeError('custody_host_identity_refused')
        if saved is None:
            started = time.monotonic()
            code = compile(body, str(path), 'exec', flags=flags, dont_inherit=True, optimize=-1)
            self._custody_code = (key, code)
            phases['support_compiles'] += 1
            phases['support_compile_seconds'] += time.monotonic() - started
        support = {}
        started = time.monotonic()
        exec(self._custody_code[1], support)
        phases['support_exec_seconds'] += time.monotonic() - started
        return support

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
        if kind == 'source_response_output':
            callback = getattr(self, 'source_response_output', None)
            if callback is None:
                raise RuntimeError('source_response_observer_missing')
            return callback(request)
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
            support = self.custody_support()
            started = time.monotonic()
            try:
                answer = support["handle"](self, request, events)
            except (OSError, ValueError, TypeError, AttributeError) as error:
                raise RuntimeError("custody_bound_input_error:" + type(error).__name__) from error
            finally:
                self.pure_phases['custody_handler_seconds'] += time.monotonic() - started
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
            server_sockets = self.observe(listener["pid"])
            current = next(
                (s for s in server_sockets if s["fd"] == listener["fd"]), None
            )
            own = next((s for s in self.observe(request["pid"]) if s["fd"] == request["fd"]), None)
            if (
                not own
                or own["remote_host"] != "127.0.0.1"
                or (own["remote_port"] != listener["local_port"])
                or (own["state"] not in (2, 3, 1, 8))
            ):
                raise RuntimeError("connected_binding_drift:" + json.dumps({"admitted_listener": listener, "current_listener": current, "connecting_socket": own}, sort_keys=True))
            accepted = sockets.reciprocal_peer(listener, own, server_sockets)
            # A one-shot listener can close after accept. Its exact kernel peer
            # in the same birth-bound server is then the surviving authority.
            if current != listener and accepted is None:
                raise RuntimeError("closed_listener_without_owned_accepted_peer")
            own_key = (
                request["pid"],
                own["socket_cookie"],
                own["inode"],
                own["local_port"],
                own["remote_port"],
            )
            self.connections.add(own_key)
            if accepted is not None:
                peer_key = (
                    listener["pid"], accepted["socket_cookie"], accepted["inode"],
                    accepted["local_port"], accepted["remote_port"],
                )
                self.connections.add(peer_key)
                return {"socket": own, "accepted_peer": accepted,
                        "listener_still_open": current == listener}
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
                        retained_pair_member = sockets.retained_unix_member(pid, request['fd'], pair)
                        if retained_pair_member is not None:
                            return {'retained_unix_pair_member': retained_pair_member,
                                    'previous_authenticated_pair': pair}
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
        self.timed_events = set()
        self.event_timings = []
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
        self.channel_diagnostics = []
        self.channel_diagnostic_hash = hashlib.sha256()
        self.channel_diagnostic_summary = {'records': 0, 'successful_completions': 0,
                                           'aggregated_successful_completions': 0,
                                           'sample_ordinals': [], 'last_successful_completion': None}
        self.diagnostic_schedule = {"refresh_wall_ns": 0, "refresh_cpu_ns": 0,
                                    "tick_wall_ns": 0, "tick_cpu_ns": 0,
                                    "last_tick_ns": 0, "max_tick_gap_ns": 0}
        self.tick_count = 0
        self.event_count = 0
        self.trace_progress = {}

    def channel_snapshot(self, state, outcome):
        request = state['request'] if type(state['request']) is dict else {}
        kind = request.get('kind')
        known = {'ready', 'poison', 'plan', 'listen', 'connect', 'connected',
                 'socketpair', 'payload', 'custody_owner', 'custody_peer',
                 'custody_submit', 'custody_close', 'custody_poll', 'custody_spawned', 'source_response_output',
                 'custody_signal', 'custody_cancel', 'drain_inventory', 'drain_child',
                 'drain_complete'}
        saved = self.registered.get(state.get('peer_pid'))
        now = time.monotonic()
        return {'kind': kind if isinstance(kind, str) and kind in known else 'unknown',
                'unknown_kind_sha256': (hashlib.sha256(json.dumps(kind, sort_keys=True).encode()).hexdigest()
                                        if kind is not None and (not isinstance(kind, str) or kind not in known) else None),
                'frame_bytes': len(state['buffer']),
                'declared_size': (struct.unpack('!I', state['buffer'][:4])[0]
                                  if len(state['buffer']) >= 4 else None),
                'received': state['request'] is not None,
                'authenticated': state['authenticated'],
                'output_pending': state['output'] is not None and bool(state['output']),
                'accepted_monotonic': state['started'], 'finished_monotonic': now,
                'elapsed': now - state['started'],
                'peer_pid': state.get('peer_pid'), 'peer_uid': state.get('peer_uid'),
                'registered_peer_birth': saved['identity'] if saved else None,
                'pending_reason': state['pending_reason'], 'outcome': outcome,
                'tick_count': self.tick_count, 'accepted_tick': state['accepted_tick'],
                'event_count': self.event_count, 'trace_progress': dict(self.trace_progress),
                'policy_attempts': state.get('policy_attempts', 0),
                'policy_seconds': state.get('policy_seconds', 0),
                'pure_phases': dict(getattr(self, 'pure_phases', {})),
                'diagnostic_schedule': dict(getattr(self, 'diagnostic_schedule', {}))}

    def record_channel_diagnostic(self, state, outcome):
        # ReceiptLedger admission, policy answers and self.receipts remain full.
        # Only the redundant successful-send timing snapshots are sampled.
        row = self.channel_snapshot(state, outcome)
        summary = self.channel_diagnostic_summary
        ordinal = summary['records']
        encoded = json.dumps(row, sort_keys=True).encode()
        self.channel_diagnostic_hash.update(len(encoded).to_bytes(8, 'big'))
        self.channel_diagnostic_hash.update(encoded)
        summary['records'] += 1
        successful = outcome == 'complete' and state.get('diagnostic_success') is True
        if successful:
            summary['successful_completions'] += 1
            summary['last_successful_completion'] = {'ordinal': ordinal, 'snapshot': row}
        if successful and summary['successful_completions'] > 128:
            summary['aggregated_successful_completions'] += 1
        else:
            self.channel_diagnostics.append(row)
            summary['sample_ordinals'].append(ordinal)

    def diagnostic_summary(self):
        return {**self.channel_diagnostic_summary,
                'sequence_sha256': self.channel_diagnostic_hash.hexdigest(),
                'successful_completion_sample_limit': 128}

    def tick(self):
        diagnostic_tick_wall = time.monotonic_ns()
        diagnostic_tick_cpu = time.process_time_ns()
        self.diagnostic_schedule["max_tick_gap_ns"] = max(
            self.diagnostic_schedule["max_tick_gap_ns"],
            diagnostic_tick_wall - (self.diagnostic_schedule["last_tick_ns"] or diagnostic_tick_wall))
        self.diagnostic_schedule["last_tick_ns"] = diagnostic_tick_wall
        self.tick_count += 1
        events = self.refresh()
        self.event_count = len(events)
        while len(self.clients) < 128:
            try:
                stream, _ = self.channel.accept()
            except BlockingIOError:
                break
            stream.setblocking(False)
            self.clients[stream] = {
                "pending_reason": "frame",
                "accepted_tick": self.tick_count,
                "policy_attempts": 0,
                "policy_seconds": 0,
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
                    state["peer_pid"], state["peer_uid"] = pid, uid
                    if uid != self.root["uid"] or request.get("pid") != pid:
                        raise RuntimeError("kernel_receipt_peer_refused")
                    registered = self.registered.get(pid)
                    if registered is None:
                        state["pending_reason"] = "peer_registration"
                        continue  # No effect while the parent's registration settles.
                    if pid not in self.ledger.registered:
                        self.ledger.register(pid, registered["token"])
                    state["peer"] = self.ledger.admit(stream, request)
                    state["authenticated"] = True
                    state["pending_reason"] = "policy"
                if state["output"] is None:
                    policy_started = time.monotonic()
                    state['policy_attempts'] += 1
                    try:
                        answer = self.handle(request, events)
                        result = {"ok": True, "request": request, **answer}
                    except AwaitOwnedPeer as error:
                        state["pending_reason"] = (str(error) if str(error) in {
                            "actual_parent_wait_record_still_pending", "finite_custody_pending"}
                            else "owned_peer")
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
                    finally:
                        state['policy_seconds'] += time.monotonic() - policy_started
                    result['observer_timing'] = {'accepted_monotonic': state['started'],
                                                 'finished_monotonic': time.monotonic()}
                    result["kernel_peer"] = state["peer"]
                    encoded = json.dumps(result, sort_keys=True).encode()
                    if len(encoded) > 16384:
                        raise RuntimeError("bounded_receipt_response_exceeded")
                    state["output"] = struct.pack("!I", len(encoded)) + encoded
                    self.receipts.append(result)
                    state['diagnostic_success'] = (result.get('ok') is True
                                                   and not result.get('pending_owned_listener', False))
                    state["pending_reason"] = "output"
                try:
                    count = stream.send(state["output"])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise RuntimeError("receipt_channel_write_failed")
                state["output"] = state["output"][count:]
                if not state["output"]:
                    self.record_channel_diagnostic(state, "complete")
                    stream.close()
                    del self.clients[stream]
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                self.record_channel_diagnostic(state, "refused")
                self.poison(type(error).__name__ + ":" + str(error))
                stream.close()
                del self.clients[stream]

        self.diagnostic_schedule["tick_wall_ns"] += time.monotonic_ns() - diagnostic_tick_wall
        self.diagnostic_schedule["tick_cpu_ns"] += time.process_time_ns() - diagnostic_tick_cpu

    def close(self):
        for stream, state in self.clients.items():
            self.record_channel_diagnostic(state, "closed")
            stream.close()
        self.clients.clear()
        self.channel.close()
