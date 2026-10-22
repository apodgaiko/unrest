"""Separate inherited complementary admission; never a kernel-denial claim."""

import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import stat
import sys
import threading
import time
import uuid
import types

_CONTROL_SOCKET = socket.socket
_CONTROL_CONNECT = socket.socket.connect
_CONTROL_SENDALL = socket.socket.sendall
_CONTROL_RECV = socket.socket.recv
_CONTROL_GETSOCKOPT = socket.socket.getsockopt
_CONTROL_CLOSE = socket.socket.close

STATE = {"ready": False, "poison": False}
LOCAL = threading.local()


class EndpointRefusal(RuntimeError):
    pass


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def request(kind, **values):
    spec = STATE["spec"]
    token = uuid.uuid4().hex
    body = {
        "id": token,
        "kind": kind,
        "nonce": spec["nonce"],
        "pid": os.getpid(),
        "token": STATE.get("token"),
        "identity": STATE.get("identity"),
        **values,
    }
    encoded = json.dumps(body, sort_keys=True).encode()
    if not 0 < len(encoded) <= 8192:
        STATE["poison"] = True
        raise EndpointRefusal("request_size_refused")
    stream = _CONTROL_SOCKET(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(4)
    LOCAL.control_stream = stream
    try:
        _CONTROL_CONNECT(stream, spec["socket"])
        peer_pid, peer_uid, _ = struct.unpack(
            "3i", _CONTROL_GETSOCKOPT(stream, socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if peer_pid != spec["observer_pid"] or peer_uid != spec["observer_uid"]:
            raise EndpointRefusal("observer_kernel_peer_refused")
        _CONTROL_SENDALL(stream, struct.pack("!I", len(encoded)) + encoded)

        def exact(size):
            result = bytearray()
            while len(result) < size:
                block = _CONTROL_RECV(stream, size - len(result))
                if not block:
                    raise EndpointRefusal("receipt_channel_closed")
                result.extend(block)
            return bytes(result)

        length = struct.unpack("!I", exact(4))[0]
        if not 0 < length <= 16384:
            raise EndpointRefusal("response_size_refused")
        answer = json.loads(exact(length))
    except (OSError, ValueError, EndpointRefusal):
        STATE["poison"] = True
        raise
    finally:
        LOCAL.control_stream = None
        _CONTROL_CLOSE(stream)
    if (
        answer.get("request") == body
        and answer.get("pending_owned_listener") is True
        and kind == "connect"
    ):
        raise ConnectionRefusedError(
            errno.ECONNREFUSED, "owned finite child listener not ready; no connect issued"
        )
    if answer.get("request") != body or answer.get("ok") is not True:
        STATE["poison"] = True
        raise EndpointRefusal(answer.get("reason", "receipt_binding_refused"))
    return answer


def refuse(reason):
    STATE["poison"] = True
    request("poison", reason=reason)
    raise EndpointRefusal(reason)


def check():
    if not STATE["ready"]:
        refuse("pre_READY_effect")
    if STATE["poison"] or (Path(STATE["spec"]["responses"]) / "POISON.json").exists():
        raise EndpointRefusal("global_poison_retained")


def approval_unix():
    guard = sys.modules.get('runtime_guard')
    if (guard is None or type(getattr(guard, '_STATE', None)) is not dict
            or not str(guard._STATE.get('case', '')).startswith('tests/test_approval_recovery.py::')
            or 'guard' not in guard._STATE):
        return None
    path = Path(guard._STATE['guard']).with_name('approval_unix.py')
    pin = guard._STATE.get('direct_support', {}).get('files', {}).get(str(path))
    return None if pin is None else guard.checked_source(path, pin)


def approval_unix_receipt(operation, stream):
    support = approval_unix()
    return (support is not None and support['receipt'](
        operation, stream, sys.modules['runtime_guard']._STATE, sys.modules[__name__]))


def audit(event, args):
    if event == "socket.connect":
        stream, address = args
        if stream is getattr(LOCAL, "control_stream", None) and address == STATE["spec"]["socket"]:
            return
    if STATE.get("dependency_window") and event == "exec":
        filename = args[0].co_filename
        checkout = STATE["checkout"]
        if filename.startswith(checkout + "/src/") or filename.startswith(checkout + "/tests/"):
            refuse("product_source_in_dependency_window")
    if event in (
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getnameinfo",
    ):
        check()
        host = args[0][0] if isinstance(args[0], tuple) else args[0]
        if host not in ("127.0.0.1", "localhost"):
            refuse("external_name_resolution")
    if event in (
        "subprocess.Popen",
        "os.exec",
        "os.posix_spawn",
        "os.system",
        "os.fork",
        "os.forkpty",
    ):
        check()
    if event in ("socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg"):
        check()
        stream, address = args[:2]
        if stream.family == socket.AF_UNIX and event in ("socket.bind", "socket.connect"):
            support = approval_unix()
            if support is not None and support['authorize'](
                    event, stream, address, sys.modules['runtime_guard']._STATE,
                    sys.modules[__name__], sys.modules['runtime_guard']):
                return
            return sys.modules["custody_ipc"].authorize(event, args)
        if (
            stream.family != socket.AF_INET
            or stream.type != socket.SOCK_STREAM
            or not isinstance(address, tuple)
            or address[0] != "127.0.0.1"
        ):
            refuse("non_owned_address_class:" + event)
        if event == "socket.bind":
            return  # Original bind0 selection is unchanged; listen is checked separately.
        if event != "socket.connect":
            refuse("datagram_or_unregistered_payload")
        request("connect", fd=stream.fileno(), host=address[0], port=address[1])


def early(spec):
    if "spec" in STATE:
        raise EndpointRefusal("duplicate_endpoint_install")
    STATE["spec"] = spec
    sys.addaudithook(audit)
    closure = json.loads((Path(spec["responses"]) / "HOST-FDS.json").read_bytes())
    if closure["nonce"] != spec["nonce"]:
        refuse("descriptor_closure_nonce_refused")
    controls = {(row["device"], row["inode"], row["type"]) for row in closure["objects"]}
    directory = Path("/proc/self/fd")
    descriptors = sorted(int(path.name) for path in directory.iterdir() if int(path.name) > 2)
    if len(descriptors) >= 4096:
        refuse("own_descriptor_inventory_unavailable_or_unbounded")
    observed = 0
    for descriptor in descriptors:
        try:
            info = os.fstat(descriptor)
        except OSError:
            continue
        observed += 1
        if (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) in controls:
            refuse("ambient_control_descriptor_inherited")
    STATE["descriptor_closure"] = {
        "host_control_objects_absent": True,
        "kernel_inventory_complete": True,
        "inventory_bound": 4096,
        "nonstdio_open_count": observed,
    }
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def connect(stream, address):
        try:
            result = original_connect(stream, address)
        except BlockingIOError:
            if not approval_unix_receipt('connected', stream):
                request("connected", fd=stream.fileno())
            raise
        if not approval_unix_receipt('connected', stream):
            request("connected", fd=stream.fileno())
        return result

    def connect_ex(stream, address):
        result = original_connect_ex(stream, address)
        if result in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            if not approval_unix_receipt('connected', stream):
                request("connected", fd=stream.fileno())
        return result

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    original_setsockopt = socket.socket.setsockopt

    def setsockopt(stream, level, option, *values):
        if level == socket.SOL_SOCKET and option == socket.SO_REUSEPORT:
            refuse("shared_listener_binding_refused")
        return original_setsockopt(stream, level, option, *values)

    socket.socket.setsockopt = setsockopt
    original_pair = socket.socketpair

    def socketpair(*args, **kwargs):
        left = right = None
        try:
            check()
            left, right = original_pair(*args, **kwargs)
            request("socketpair", fds=[left.fileno(), right.fileno()])
            return left, right
        except BaseException:
            # A rejected receipt must not strand sockets in retained tracebacks.
            for stream in (left, right):
                if stream is not None:
                    _CONTROL_CLOSE(stream)
            release = STATE.get("failed_loop_release")
            if release is not None:
                release(sys._getframe(1))
            raise

    socket.socketpair = socketpair
    original_listen = socket.socket.listen
    original_send = socket.socket.send
    original_sendall = socket.socket.sendall
    original_recv = socket.socket.recv
    original_recv_into = socket.socket.recv_into

    def listen(stream, backlog=128):
        check()
        if stream.family == socket.AF_UNIX:
            support = approval_unix()
            if support is not None and support['bound'](stream, sys.modules['runtime_guard']._STATE) is not None:
                original_listen(stream, backlog)
                if not approval_unix_receipt('listen', stream):
                    refuse('approval_unix_listener_unregistered')
                return
        if stream.family != socket.AF_INET or stream.type != socket.SOCK_STREAM:
            refuse("listener_address_class")
        address = stream.getsockname()
        if address[0] != "127.0.0.1":
            refuse("listener_bind_drift")
        original_listen(stream, backlog)
        request("listen", fd=stream.fileno(), host=address[0], port=address[1])

    def payload(stream):
        check()
        if approval_unix_receipt('payload', stream):
            return
        if getattr(LOCAL, "checking", False):
            return
        LOCAL.checking = True
        try:
            request("payload", fd=stream.fileno())
        finally:
            LOCAL.checking = False

    def send(stream, *args, **kwargs):
        payload(stream)
        return original_send(stream, *args, **kwargs)

    def sendall(stream, *args, **kwargs):
        payload(stream)
        return original_sendall(stream, *args, **kwargs)

    def recv(stream, *args, **kwargs):
        payload(stream)
        return original_recv(stream, *args, **kwargs)

    def recv_into(stream, *args, **kwargs):
        payload(stream)
        return original_recv_into(stream, *args, **kwargs)

    socket.socket.listen = listen
    socket.socket.send = send
    socket.socket.sendall = sendall
    socket.socket.recv = recv
    socket.socket.recv_into = recv_into


def attach(guard):
    original_install = guard.install
    original_bootstrap = guard.bootstrap
    spec = STATE["spec"]
    actual_waitpid = os.waitpid
    decoder_path = Path(__file__).resolve().parent.parent / 'journal_decode.py'
    decoder_body = decoder_path.read_bytes()
    if hashlib.sha256(decoder_body).hexdigest() != '0c5b90ad9ef52e88771caba513c9199d5b71e60da72de275090b8bcc9c9621f6':
        raise EndpointRefusal('journal_decoder_source_drift')
    decoder_namespace = {'__file__': str(decoder_path), '__name__': '_wait_journal_decode'}
    exec(compile(decoder_body, str(decoder_path), 'exec'), decoder_namespace)
    wait_decoder = decoder_namespace['JournalDecoder']()

    def observed_waitpid(pid, options):
        result = actual_waitpid(pid, options)
        if result[0] and guard._STATE is not None:
            state = guard._STATE
            journal = Path(state["events"]) / (str(os.getpid()) + ".jsonl")
            records = wait_decoder.decode(str(journal), journal.read_bytes())
            registration = next(
                (
                    event
                    for event in reversed(records)
                    if event["kind"] == "registered"
                    and event["owner_pid"] == os.getpid()
                    and event["pid"] == result[0]
                ),
                None,
            )
            guard.append(
                {
                    "kind": "raw_actual_parent_waitpid",
                    "pid": result[0],
                    "requested_pid": pid,
                    "options": options,
                    "raw_status": result[1],
                    "numeric_returncode": os.waitstatus_to_exitcode(result[1]),
                    "nonce": spec["nonce"],
                    "owner_token": state["token"],
                    "owner_identity": STATE.get("identity"),
                    "child_token": registration["token"] if registration else None,
                    "wait_event": "actual_os_waitpid_return",
                }
            )
        return result

    os.waitpid = observed_waitpid

    def install(*args, **kwargs):
        STATE["ready"] = False
        original_install(*args, **kwargs)
        multiprocess_path = Path(guard._STATE['guard']).with_name('multiprocess_routes.py')
        if str(multiprocess_path) in guard._STATE['direct_support']['files']:
            if '_owned_multiprocess_hook' not in guard._STATE:
                support = guard.checked_source(multiprocess_path,
                    guard._STATE['direct_support']['files'][str(multiprocess_path)])
                guard._STATE['_owned_multiprocess_hook'] = support['install'](
                    guard._STATE, guard.append, guard.refuse, guard.require_ready,
                    guard.bootstrap, guard.inherited_environment)
            else:
                from multiprocessing import util
                if util.spawnv_passfds is not guard._STATE['_owned_multiprocess_hook']:
                    guard.refuse('multiprocess_installed_hook_drift')
        guard.append({"kind": "descriptor_closure", **STATE["descriptor_closure"]})
        STATE["token"] = guard._STATE["token"]
        answer = request("ready")
        STATE["identity"] = answer["identity"]
        setup_path = Path(guard._STATE['guard']).with_name('mock_backend_setup.py')
        setup = guard.checked_source(setup_path, guard._STATE['direct_support']['files'][str(setup_path)])
        inapplicable = setup['select'](guard, STATE)
        if inapplicable is None and guard._STATE.get('class') in {
                'source-approval-adapter', 'source-approval-relay', 'source-approval-python-backend'}:
            approval_path = Path(guard._STATE['guard']).with_name('approval_json_setup.py')
            approval = guard.checked_source(approval_path,
                guard._STATE['direct_support']['files'][str(approval_path)])
            inapplicable = approval['select'](guard, STATE)
        if inapplicable is None and guard._STATE.get('class') == 'source-run-worker':
            worker_path = Path(guard._STATE['guard']).with_name('approval_worker_setup.py')
            worker = guard.checked_source(worker_path,
                guard._STATE['direct_support']['files'][str(worker_path)])
            inapplicable = worker['select'](guard, STATE)
        if inapplicable is not None:
            guard.append(inapplicable)
        else:
            # Source role policy intentionally filters FASTMCP_* environment names.
            # Configure only the supported optional banner check, in every inherited
            # process, after identity/READY and before any product body or payload.
            environment = dict(os.environ)
            saved_path = list(sys.path)
            saved_profile = sys.getprofile()
            saved_thread_profile = threading.getprofile()
            diagnostic = guard._STATE.get("setup_mode") == "profile-timing"
            stats = {"calls": 0, "observer_seconds": 0.0, "product_or_test_frames": 0}

            def measured(frame, event, value):
                started = time.perf_counter()
                try:
                    return saved_profile(frame, event, value)
                finally:
                    stats["calls"] += 1
                    stats["observer_seconds"] += time.perf_counter() - started
                    if frame.f_code.co_filename.startswith(
                        guard._STATE["checkout"] + "/src/"
                    ) or frame.f_code.co_filename.startswith(guard._STATE["checkout"] + "/tests/"):
                        stats["product_or_test_frames"] += 1

            STATE["checkout"] = guard._STATE["checkout"]
            STATE["dependency_window"] = True
            started = time.perf_counter()
            if diagnostic:
                sys.setprofile(measured)
                threading.setprofile(measured)
            else:
                # The observer measured 3.27M callbacks / 3.04s in a dependency-only
                # window with zero product/test frames. Audit hooks, finite Popen
                # admission and the no-source/pre-READY barriers stay active.
                sys.setprofile(None)
                threading.setprofile(None)
            try:
                mode = guard._STATE.get("setup_mode")
                if mode == "dependency-source-negative":
                    exec(
                        compile(
                            'raise AssertionError("uncontained source body")',
                            guard._STATE["checkout"] + "/src/unrest_harness/server.py",
                            "exec",
                        ),
                        {},
                    )
                if mode == "dependency-launch-negative":
                    import subprocess

                    subprocess.Popen(["/usr/bin/true"])
                sys.path.insert(
                    0, "/opt/deps/lib/python3.13/site-packages"
                )
                import fastmcp
                from fastmcp.utilities.version_check import check_for_newer_version

                fastmcp.settings.check_for_updates = "off"
                assert check_for_newer_version() is None
            finally:
                sys.path[:] = saved_path
                STATE["dependency_window"] = False
                sys.setprofile(saved_profile)
                threading.setprofile(saved_thread_profile)
            if diagnostic:
                guard.append(
                    {
                        "kind": "dependency_profile_timing",
                        "wall_seconds": time.perf_counter() - started,
                        **stats,
                    }
                )
            else:
                guard.append(
                    {
                        "kind": "bounded_dependency_window",
                        "wall_seconds": time.perf_counter() - started,
                        "profile_restored": sys.getprofile() is saved_profile,
                        "thread_profile_restored": threading.getprofile() is saved_thread_profile,
                        "source_execution_barrier": True,
                        "finite_audit_and_constructor_enforcement": True,
                    }
                )
            if dict(os.environ) != environment:
                refuse("dependency_configuration_environment_drift")
            guard.append(
                {
                    "kind": "dependency_offline_configuration",
                    "setting": "check_for_updates=off",
                    "module": fastmcp.__file__,
                    "module_sha256": digest(fastmcp.__file__),
                    "environment_unchanged": True,
                    "sys_path_restored": True,
                }
            )
        lifetime = Path(__file__).with_name("descriptor_lifetime.py")
        lifetime_pin = guard._STATE["direct_support"]["files"][str(lifetime)]
        release, pins = guard.checked_source(lifetime, lifetime_pin)["prepare"]()
        STATE["failed_loop_release"] = release
        guard.append({"kind": "descriptor_lifetime_binding", "support_sha256": lifetime_pin,
                      "runtime_sources": pins, "ownership": "unreturned default loop only"})
        STATE["ready"] = True
        if "inventory_image" in guard._STATE:
            image_hook = Path(__file__).with_name("inventory_image.py")
            if digest(image_hook) != guard._STATE["direct_support"]["files"][str(image_hook)]:
                refuse("inventory_image_support_pin")
            image_module = types.ModuleType("inventory_image")
            image_module.__file__ = str(image_hook)
            exec(compile(image_hook.read_bytes(), str(image_hook), "exec"), image_module.__dict__)
            image_module.install(guard, guard._STATE["inventory_image"])
        hook = Path(__file__).with_name("restart_custody.py")
        module = types.ModuleType("restart_custody")
        module.__file__ = str(hook)
        if digest(hook) != guard._STATE["direct_support"]["files"][str(hook)]:
            refuse("custody_support_pin_refused")
        sys.modules["restart_custody"] = module
        exec(compile(hook.read_bytes(), str(hook), "exec"), module.__dict__)
        ipc_path = hook.with_name("custody_ipc.py")
        ipc = types.ModuleType("custody_ipc")
        ipc.__file__ = str(ipc_path)
        if digest(ipc_path) != guard._STATE["direct_support"]["files"][str(ipc_path)]:
            refuse("custody_IPC_pin_refused")
        sys.modules["custody_ipc"] = ipc
        exec(compile(ipc_path.read_bytes(), str(ipc_path), "exec"), ipc.__dict__)
        module.install(guard, sys.modules[__name__])
        drain_path = hook.with_name("preexit_drain.py")
        if digest(drain_path) != guard._STATE["direct_support"]["files"][str(drain_path)]:
            refuse("preexit_support_pin_refused")
        drain = types.ModuleType("preexit_drain")
        drain.__file__ = str(drain_path)
        sys.modules["preexit_drain"] = drain
        exec(compile(drain_path.read_bytes(), str(drain_path), "exec"), drain.__dict__)
        drain.install(guard, sys.modules[__name__])
        # The core READY record precedes endpoint authentication and setup.
        # Parents may proceed only after this child has completed both.
        guard.append({
            "kind": "endpoint_install_complete",
            "token": STATE["token"],
            "nonce": spec["nonce"],
            "identity": STATE["identity"],
            "manifest_sha256": guard._STATE["pin"],
            "guard_sha256": guard._STATE["guard_sha256"],
        })

    def bootstrap(*args, **kwargs):
        text = original_bootstrap(*args, **kwargs)
        payload = args[4]
        vector = payload.get("orig_argv", [])
        support = Path(guard._STATE['guard']).with_name('negative_startup.py')
        guard.checked_source(support, guard._STATE['direct_support']['files'][str(support)])[
            'plan'](guard, payload, request)
        if "--host" in vector and "--port" in vector:
            host = vector[vector.index("--host") + 1]
            port = int(vector[vector.index("--port") + 1])
            if host != "127.0.0.1" or not 0 < port < 65536:
                refuse("finite_child_endpoint_plan_refused")
            request(
                "plan",
                host=host,
                port=port,
                child_token=payload["token"],
                argv_sha256=hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
            )
        marker = "g.child("
        if text.count(marker) != 1:
            refuse("bootstrap_composition_shape_drift")
        path = Path(__file__)
        pin = digest(path)
        prefix = (
            "import hashlib,types,sys;from pathlib import Path;"
            f"_ep_path=Path({str(path)!r});_ep_data=_ep_path.read_bytes();"
            f"assert hashlib.sha256(_ep_data).hexdigest()=={pin!r};"
            '_ep=types.ModuleType("endpoint");_ep.__file__=str(_ep_path);sys.modules["endpoint"]=_ep;'
            'exec(compile(_ep_data,str(_ep_path),"exec"),_ep.__dict__);'
            f"_ep.early({spec!r})\n"
        )
        return prefix + text.replace(marker, "_ep.attach(g);g.child(")

    guard.install = install
    guard.bootstrap = bootstrap
