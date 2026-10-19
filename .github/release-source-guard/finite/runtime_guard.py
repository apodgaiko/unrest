"""Finite source-test child guard. This is test setup, not OS confinement."""

from __future__ import annotations

import atexit
import ast
import ctypes
import hashlib
import json
import inspect
import importlib.util
import os
import re
from pathlib import Path
import runpy
import signal
import shutil
import subprocess
import sys
import threading
import time
import types
import uuid
import weakref


diagnostic_seen = set()
diagnostic_phases = frozenset(['activation_begin', 'activation_end', 'admit_begin', 'admit_cohort_support_end', 'admit_direct_begin', 'admit_direct_end', 'admit_end', 'admit_enter', 'admit_fixed_support_end', 'admit_native_end', 'anchor_begin', 'anchor_end', 'bootstrap_end', 'fresh_support_begin', 'fresh_support_end', 'inner_enter', 'inner_return', 'operation_input_files_end', 'operation_input_trees_end', 'operation_inputs_enter', 'ordinary_direct_begin', 'ordinary_enter', 'ordinary_owner_begin', 'ordinary_reresolve_begin', 'ordinary_reresolve_end', 'original_init_begin', 'original_init_end', 'shared_absent_end', 'shared_enter', 'shared_files_end', 'shared_inputs_end', 'shared_link_end', 'shared_ready_end', 'shared_trees_end'])


def _diagnostic_mark(phase):
    """Closed, body-free phase observations; never consumed by admission."""
    if phase not in diagnostic_phases:
        raise ValueError('unknown startup diagnostic phase')
    diagnostic_key = (os.getpid(), phase)
    if diagnostic_key in diagnostic_seen:
        return
    diagnostic_seen.add(diagnostic_key)
    import resource
    usage = resource.getrusage(resource.RUSAGE_SELF)
    frame = sys._getframe(1)
    event = {
        "kind": "startup_phase", "phase": phase,
        "monotonic_ns": time.monotonic_ns(),
        "process_cpu_ns": time.process_time_ns(),
        "thread_cpu_ns": time.thread_time_ns(),
        "thread_id": threading.get_ident(),
        "function_code_sha256": hashlib.sha256(frame.f_code.co_code).hexdigest(),
        "location_sha256": hashlib.sha256(
            (frame.f_code.co_filename + ":" + frame.f_code.co_qualname).encode()
        ).hexdigest(),
        "voluntary_switches": usage.ru_nvcsw,
        "involuntary_switches": usage.ru_nivcsw,
        "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
        "block_inputs": usage.ru_inblock, "block_outputs": usage.ru_oublock,
    }
    del frame
    append(event)


def inherited_environment():
    # execve inherits libc's environment, which native dependencies can change
    # without updating os.environ. Bind those actual bytes rather than a cache.
    rows = ctypes.POINTER(ctypes.c_char_p).in_dll(ctypes.CDLL(None), "environ")
    result = {}
    for index in range(4096):
        row = rows[index]
        if row is None:
            return result
        key, separator, value = os.fsdecode(row).partition("=")
        if not separator or not key or key in result:
            refuse("invalid_native_inherited_environment")
        result[key] = value
    refuse("unbounded_native_inherited_environment")

# Capture before product imports can patch the shared os module. The journal
# keeps its append protocol; atomic replacement users retain their own custody.
_JOURNAL_OPEN = os.open
_JOURNAL_WRITE = os.write
_JOURNAL_FSYNC = os.fsync
_JOURNAL_CLOSE = os.close
_JOURNAL_REPLACE = os.replace
_ORIGINAL_SYSTEM = os.system
_ORIGINAL_RUN = subprocess.run

_STATE = None
_LOCAL = threading.local()


class GuardRefusal(RuntimeError):
    """An already journaled refusal, including when an original caller catches it."""


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def append(event):
    state = _STATE
    event = {
        "owner_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "case": state.get("case"),
        **event,
    }
    path = Path(state["events"]) / (str(os.getpid()) + ".jsonl")
    data = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if state.get("journal_failed"):
        raise OSError("finite guard journal durability previously failed")
    try:
        fd = _JOURNAL_OPEN(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = _JOURNAL_WRITE(fd, view)
                if written <= 0:
                    raise OSError("incomplete finite guard record")
                view = view[written:]
            _JOURNAL_FSYNC(fd)
        finally:
            _JOURNAL_CLOSE(fd)
        directory = _JOURNAL_OPEN(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            _JOURNAL_FSYNC(directory)
        finally:
            _JOURNAL_CLOSE(directory)
    except OSError:
        state["journal_failed"] = True
        raise


_CHECKED_CODE_CACHE: dict[tuple[str, str], types.CodeType] = {}


def checked_source(path, pin):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != pin:
        raise RuntimeError("finite checked-source drift")
    namespace = {"__name__": "_finite_support", "__file__": str(path)}
    key = (str(path), pin)
    if key not in _CHECKED_CODE_CACHE:
        _CHECKED_CODE_CACHE[key] = compile(data, str(path), "exec")
    exec(_CHECKED_CODE_CACHE[key], namespace)
    return namespace


def require_ready(token):
    if _STATE is None or _STATE.get("phase") != "READY" or _STATE.get("token") != token:
        if _STATE is not None:
            refuse("finite_guard_installation_not_READY")
        raise RuntimeError("finite guard installation not READY")
    for support in _STATE.get("source_only_support", []):
        source = Path(support)
        if source.with_suffix(".pyc").exists() or list(
            (source.parent / "__pycache__").glob(source.stem + ".*.pyc")
        ):
            refuse("source_only_support_cache_poison")
    expected = _STATE["ready_record"]
    path = Path(_STATE["events"]) / (str(os.getpid()) + ".jsonl")
    with path.open() as stream:
        present = any(json.loads(line) == expected for line in stream)
    if not present:
        refuse("finite_durable_READY_missing")
    if digest(_STATE["guard"]) != expected["guard_sha256"]:
        refuse("ready_guard_source_drift")
    if digest(_STATE["registry"]["path"]) != expected["registry_sha256"]:
        refuse("ready_registry_source_drift")
    isolated = _STATE.get("isolated_support")
    if isolated is not None:
        for key, pin_key in [
            ("path", "sha256"),
            ("inputs_path", "inputs_sha256"),
            ("spec_path", "spec_sha256"),
        ]:
            if digest(isolated[key]) != isolated[pin_key]:
                refuse("ready_isolated_support_drift")
    activation = _STATE.get("activation_support")
    if activation is not None:
        if (
            digest(activation["path"]) != activation["sha256"]
            or digest(activation["spec_path"]) != activation["spec_sha256"]
        ):
            refuse("ready_activation_support_drift")
        if _STATE.get("operation_activation") is not _STATE.get("activation_owner"):
            refuse("ready_activation_callback_replaced")
    support = _STATE.get("operation_support")
    if support is not None:
        owner = _STATE.get('operations')
        method = getattr(owner, 'profile', None)
        if (owner is not _STATE.get('operation_profile_owner')
                or getattr(method, '__func__', None) is not _STATE.get('operation_profile_function')
                or method.__func__.__code__ is not _STATE.get('operation_profile_code')
                or method.__func__.__globals__ is not _STATE.get('operation_profile_globals')
                or _STATE.get('operation_profile_sources') != frozenset(
                    method.__func__.__globals__['SOURCE_FRAME_PATHS'])):
            refuse('ready_operation_profile_replaced')
        if (
            digest(support["path"]) != support["sha256"]
            or digest(support["spec_path"]) != support["spec_sha256"]
        ):
            refuse("ready_operation_support_drift")
    for path, pin in _STATE["direct_support"]["files"].items():
        if digest(path) != pin:
            refuse("ready_support_source_drift")


def refuse(reason):
    append({"kind": "forbidden", "reason": reason})
    # Publish before returning to a caller that may catch the local refusal.
    endpoint = sys.modules.get("endpoint")
    if endpoint is not None and _STATE is not None:
        try:
            endpoint.request("poison", reason=reason, token=_STATE["token"])
        except Exception:
            pass  # The protected observer retains a rejected poison request too.
    raise GuardRefusal("finite source guard: " + reason)


def owned(value):
    try:
        path = Path(value)
        root = Path(_STATE["owned_root"])
        return (
            path.is_absolute()
            and ".." not in path.parts
            and path.resolve().is_relative_to(root)
            and path != root
        )
    except (TypeError, ValueError, OSError):
        return False


def match_arg(actual, expected):
    if isinstance(expected, str):
        return actual == expected
    if set(expected) == {"source_http_port"}:
        # The value comes from the byte-bound source helper, never from a
        # caller-provided port range or digest.
        frame = inspect.currentframe()
        try:
            while frame:
                if (
                    frame.f_code.co_name == "_http_server_process"
                    and str(Path(frame.f_code.co_filename).resolve())
                    == expected["source_http_port"]
                ):
                    return actual == str(frame.f_locals.get("port"))
                frame = frame.f_back
            return False
        finally:
            del frame
    if set(expected) == {"owned"}:
        return owned(actual) and (not expected["owned"] or Path(actual).name == expected["owned"])
    if set(expected) == {"owned_toml"}:
        key, basename = expected["owned_toml"]
        if not actual.startswith(key + "="):
            return False
        try:
            value = json.loads(actual[len(key) + 1 :])
        except ValueError:
            return False
        return owned(value) and Path(value).name == basename
    if set(expected) == {"object_id"}:
        return re.fullmatch("[0-9a-f]{40}", actual) is not None
    if set(expected) == {"inline_ast", "owned_constants"}:
        try:
            tree = ast.parse(actual)
            seen = []
            for node in tree.body:
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in expected["owned_constants"]
                ):
                    call = node.value
                    if (
                        not isinstance(call, ast.Call)
                        or not isinstance(call.func, ast.Name)
                        or call.func.id != "Path"
                        or len(call.args) != 1
                        or call.keywords
                        or not isinstance(call.args[0], ast.Constant)
                        or not owned(call.args[0].value)
                    ):
                        return False
                    seen.append(node.targets[0].id)
                    call.args[0].value = "OWNED_ROOT"
            return (
                sorted(seen) == sorted(expected["owned_constants"])
                and hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()
                == expected["inline_ast"]
            )
        except (SyntaxError, ValueError, TypeError):
            return False
    if set(expected) == {"one_of"}:
        return actual in expected["one_of"]
    return False


def admit(argv, cwd, environment=None):
    _diagnostic_mark("admit_enter")
    state = _STATE
    runtime = state["runtime"]
    if (
        not isinstance(argv, (tuple, list))
        or not argv
        or any(not isinstance(arg, (str, os.PathLike)) for arg in argv)
    ):
        refuse("non_vector_command")
    argv = [os.fspath(arg) for arg in argv]
    static_path = Path(state["guard"]).with_name("static_binding.py")
    static_pin = state["direct_support"]["files"].get(str(static_path))
    if static_pin is not None:
        checked_source(static_path, static_pin)["check"](state, append, refuse)
    lifecycle_path = Path(state["guard"]).with_name("lifecycle_binding.py")
    lifecycle_pin = state["direct_support"]["files"].get(str(lifecycle_path))
    if lifecycle_pin is not None:
        checked_source(lifecycle_path, lifecycle_pin)["check"](
            argv, cwd, environment, state, append, refuse
        )
    approval_path = Path(state["guard"]).with_name("approval_routes.py")
    approval_pin = state["direct_support"]["files"].get(str(approval_path))
    if approval_pin is not None:
        selected = checked_source(approval_path, approval_pin)["select"](
            argv, cwd, environment, state, append, refuse
        )
        if selected is not None:
            return selected
    _diagnostic_mark("admit_fixed_support_end")
    for name in (
        "desktop_route.py",
        "cohort4_routes.py",
        "cohort3_routes.py",
        "cohort3_plan.py",
        "cohort_routes.py",
        "cohort_plan.py",
        "cohort_stdio.py",
    ):
        carrier = Path(state["guard"]).with_name(name)
        carrier_pin = state["direct_support"]["files"].get(str(carrier))
        if carrier_pin is None:
            continue
        try:
            selected = checked_source(carrier, carrier_pin)["select"](
                argv, cwd, environment, state, append, refuse
            )
        except GuardRefusal:
            raise
        except (
            OSError,
            RuntimeError,
            KeyError,
            ValueError,
            TypeError,
            AttributeError,
            StopIteration,
        ):
            refuse("cohort_source_binding_error")
        if selected is not None:
            return selected
    _diagnostic_mark("admit_cohort_support_end")
    copied_support = state["direct_support"]["files"].get(
        str(Path(state["guard"]).with_name("copied_cli.py"))
    )
    if copied_support is not None:
        selected = checked_source(Path(state["guard"]).with_name("copied_cli.py"), copied_support)[
            "translate"
        ](argv, cwd, environment, state, append, refuse)
        if selected is not None:
            return selected
    for console in state.get("console_routes", []):
        if argv[0] == console["name"] and argv[1:] == console["argv"]:
            resolved = shutil.which(argv[0], path=(environment or os.environ).get("PATH"))
            if resolved != console["path"] or digest(resolved) != console["sha256"]:
                refuse("console_identity_drift")
            if Path(resolved).read_bytes().splitlines()[0] != ("#!" + console["python"]).encode():
                refuse("console_interpreter_drift")
            append(
                {
                    "kind": "finite_console_translation",
                    "original_argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                    "console_sha256": console["sha256"],
                }
            )
            argv = [console["python"], resolved, *argv[1:]]
            break
    try:
        executable = Path(argv[0])
        python = (
            str(executable) in runtime["paths"]
            and str(executable.resolve()) == runtime["realpath"]
            and digest(executable) == runtime["sha256"]
        )
    except OSError:
        python = False
    if not python:
        native_support = state["direct_support"]["files"][
            str(Path(state["guard"]).with_name("git_routes.py"))
        ]
        native = checked_source(Path(state["guard"]).with_name("git_routes.py"), native_support)[
            "admit"
        ](argv, cwd, environment, state, append, refuse)
        if native is not None:
            return native, argv
    _diagnostic_mark("admit_native_end")
    operations = state.get("operations")
    if operations is not None:
        try:
            operation = operations.admit(argv, cwd, environment)
        except GuardRefusal:
            raise
        except (OSError, RuntimeError, KeyError, ValueError, TypeError):
            refuse("source_operation_binding_error")
        if operation is not None:
            return operation, argv
    _diagnostic_mark("admit_direct_begin")
    try:
        direct = (
            state["direct_admit"](argv, cwd, environment, state, append, refuse) if python else None
        )
    except GuardRefusal:
        raise
    except (OSError, RuntimeError, KeyError, ValueError, TypeError):
        refuse("direct_source_binding_error")
    _diagnostic_mark("admit_direct_end")
    if direct is not None:
        return direct, argv
    for registration in state["commands"]:
        if registration['class'] in {'canonical-backend', 'controlled-acp'}:
            append({'kind': 'source_registry_diagnostic', 'candidate': registration['class'],
                    'python_detected': python,
                    'arguments_match': len(argv[1:]) == len(registration['argv']) and all(
                        match_arg(a, b) for a, b in zip(argv[1:], registration['argv'])),
                    'script_matches': digest(argv[1]) == registration.get('script_sha256')
                        if 'script_sha256' in registration and len(argv) > 1 and Path(argv[1]).is_file() else None,
                    'owned_cwd': owned(str(Path(cwd or os.getcwd()).resolve()))})
        if registration["class"].startswith("source-speed-nested"):
            continue
        if registration["python"] != python:
            continue
        if not python:
            if not match_arg(argv[0], registration["executable"]):
                continue
            path = argv[0]
            if "executable_resolved" in registration:
                path = shutil.which(path, path=(environment or os.environ).get("PATH"))
                if path != registration["executable_resolved"]:
                    continue
            if digest(path) != registration["executable_sha256"]:
                continue
        actual = argv[1:]
        template = registration["argv"]
        if len(actual) != len(template) or not all(
            match_arg(a, b) for a, b in zip(actual, template, strict=True)
        ):
            continue
        if "parent_helper" in registration:
            parent = state.get("original_argv", [])
            if (
                state["class"] != registration["parent_helper"]
                or "--child-stop-path" not in parent
                or argv[-1] != parent[parent.index("--child-stop-path") + 1]
            ):
                continue
        directory = Path(cwd if cwd is not None else os.getcwd()).resolve()
        if registration.get("session_timeout_scenario") and not (
            Path(argv[5]).parent == Path(argv[7]).parent == directory.parent
            and directory.name == "workspace"
        ):
            continue
        if not (
            directory.is_relative_to(Path(state["owned_root"]))
            or registration["checkout_cwd"]
            and directory == Path(state["checkout"])
        ):
            continue
        source = registration["source_binding"]
        source_path = Path(source["path"])
        if not source_path.is_absolute():
            source_path = Path(state["checkout"]) / source_path
        if digest(source_path) != source["sha256"]:
            refuse("registered_source_drift")
        if "source_function" in registration:
            frame = inspect.currentframe()
            try:
                while frame and not (
                    frame.f_code.co_name == registration["source_function"]
                    and frame.f_code.co_firstlineno == registration["source_function_line"]
                    and Path(frame.f_code.co_filename).resolve() == source_path
                ):
                    frame = frame.f_back
                if (
                    frame is None
                    or directory != Path(frame.f_locals[registration["source_cwd_local"]]).resolve()
                ):
                    continue
            finally:
                del frame
        if registration.get("http_scenario"):
            frame = inspect.currentframe()
            try:
                while frame and not (
                    frame.f_code.co_name == "_http_server_process"
                    and Path(frame.f_code.co_filename).resolve() == source_path
                ):
                    frame = frame.f_back
                if frame is None:
                    continue
                local = frame.f_locals
                config = local["config"]
                selected = state["http_ports"].pop((threading.get_ident(), id(frame)), None)
                if (
                    directory != Path(local["workspace"]).resolve()
                    or selected != local["port"]
                    or not owned(str(config.harness_home))
                    or not owned(str(config.projects_dir))
                    or environment is None
                    or environment.get("UNREST_HOME") != str(config.harness_home)
                    or environment.get("UNREST_PROJECTS_DIR") != str(config.projects_dir)
                    or argv[4] != local["mode"]
                ):
                    continue
                append(
                    {
                        "kind": "concrete_http_registration",
                        "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                        "cwd": str(directory),
                        "source_binding": source,
                        "home": str(config.harness_home),
                        "projects": str(config.projects_dir),
                    }
                )
            finally:
                del frame
        if "script_sha256" in registration and digest(argv[1]) != registration["script_sha256"]:
            continue
        for path, pin in registration.get("files", {}).items():
            if digest(path) != pin:
                refuse("registered_file_drift")
        binding_path = Path(state["guard"]).with_name("fallback_binding.py")
        binding = checked_source(binding_path, state["direct_support"]["files"][str(binding_path)])[
            "matches"
        ](registration, argv, cwd, environment, state)
        if binding is None:
            continue
        append(
            {
                "kind": "finite_fallback_source_context",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            }
        )
        return registration, argv
    frame = inspect.currentframe().f_back
    append(
        {
            "kind": "unknown_vector_identity",
            "executable": argv[0],
            "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            "argument_sha256": [hashlib.sha256(a.encode()).hexdigest() for a in argv[1:]],
            "cwd": str(Path(cwd or os.getcwd()).resolve()),
            "source_path": frame.f_code.co_filename,
            "source_line": frame.f_lineno,
        }
    )
    refuse("unknown_command")


def audit(event, args):
    if _STATE.get("network_policy") == "package-no-network" and event in (
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getnameinfo",
        "socket.sendto",
        "socket.sendmsg",
    ):
        refuse("forbidden_package_network:" + event)
    if (
        event
        in ("os.exec", "os.posix_spawn", "os.system", "os.fork", "os.forkpty", "subprocess.Popen")
        and _STATE["phase"] != "READY"
    ):
        refuse("finite_guard_installation_not_READY")
    if event in ("os.system", "subprocess.Popen") and _STATE["isolated_composition"].delegate(
        event, args
    ):
        return
    if event == "os.system" and _STATE["refusal_composition"].delegate(event, args):
        return
    if event in ("os.exec", "os.posix_spawn", "os.system", "os.fork", "os.forkpty"):
        refuse("unsupported_route:" + event)
    if event == "subprocess.Popen":
        expected = getattr(_LOCAL, "launch", None)
        if expected is None or list(args[1]) != expected:
            refuse("unregistered_popen_boundary")
        _LOCAL.launch = None


def bootstrap(manifest, manifest_pin, guard_path, guard_pin, payload):
    # -I and -S cannot rely on sitecustomize or PYTHONPATH. Absolute loading is
    # performed explicitly before executing any admitted program body.
    early = {
        "kind": "bootstrap_guard_active",
        "token": payload["token"],
        "class": payload["class"],
        "case": payload.get("case"),
    }
    forbidden = {**early, "kind": "forbidden", "reason": "pre_install_launch"}
    events = json.loads(Path(manifest).read_text())["events"]
    prefix = (
        "import sys,os\n"
        "_finite_gate={'active':True}\n"
        "sys._finite_source_bootstrap_gate=_finite_gate\n"
        "def _finite_record(template):\n"
        f"    fd=os.open({events!r}+'/'+str(os.getpid())+'.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)\n"
        "    try:\n"
        "        data=(template[:-1]+',\"owner_pid\":'+str(os.getpid())+',\"parent_pid\":'+str(os.getppid())+'}\\n').encode()\n"
        "        view=memoryview(data)\n"
        "        while view:\n"
        "            written=os.write(fd,view)\n"
        "            if written<=0: raise OSError('incomplete early record')\n"
        "            view=view[written:]\n"
        "        os.fsync(fd)\n"
        "    finally: os.close(fd)\n"
        "def _finite_early_audit(event,args):\n"
        "    if _finite_gate['active'] and event in ('subprocess.Popen','os.exec','os.posix_spawn','os.system','os.fork','os.forkpty'):\n"
        f"        _finite_record({json.dumps(forbidden)!r})\n"
        "        raise RuntimeError('finite early guard: pre_install_launch')\n"
        "sys.addaudithook(_finite_early_audit)\n"
        f"_finite_record({json.dumps(early)!r})\n"
    )
    return (
        prefix + "import hashlib,types,sys;from pathlib import Path;"
        f"p=Path({guard_path!r});"
        "data=p.read_bytes();"
        f"assert hashlib.sha256(data).hexdigest()=={guard_pin!r};"
        "g=types.ModuleType('runtime_guard');g.__file__=str(p);sys.modules['runtime_guard']=g;"
        "exec(compile(data,str(p),'exec'),g.__dict__);"
        f"g.child({manifest!r},{manifest_pin!r},{payload!r})"
    )


def child(manifest, pin, payload):
    install(manifest, pin, payload["token"], payload["class"], payload.get("case"))
    require_ready(payload["token"])
    if payload.get("operation_lineage"):
        operations = _STATE.get("operations")
        if operations is None:
            refuse("source_operation_inheritance_support_missing")
        operations.inherited(payload["operation_lineage"])
    _STATE["original_argv"] = payload["sys_argv"]
    _STATE["registered_payload"] = payload
    append(
        {
            "kind": "source_entry",
            "class": payload["class"],
            "pgid": os.getpgid(0),
            "sigterm_default": signal.getsignal(signal.SIGTERM) == signal.SIG_DFL,
        }
    )
    sys.argv = payload["sys_argv"]
    if "orig_argv" in payload:
        sys.orig_argv = payload["orig_argv"]
    if not payload["isolated"]:
        sys.path[0] = payload["path0"]
    append(
        {
            "kind": "effective_entry",
            "flags": {"isolated": sys.flags.isolated, "no_site": sys.flags.no_site},
            "sys_path": list(sys.path),
            "cwd": os.getcwd(),
            "argv_sha256": hashlib.sha256(json.dumps(sys.argv).encode()).hexdigest(),
            "environment_sha256": hashlib.sha256(
                json.dumps(dict(os.environ), sort_keys=True).encode()
            ).hexdigest(),
            "source_binding": payload.get("source_binding"),
        }
    )
    require_ready(payload["token"])
    if payload["class"] == "source-cache-import":
        expected = _STATE["operation_activation"].spec["cache_body"]
        checker = sys.modules["operation_activation"].identity
        if checker(payload["target"]) != expected:
            refuse("source_cache_body_before_dispatch_drift")
    append(
        {
            "kind": "payload_dispatch",
            "token": payload["token"],
            "mode": payload["mode"],
            "source_binding": payload.get("source_binding"),
        }
    )
    if payload.get("isolated_refusal"):
        _STATE["isolated_composition"].activate(payload["isolated_refusal"], payload["target"])
    if payload["mode"] == "inline":
        code = compile(payload["target"], "<string>", "exec", dont_inherit=True)
        namespace = {"__name__": "__main__", "__package__": None, "__spec__": None}
        _STATE["payload_code"] = code
        _STATE["payload_globals"] = namespace
        exec(code, namespace)
    elif payload["mode"] == "module":
        runpy.run_module(payload["target"], run_name="__main__", alter_sys=True)
    else:
        runpy.run_path(payload["target"], run_name="__main__")


def install(manifest, pin, token="root", command_class="pytest-root", case=None):
    global _STATE
    if _STATE is not None:
        if digest(manifest) != pin or pin != _STATE["ready_record"]["manifest_sha256"]:
            refuse("duplicate_install_manifest_drift")
        require_ready(token)
        return
    if digest(manifest) != pin:
        raise RuntimeError("finite guard manifest drift")
    state = json.loads(Path(manifest).read_text())
    state["manifest_path"] = str(manifest)
    state["pin"] = pin
    if digest(state["guard"]) != state["guard_sha256"]:
        raise RuntimeError("finite guard support drift")
    registry = state["registry"]
    if digest(registry["path"]) != registry["sha256"]:
        raise RuntimeError("finite guard registry drift")
    state["commands"] = checked_source(registry["path"], registry["sha256"])["COMMANDS"]
    support = state["direct_support"]
    for path, value in support["files"].items():
        if digest(path) != value:
            raise RuntimeError("finite direct support drift")
    state["direct_admit"] = checked_source(support["path"], support["files"][support["path"]])[
        "admit"
    ]
    state["handles"] = []
    runtime = state["runtime"]
    isolated = state.get("isolated_support")
    if isolated is not None and command_class == "isolated-uv-helper":
        if digest(isolated["inputs_path"]) != isolated["inputs_sha256"]:
            raise RuntimeError("isolated input support drift")
        resolved = checked_source(isolated["path"], isolated["sha256"])["resolve_runtime"](
            state, sys.executable
        )
        state["isolated_runtime_observation"] = resolved
        runtime["paths"] = [*runtime["paths"], sys.executable]
    if isolated is not None and command_class == "isolated-uv-query":
        spec = json.loads(Path(isolated["spec_path"]).read_text())
        query_support = spec["query_support"]["interface"]
        query = checked_source(query_support["path"], query_support["sha256"])["resolve_query"](
            state, sys.executable
        )
        runtime["paths"] = [*runtime["paths"], query["python"]]
    if isolated is not None and command_class == "source-generated-console":
        spec = json.loads(Path(isolated["spec_path"]).read_text())
        item = spec["query_support"]["interface"]
        query = checked_source(item["path"], item["sha256"])["validate"](spec, child=True)
        if sys.executable != query["python"]:
            raise RuntimeError("console_selected_interpreter_drift")
        runtime["paths"] = [*runtime["paths"], query["python"]]
    if (
        str(Path(sys.executable)) not in runtime["paths"]
        or str(Path(sys.executable).resolve()) != runtime["realpath"]
        or digest(sys.executable) != runtime["sha256"]
    ):
        raise RuntimeError("finite guard runtime drift")
    _STATE = state
    state["phase"] = "INSTALLING"
    state["http_ports"] = {}
    state["token"] = token
    state["class"] = command_class
    state["case"] = case
    append(
        {
            "kind": "installing",
            "token": token,
            "class": command_class,
            "runtime_sha256": runtime["sha256"],
            "manifest_sha256": pin,
            "guard_sha256": state["guard_sha256"],
        }
    )
    if getattr(sys, "_unrest_finite_source_audit", None) is not None:
        refuse("duplicate_finite_audit_install")
    sys.addaudithook(audit)
    sys._unrest_finite_source_audit = audit
    composition = Path(__file__).with_name("refusal_composition.py")
    isolated = Path(__file__).with_name("isolated_refusal.py")
    isolated_namespace = checked_source(isolated, state["direct_support"]["files"][str(isolated)])
    state["isolated_source_code"], state["isolated_named"] = (
        isolated_namespace["source_code"],
        isolated_namespace["named"],
    )
    original_source_code = state["isolated_source_code"]
    original_code_cache = {}

    def current_source_code(source):
        body = Path(source).read_bytes()
        key = (
            str(source),
            hashlib.sha256(body).hexdigest(),
            "_pytest.assertion.rewrite" in sys.modules,
        )
        if key not in original_code_cache:
            original_code_cache[key] = original_source_code(Path(source))
        return original_code_cache[key]

    state["isolated_source_code"] = current_source_code
    state["isolated_composition"] = isolated_namespace["IsolatedComposition"](
        state, append, refuse, _ORIGINAL_SYSTEM, _ORIGINAL_RUN
    )
    state["refusal_composition"] = checked_source(
        composition, state["direct_support"]["files"][str(composition)]
    )["Composition"](state, append, refuse, _ORIGINAL_SYSTEM)
    operation_support = state.get("operation_support")
    if operation_support is not None:
        spec_path = operation_support["spec_path"]
        if digest(spec_path) != operation_support["spec_sha256"]:
            refuse("source_operation_preparation_spec_drift")
        state["operation_spec"] = json.loads(Path(spec_path).read_text())
        operation_ns = checked_source(operation_support["path"], operation_support["sha256"])
        state["operations"] = operation_ns["Operations"](state, append, refuse, require_ready)
        state['operation_profile_owner'] = state['operations']
        state['operation_profile_function'] = state['operations'].profile.__func__
        state['operation_profile_code'] = state['operations'].profile.__func__.__code__
        state['operation_profile_globals'] = operation_ns
        state['operation_profile_sources'] = frozenset(operation_ns['SOURCE_FRAME_PATHS'])

    activation_support = state.get("activation_support")
    if activation_support is not None:
        if digest(activation_support["spec_path"]) != activation_support["spec_sha256"]:
            refuse("activation_spec_drift")
        state["activation_spec"] = json.loads(Path(activation_support["spec_path"]).read_text())
        activation_ns = checked_source(activation_support["path"], activation_support["sha256"])
        state["operation_activation"] = activation_ns["create"](
            state, append, refuse, require_ready
        )
        state["activation_owner"] = state["operation_activation"]

    profile_sources = {
        str(Path(state["checkout"]) / p)
        for p in (
            "tests/test_acp_runner.py",
            "tests/test_server.py",
            "tests/contracts/conftest.py",
            "tests/mock_provider_session_acp.py",
            "tests/test_v04_speed_runner.py",
            "tools/v04_speed_runner.py",
        )
    }
    profile_sources.add(signal.__file__)
    if state.get('operation_profile_sources') is not None:
        profile_sources.update(state['operation_profile_sources'])
        profile_sources.add(shutil.__file__)
    for observer in (state["refusal_composition"], state["isolated_composition"]):
        for attribute in ("source", "product"):
            value = getattr(observer, attribute, None)
            if value is not None:
                profile_sources.add(str(value))
    profile_sources.update(("<string>", "<source-registered-inline>"))

    def selected_port(frame, event, value):
        if state.get('primary_snapshot_observer') is not None:
            state['primary_snapshot_observer'](frame, event, value)
        if (
            event == "call"
            and state["token"] == "root"
            and not state.get("cohort3_rpc_delegate")
            and frame.f_code.co_filename == state.get("http_source")
            and frame.f_code.co_name
            in (
                "test_composed_hermetic_acp_topology_uses_public_attached_control",
                "test_real_targetless_dispatch_consumption",
            )
            and state.get("case", "").split("[")[0]
            == "tests/test_server.py::" + frame.f_code.co_name
        ):
            source = Path(state["http_source"])
            original = frame.f_globals["_call_process_mcp"]
            expected = state["isolated_named"](
                state["isolated_source_code"](source), "_call_process_mcp"
            )
            if (
                digest(source) != state["http_source_sha256"]
                or original.__globals__ is not frame.f_globals
                or original.__code__ != expected
            ):
                refuse("cohort3_rpc_original_identity_drift")

            def delegated(*args, **kwargs):
                saved = sys.getprofile()
                if (
                    saved is not selected_port
                    or digest(source) != state["http_source_sha256"]
                    or original.__code__ != expected
                ):
                    refuse("cohort3_rpc_delegate_identity_drift")
                started = time.monotonic()
                sys.setprofile(None)
                try:
                    return original(*args, **kwargs)
                finally:
                    sys.setprofile(saved)
                    append(
                        {
                            "kind": "exact_rpc_unprofiled_elapsed",
                            "seconds": time.monotonic() - started,
                            "helper_source_sha256": state["http_source_sha256"],
                            "original_deadline_seconds": 10,
                        }
                    )

            delegated.__wrapped__ = original
            frame.f_globals["_call_process_mcp"] = delegated
            state["cohort3_rpc_delegate"] = delegated
            append(
                {
                    "kind": "exact_original_rpc_profile_delegation",
                    "source_sha256": state["http_source_sha256"],
                    "original_helper": "_call_process_mcp",
                    "original_body_and_RPC_requests_retained": True,
                    "profile_restored_in_finally": True,
                    "audit_enforcement_retained": True,
                }
            )
        # The pinned operation observer consumes its source files and shutil's
        # copytree only. Their union with the existing observer domains preserves
        # every consumed event without profiling ignored dependency internals.
        if (
            (state.get("operations") is None or state.get('operation_profile_sources') is not None)
            and frame.f_code.co_filename not in profile_sources
            and not (
                frame.f_code.co_name == "call_and_report"
                and frame.f_code.co_filename.endswith("/_pytest/runner.py")
            )
            and not (
                state["isolated_composition"].codes is not None
                and frame.f_code == state["isolated_composition"].codes
            )
        ):
            return
        if (
            frame.f_code.co_name in ("_send_request_fixture", "_start_fixture")
            and frame.f_code.co_filename
            == str(Path(state["checkout"]) / "tests/test_acp_runner.py")
            and event in ("call", "return")
        ):
            append(
                {
                    "kind": "cohort_original_rendezvous_observation",
                    "function": frame.f_code.co_name,
                    "event": event,
                    "method": frame.f_locals.get("method"),
                    "monotonic": time.monotonic(),
                }
            )
        state["refusal_composition"].observe(frame, event)
        state["isolated_composition"].observe(frame, event)
        if (
            event == "return"
            and frame.f_code.co_name == "call_and_report"
            and frame.f_code.co_filename.endswith("/_pytest/runner.py")
            and value is not None
        ):
            append(
                {
                    "kind": "nested_test_outcome",
                    "nodeid": value.nodeid,
                    "phase": value.when,
                    "outcome": value.outcome,
                }
            )
        # Observe the original parsed JUnit carrier before TemporaryDirectory
        # removes it. No report content, subprocess result or timeout is altered.
        if (
            event == "c_call"
            and frame.f_code.co_name == "run_reference_nodes"
            and frame.f_code.co_filename
            == str(Path(state["checkout"]) / "tests/contracts/conftest.py")
            and all(
                k in frame.f_locals for k in ("cases", "skipped", "failures", "errors", "completed")
            )
        ):
            local = frame.f_locals
            report = Path(local["report_path"])
            if report.is_file() and str(report) not in state.setdefault("junit_seen", set()):
                state["junit_seen"].add(str(report))
                info = report.lstat()
                append(
                    {
                        "kind": "original_junit_observed",
                        "path": str(report),
                        "sha256": digest(report),
                        "size": info.st_size,
                        "device": info.st_dev,
                        "inode": info.st_ino,
                        "cases": len(local["cases"]),
                        "skipped": len(local["skipped"]),
                        "failures": len(local["failures"]),
                        "errors": len(local["errors"]),
                        "numeric_returncode": local["completed"].returncode,
                        "selection_sha256": hashlib.sha256(
                            json.dumps(local["nodes"]).encode()
                        ).hexdigest(),
                    }
                )
        operations = state.get("operations")
        if operations is not None:
            try:
                operations.profile(frame, event, value)
            except GuardRefusal:
                raise
            except (OSError, RuntimeError, KeyError, ValueError, TypeError):
                refuse("source_operation_profile_error")
        if (
            event == "return"
            and command_class == "source-session-child"
            and frame.f_code.co_name == "signal"
            and frame.f_code.co_filename == signal.__file__
            and frame.f_locals.get("signalnum") == signal.SIGTERM
        ):
            caller = frame.f_back
            handler = caller.f_locals.get("record_stop") if caller is not None else None
            fixture = state["timeout_fixture"]
            if (
                caller is not None
                and caller.f_code.co_filename == fixture["path"]
                and caller.f_code.co_name == "main"
                and caller.f_lineno == 27
                and digest(fixture["path"]) == fixture["sha256"]
                and isinstance(handler, types.FunctionType)
                and signal.getsignal(signal.SIGTERM) is handler
                and handler.__globals__ is caller.f_globals
                and handler.__code__
                == state["isolated_named"](
                    state["isolated_source_code"](Path(fixture["path"])), "record_stop"
                )
            ):
                append(
                    {
                        "kind": "original_leaf_handler_installed",
                        "token": state["token"],
                        "source_sha256": fixture["sha256"],
                        "original_signal_policy_unchanged": True,
                    }
                )
        if (
            event == "call"
            and frame.f_code.co_name == "record_stop"
            and command_class == "source-session-child"
            and str(Path(frame.f_code.co_filename).resolve()) == state["timeout_fixture"]["path"]
            and digest(frame.f_code.co_filename) == state["timeout_fixture"]["sha256"]
        ):
            append(
                {
                    "kind": "original_leaf_stop_handler",
                    "signal": frame.f_locals["_signum"],
                    "pgid": os.getpgid(0),
                    "source_line": frame.f_code.co_firstlineno,
                    "source_sha256": state["timeout_fixture"]["sha256"],
                }
            )
        if (
            event == "return"
            and frame.f_code.co_name == "_free_loopback_port"
            and str(Path(frame.f_code.co_filename).resolve()) == state.get("http_source")
        ):
            caller = frame.f_back
            if (
                caller
                and caller.f_code.co_name == "_http_server_process"
                and caller.f_code.co_filename == frame.f_code.co_filename
                and isinstance(value, int)
                and 0 < value < 65536
                and digest(frame.f_code.co_filename) == state["http_source_sha256"]
            ):
                state["http_ports"][(threading.get_ident(), id(caller))] = value
                append(
                    {
                        "kind": "source_port_selected",
                        "port": value,
                        "workspace": str(caller.f_locals["workspace"]),
                    }
                )
        if (
            event == "return"
            and frame.f_code.co_name == "_process_group_inventory"
            and str(Path(frame.f_code.co_filename).resolve()) == state.get("http_source")
            and digest(frame.f_code.co_filename) == state["http_source_sha256"]
            and isinstance(value, list)
        ):
            append(
                {
                    "kind": "original_group_inventory",
                    "case": state.get("case"),
                    "members": value,
                    "source_sha256": state["http_source_sha256"],
                }
            )

    topology_profile_classes = (
        "composed-http-role:orchestrator",
        "source-run-worker",
        "source-owned-role:worker",
        "source-owned-role:validator",
        "source-owned-role:terminal-reviewer",
        "source-composed-adapter",
    )
    topology_case = (
        "tests/test_server.py::test_composed_hermetic_acp_topology_uses_public_attached_control"
    )
    profile_observer = selected_port
    if (
        case == topology_case
        and command_class in topology_profile_classes
        and state.get("operations") is None
    ):
        # These exact descendants execute product/owned-adapter bodies, never
        # the root test helper/JUnit/alias/timeout-fixture observer domains.
        # Their constructors, audit hooks, READY and waitpid remain enforced.
        facts = {
            p: digest(Path(state["checkout"]) / p)
            for p in (
                "tests/test_server.py",
                "src/unrest_harness/run_worker.py",
                "src/unrest_harness/server.py",
                "src/unrest_harness/acp_runner.py",
            )
        }
        if any(value != state["product_pins"][p] for p, value in facts.items()):
            refuse("topology_profile_source_facts_drift")
        if state["refusal_composition"].pending or state["isolated_composition"].codes is not None:
            refuse("topology_profile_observer_domain_drift")
        profile_observer = None
        append(
            {
                "kind": "exact_topology_profile_domain_binding",
                "case": case,
                "class": command_class,
                "source_facts": facts,
                "observer_domains": "root source helpers/JUnit/refusal/timeout-fixture only; absent in exact descendant",
                "constructor_audit_READY_identity_wait_enforcement_retained": True,
            }
        )
    if profile_observer is selected_port:
        native = state['linux_profile_gate']
        if (digest(native['path']) != native['sha256']
                or digest(Path(state['guard']).parent.parent / 'profile_gate.c') != native['source_sha256']):
            refuse('native_profile_predicate_drift')
        specification = importlib.util.spec_from_file_location('profile_gate', native['path'])
        if specification is None or specification.loader is None:
            refuse('native_profile_predicate_loader_missing')
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        selected_port = module.make(selected_port, state, profile_sources)
        profile_observer = selected_port
        append({'kind': 'native_profile_predicate_installed',
                'module_sha256': native['sha256'], 'source_sha256': native['source_sha256'],
                'profile_sources_sha256': hashlib.sha256(json.dumps(sorted(profile_sources)).encode()).hexdigest(),
                'original_Python_observer_and_event_arguments_retained': True})
    sys.setprofile(profile_observer)
    threading.setprofile(profile_observer)
    original_init = subprocess.Popen.__init__
    original_poll = subprocess.Popen._internal_poll
    original_wait = subprocess.Popen.wait
    original_waitpid = os.waitpid
    original_exit = os._exit
    original_killpg = os.killpg
    topology_path = Path(state["guard"]).with_name("topology_teardown.py")
    topology = checked_source(topology_path, state["direct_support"]["files"][str(topology_path)])
    custody_path = Path(state["guard"]).with_name("native_custody.py")
    custody_ns = checked_source(custody_path, state["direct_support"]["files"][str(custody_path)])
    custody_query = custody_ns["prepare"](state["native_sysctl_offsets"])
    teardown = topology["install"](
        state, append, refuse, lambda pid: custody_ns["observe"](pid, custody_query)
    )

    def initialize_inner(handle, args, *positional, **kwargs):
        _diagnostic_mark("inner_enter")
        state["isolated_composition"].before_popen(args, positional, kwargs)
        if positional or kwargs.get("shell") or kwargs.get("executable"):
            refuse("unsupported_popen_options")
        if (
            digest(manifest) != pin
            or digest(state["guard"]) != state["guard_sha256"]
            or digest(state["registry"]["path"]) != state["registry"]["sha256"]
        ):
            refuse("support_drift_before_launch")
        _diagnostic_mark("fresh_support_begin")
        for path, value in state["direct_support"]["files"].items():
            if digest(path) != value:
                refuse("finite_direct_support_drift")
        _diagnostic_mark("fresh_support_end")
        require_ready(state["token"])
        _diagnostic_mark("admit_begin")
        registration, argv = admit(args, kwargs.get("cwd"), kwargs.get("env"))
        _diagnostic_mark("admit_end")
        launch_token = uuid.uuid4().hex
        crash_path = Path(state["guard"]).with_name("crash_disposition.py")
        crash_support = (
            checked_source(crash_path, state["direct_support"]["files"][str(crash_path)])
            if "exact_crash_disposition" in state
            else None
        )
        if crash_support is not None:
            crash_support["before_launch"](
                state, registration, argv, kwargs, launch_token, append, refuse
            )
        _diagnostic_mark("anchor_begin")
        anchor_support = state["direct_support"]["files"].get(
            str(Path(state["guard"]).with_name("anchor_probe.py"))
        )
        if anchor_support is not None:
            try:
                anchors = checked_source(
                    Path(state["guard"]).with_name("anchor_probe.py"), anchor_support
                )["observe"](state, Path(kwargs.get("cwd") or os.getcwd()).resolve())
            except (OSError, RuntimeError, KeyError, ValueError, TypeError):
                refuse("source_anchor_binding_error")
            append(
                {
                    "kind": "actual_source_anchor_observation",
                    "token": launch_token,
                    "anchors": anchors,
                }
            )
        _diagnostic_mark("anchor_end")
        child_argv = argv
        if registration["class"] == "isolated-scratch-wheel" or (
            registration["class"] == "source-build"
            and state.get("source_activation_support") is not None
            and not state["operation_activation"].spec.get("native_preinit")
        ):
            original_environment = dict(os.environ if kwargs.get("env") is None else kwargs["env"])
            kwargs["env"] = {
                **original_environment,
                "PYTHONPATH": state["operation_activation"].spec["hook"],
            }
            append(
                {
                    "kind": "isolated_temporary_environment",
                    "original_environment_sha256": hashlib.sha256(
                        json.dumps(original_environment, sort_keys=True).encode()
                    ).hexdigest(),
                    "restoration": "required before unchanged helper body",
                }
            )
        _diagnostic_mark("activation_begin")
        if registration["python"]:
            if state.get("operation_activation") is not None:
                activation = state["operation_activation"]
                if state.get("source_activation_support") is not None:
                    activation.before_python(argv, kwargs.get("cwd"), kwargs.get("env"), registration)
                else:
                    activation.before_python(argv, kwargs.get("cwd"), kwargs.get("env"))
            _diagnostic_mark("activation_end")
            flags = []
            i = 1
            while argv[i] in ("-I", "-S", "-B", "-u"):
                flags.append(argv[i])
                i += 1
            mode = "script"
            target = argv[i]
            tail = argv[i + 1 :]
            if target in ("-c", "-m"):
                mode = "inline" if target == "-c" else "module"
                target, tail = argv[i + 1], argv[i + 2 :]
            if mode == "script":
                target = str(Path(target).resolve())
            payload = {
                "token": launch_token,
                "class": registration["class"],
                "case": state.get("case"),
                "mode": mode,
                "target": target,
                "isolated": "-I" in flags,
                "sys_argv": ["-c" if mode == "inline" else target, *tail],
                "orig_argv": list(argv),
                "path0": (
                    str(Path(target).parent)
                    if mode == "script"
                    else ""
                    if mode == "inline"
                    else str(Path(kwargs.get("cwd") or os.getcwd()).resolve())
                ),
                "source_binding": registration["source_binding"],
                "operation_lineage": registration.get("operation_lineage", []),
                "isolated_refusal": registration.get("isolated_refusal"),
            }
            code = bootstrap(str(manifest), pin, state["guard"], state["guard_sha256"], payload)
            child_argv = [argv[0], *flags, "-c", code]
        append(
            {
                "kind": "actual_launch_binding",
                "token": launch_token,
                "transformed_argv_sha256": hashlib.sha256(
                    json.dumps(child_argv).encode()
                ).hexdigest(),
                "bootstrap_sha256": hashlib.sha256(code.encode()).hexdigest()
                if registration["python"]
                else None,
                "environment_sha256": hashlib.sha256(
                    json.dumps(
                        inherited_environment() if kwargs.get("env") is None else dict(kwargs["env"]),
                        sort_keys=True,
                    ).encode()
                ).hexdigest(),
                "cwd": str(Path(kwargs.get("cwd") or os.getcwd()).resolve()),
            }
        )
        append(
            {
                "kind": "admitted",
                "token": launch_token,
                "class": registration["class"],
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "source_binding": registration["source_binding"],
            }
        )
        _diagnostic_mark("bootstrap_end")
        native_support = None
        native_query = None
        if not registration["python"]:
            native_path = Path(state["guard"]).with_name("native_custody.py")
            native_support = checked_source(
                native_path, state["direct_support"]["files"][str(native_path)]
            )
            native_query = native_support["prepare"](state["native_sysctl_offsets"])
        _diagnostic_mark("original_init_begin")
        _LOCAL.launch = child_argv
        try:
            original_init(handle, child_argv, **kwargs)
        finally:
            _LOCAL.launch = None
        _diagnostic_mark("original_init_end")
        native = {}
        if not registration["python"]:
            try:
                native = native_support["observe"](handle.pid, native_query)
            except (OSError, RuntimeError):
                append(
                    {
                        "kind": "registered",
                        "token": launch_token,
                        "pid": handle.pid,
                        "class": registration["class"],
                        "python": False,
                        "native_ownership_observation_failed": True,
                    }
                )
                handle.kill()
                handle.wait(timeout=5)
                refuse("native_parent_ownership_unobserved")
        append(
            {
                "kind": "launch_lifecycle_binding",
                "token": launch_token,
                "start_new_session": kwargs.get("start_new_session", False),
                "executable_sha256": digest(
                    shutil.which(
                        argv[0],
                        path=dict(os.environ if kwargs.get("env") is None else kwargs["env"]).get(
                            "PATH"
                        ),
                    )
                    or argv[0]
                ),
            }
        )
        teardown["retain"](handle, registration, launch_token)
        state["handles"].append(weakref.ref(handle))
        append(
            {
                "kind": "registered",
                "token": launch_token,
                "pid": handle.pid,
                "class": registration["class"],
                "python": registration["python"],
                **native,
            }
        )
        if (
            registration["class"].startswith("source-cohort2:tests/")
            and registration["python"]
            or registration["class"]
            in (
                "canonical-backend",
                "controlled-acp",
                "source-foreign-journal-owner",
                "source-benchmark-five-run",
                "source-isolated-precaptured-refusal",
                "inline:test_acp_cleanup.py:50",
                "inline:test_acp_cleanup.py:51",
                "source-cleanup-adapter",
                "source-lease-owned-child",
                "source-workspace-owned-sleep",
                "source-approval-mcp",
                "source-approval-adapter",
                "source-approval-relay",
                "source-approval-python-backend",
            )
        ):
            deadline = time.monotonic() + 5
            journal = Path(state["events"]) / (str(handle.pid) + ".jsonl")
            while True:
                records = (
                    [json.loads(line) for line in journal.read_text().splitlines()]
                    if journal.exists()
                    else []
                )
                expected = {
                    "kind": "ready",
                    "token": launch_token,
                    "class": registration["class"],
                    "owner_pid": handle.pid,
                    "parent_pid": os.getpid(),
                    "guard_sha256": state["guard_sha256"],
                    "manifest_sha256": pin,
                    "registry_sha256": state["registry"]["sha256"],
                    "runtime_sha256": state["runtime"]["sha256"],
                }
                if any(
                    all(record.get(key) == value for key, value in expected.items())
                    for record in records
                ):
                    append(
                        {
                            "kind": "bounded_controlled_READY_handshake",
                            "token": launch_token,
                            "pid": handle.pid,
                            "class": registration["class"],
                            "deadline_seconds": 5,
                            "original_probe_deadline_changed": False,
                        }
                    )
                    break
                if handle.poll() is not None or time.monotonic() >= deadline:
                    if handle.poll() is None:
                        handle.kill()
                    handle.wait(timeout=5)
                    refuse("controlled_startup_not_READY")
                time.sleep(0.001)
        if crash_support is not None:
            crash_support["snapshot"](state, registration, handle.pid, launch_token, append, refuse)
        if registration["class"] == "source-run-worker" and (
            command_class != "composed-http-role:orchestrator"
            or state.get("case") in state.get("cohort3_http_reaper_cases", [])
        ):
            # Detached source workers intentionally discard their public handle.
            # A test-only daemon reaps that exact admitted child without joining
            # submission, signalling it, or retaining any other Popen handle.
            def reap_detached():
                append(
                    {
                        "kind": "detached_wait_started",
                        "pid": handle.pid,
                        "token": launch_token,
                        "class": registration["class"],
                    }
                )
                code = (
                    handle.wait(timeout=300)
                    if state.get("case") in state.get("cohort3_http_reaper_cases", [])
                    else handle.wait()
                )
                append(
                    {
                        "kind": "detached_wait_finished",
                        "pid": handle.pid,
                        "token": launch_token,
                        "numeric_returncode": code,
                    }
                )

            threading.Thread(
                target=reap_detached, daemon=True, name="finite-detached-worker-wait"
            ).start()
        if registration["class"] == "reference-integrity:test_waits" or registration[
            "class"
        ].startswith("source-owned-role:"):
            # The original 50ms timeout measures the test body. Finish guard
            # startup before returning its handle; keep the source deadline.
            deadline = time.monotonic() + 5
            path = Path(state["events"]) / (str(handle.pid) + ".jsonl")
            while True:
                records = (
                    [json.loads(line) for line in path.read_text().splitlines()]
                    if path.exists()
                    else []
                )
                if any(e["kind"] == "ready" and e["token"] == launch_token for e in records):
                    append(
                        {
                            "kind": "bounded_child_READY_handshake",
                            "token": launch_token,
                            "pid": handle.pid,
                            "deadline_seconds": 5,
                        }
                    )
                    break
                if handle.poll() is not None or time.monotonic() >= deadline:
                    if handle.poll() is None:
                        handle.kill()
                    handle.wait(timeout=5)
                    refuse("reference_timeout_startup_not_READY")
                time.sleep(0.001)
        if registration["class"] == "source-session-helper:timeout":
            deadline = time.monotonic() + 5
            marker = Path(argv[5])
            while True:
                records = [
                    json.loads(line)
                    for journal in sorted(Path(state["events"]).glob("*.jsonl"))
                    for line in journal.read_text().splitlines()
                ]
                children = [
                    record
                    for record in records
                    if record["kind"] == "registered"
                    and record["owner_pid"] == handle.pid
                    and record["class"] == "source-session-child"
                ]
                if len(children) == 1:
                    child = children[0]
                    ready = [
                        record
                        for record in records
                        if record["kind"] == "ready"
                        and record["owner_pid"] == child["pid"]
                        and record["token"] == child["token"]
                        and record["manifest_sha256"] == pin
                        and record["guard_sha256"] == state["guard_sha256"]
                    ]
                    handlers = [
                        record
                        for record in records
                        if record["kind"] == "original_leaf_handler_installed"
                        and record["owner_pid"] == child["pid"]
                        and record["token"] == child["token"]
                    ]
                    if (
                        len(ready) == len(handlers) == 1
                        and marker.is_file()
                        and marker.read_text() == str(child["pid"])
                    ):
                        append(
                            {
                                "kind": "bounded_timeout_descendant_READY",
                                "pid": child["pid"],
                                "token": child["token"],
                                "deadline_seconds": 5,
                                "original_timeout_seconds": 0.3,
                                "original_signal_policy_unchanged": True,
                            }
                        )
                        break
                if handle.poll() is not None or time.monotonic() >= deadline:
                    if handle.poll() is None:
                        handle.kill()
                    handle.wait(timeout=5)
                    refuse("timeout_descendant_not_READY")
                time.sleep(0.001)
        if state.get("operations") is not None:
            state["operations"].retained(registration, handle, launch_token)
        if registration["class"] in ("source-session-child", "source-session-helper:timeout"):
            append(
                {
                    "kind": "group_member",
                    "pid": handle.pid,
                    "pgid": os.getpgid(handle.pid),
                    "class": registration["class"],
                    "token": launch_token,
                    "stop_path": argv[-1],
                }
            )

        _diagnostic_mark("inner_return")

    def killpg(pgid, sig):
        frame = inspect.currentframe().f_back
        binding = {
            "path": frame.f_code.co_filename,
            "line": frame.f_lineno,
            "sha256": digest(frame.f_code.co_filename),
        }
        append(
            {
                "kind": "group_signal_attempt",
                "pgid": pgid,
                "signal": int(sig),
                "source_binding": binding,
            }
        )
        teardown["before_signal"](frame, pgid, int(sig))
        result = original_killpg(pgid, sig)
        append(
            {
                "kind": "group_signal_delivered",
                "pgid": pgid,
                "signal": int(sig),
                "source_binding": binding,
            }
        )
        return result

    def wait(handle, *args, **kwargs):
        code = original_wait(handle, *args, **kwargs)
        append({"kind": "handle_wait", "pid": handle.pid, "numeric_returncode": code})
        return code

    def waitpid(pid, options):
        result = original_waitpid(pid, options)
        if result[0]:
            append(
                {
                    "kind": "actual_waitpid",
                    "pid": result[0],
                    "numeric_returncode": os.waitstatus_to_exitcode(result[1]),
                }
            )
            if state.get("operations") is not None:
                state["operations"].waited(result[0], os.waitstatus_to_exitcode(result[1]))
        return result

    class PollWait:
        WNOHANG = os.WNOHANG
        ECHILD = subprocess._del_safe.ECHILD

    PollWait.waitpid = staticmethod(waitpid)

    def poll(handle, _deadstate=None, _del_safe=None):
        return original_poll(handle, _deadstate=_deadstate, _del_safe=PollWait)

    def abrupt(code):
        append(
            {
                "kind": "abrupt_exit",
                "token": token,
                "class": command_class,
                "numeric_returncode": code,
            }
        )
        original_exit(code)

    def initialize(handle, args, *positional, **kwargs):
        frame = inspect.currentframe().f_back
        selected = False
        try:
            while frame:
                if (
                    frame.f_code.co_filename == state.get("http_source")
                    and frame.f_code.co_name == "_process_group_inventory"
                    and frame.f_lineno == 3284
                ):
                    selected = (
                        list(args) == ["ps", "-axo", "pid=,ppid=,pgid="]
                        and kwargs.get("cwd") is None
                        and kwargs.get("env") is None
                        and state.get("case") in state.get("cohort3_full_cases", [])
                    )
                    break
                frame = frame.f_back
        finally:
            del frame
        if not selected:
            return initialize_inner(handle, args, *positional, **kwargs)
        saved = sys.getprofile()
        if saved is not selected_port:
            refuse("cohort3_inventory_profile_identity_drift")
        # This exact literal native admission executes guard and stdlib metadata
        # work. Restore the original observer before the source helper returns;
        # audit enforcement and every durable READY/custody/wait record stay live.
        sys.setprofile(None)
        try:
            return initialize_inner(handle, args, *positional, **kwargs)
        finally:
            sys.setprofile(saved)

    subprocess.Popen.__init__ = initialize
    subprocess.Popen._internal_poll = poll
    subprocess.Popen.wait = wait
    os.killpg = killpg
    os.waitpid = waitpid
    os._exit = abrupt
    atexit.register(lambda: append({"kind": "finished", "token": token}))
    record = {
        "kind": "ready",
        "token": token,
        "class": command_class,
        "owner_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "case": case,
        "sid": os.getsid(0),
        "pgid": os.getpgid(0),
        "runtime_sha256": runtime["sha256"],
        "manifest_sha256": pin,
        "guard_sha256": state["guard_sha256"],
        "registry_sha256": registry["sha256"],
        "support_sha256": hashlib.sha256(
            json.dumps(support["files"], sort_keys=True).encode()
        ).hexdigest(),
    }
    append(record)
    state["ready_record"] = record
    state["phase"] = "READY"
    require_ready(token)
    gate = getattr(sys, "_finite_source_bootstrap_gate", None)
    if gate is not None:
        gate["active"] = False


def summarize(manifest):
    state = json.loads(Path(manifest).read_text())
    state["manifest_path"] = str(manifest)
    events = [
        json.loads(line)
        for path in sorted(Path(state["events"]).glob("*.jsonl"))
        for line in path.read_text().splitlines()
    ]
    starts = {e["token"]: e for e in events if e["kind"] == "ready"}
    waited = {
        (e["owner_pid"], e["pid"]): e["numeric_returncode"]
        for e in events
        if e["kind"] == "actual_waitpid"
    }
    failures = [e for e in events if e["kind"] == "forbidden"]
    if _STATE is not None and _STATE.get("journal_failed"):
        failures.append({"kind": "journal_durability_failed"})
    descendants = []
    for e in events:
        if e["kind"] != "registered":
            continue
        status = "actually_waited" if (e["owner_pid"], e["pid"]) in waited else "missing_wait"
        if e["python"] and e["token"] not in starts:
            failures.append({"kind": "missing_activation", "pid": e["pid"]})
        if status == "missing_wait":
            carrier = Path(__file__).with_name("orphan_disposition.py")
            namespace = {}
            exec(compile(carrier.read_bytes(), str(carrier), "exec"), namespace)
            disposition = namespace["record"](state, events, e)
            if disposition is not None:
                status = disposition["wait_status"]
                e = {**e, **disposition}
        if status == "missing_wait" and "exact_crash_disposition" in state:
            carrier = Path(__file__).with_name("crash_disposition.py")
            namespace = checked_source(carrier, state["direct_support"]["files"][str(carrier)])
            disposition = namespace["record"](state, events, e)
            if disposition is not None:
                status = disposition["wait_status"]
                e = {**e, **disposition}
        if status == "missing_wait":
            failures.append({"kind": "missing_wait", "owner_pid": e["owner_pid"], "pid": e["pid"]})
        descendants.append({**e, "wait_status": status})
    return {
        "events": events,
        "descendants": descendants,
        "failures": failures,
        "ready": not failures,
        "orphan_exception": "exact composed RunControl route only; final child timing UNVERIFIED",
    }


def observe_summary(manifest):
    # Only exact dead-controller descendants receive an absence observation
    # allowance. No child wait is performed or inferred for an exited owner.
    for reference in _STATE.get("handles", []):
        handle = reference()
        if handle is not None and handle.returncode is None:
            try:
                events = summarize(manifest)["events"]
                selected = next(
                    (
                        e
                        for e in events
                        if e["kind"] == "registered"
                        and e["pid"] == handle.pid
                        and e["owner_pid"] == os.getpid()
                    ),
                    None,
                )
                exact = _STATE.get("cohort3_teardown_wait")
                timeout = 1
                if (
                    exact is not None
                    and selected is not None
                    and selected["class"] == "source-run-worker"
                    and selected.get("case") == exact["case"]
                ):
                    if (
                        digest(exact["source"]) != exact["source_sha256"]
                        or selected["python"] is not True
                    ):
                        refuse("cohort3_teardown_identity_drift")
                    timeout = exact["seconds"]
                    append(
                        {
                            "kind": "exact_source_owner_teardown_wait",
                            "pid": handle.pid,
                            "seconds": timeout,
                            "source_sha256": exact["source_sha256"],
                            "case": exact["case"],
                        }
                    )
                handle.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                append({"kind": "forbidden", "reason": "owned_handle_unsettled", "pid": handle.pid})
    if "exact_crash_disposition" in _STATE:
        carrier = Path(__file__).with_name("crash_disposition.py")
        support = checked_source(carrier, _STATE["direct_support"]["files"][str(carrier)])
        support["closeout"](_STATE, summarize(manifest)["events"], append)
    deadline = time.monotonic() + 20
    while True:
        summary = summarize(manifest)
        crash_pids = {
            e["owner_pid"]
            for e in summary["events"]
            if e["kind"] == "abrupt_exit"
            and e["numeric_returncode"] == 73
            and e["class"].startswith("crash-controller:")
        }
        pending = [
            e
            for e in summary["failures"]
            if e["kind"] == "missing_wait"
            and (
                e["owner_pid"] in crash_pids
                or (
                    any(
                        s["kind"] == "group_signal_delivered" and s["pgid"] == e["owner_pid"]
                        for s in summary["events"]
                    )
                    and any(
                        p["kind"] == "registered"
                        and p["pid"] == e["owner_pid"]
                        and p["class"] == "source-session-helper:timeout"
                        and p["case"] == _STATE["timeout_case"]
                        for p in summary["events"]
                    )
                )
            )
        ]
        if not pending or time.monotonic() >= deadline:
            summary["absence_observation_bound_seconds"] = 20
            return summary
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
