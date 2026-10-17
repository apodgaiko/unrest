"""Exact source-generated alias oracle; downstream audit rejection is mandatory."""

import ast
import contextlib
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import types

NAME = "test_precaptured_constructor_resolver_and_command_aliases_are_audit_denied"
ENV = {"LANG": "C", "LC_ALL": "C", "PYTHONUTF8": "1", "TZ": "UTC"}
CLASS = "source-isolated-precaptured-refusal"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def named(code, name):
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            if item.co_name == name:
                return item
            found = named(item, name)
            if found is not None:
                return found
    return None


def source_code(path):
    body = path.read_bytes()
    tree = ast.parse(body, filename=str(path))
    if "_pytest.assertion.rewrite" in sys.modules:
        from _pytest.assertion.rewrite import rewrite_asserts

        rewrite_asserts(tree, body, str(path))
    return compile(tree, str(path), "exec", dont_inherit=True)


def body_for(source, markers):
    fn = next(
        n
        for n in ast.parse(source.read_bytes()).body
        if isinstance(n, ast.FunctionDef) and n.name == NAME
    )
    call = next(
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_isolated_python"
    )
    return eval(
        compile(ast.Expression(call.args[0]), str(source), "eval"), {"__builtins__": {}}, markers
    )


def marker_check(markers, state, refuse):
    root = Path(state["owned_root"]).resolve()
    values = [Path(markers[key]) for key in ("marker_system", "marker_run")]
    if (
        values[0].name != "system-marker"
        or values[1].name != "run-marker"
        or values[0].parent != values[1].parent
        or not values[0].parent.is_dir()
        or any(
            not p.is_absolute()
            or ".." in p.parts
            or p != p.resolve()
            or not p.is_relative_to(root)
            or p.parent == root
            or p.exists()
            or p.is_symlink()
            for p in values
        )
    ):
        refuse("isolated_refusal_marker_drift")


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/test_v04_speed_runner.py"
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename == str(source) and frame.f_code.co_name == "_isolated_python"
        ):
            frame = frame.f_back
        if frame is None:
            return None
        owner = frame.f_back
        if owner is None or owner.f_code.co_name != NAME:
            return None
        if sha(source) != state["product_pins"]["tests/test_v04_speed_runner.py"]:
            refuse("isolated_refusal_source_drift")
        codes = source_code(source)
        for current, name in ((frame, "_isolated_python"), (owner, NAME)):
            fn = current.f_globals.get(name)
            if (
                not isinstance(fn, types.FunctionType)
                or fn.__globals__ is not current.f_globals
                or fn.__code__ is not current.f_code
                or fn.__code__ != named(codes, name)
            ):
                refuse("isolated_refusal_caller_drift")
        local = owner.f_locals
        markers = {key: str(local[key]) for key in ("marker_system", "marker_run")}
        marker_check(markers, state, refuse)
        body = body_for(source, markers)
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        if (
            frame.f_lineno != 1292
            or owner.f_lineno != 1308
            or frame.f_locals["source"] != body
            or argv != [sys.executable, "-c", body]
            or Path(cwd).resolve() != Path(state["checkout"])
            or env != environment
        ):
            refuse("isolated_refusal_vector_drift")
        proof = {
            "markers": markers,
            "body": body,
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "environment": environment,
            "cwd": state["checkout"],
            "source_sha256": sha(source),
        }
        binding = {
            "path": str(source),
            "line": 1292,
            "function": "_isolated_python",
            "owner": NAME,
            "sha256": sha(source),
        }
        append(
            {
                "kind": "concrete_isolated_refusal_registration",
                "source_binding": binding,
                "helper_sha256": proof["body_sha256"],
                "markers": markers,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(environment, sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        return {
            "class": CLASS,
            "python": True,
            "source_binding": binding,
            "isolated_refusal": proof,
        }
    finally:
        del frame


class IsolatedComposition:
    def __init__(self, state, append, refuse, system, run):
        self.state, self.append, self.refuse = state, append, refuse
        self.system, self.run = system, run
        self.run_globals = run.__globals__
        self.run_code = run.__code__
        self.pending = None
        self.tail_installed = False
        self.tail_ack = False
        self.probe = object()
        self.add_hook, self.audit = sys.addaudithook, sys.audit
        self.proof = None
        self.codes = None
        self.product = Path(state["checkout"]) / "tools/v04_speed_runner.py"
        self.guard_identity = None
        self.context_globals = vars(contextlib)
        self.context_helper_code = named(contextlib.contextmanager.__code__, "helper")
        self.product_code = compile(
            self.product.read_bytes(), str(self.product), "exec", dont_inherit=True
        )

    def activate(self, proof, target):
        source = Path(self.state["checkout"]) / "tests/test_v04_speed_runner.py"
        if (
            self.state["class"] != CLASS
            or proof["body"] != target
            or sha(source) != proof["source_sha256"]
            or proof["source_sha256"]
            != self.state["product_pins"]["tests/test_v04_speed_runner.py"]
            or hashlib.sha256(target.encode()).hexdigest() != proof["body_sha256"]
            or target != body_for(source, proof["markers"])
            or dict(os.environ) != proof["environment"]
            or os.getcwd() != proof["cwd"]
        ):
            self.refuse("isolated_refusal_activation_drift")
        marker_check(proof["markers"], self.state, self.refuse)
        existing = sys.modules.get("tools.v04_speed_runner")
        if existing is not None and self.guard_identity is None:
            self.guard_identity = existing._guards
        self.proof = proof
        self.codes = compile(target, "<string>", "exec", dont_inherit=True)
        self.append(
            {
                "kind": "isolated_refusal_activated",
                "helper_sha256": proof["body_sha256"],
                "markers": proof["markers"],
                "classification": "CONTROLLED_REGISTERED",
            }
        )

    def tail(self, event, args):
        if event == "unrest.finite.isolated_tail_probe" and args == (self.probe,):
            self.tail_ack = True
        if self.pending == event:
            self.pending = None
            self.refuse("isolated_required_product_rejection_missing")

    def delegate(self, event, args):
        if self.proof is None or event not in (
            "os.system",
            "subprocess.Popen",
            "product.subprocess.wrapper",
        ):
            return False
        source = Path(self.state["checkout"]) / "tests/test_v04_speed_runner.py"
        if (
            sha(source) != self.proof["source_sha256"]
            or self.proof["source_sha256"]
            != self.state["product_pins"]["tests/test_v04_speed_runner.py"]
            or hashlib.sha256(self.proof["body"].encode()).hexdigest() != self.proof["body_sha256"]
            or self.codes != compile(self.proof["body"], "<string>", "exec", dont_inherit=True)
            or sha(sys.executable) != self.state["runtime"]["sha256"]
        ):
            self.refuse("isolated_refusal_binding_drift")
        markers = self.proof["markers"]
        command = "/usr/bin/touch " + markers["marker_system"]
        expected = (
            (command.encode(),)
            if event == "os.system"
            else ((("/usr/bin/touch", markers["marker_run"]),), {})
            if event == "product.subprocess.wrapper"
            else ("/usr/bin/touch", ["/usr/bin/touch", markers["marker_run"]], None, None)
        )
        if args != expected:
            self.refuse("isolated_refusal_command_drift")
        frame = inspect.currentframe()
        try:
            while frame and frame.f_code.co_filename != "<string>":
                frame = frame.f_back
            if frame is None or frame.f_code.co_name != "<lambda>":
                self.refuse("isolated_refusal_alias_frame_drift")
            owner = frame.f_back
            code = next(
                c
                for c in self.codes.co_consts
                if isinstance(c, types.CodeType)
                and c.co_name == "<lambda>"
                and c.co_firstlineno == frame.f_code.co_firstlineno
            )
            local = frame.f_globals
            if (
                frame.f_code != code
                or owner is None
                or owner.f_code != self.codes
                or owner.f_globals is not local
                or local.get("system_alias") is not self.system
                or local.get("run_alias") is not self.run
                or self.run.__globals__ is not self.run_globals
                or self.run.__code__ is not self.run_code
                or self.run_globals is not vars(sys.modules["subprocess"])
            ):
                self.refuse("isolated_refusal_alias_identity_drift")
            if sha(self.product) != self.state["product_pins"]["tools/v04_speed_runner.py"]:
                self.refuse("isolated_refusal_product_source_drift")
            runner = sys.modules.get("tools.v04_speed_runner")
            if runner is None or local.get("runner") is not runner:
                self.refuse("isolated_refusal_product_module_drift")
            for name in ("_audit_hook", "_deny_guarded_attempt", "_active_guard_state"):
                fn = getattr(runner, name, None)
                if (
                    not isinstance(fn, types.FunctionType)
                    or fn.__globals__ is not vars(runner)
                    or fn.__code__ != named(self.product_code, name)
                ):
                    self.refuse("isolated_refusal_product_function_drift")
            guarded = getattr(runner._guards, "__wrapped__", None)
            error_init = runner.SpeedRunnerError.__init__
            error_code = named(self.product_code, "SpeedRunnerError")
            outer = runner._guards
            if (
                outer is not self.guard_identity
                or not isinstance(outer, types.FunctionType)
                or outer.__globals__ is not self.context_globals
                or outer.__code__ is not self.context_helper_code
                or outer.__closure__ is None
                or len(outer.__closure__) != 1
                or outer.__closure__[0].cell_contents is not guarded
                or not isinstance(guarded, types.FunctionType)
                or guarded.__globals__ is not vars(runner)
                or guarded.__code__ != named(self.product_code, "_guards")
                or not isinstance(error_init, types.FunctionType)
                or error_init.__globals__ is not vars(runner)
                or error_init.__code__ != named(error_code, "__init__")
            ):
                self.refuse("isolated_refusal_product_guard_drift")
            controller = getattr(sys, "_unrest_v04_speed_audit_controller", None)
            active = local.get("state")
            index = 0 if event == "os.system" else 1
            if (
                controller is not runner._audit_controller
                or controller["installed"] is not True
                or controller["installations"] != 1
                or controller["depth"] != 1
                or controller["process_state"] is not active
                or controller["states"] != [active]
                or runner._ACTIVE_GUARDS.get() != (active,)
                or local.get("name") != ("system" if index == 0 else "run")
                or active["network_attempts"] != 2
                or active["subprocess_attempts"] != index
                or local.get("before") != (2, index)
                or dict(os.environ) != ENV
                or os.getcwd() != self.proof["cwd"]
            ):
                self.refuse("isolated_refusal_context_drift")
            marker_check(markers, self.state, self.refuse)
            if not self.tail_installed:
                self.add_hook(self.tail)
                self.audit("unrest.finite.isolated_tail_probe", self.probe)
                if not self.tail_ack:
                    self.refuse("isolated_refusal_tail_missing")
                self.tail_installed = True
            self.append(
                {
                    "kind": "required_refusal_no_launch",
                    "classification": "REQUIRED_REFUSAL_NO_LAUNCH",
                    "delegated": True,
                    "event": event,
                    "helper_sha256": self.proof["body_sha256"],
                    "before": {"network": 2, "subprocess": index},
                    "registered_children": 0,
                    "markers": markers,
                }
            )
            self.pending = event
            return True
        finally:
            del frame

    def before_popen(self, args, positional, kwargs):
        if self.proof is None:
            return
        # The precaptured run alias reaches the finite constructor before the
        # native Popen audit. Dispatch the same event without constructing a
        # child; both the finite audit and authentic product hook must see it.
        if positional or kwargs != {}:
            # subprocess.run passes no options for check=False in this helper.
            self.refuse("isolated_refusal_popen_options_drift")
        vector = list(args)
        self.audit("subprocess.Popen", vector[0], vector, None, None)
        self.refuse("isolated_required_product_rejection_missing")

    def observe(self, frame, event):
        if (
            event == "return"
            and frame.f_code.co_name == "<module>"
            and frame.f_code.co_filename == str(self.product)
            and self.guard_identity is None
        ):
            runner = sys.modules.get("tools.v04_speed_runner")
            if runner is not None:
                self.guard_identity = runner._guards
        if (
            self.proof is not None
            and frame.f_code.co_filename == str(self.product)
            and frame.f_code.co_name == "reject_subprocess"
        ):
            if event == "call":
                fn = sys.modules["subprocess"].Popen
                if (
                    not isinstance(fn, types.FunctionType)
                    or fn.__globals__ is not frame.f_globals
                    or fn.__code__ is not frame.f_code
                    or frame.f_code != named(self.product_code, "reject_subprocess")
                ):
                    self.refuse("isolated_refusal_wrapper_identity_drift")
                self.delegate(
                    "product.subprocess.wrapper", (frame.f_locals["args"], frame.f_locals["kwargs"])
                )
            elif event == "return" and self.pending == "product.subprocess.wrapper":
                active = sys.modules["tools.v04_speed_runner"]._active_guard_state()
                if active is None or active["subprocess_attempts"] != 2:
                    self.refuse("isolated_required_product_rejection_missing")
                self.pending = None
        if self.proof is None or event != "return" or frame.f_code != self.codes:
            return
        local = frame.f_locals
        active = local.get("state", {})
        observed = local.get("observed", [])
        if (
            active.get("network_attempts") != 2
            or active.get("subprocess_attempts") != 2
            or len(observed) != 4
            or any(row[1] == "BYPASS" for row in observed)
        ):
            self.refuse("isolated_required_product_oracle_incomplete")
        marker_check(self.proof["markers"], self.state, self.refuse)
        self.append(
            {
                "kind": "isolated_required_refusal_observed",
                "network": 2,
                "subprocess": 2,
                "total": 4,
                "registered_children": 0,
                "markers_absent": True,
                "helper_sha256": self.proof["body_sha256"],
            }
        )
        self.pending = None
