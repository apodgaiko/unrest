"""One original no-launch oracle; tail audit prevents a failed product rejection."""

import ast
import hashlib
import inspect
import os
from pathlib import Path
import sys
import types

NAME = "test_audit_and_wrapper_denials_each_count_exactly_once"
ENV = {"LANG": "C", "LC_ALL": "C", "PYTHONUTF8": "1", "TZ": "UTC"}


def code_named(code, name, line=None):
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            if item.co_name == name and (line is None or item.co_firstlineno == line):
                return item
            found = code_named(item, name, line)
            if found is not None:
                return found
    return None


class Composition:
    def __init__(self, state, append, refuse, system):
        self.state, self.append, self.refuse, self.system = state, append, refuse, system
        self.tail_installed = False
        self.pending = False
        self.add_hook = sys.addaudithook
        self.audit = sys.audit
        self.tail_ack = False
        self.probe_identity = object()
        self.source = Path(state["checkout"]) / "tests/test_v04_speed_runner.py"
        self.product = Path(state["checkout"]) / "tools/v04_speed_runner.py"
        self.codes = {}
        for path in (self.source, self.product):
            body = path.read_bytes()
            if (
                hashlib.sha256(body).hexdigest()
                != state["product_pins"][str(path.relative_to(state["checkout"]))]
            ):
                refuse("refusal_composition_source_drift")
            tree = ast.parse(body, filename=str(path))
            if path == self.source and "_pytest.assertion.rewrite" in sys.modules:
                from _pytest.assertion.rewrite import rewrite_asserts

                rewrite_asserts(tree, body, str(path))
            self.codes[path] = compile(tree, str(path), "exec", dont_inherit=True)
        # A product-first hook could hide unknown routes from the finite audit.
        if getattr(sys, "_unrest_v04_speed_audit_controller", {}).get("installed"):
            refuse("refusal_composition_hook_order")

    def observe(self, frame, event):
        if (
            event == "return"
            and frame.f_code.co_name == NAME
            and frame.f_code.co_filename == str(self.source)
            and self.pending
        ):
            active = frame.f_locals["state"]
            if active["network_attempts"] != 2 or active["subprocess_attempts"] != 2:
                self.refuse("required_product_refusal_counter_mismatch")
            self.append(
                {
                    "kind": "required_refusal_observed",
                    "network": 2,
                    "subprocess": 2,
                    "total": 4,
                    "registered_children": 0,
                    "oracle": NAME,
                }
            )
            self.pending = False

    def tail(self, event, args):
        if event == "unrest.finite.refusal_tail_probe" and args == (self.probe_identity,):
            self.tail_ack = True
        if event == "os.system" and self.pending:
            self.pending = False
            self.refuse("required_product_rejection_missing")

    def delegate(self, event, args):
        self.pending = False
        if event != "os.system" or args != (b"true",):
            return False
        frame = inspect.currentframe()
        try:
            while frame and frame.f_code.co_filename != str(self.source):
                frame = frame.f_back
            if frame is None:
                return False
            alias_frame = frame
            owner = frame.f_back
            if (
                alias_frame.f_lineno != 1514
                or owner is None
                or owner.f_code.co_name != NAME
                or owner.f_code.co_filename != str(self.source)
                or owner.f_lineno != 1519
            ):
                return False
            for path in (self.source, self.product):
                if (
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    != self.state["product_pins"][str(path.relative_to(self.state["checkout"]))]
                ):
                    self.refuse("refusal_composition_source_drift")
            fn = owner.f_globals.get(NAME)
            if (
                not isinstance(fn, types.FunctionType)
                or fn.__globals__ is not owner.f_globals
                or fn.__code__ is not owner.f_code
                or owner.f_code != code_named(self.codes[self.source], NAME)
                or alias_frame.f_code != code_named(self.codes[self.source], "<lambda>", 1514)
                or owner.f_locals.get("system_alias") is not self.system
            ):
                self.refuse("refusal_composition_function_drift")
            runner = sys.modules.get("tools.v04_speed_runner")
            if runner is None or owner.f_globals.get("runner") is not runner:
                return False
            for name in ("_audit_hook", "_deny_guarded_attempt", "_active_guard_state"):
                function = getattr(runner, name, None)
                if (
                    not isinstance(function, types.FunctionType)
                    or function.__globals__ is not vars(runner)
                    or function.__code__ != code_named(self.codes[self.product], name)
                ):
                    self.refuse("refusal_composition_product_function_drift")
            controller = getattr(sys, "_unrest_v04_speed_audit_controller", None)
            local = owner.f_locals
            active = local.get("state")
            if (
                controller is not runner._audit_controller
                or controller["installed"] is not True
                or controller["installations"] != 1
                or controller["depth"] != 1
                or controller["process_state"] is not active
                or controller["states"] != [active]
                or runner._ACTIVE_GUARDS.get() != (active,)
                or local.get("before") != 3
                or local.get("expected_index") != 4
                or active["network_attempts"] != 2
                or active["subprocess_attempts"] != 1
                or os.getcwd() != self.state["checkout"]
                or dict(os.environ) != ENV
            ):
                self.refuse("refusal_composition_context_drift")
            if not self.tail_installed:
                self.add_hook(self.tail)
                self.audit("unrest.finite.refusal_tail_probe", self.probe_identity)
                if not self.tail_ack:
                    self.refuse("required_product_rejection_tail_missing")
                self.tail_installed = True
            self.append(
                {
                    "kind": "required_refusal_no_launch",
                    "classification": "REQUIRED_REFUSAL_NO_LAUNCH",
                    "delegated": True,
                    "event": event,
                    "command_sha256": hashlib.sha256(args[0]).hexdigest(),
                    "path": str(self.source),
                    "line": 1514,
                    "source_sha256": self.state["product_pins"]["tests/test_v04_speed_runner.py"],
                    "function": NAME,
                    "cwd": os.getcwd(),
                    "environment_sha256": hashlib.sha256(
                        repr(sorted(ENV.items())).encode()
                    ).hexdigest(),
                    "before": {"network": 2, "subprocess": 1, "total": 3},
                    "registered_children": 0,
                    "tail_installed": self.tail_installed,
                }
            )
            self.pending = True
            return True
        finally:
            del frame
