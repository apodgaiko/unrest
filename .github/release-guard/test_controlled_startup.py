"""Actual product/asyncio pre-exec path, stopped before every OS launch.

These controls prove source-derived selection, not child execution, endpoint
custody, the original timing cases or source-checkpoint certification.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import sys

import pytest

from content_manifest import Refused
from control_transport import finite, encode, REQUEST_LIMIT
from controlled_startup import CASES, expected_entry, ACP
from launch_policy import Expected, Rule, render
from content_manifest import capture

sys.path.insert(
    0, str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()))
)

from tests import test_experimental_bootstrap as bootstrap  # noqa: E402
from tests.test_experimental_session import session as owner_fixture  # noqa: E402
from unrest_harness import experimental_session as session  # noqa: E402
from unrest_harness.experimental_diagnostics import StartupDiagnostics  # noqa: E402


@dataclass(frozen=True)
class Observation:
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    payload_kind: str
    payload_sha256: str


@dataclass(frozen=True)
class Intent:
    original: Expected
    translated_argv: tuple[str, ...]
    original_source_line: int
    script_sha256: str | None


ACTIVE = [None]


class StoppedBeforeExec(RuntimeError):
    pass


def audit(event, args):
    handler = ACTIVE[0]
    if handler is None:
        return
    if event == "subprocess.Popen":
        handler(args)
        raise StoppedBeforeExec("source selection completed before exec")
    if event in (
        "os.exec",
        "os.posix_spawn",
        "os.system",
        "os.fork",
        "os.forkpty",
        "socket.bind",
        "socket.connect",
        "os.kill",
        "os.killpg",
    ):
        raise AssertionError("pre-exec source control attempted an external effect")


sys.addaudithook(audit)


class Server:
    sockets = ()

    def __init__(self):
        self.sockets = (self,)

    def getsockname(self):
        return "127.0.0.1", 12345

    def close(self):
        pass

    async def wait_closed(self):
        pass


class OperandModel:
    """Test-only operand comparison; never execution authority or native proof."""

    def __init__(self, owner, checkout, role="worker"):
        self.owner, self.checkout, self.home = owner, checkout, owner.root / role

    def select(self, case, observed):
        native = str(Path(sys.executable).resolve())
        if type(observed.argv) is not tuple or any(type(v) is not str for v in observed.argv):
            raise Refused("nonprimitive command vector")
        backend = observed.argv[1:2] != (str(self.checkout / ACP),)
        relay = None
        if not backend:
            value = self.owner.backends[self.home.name]
            relay = [
                value.bridge.server.sockets[0].getsockname()[1],
                value.bridge.nonce,
                value.lifetime.server.sockets[0].getsockname()[1],
                value.lifetime.nonce,
            ]
        expected, _, pin = expected_entry(
            case,
            self.checkout,
            self.home,
            native,
            hashlib.sha256(Path(native).read_bytes()).hexdigest(),
            backend=backend,
            relay=relay,
        )
        observed_rule = Rule(expected.rule, expected.owner, (case,),
            observed.executable, observed.executable_sha256, observed.argv,
            observed.environment, observed.cwd, observed.payload_kind,
            None if observed.payload_kind=='python-command' else observed.payload_sha256)
        if (type(observed.payload_sha256) is not str or observed.payload_sha256!=expected.payload_sha256
                or render(observed_rule, case, expected.owner, {}, {}) != expected):
            raise Refused('test model operand mismatch')
        if backend:
            file = self.owner.backend_launcher
            assert capture(file.parent, [file.name])["files"][0]["sha256"] == pin
        return Intent(
            expected, (native, "-I", "-S", *expected.argv[1:]), 506 if backend else 553, pin
        )


@pytest.fixture
def context(tmp_path, monkeypatch):
    checkout = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    owner = owner_fixture.__wrapped__(tmp_path, None)

    async def start_server(*args, **kwargs):
        return Server()

    monkeypatch.setattr(asyncio, "start_server", start_server)
    yield OperandModel(owner, checkout), owner
    ACTIVE[0] = None


def observation(args):
    executable, vector, cwd, environment = args
    command = len(vector) > 1 and vector[1] == "-c"
    payload = vector[2].encode() if command else Path(vector[1]).read_bytes()
    return Observation(
        str(executable),
        hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        tuple(vector),
        tuple(sorted(environment.items())),
        str(cwd),
        "python-command" if command else "python-script",
        hashlib.sha256(payload).hexdigest(),
    )


@pytest.mark.parametrize("case", CASES)
def test_real_product_caller_and_original_asyncio_options_select_backend_before_exec(
    context, monkeypatch, case
):
    gate, owner = context
    if case == CASES[1]:
        bootstrap.delayed_backend.__wrapped__(monkeypatch)(0.5)
    selected = []

    def inspect(args):
        intent = gate.select(case, observation(args))
        request = {
            "case": case,
            "original": intent.original.wire(),
            "translated": list(intent.translated_argv),
            "source_line": intent.original_source_line,
            "script_sha256": intent.script_sha256,
        }
        finite(request)
        assert __import__("json").loads(encode(request, REQUEST_LIMIT)[4:]) == request
        selected.append(intent)

    ACTIVE[0] = inspect

    async def run():
        try:
            with pytest.raises(StoppedBeforeExec):
                await owner._open_role_owned("worker", StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()

    asyncio.run(run())
    assert len(selected) == 1
    assert selected[0].original_source_line == 506
    assert selected[0].translated_argv[1:3] == ("-I", "-S")
    assert not owner.backends and not owner.roles


@pytest.mark.parametrize(
    "mutation", ["case", "argv", "cwd", "environment", "payload", "runtime", "controlled"]
)
def test_source_selection_refuses_drift_without_starting_a_child(context, mutation):
    gate, owner = context
    seen = []
    if mutation == "controlled":
        owner.controlled = False

    def inspect(args):
        observed = observation(args)
        if mutation == "argv":
            observed = replace(observed, argv=(*observed.argv, "foreign"))
        elif mutation == "cwd":
            observed = replace(observed, cwd="/foreign")
        elif mutation == "environment":
            observed = replace(observed, environment=(*observed.environment, ("FOREIGN", "1")))
        elif mutation == "payload":
            observed = replace(observed, payload_sha256="0" * 64)
        elif mutation == "runtime":
            observed = replace(observed, executable_sha256="0" * 64)
        seen.append("preexec")
        gate.select("foreign" if mutation == "case" else CASES[0], observed)

    ACTIVE[0] = inspect

    async def run():
        try:
            with pytest.raises((Refused, session.LeaseRefused)):
                await owner._open_role_owned("worker", StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()

    asyncio.run(run())
    assert not owner.backends and not owner.roles
    assert seen == ([] if mutation == "controlled" else ["preexec"])


class Pipe:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name, default=None):
        return default


class BackendModel:
    """No PID or OS process. Only supplies the protocol preceding ACP selection."""

    def __init__(self, protocol):
        self.pipes = {index: Pipe() for index in range(3)}
        protocol.connection_made(self)
        protocol.stdout.feed_eof()
        protocol.stderr.feed_eof()
        protocol._stdin_closed.set_result(None)

    def get_pipe_transport(self, index):
        return self.pipes[index]

    def get_pid(self):
        return 0

    def get_returncode(self):
        return 0

    async def _wait(self):
        return 0

    def close(self):
        for pipe in self.pipes.values():
            pipe.close()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("mutation", [None, "relay"])
def test_actual_acp_preexec_branch_and_original_defaults(context, monkeypatch, case, mutation):
    gate, owner = context
    if case == CASES[1]:
        bootstrap.delayed_backend.__wrapped__(monkeypatch)(0.5)
    selected, models = [], []

    def inspect(args):
        if mutation == "relay":
            args[3]["SYNTHETIC_RELAY"] = '[1, "foreign", 2, "foreign"]'
        selected.append(gate.select(case, observation(args)))

    ACTIVE[0] = inspect

    async def run():
        loop = asyncio.get_running_loop()
        original = loop._make_subprocess_transport

        async def make(protocol, args, *values, **keywords):
            if str(owner.backend_launcher) in args:
                model = BackendModel(protocol)
                models.append(model)
                return model
            return await original(protocol, args, *values, **keywords)

        monkeypatch.setattr(loop, "_make_subprocess_transport", make)
        try:
            with pytest.raises(StoppedBeforeExec if mutation is None else Refused):
                await owner._open_role_owned("worker", StartupDiagnostics())
        finally:
            try:
                await owner.close()
            finally:
                ACTIVE[0] = None

    asyncio.run(run())
    assert len(models) == 1
    assert not owner.roles  # no ACP body was started
    if mutation is None:
        assert len(selected) == 1 and selected[0].original_source_line == 553
        assert selected[0].original.argv[-1] == "--controlled-local-acp-v1"
    else:
        assert not selected


@pytest.mark.parametrize(
    "field", ["environment-key", "environment-value", "argv", "payload", "cwd"]
)
def test_live_context_refuses_callback_objects_without_invoking_them(context, field):
    gate, owner = context

    class Trap:
        def __hash__(self):
            return 421771

        def __eq__(self, other):
            pytest.fail("operand equality callback")

        def __iter__(self):
            pytest.fail("operand iteration callback")

    def inspect(args):
        value = observation(args)
        if field == "environment-key":
            value = replace(value, environment=((Trap(), "value"),))
        elif field == "environment-value":
            value = replace(value, environment=(("HOME", Trap()),))
        elif field == "argv":
            value = replace(value, argv=(value.argv[0], Trap()))
        elif field == "payload":
            value = replace(value, payload_sha256=Trap())
        else:
            value = replace(value, cwd=Trap())
        gate.select(CASES[0], value)

    ACTIVE[0] = inspect

    async def run():
        try:
            with pytest.raises(Refused):
                await owner._open_role_owned("worker", StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()

    asyncio.run(run())
    assert not owner.backends and not owner.roles


@pytest.mark.parametrize(
    "case",
    [
        "tests/test_controlled_python_acp.py::test_single_c1_fixed_timing_protocol_witness",
        "tests/test_experimental_ack_durability.py::test_ack_durability[False--1-None-write]",
    ],
)
def test_finite_unconfigured_owner_selection_uses_actual_backend_bytes(tmp_path, monkeypatch, case):
    from controlled_cases import CASES as CONTROLLED
    from tests.test_experimental_finite_orders import CompletionBarriers

    if "ack_durability" in case:
        case = next(name for name in CONTROLLED if "test_ack_durability[" in name)
    checkout = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    owner = owner_fixture.__wrapped__(tmp_path, None)
    gate = OperandModel(owner, checkout, "validator")
    if "ack_durability" in case:
        barriers = CompletionBarriers(monkeypatch, tmp_path)
        owner.backend_launcher.write_bytes(barriers.fixture.read_bytes())
        owner.backend_digest = hashlib.sha256(owner.backend_launcher.read_bytes()).hexdigest()

    async def start_server(*args, **kwargs):
        return Server()

    monkeypatch.setattr(asyncio, "start_server", start_server)
    selected = []

    def inspect(args):
        selected.append(gate.select(case, observation(args)))

    ACTIVE[0] = inspect

    async def run():
        try:
            with pytest.raises(StoppedBeforeExec):
                await owner._open_role_owned("validator", StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()

    asyncio.run(run())
    assert len(selected) == 1 and selected[0].original.argv[-1] == "app-server"
    assert selected[0].original.cwd == str(owner.root / "validator")


@pytest.mark.parametrize(
    "mutation", ["unrelated-sibling", "file-parent", "ancestor-replaced", "leaf-replaced"]
)
def test_owned_postimage_capture_binds_its_path_without_unrelated_subtree_clock(
    tmp_path, monkeypatch, mutation
):
    import os
    import content_manifest

    target = tmp_path / "common" / "owner" / "backend"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"pinned backend")
    pin = hashlib.sha256(target.read_bytes()).hexdigest()
    inode = target.stat().st_ino
    read = os.read
    changed = []

    def reading(fd, count):
        block = read(fd, count)
        if block and os.fstat(fd).st_ino == inode and not changed:
            changed.append(True)
            if mutation == "unrelated-sibling":
                (tmp_path / "common" / "other-owner").mkdir()
            elif mutation == "file-parent":
                (target.parent / "new-role").mkdir()
            elif mutation == "ancestor-replaced":
                tmp_path.rename(tmp_path.with_name(tmp_path.name + "-saved"))
                tmp_path.mkdir()
            else:
                target.rename(target.with_name("saved"))
                target.write_bytes(b"pinned backend")
        return block

    monkeypatch.setattr(content_manifest.os, "read", reading)
    if mutation == "unrelated-sibling":
        assert capture(target.parent, [target.name])["files"][0]["sha256"] == pin
    else:
        with pytest.raises(Refused):
            assert capture(target.parent, [target.name])["files"][0]["sha256"] == pin
    assert changed
