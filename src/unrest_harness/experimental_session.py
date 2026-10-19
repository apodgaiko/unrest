"""Opt-in retained ACP owners, separate from ordinary dispatch.

Trusted processes only. Strong OS write isolation and ownership of unknown
descendants are unverified. Controlled and real backends share transport custody.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import time
from typing import Any, Callable, Literal

import uvicorn

from .acp_runner import ACPClient, _acp_subprocess_env, _redact_json_value
from .capability_policy import ResolvedRoleCapability
from .experimental_relay import Bridge, ConnectionCleanup
from .experimental_diagnostics import (
    StartupDiagnostics, startup_timeout, startup_timeout_at,
)
from .experimental_broker import broker_server
from .experimental_confinement import ADAPTER_SHA256, check_pin
from .experimental_provider import CODEX_SHA256, check_package
from .experimental_provider_config import PREFLIGHT_BYTES, ProviderConfig, ThreadObservation
from .experimental_lease import REAL_PROVIDER
from .providers import PROVIDERS
from .experimental_lease import Completion, LeaseRefused, PilotLedger, TurnBroker, TurnIdentity

# Node v22.22.0 darwin-arm64, independently verified against nodejs.org release archive.
NODE_SHA256 = '913b144fdb40638b1acef7974ab3c33fbd527cc0974cb5da467ab1e6ac51b4d4'

FIXTURE_SHA256 = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'


CONTROLLED_ACP_SHA256 = 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'


@dataclass(frozen=True)
class _TrustedTestRuntime:
    path: Path
    realpath: Path
    sha256: str

    def verify(self, interpreter: Path) -> None:
        if (sys.implementation.name != 'cpython' or sys.version_info < (3, 13)
                or Path(sys.executable) != self.path or interpreter != self.path
                or interpreter.resolve() != self.realpath):
            raise LeaseRefused('controlled_interpreter_identity_mismatch')
        check_pin(self.realpath, self.sha256)


# Capture the executing runtime before any caller selects a transport. The pin
# belongs to this process instance, not a platform, configuration or caller hash.
_TRUSTED_TEST_RUNTIME = _TrustedTestRuntime(
    Path(sys.executable), Path(sys.executable).resolve(),
    hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest())


@dataclass(frozen=True)
class ControlledTransport:
    """Internal local-only transport selection, never inferred from a backend.

    This fixture exercises ACP wire behavior; it does not establish native
    adapter conversion. No caller-defined commands, hashes or flags are accepted.
    """

    fixture: Path
    interpreter: Path
    _runtime: _TrustedTestRuntime = field(default=_TRUSTED_TEST_RUNTIME, init=False, repr=False)

    def verify(self, *, controlled: bool, package: Path | None) -> None:
        if controlled is not True or package is not None:
            raise LeaseRefused('controlled_transport_requires_local_setup')
        if type(self) is not ControlledTransport:
            raise LeaseRefused('invalid_controlled_transport')
        if self._runtime is not _TRUSTED_TEST_RUNTIME:
            raise LeaseRefused('invalid_controlled_runtime_binding')
        check_pin(self.fixture, CONTROLLED_ACP_SHA256)
        self._runtime.verify(self.interpreter)

    def argv(self) -> tuple[str, ...]:
        self.verify(controlled=True, package=None)
        return (str(self.interpreter.resolve()), str(self.fixture.resolve()),
                '--controlled-local-acp-v1')


def verify_transport(transport: ControlledTransport | None, *, controlled: bool,
                     package: Path | None, adapter: Path) -> None:
    if transport is None:
        check_pin(adapter, ADAPTER_SHA256)
        check_pin(adapter.parents[5] / 'bin/node', NODE_SHA256)
    elif type(transport) is ControlledTransport:
        transport.verify(controlled=controlled, package=package)
    else:
        raise LeaseRefused('invalid_controlled_transport')


class _TurnClient(ACPClient):
    """Experimental send observation after bytes reach the owned pipe.

    This does not acknowledge backend receipt. A failed drain remains ambiguous
    and consumes the reservation without granting permission to drain after stop.
    """

    before_prompt: Callable[[], None] | None = None
    after_prompt: Callable[[], None] | None = None

    async def _write(self, msg: dict[str, Any]) -> None:
        if msg.get('method') != 'session/prompt':
            await super()._write(msg)
            return
        assert self._process.stdin is not None
        safe_msg = _redact_json_value(
            msg, self._credentials if self._wire_credentials is None else self._wire_credentials)
        data = json.dumps(safe_msg).encode('utf-8') + b'\n'
        # Serialization can consume the remaining allowance. Guard the actual
        # pipe write, with no intervening await or preparation after admission.
        if self.before_prompt is not None:
            self.before_prompt()
        self._process.stdin.write(data)
        await self._process.stdin.drain()
        if self.after_prompt is not None:
            self.after_prompt()



@dataclass
class _FixtureLifetime:
    """Exit observation for the pinned, non-forking fixture only, never a PID oracle."""

    nonce: str = field(default_factory=lambda: secrets.token_hex(32))
    connected: asyncio.Event = field(default_factory=asyncio.Event)
    exited: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: set[asyncio.Task[None]] = field(default_factory=set)
    server: asyncio.Server | None = None
    closing: bool = False
    claimed: bool = False
    on_exit: Callable[[], None] | None = None
    writer: asyncio.StreamWriter | None = None
    cleanup: ConnectionCleanup = field(default_factory=ConnectionCleanup)

    def accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.cleanup.register(writer)
        if self.closing or self.claimed:
            writer.close()
            return
        self.claimed = True
        self.writer = writer
        assert self.server is not None
        self.server.close()
        task = asyncio.create_task(self.observe(reader, writer))
        self.tasks.add(task)

    async def observe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(1):
                greeting = await reader.readexactly(65)
            if greeting != (self.nonce + '\n').encode() or self.connected.is_set():
                return
            self.connected.set()
            assert self.server is not None
            self.server.close()
            # The pinned relay keeps its sole socket alive until interpreter exit.
            # Unexpected payload or connection failure is not an exit acknowledgement.
            if await reader.read(1) == b'':
                self.exited.set()

        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if not self.closing and self.on_exit is not None:
                self.on_exit()
            writer.close()
            # The retained close owner alone waits on the shared close future.

    async def close(self) -> None:
        self.closing = True
        await self.cleanup.close(self.server, self.tasks)


@dataclass
class _Backend:
    process: asyncio.subprocess.Process
    lifetime: _FixtureLifetime
    bridge: Bridge
    stop_task: asyncio.Task[None] | None = None
    watch: asyncio.Task[None] | None = None
    stderr: asyncio.Task[None] | None = None
    diagnostic_bytes: int = 0
    diagnostic_truncated: bool = False


@dataclass
class _Role:
    process: asyncio.subprocess.Process
    client: ACPClient
    generation: str
    session: str = ''
    ordinal: int = 0
    opening_updates: list[str] | None = None
    stop_task: asyncio.Task[None] | None = None
    lifetime: _FixtureLifetime | None = None
    watch: asyncio.Task[None] | None = None


class _SessionOwner:
    """One async lifecycle owner, serial turns, two retained role transports.

    `root` must not exist. Policy is supplied for ACP compatibility only; exclusive
    callbacks prevent invoking ordinary policy handlers. No environment or
    command override is accepted. `fixture` bytes are pinned before copying.
    """

    def __init__(self, root: Path, candidate: Path, scope: tuple[str, ...], *,
                 adapter: Path, fixture: Path, policy: ResolvedRoleCapability,
                 controlled: bool = True, ledger: PilotLedger | None = None,
                 lane: str = 'synthetic', provider_package: Path | None = None,
                 drain_after_halt: bool = False,
                 provider_config: ProviderConfig | None = None,
                 transport: ControlledTransport | None = None):
        self.controlled, self.lane = controlled, lane
        self.drain_after_halt = drain_after_halt
        self.drain_requested = False
        self.on_failure: Callable[[BaseException | None], None] | None = None
        self.failure: BaseException | None = None
        self._acknowledged = False
        self.sent_active = False
        self.last_completion: Completion | None = None
        self.provider_config = provider_config
        self.startup_diagnostics: dict[str, StartupDiagnostics] = {}
        self.owner_diagnostics = StartupDiagnostics()
        self._pre_cleanup: dict[str, object] | None = None
        self.thread_observations: dict[str, ThreadObservation] = {}
        self._owns_ledger = ledger is None
        verify_transport(transport, controlled=controlled, package=provider_package, adapter=adapter)
        self.transport = transport
        self.provider_package = provider_package
        if controlled:
            check_pin(fixture, FIXTURE_SHA256)
        elif check_package(provider_package) != fixture:
            raise LeaseRefused('provider_package_backend_mismatch')
        node = adapter.parents[5] / 'bin' / 'node' if transport is None else Path(sys.executable)
        if transport is None and not node.is_file():
            raise LeaseRefused('pinned_adapter_node_missing')
        if transport is None:
            check_pin(node, NODE_SHA256)
        root.mkdir(mode=0o700)
        self.root, self.scope, self.policy = root, scope, policy
        self.adapter, self.node = adapter.resolve(), node.resolve()
        self.backend_launcher = root / 'fake-app-server' if controlled else fixture
        if controlled:
            self.backend_launcher.write_bytes(fixture.read_bytes())
        self.backend_digest = (hashlib.sha256(self.backend_launcher.read_bytes()).hexdigest()
                               if controlled else CODEX_SHA256)
        self.launcher = root / 'fixed-relay'
        relay = Path(__file__).with_name('experimental_relay.py').read_bytes()
        self.launcher.write_bytes(('#!' + sys.executable + '\n').encode() + relay)
        self.launcher.chmod(0o500)
        self.launcher_digest = hashlib.sha256(self.launcher.read_bytes()).hexdigest()
        self.roles: dict[str, _Role] = {}
        self.backends: dict[str, _Backend] = {}
        self._lock = asyncio.Lock()
        self._launches: set[asyncio.Task[Any]] = set()
        self._claims: list[str] = []
        self._close_task: asyncio.Task[None] | None = None
        self._server_task: asyncio.Task[None] | None = None
        self._server: uvicorn.Server | None = None
        self._listener: socket.socket | None = None
        self._monitor: asyncio.Task[None] | None = None
        self._watchdog: asyncio.Task[None] | None = None
        self._connection = secrets.token_urlsafe(48)
        self.url = ''
        self.stopped = False
        self.quarantined = False
        self._closing = False
        self._fault = asyncio.Event()
        self._unstarted_closed = False
        self.broker = TurnBroker(candidate, root / 'completions')
        try:
            self.ledger = ledger if ledger is not None else PilotLedger(root / 'journal.jsonl')
        except BaseException:
            self.broker.close()
            raise

    def _revoke(self, *, quarantine: bool) -> None:
        # Synchronous: authority is gone before cancellation or process teardown.
        self.broker.park()
        for observation in self.thread_observations.values():
            observation.stop()
        self._observe_before_cleanup()
        self.quarantined |= quarantine
        if not self.stopped:
            self.stopped = True
            try:
                if quarantine and self.on_failure is not None:
                    self.on_failure(self.failure)
                self._record_stop('stop')
                if quarantine or self._owns_ledger:
                    self.ledger.stop(quarantine=quarantine)
            except Exception:
                self.quarantined = True
        self._fault.set()
        if self._close_task is None:
            self._closing = True
            self._close_task = asyncio.create_task(self._close())

    def request_drain(self) -> None:
        """Called synchronously before the coordinator halts a usable ledger."""
        if self.drain_after_halt and self.sent_active and not self.stopped and not self.quarantined:
            self.drain_requested = True

    def complete_turn(self) -> None:
        """Commit successful custody processing and retirement without a yield.

        Acknowledgement owns the original ticket cutoff. Custody processing keeps
        the original episode/campaign bounds, not a new inference deadline.
        """
        if self.stopped or self.quarantined or not self._acknowledged:
            raise LeaseRefused('turn_not_acknowledged')
        if (self._server_task is None or self._server_task.done()
                or not all(self._healthy(name, role) for name, role in self.roles.items())):
            raise LeaseRefused('transport_lost')
        self.ledger.lifetime_remaining(drain=self.drain_requested)
        if self.drain_requested:
            self._revoke(quarantine=False)
        self.sent_active = False

    def _record_stop(self, name: str) -> None:
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            payload = (json.dumps({'controlled': self.controlled, 'resumable': False,
                                   'os_write_isolation': 'unverified'}, sort_keys=True) + '\n').encode()
            while payload:
                written = os.write(fd, payload)
                if written <= 0:
                    raise OSError('stop_record_short_write')
                payload = payload[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _callback(self, role: _Role, method: str, params: dict[str, Any]) -> None:
        session = params.get('sessionId') if isinstance(params, dict) else None
        valid = (method == 'session/update' and type(session) is str and bool(session)
                 and isinstance(params.get('update'), dict))
        if valid and not role.session and role.opening_updates is not None:
            role.opening_updates.append(str(session))
            return
        if not valid or session != role.session:
            self._revoke(quarantine=True)
            raise LeaseRefused('callback_or_session_violation')

    async def start(self, episode: str = 'P2') -> None:
        async with self._lock:
            if self.stopped or self._server_task is not None:
                raise LeaseRefused('session_unavailable')
            try:
                self.owner_diagnostics.phase('broker_start')
                if self._owns_ledger:
                    self.ledger.admit(episode)
                else:
                    self.ledger.lifetime_remaining()
                listener = self._listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                self.url = f'http://127.0.0.1:{listener.getsockname()[1]}/mcp'
                # Finite stateless calls need no SSE lifetime or process-global drain state.
                app = broker_server(self.broker, self._connection).http_app(
                    stateless_http=True, json_response=True)
                self._server = uvicorn.Server(uvicorn.Config(
                    app, log_level='critical', access_log=False))
                self._server_task = asyncio.create_task(self._server.serve(sockets=[listener]))
                async with startup_timeout(3, 'broker_start'):
                    while not self._server.started:
                        if self._server_task.done():
                            raise LeaseRefused('broker_unavailable')
                        await asyncio.sleep(.01)
                self._monitor = asyncio.create_task(self._watch_broker())
                self._watchdog = asyncio.create_task(self._watch_deadline())
            except BaseException as error:
                self.owner_diagnostics.fail(error)
                self._revoke(quarantine=True)
                try:
                    await self.close()
                except (Exception, asyncio.CancelledError):
                    # close records cleanup separately; preserve the startup cause.
                    pass
                raise

    async def _watch_broker(self) -> None:
        assert self._server_task is not None
        try:
            await asyncio.shield(self._server_task)
        except asyncio.CancelledError:
            return
        except Exception:
            pass
        if not self._closing:
            self._revoke(quarantine=True)

    async def _watch_deadline(self) -> None:
        try:
            while not self.stopped:
                self.ledger.lifetime_remaining(drain=self.drain_requested and self.sent_active)
                await asyncio.sleep(.02)
        except asyncio.CancelledError:
            return
        except Exception:
            self._revoke(quarantine=True)

    def _environment(self, home: Path) -> dict[str, str]:
        if not self.controlled:
            environment = _acp_subprocess_env(
                PROVIDERS['codex'], policy=self.policy,
                model='gpt-6-astra', reasoning_effort='medium')
            # Keep the ordinary supported subscription HOME/config route. This
            # is defense in depth, not the refused OS sanitizer/bootstrap.
            config = json.loads(environment['CODEX_CONFIG'])
            config.update({'sandbox_mode': 'read-only', 'approval_policy': 'never',
                           'forced_login_method': 'chatgpt', 'model_provider': 'openai'})
            config['features'] = {**config.get('features', {}), 'shell_tool': False}
            if self.provider_config is None:
                user_home = Path(environment.get('HOME', str(Path.home())))
                self.provider_config = ProviderConfig(
                    codex_home=Path(environment.get('CODEX_HOME', str(user_home / '.codex'))),
                    user_home=user_home, cwd=self.root, ambient=config)
            self.provider_config.inputs.verify()
            environment['CODEX_HOME'] = str(self.provider_config.codex_home)
            environment['CODEX_CONFIG'] = json.dumps(self.provider_config.thread_config(home), sort_keys=True)
            environment['TMPDIR'] = str(home / 'tmp')
            environment['INITIAL_AGENT_MODE'] = 'read-only'
            environment['CODEX_PATH'] = str(self.launcher)
            for key in ('CODEX_SANDBOX', 'CODEX_DISABLE_SANDBOX', 'OPENAI_API_KEY',
                        'CODEX_API_KEY', 'DEFAULT_AUTH_REQUEST', 'MODEL_PROVIDER', 'APP_SERVER_LOGS'):
                environment.pop(key, None)
            return environment
        # Controlled processes never inherit subscription credentials.
        environment = {'HOME': str(home), 'CODEX_HOME': str(home / 'codex'),
                'TMPDIR': str(home / 'tmp'), 'PATH': '/usr/bin:/bin',
                'INITIAL_AGENT_MODE': 'read-only', 'CODEX_PATH': str(self.launcher)}
        if self.provider_config is not None:
            environment['CODEX_CONFIG'] = json.dumps(self.provider_config.thread_config(home), sort_keys=True)
        return environment

    async def _open_role(self, name: str) -> _Role:
        diagnostic = self.startup_diagnostics.setdefault(name, StartupDiagnostics())
        try:
            return await self._open_role_owned(name, diagnostic)
        except BaseException as error:
            diagnostic.fail(error)
            raise

    async def _open_role_owned(self, name: str, diagnostic: StartupDiagnostics) -> _Role:
        diagnostic.phase('pin_check')
        verify_transport(self.transport, controlled=self.controlled,
                         package=self.provider_package, adapter=self.adapter)
        if self.transport is None:
            check_pin(self.node, NODE_SHA256)
        check_pin(self.launcher, self.launcher_digest)
        if not self.controlled:
            if check_package(self.provider_package) != self.backend_launcher:
                raise LeaseRefused('provider_package_backend_mismatch')
        else:
            check_pin(self.backend_launcher, self.backend_digest)
        self._claims.append(self.ledger.claim_session())
        home = self.root / name
        home.mkdir(mode=0o700)
        (home / 'codex').mkdir()
        (home / 'tmp').mkdir()
        (home / 'sqlite').mkdir(mode=0o700)
        (home / 'logs').mkdir(mode=0o700)
        environment = self._environment(home)
        backend_environment = {key: value for key, value in environment.items()
                               if key not in ('CODEX_PATH', 'INITIAL_AGENT_MODE')}
        interpreter = sys.executable if self.transport is None else str(self.transport.interpreter.resolve())
        argv = [interpreter, str(self.backend_launcher), 'app-server']
        if not self.controlled:
            assert self.provider_config is not None
            argv = self.provider_config.argv(self.backend_launcher, home)
        elif self.provider_config is not None:
            argv = [interpreter, *self.provider_config.argv(self.backend_launcher, home)]
        def backend_exited() -> None:
            if not self._closing:
                self._revoke(quarantine=True)
        lifetime = _FixtureLifetime(on_exit=backend_exited)
        lifetime.server = await asyncio.start_server(lifetime.accept, '127.0.0.1', 0)
        port = lifetime.server.sockets[0].getsockname()[1]
        try:
            diagnostic.phase('backend_spawn')
            if self.transport is not None:
                self.transport.verify(controlled=self.controlled, package=self.provider_package)
            backend_process = await asyncio.create_subprocess_exec(
                *argv, cwd=home,
                env=backend_environment, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                close_fds=True, start_new_session=True, limit=PREFLIGHT_BYTES - 1)
        except BaseException:
            await lifetime.close()
            raise
        assert backend_process.stdout is not None and backend_process.stdin is not None
        bridge = Bridge(backend_process.stdout, backend_process.stdin, backend_exited,
                        diagnostic_phase=diagnostic.phase, diagnostic_failure=diagnostic.fail)
        if self.provider_config is not None:
            observation = self.thread_observations[name] = ThreadObservation(
                self.provider_config.thread_config(home),
                {'url': self.url, 'http_headers': {'Authorization': 'Bearer ' + self._connection}})
            bridge.observe_adapter = observation.adapter
            bridge.observe_backend = observation.backend
            bridge.restrict_adapter = observation.restrict_adapter
            bridge.restrict_backend = observation.restrict_backend
            async def admit(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                assert backend_process.stdout is not None and backend_process.stdin is not None
                assert self.provider_config is not None
                await self.provider_config.admit_bridge(
                    reader, writer, backend_process.stdout, backend_process.stdin, home, diagnostic.phase)
                if self.stopped:
                    raise LeaseRefused('session_stopped_during_launch')
                observation.seal_configuration(
                    self.provider_config.effective_digests[str(home)], str(home),
                    self.provider_config.inputs.verify)
            bridge.admit = admit
        backend = _Backend(backend_process, lifetime, bridge)
        self.backends[name] = backend  # Returned handle registered before any await.
        backend.stderr = asyncio.create_task(self._drain_backend_stderr(backend))
        backend.watch = asyncio.create_task(self._watch_process(backend_process))
        if self.stopped:
            await self._stop_backend(backend)
            raise LeaseRefused('session_stopped_during_launch')
        diagnostic.phase('bridge_listen')
        relay_port = await bridge.start()
        if self.stopped:
            await self._stop_backend(backend)
            raise LeaseRefused('session_stopped_during_launch')
        environment['SYNTHETIC_RELAY'] = json.dumps(
            [relay_port, bridge.nonce, port, lifetime.nonce])
        diagnostic.phase('adapter_spawn')
        adapter_argv = ((str(self.node), str(self.adapter)) if self.transport is None
                        else self.transport.argv())
        process = await asyncio.create_subprocess_exec(
            *adapter_argv, cwd=home, env=environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, close_fds=True, start_new_session=True)
        # Registration is in the retained launch task, before its next await.
        client = _TurnClient(process, str(home), self.policy, {},
                           exclusive_callback=lambda method, params: self._callback(role, method, params),
                           transport_closed=lambda: self._revoke(quarantine=True) if not self._closing else None,
                           wire_credentials={})
        role = _Role(process, client, secrets.token_hex(24), opening_updates=[], lifetime=lifetime)
        self.roles[name] = role
        role.watch = asyncio.create_task(self._watch_process(process))
        if self.stopped:
            # A late registration remains owned even after the bounded close failed.
            await self._stop_role(role)
            raise LeaseRefused('session_stopped_during_launch')
        await client.start()
        if self.stopped:
            raise LeaseRefused('session_stopped_during_launch')
        async with startup_timeout(None, 'acp_initialize_session'):
            diagnostic.phase('acp_initialize')
            result = await client.send_request('initialize', {
                'protocolVersion': 1, 'clientCapabilities': {},
                'clientInfo': {'name': 'experimental-lease', 'version': '1'}})
            expected_agent = ({'name': 'controlled-python-acp', 'version': 'local-1'}
                              if self.transport is not None else None)
            if ((expected_agent is not None and result.get('agentInfo') != expected_agent)
                    or (expected_agent is None
                        and result.get('agentInfo', {}).get('version') != '1.1.0')):
                raise LeaseRefused('adapter_version_mismatch')
            if self.stopped:
                raise LeaseRefused('session_stopped_during_launch')
            diagnostic.phase('acp_session_new')
            result = await client.send_request('session/new', {'cwd': str(home), 'mcpServers': [{
                'type': 'http', 'name': 'unrest_turn_broker', 'url': self.url,
                'headers': [{'name': 'Authorization', 'value': 'Bearer ' + self._connection}]}]})
            session = result.get('sessionId')
            if type(session) is not str or not session:
                raise LeaseRefused('invalid_session')
            if (name in self.thread_observations
                    and self.thread_observations[name].session != session):
                raise LeaseRefused('adapter_backend_thread_mismatch')
            with self.ledger.owned_operation(self):
                self.ledger.bind_session(session)
            role.session = session
            if any(s != session for s in role.opening_updates or []):
                raise LeaseRefused('wrong_opening_session')
            role.opening_updates = None
        diagnostic.phase('lifetime_connect')
        async with startup_timeout(1, 'lifetime_connect'):
            await lifetime.connected.wait()
        diagnostic.phase('bridge_connect')
        async with startup_timeout(1, 'bridge_connect'):
            await bridge.connected.wait()
        diagnostic.phase('ready')
        return role

    def _check_start_deadline(self, deadline: float) -> float:
        if self.stopped:
            raise LeaseRefused('session_stopped_during_launch')
        return self.ledger.remaining_until(deadline)

    async def _launch_role(self, name: str, deadline: float) -> _Role:
        diagnostic = self.startup_diagnostics.setdefault(name, StartupDiagnostics())
        try:
            # Check before task creation. The bridge callbacks inherit this same
            # absolute deadline; sequential phases cannot replenish the allowance.
            # Translate ledger clocks conservatively: checking time cannot add time.
            loop_now = asyncio.get_running_loop().time()
            remaining = self._check_start_deadline(deadline)
            cutoff = loop_now + remaining
            async with startup_timeout_at(cutoff, 'owner_launch'):
                launch = asyncio.create_task(self._open_role(name))
                self._launches.add(launch)
                launch.add_done_callback(self._launch_finished)
                stopped = asyncio.create_task(self._fault.wait())
                try:
                    await asyncio.wait({launch, stopped}, return_when=asyncio.FIRST_COMPLETED)
                    if self.stopped:
                        raise LeaseRefused('session_stopped_during_launch')
                    return launch.result()
                finally:
                    stopped.cancel()
                    await asyncio.gather(stopped, return_exceptions=True)
        except BaseException as error:
            diagnostic.fail(error)
            raise

    async def initialize_only(self, *, deadline: float | None = None) -> None:
        """One fresh startup, no entitlement reservation, grant or prompt.

        The independent probe owns close, including failure. A stopped or already
        launched owner can never use this entry point to retry initialization.
        """
        async with self._lock:
            if (self.stopped or self._launches or self.roles or self.backends
                    or self._server_task is None or self._server_task.done()):
                raise LeaseRefused('session_unavailable')
            self.ledger.available()
            try:
                bound = self.ledger.turn_deadline()
                deadline = bound if deadline is None else min(deadline, bound)
                role = await self._launch_role('worker', deadline)
                self._check_start_deadline(deadline)
                if not self._healthy('worker', role):
                    raise LeaseRefused('transport_lost')
            except BaseException:
                self._revoke(quarantine=True)
                raise

    def diagnostics(self) -> dict[str, object]:
        return {'owner': self.owner_diagnostics.snapshot(),
                'pre_cleanup': self._pre_cleanup,
                'roles': {name: value.snapshot()
                          for name, value in sorted(self.startup_diagnostics.items())}}

    def _observe_before_cleanup(self) -> None:
        if self._pre_cleanup is not None:
            return
        # Cached direct-handle observations only: no reads, waits, or raw bodies.
        self._pre_cleanup = {
            'backends': {name: {
                'exit_status': backend.process.returncode,
                'stdout_eof': (backend.process.stdout.at_eof()
                               if backend.process.stdout is not None else None),
                'stderr_bytes': backend.diagnostic_bytes,
                'stderr_truncated': backend.diagnostic_truncated,
                'stderr_eof': (backend.process.stderr.at_eof()
                               if backend.process.stderr is not None else None),
            } for name, backend in sorted(self.backends.items())},
            'adapters': {name: {'exit_status': role.process.returncode,
                'stdout_eof': (role.process.stdout.at_eof()
                               if role.process.stdout is not None else None)}
                         for name, role in sorted(self.roles.items())}}

    async def turn(self, name: Literal['worker', 'validator'], *,
                   disposition: str | None = None,
                   scenario: Literal['complete', 'missing_completion', 'stall', 'ignore_term'] = 'complete',
                   final: bool = False, instruction: str = '',
                   targets: tuple[str, ...] = (),
                   on_send: Callable[[], None] | None = None,
                   after_send: Callable[[], None] | None = None) -> Completion:
        async with self._lock:
            ticket = None
            self.last_completion = None
            self._acknowledged = False
            try:
                if self.stopped or self._server_task is None or self._server_task.done():
                    raise LeaseRefused('session_unavailable')
                if name not in ('worker', 'validator') or scenario not in ('complete', 'missing_completion', 'stall', 'ignore_term'):
                    raise LeaseRefused('invalid_synthetic_turn')
                self.ledger.available(final=final)
                turn_deadline = self.ledger.turn_deadline()
                role = self.roles.get(name)
                if role is None:
                    role = await self._launch_role(name, turn_deadline)
                if not self._healthy(name, role):
                    raise LeaseRefused('transport_lost')
                role.ordinal += 1
                candidate = (self.broker.digest(self.scope) if self.broker._expected is None
                             else self.broker.verify(self.scope))
                identity = TurnIdentity(self.lane, name, name, name, role.session,
                                        role.generation, role.ordinal, self.scope,
                                        candidate, targets)
                self._check_start_deadline(turn_deadline)
                with self.ledger.owned_operation(self):
                    ticket = self.ledger.reserve(identity, final=final, deadline=turn_deadline)
                self._check_start_deadline(turn_deadline)
                grant_clock = time.monotonic()
                remaining = self.ledger.remaining(ticket)
                token = self.broker.grant(identity, deadline=grant_clock + remaining)
                role.client.set_credential_inventory({'capability': token, 'connection': self._connection})
                envelope = {'turn': asdict(identity), 'capability': token,
                            'connection': self._connection, 'url': self.url,
                            'scenario': scenario, 'instruction': instruction,
                            'files': self.broker.contents(identity.scope),
                            'protocol': ('Use only unrest_turn_broker MCP tools. replace_file is '
                                         'worker-only. Complete with complete_turn using this exact '
                                         'turn and capability and the digest returned by replacement '
                                         '(or the input candidate if unchanged). Validate the entire '
                                         'scope and all targets. Validator completion must include a verdicts '
                                         'object with exactly every target mapped to a boolean. '
                                         'Never use direct filesystem writes or terminal tools. '
                                         'Validator dispositions: pass, reproducible_product_defect, '
                                         'conflict, missing_authority, scope_expansion, unknown, '
                                         'malformed_handoff. Worker disposition: sealed.'),
                            'disposition': disposition or ('sealed' if name == 'worker' else 'pass')}
                if not self.controlled:
                    envelope.pop('disposition')
                def before_prompt() -> None:
                    self._check_start_deadline(turn_deadline)
                    self.ledger.remaining(ticket)
                    if self.provider_config is not None:
                        self.provider_config.inputs.verify()
                    if on_send is not None:
                        on_send()
                    self._check_start_deadline(turn_deadline)
                    self.ledger.remaining(ticket)

                def after_prompt() -> None:
                    with self.ledger.owned_operation(self):
                        self.ledger.sent(ticket)
                    self.sent_active = True
                    if after_send is not None:
                        after_send()

                assert isinstance(role.client, _TurnClient)
                role.client.before_prompt = before_prompt
                role.client.after_prompt = after_prompt
                async with asyncio.timeout(self.ledger.remaining(ticket)):
                    result = await role.client.send_request('session/prompt', {
                        'sessionId': role.session,
                        'prompt': [{'type': 'text', 'text': json.dumps(envelope, sort_keys=True)}]})
                if not self._healthy(name, role) or self._server_task.done():
                    raise LeaseRefused('transport_lost')
                if result.get('stopReason') != 'end_turn':
                    raise LeaseRefused('prompt_not_complete')
                completion = self.broker.completion(identity)
                self.ledger.remaining(ticket, drain=self.drain_requested)
                self.last_completion = completion
                with self.ledger.owned_operation(self):
                    self.ledger.finish(ticket)
                # finish may consume an uncertain result without raising. Read
                # its committed status, never infer acknowledgement from return.
                with self.ledger._lock:
                    self._acknowledged = self.ledger._turns[ticket][1] == 'acked'
                if not self._acknowledged:
                    raise LeaseRefused('turn_not_acknowledged')
                if not self.drain_after_halt:
                    self.sent_active = False
                return completion
            except BaseException as error:
                self.sent_active = False
                self.broker.park()
                self.failure = self.failure or error
                # Notify the coordinator before an ambiguous finish halts the
                # shared ledger, so unaffected already-sent siblings can drain.
                self._revoke(quarantine=True)
                if ticket is not None:
                    try:
                        if self.ledger._turns[ticket][1] in ('reserved', 'sent'):
                            with self.ledger.owned_operation(self):
                                self.ledger.finish(ticket, ambiguous=True)
                    except Exception:
                        self.quarantined = True
                try:
                    await self.close()
                except (Exception, asyncio.CancelledError):
                    if not self.drain_after_halt:
                        raise  # Preserve the standalone session quarantine contract.
                    # Coordinator cleanup cannot replace the original turn failure.
                raise

    def _healthy(self, name: str, role: _Role) -> bool:
        backend = self.backends[name]
        healthy = (not self.stopped and role.process.returncode is None
                   and backend.process.returncode is None
                   and not backend.lifetime.exited.is_set()
                   and backend.bridge.connected.is_set()
                   and not any(task.done() for task in backend.bridge.tasks))
        if not healthy:
            self._revoke(quarantine=True)
        return healthy

    def _launch_finished(self, task: asyncio.Task[Any]) -> None:
        if not task.cancelled():
            task.exception()  # Observe late failures; retain the task and its ownership.

    def close_unstarted(self) -> None:
        """Release constructor resources without an event loop, before start only.

        A started owner must finish its async close and genuine child waits first.
        Borrowed campaign ledgers remain entirely with their controller.
        """
        if self._unstarted_closed or self._close_task is not None and self._close_task.done():
            return
        if (self._close_task is not None or self._server_task is not None
                or self._listener is not None or self._launches or self.roles or self.backends):
            raise LeaseRefused('session_requires_async_close')
        self._unstarted_closed = True
        try:
            if not self.stopped:
                self.stopped = True
                self._closing = True
                self._record_stop('stop')
                if self._owns_ledger:
                    self.ledger.stop()
        finally:
            try:
                self.broker.close()
            finally:
                if self._owns_ledger:
                    self.ledger.close()

    async def close(self) -> None:
        try:
            await self._close_result()
        except BaseException as error:
            self.owner_diagnostics.phase('owner_cleanup')
            self.owner_diagnostics.fail(error, cleanup=True)
            raise

    async def _close_result(self) -> None:
        self._revoke(quarantine=False)
        assert self._close_task is not None
        cancelled = False
        while not self._close_task.done():
            try:
                await asyncio.shield(self._close_task)
            except asyncio.CancelledError:
                cancelled = True
        self._close_task.result()
        if cancelled:
            raise asyncio.CancelledError
        if self.quarantined:
            raise LeaseRefused('synthetic_session_quarantined')

    async def _close(self) -> None:
        self._observe_before_cleanup()
        self._closing = True
        # Retain pending creation tasks even if spawning exceeds the close deadline.
        # Their registration callback continues ownership and cleanup on late return.
        for launch in self._launches:
            try:
                await asyncio.wait_for(asyncio.shield(launch), 6)
            except BaseException as error:
                self.owner_diagnostics.phase("owner_cleanup")
                self.owner_diagnostics.fail(error, cleanup=True)
                self.quarantined = True
                # Persist registration uncertainty before any further teardown.
                try:
                    if not (self.root / 'quarantine').exists():
                        self._record_stop('quarantine')
                except OSError:
                    pass  # Retain ownership and the refused root even if persistence fails.
        self._begin_bridge_shutdown()
        for role in list(self.roles.values()):
            await self._stop_role(role)
        for backend in list(self.backends.values()):
            await self._stop_backend(backend)
        for task in [*(role.watch for role in self.roles.values()),
                     *(backend.watch for backend in self.backends.values())]:
            if task is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(task), 1)
                except BaseException as error:
                    self.owner_diagnostics.phase("owner_cleanup")
                    self.owner_diagnostics.fail(error, cleanup=True)
                    self.quarantined = True
        if not self.quarantined:
            for claim in self._claims:
                self.ledger.release_session(claim)
            self._claims.clear()
        if self._watchdog:
            self._watchdog.cancel()
            await asyncio.gather(self._watchdog, return_exceptions=True)
        if self._monitor:
            self._monitor.cancel()
            await asyncio.gather(self._monitor, return_exceptions=True)
        if self._server:
            self._server.should_exit = True
        if self._server_task:
            try:
                await asyncio.wait_for(self._server_task, 2)
            except BaseException as error:
                self.owner_diagnostics.phase("owner_cleanup")
                self.owner_diagnostics.fail(error, cleanup=True)
                self.quarantined = True
        if self._listener:
            self._listener.close()
        if self.broker._expected is not None:
            try:
                self.broker.verify(self.scope)
            except Exception as error:
                self.owner_diagnostics.phase("owner_cleanup")
                self.owner_diagnostics.fail(error, cleanup=True)
                self.quarantined = True
        try:
            if self.quarantined:
                self._record_stop('quarantine')
                self.ledger.stop(quarantine=True)
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True
        try:
            self.broker.close()
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True
        try:
            if self._owns_ledger:
                self.ledger.close()
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True
        if self.quarantined and not (self.root / 'quarantine').exists():
            try:
                self._record_stop('quarantine')
            except Exception:
                pass  # The failed result and existing root still reject restart.

    def _begin_bridge_shutdown(self) -> None:
        for backend in self.backends.values():
            backend.bridge.begin_shutdown()

    async def _stop_role(self, role: _Role) -> None:
        # Late adapter registration can reach teardown before _close's launch
        # barrier completes, or after that barrier has refused uncertainty.
        self._begin_bridge_shutdown()
        if role.stop_task is None:
            role.stop_task = asyncio.create_task(self._stop_role_owned(role))
        cancelled = False
        while not role.stop_task.done():
            try:
                await asyncio.shield(role.stop_task)
            except asyncio.CancelledError:
                cancelled = True
        role.stop_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _stop_role_owned(self, role: _Role) -> None:
        try:
            if role.session and role.process.returncode is None:
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(.3):
                        await role.client._write({'jsonrpc': '2.0', 'method': 'session/cancel',
                                                  'params': {'sessionId': role.session}})
            await asyncio.wait_for(role.client.cleanup(close_main_process=False), 1)
        except BaseException as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True
        if role.process.stdin is not None:
            role.process.stdin.close()
        await self._reap(role.process)
        if role.lifetime is not None:
            try:
                await asyncio.wait_for(role.lifetime.exited.wait(), 3)
            except TimeoutError:
                # The leader may already be reaped. Do not guess at descendants
                # or send another signal to a potentially reused process group.
                self.quarantined = True
            finally:
                try:
                    await role.lifetime.close()
                except Exception as error:
                    self.owner_diagnostics.phase("owner_cleanup")
                    self.owner_diagnostics.fail(error, cleanup=True)
                    self.quarantined = True

    async def _watch_process(self, process: asyncio.subprocess.Process) -> None:
        try:
            await process.wait()
        except Exception:
            pass
        if not self._closing:
            self._revoke(quarantine=True)

    async def _drain_backend_stderr(self, backend: _Backend) -> None:
        assert backend.process.stderr is not None
        while chunk := await backend.process.stderr.read(65536):
            # Saturating structural counter: no raw bytes, lines or exception text.
            size = backend.diagnostic_bytes + len(chunk)
            backend.diagnostic_truncated |= size > 65536
            backend.diagnostic_bytes = min(65536, size)

    async def _stop_backend(self, backend: _Backend) -> None:
        if backend.stop_task is None:
            backend.stop_task = asyncio.create_task(self._stop_backend_owned(backend))
        cancelled = False
        while not backend.stop_task.done():
            try:
                await asyncio.shield(backend.stop_task)
            except asyncio.CancelledError:
                cancelled = True
        backend.stop_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _stop_backend_owned(self, backend: _Backend) -> None:
        try:
            await backend.bridge.close()
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True
        if backend.process.stdin:
            backend.process.stdin.close()
        await self._reap(backend.process)
        if backend.stderr:
            try:
                await asyncio.wait_for(backend.stderr, 1)
            except Exception as error:
                self.owner_diagnostics.phase("owner_cleanup")
                self.owner_diagnostics.fail(error, cleanup=True)
                self.quarantined = True
        # If adapter launch failed there can be no relay, hence no lifetime proof
        # to demand. A claimed bridge always requires the independent lifetime EOF.
        if backend.bridge.claimed and not backend.lifetime.exited.is_set():
            self.quarantined = True
        try:
            await backend.lifetime.close()
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True

    async def _reap(self, process: asyncio.subprocess.Process) -> None:
        # The live leader is the only basis for using its process group. Never
        # signal after observed exit/reap; the old numeric ID is no longer owned.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if process.returncode is not None:
                break
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            except OSError:
                # Closing stdin can exit/reap the child while signal delivery
                # races the loop's returncode update. Only an actual successful
                # wait resolves that uncertainty; never infer exit from errno.
                try:
                    await asyncio.wait_for(process.wait(), .5)
                    return
                except Exception as error:
                    self.owner_diagnostics.phase("owner_cleanup")
                    self.owner_diagnostics.fail(error, cleanup=True)
                    self.quarantined = True
            try:
                await asyncio.wait_for(process.wait(), .5)
                break
            except TimeoutError:
                if sig == signal.SIGKILL:
                    self.quarantined = True
            except Exception as error:
                self.owner_diagnostics.phase("owner_cleanup")
                self.owner_diagnostics.fail(error, cleanup=True)
                self.quarantined = True
        # An observed return code forbids signals but still needs actual wait.
        try:
            await asyncio.wait_for(process.wait(), .5)
        except Exception as error:
            self.owner_diagnostics.phase("owner_cleanup")
            self.owner_diagnostics.fail(error, cleanup=True)
            self.quarantined = True


class SyntheticSession(_SessionOwner):
    """Pinned provider-free fixture on the same owned transport/broker boundaries."""

    def __init__(self, root: Path, candidate: Path, scope: tuple[str, ...], *,
                 adapter: Path, fixture: Path, policy: ResolvedRoleCapability,
                 transport: ControlledTransport | None = None):
        super().__init__(root, candidate, scope, adapter=adapter, fixture=fixture, policy=policy,
                         transport=transport)


class LeaseLane:
    """One bounded lane, not a scheduler. The caller owns one episode event loop.

    A shared, already-admitted ledger is mandatory across all lanes and final
    evaluators. Passing a pinned fixture selects controlled processes; omitting
    it selects the pinned real backend with ordinary subscription configuration.
    Expected candidate bytes come from controller materialization, not restart.
    """

    def __init__(self, root: Path, candidate: Path, scope: tuple[str, ...], *,
                 expected_candidate: str, lane: str, adapter: Path,
                 policy: ResolvedRoleCapability, ledger: PilotLedger,
                 trusted_process: bool = False, provider: str = 'codex',
                 fixture: Path | None = None, final: bool = False,
                 provider_package: Path | None = None,
                 transport: ControlledTransport | None = None):
        from .experimental_lease import require_provider
        require_provider(provider, trusted_process=trusted_process, controls=True,
                         ledger=ledger, final=final)
        expected_provider = ('local-controlled-only' if fixture is not None else
                            REAL_PROVIDER)
        if ledger.provider != expected_provider:
            raise LeaseRefused('campaign_provider_mismatch')
        self.root, self.candidate, self.scope = root, candidate, scope
        self.expected, self.lane = expected_candidate, lane
        self.adapter, self.policy, self.ledger = adapter, policy, ledger
        if fixture is not None and provider_package is not None:
            raise LeaseRefused('ambiguous_provider_selection')
        self.provider_package = provider_package
        self.fixture = fixture
        self.backend = fixture if fixture is not None else check_package(provider_package)
        if fixture is not None:
            check_pin(fixture, FIXTURE_SHA256)
        verify_transport(transport, controlled=fixture is not None,
                         package=provider_package, adapter=adapter)
        self.transport = transport
        root.mkdir(mode=0o700)
        self.final = final
        self.phase = 'validate' if final else 'work'
        self.generation = 0
        self.corrected = False
        self.owner: _SessionOwner | None = None
        self.owners: list[_SessionOwner] = []
        self._turn_lock = asyncio.Lock()

    async def _start(self) -> _SessionOwner:
        self.ledger.available(final=self.final)
        owner = _SessionOwner(self.root / f'g{self.generation}', self.candidate, self.scope,
                              adapter=self.adapter, fixture=self.backend, policy=self.policy,
                              controlled=self.fixture is not None, ledger=self.ledger,
                              lane=self.lane, provider_package=self.provider_package,
                              transport=self.transport)
        self.owner = owner
        self.owners.append(owner)
        owner.broker.seal(self.scope, self.expected)
        await owner.start()
        return owner

    async def turn(self, role: Literal['worker', 'validator'], instruction: str, *,
                   controlled_disposition: str | None = None,
                   controlled_scenario: Literal['complete', 'missing_completion', 'stall', 'ignore_term'] = 'complete'
                   ) -> Completion:
        async with self._turn_lock:
            try:
                expected_role = 'worker' if self.phase in ('work', 'correction') else 'validator'
                if self.phase in ('passed', 'attention', 'closed') or role != expected_role:
                    raise LeaseRefused('lane_turn_not_admissible')
                if (not instruction.strip() or len(instruction.encode()) > 65536
                        or instruction.lstrip().startswith('/')):
                    raise LeaseRefused('invalid_turn_instruction')
                if self.fixture is None and (controlled_disposition is not None or controlled_scenario != 'complete'):
                    raise LeaseRefused('controlled_override_on_real_provider')
                owner = self.owner if self.owner is not None else await self._start()
                owner.broker.verify(self.scope)
                result = await owner.turn(role, instruction=instruction, final=self.final,
                                          disposition=controlled_disposition,
                                          scenario=controlled_scenario)
                self.expected = owner.broker.verify(self.scope)
                if role == 'worker':
                    self.phase = 'recheck' if self.corrected else 'validate'
                elif result.disposition == 'pass':
                    self.phase = 'passed'
                    await owner.close()
                elif result.disposition == 'reproducible_product_defect' and not self.final:
                    if self.generation == 1:
                        raise LeaseRefused('fresh_generation_failed')
                    if not self.corrected:
                        self.corrected = True
                        self.phase = 'correction'
                    else:
                        await owner.close()
                        self.owner = None
                        self.generation = 1
                        self.phase = 'work'
                else:
                    raise LeaseRefused('noncorrectable_attention')
                return result
            except BaseException as exc:
                self.phase = 'attention'
                # Stop watchers synchronously before halting the shared ledger;
                # an expected attention outcome is not transport-loss evidence.
                for owner in self.owners:
                    owner._revoke(quarantine=not (
                        isinstance(exc, LeaseRefused) and str(exc) in (
                            'noncorrectable_attention', 'fresh_generation_failed',
                            'lane_turn_not_admissible', 'invalid_turn_instruction')))
                self.ledger.stop(quarantine=True)
                with contextlib.suppress(LeaseRefused):
                    await self.close()
                raise

    async def close(self) -> None:
        error: BaseException | None = None
        for owner in self.owners:
            try:
                await owner.close()
            except BaseException as exc:
                error = exc
                self.ledger.stop(quarantine=True)
        if self.phase not in ('passed', 'attention'):
            self.phase = 'closed'
        if error is not None:
            raise error

    def status(self) -> dict[str, object]:
        return {'lane': self.lane, 'phase': self.phase, 'generation': self.generation,
                'candidate': self.expected, 'controlled': self.fixture is not None,
                'os_write_isolation': 'unverified', 'live_acceptance': 'unverified',
                'native_approval': 'unverified', 'final_candidate_timing': 'unverified',
                'enabled_by_default': False,
                'broker_authority': 'turn_bound', 'cleanup': 'owned_handles_only',
                'transient_write_detection': 'unverified', 'unknown_descendants': 'unverified'}
