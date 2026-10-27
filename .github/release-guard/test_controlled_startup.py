"""Actual product/asyncio pre-exec path, stopped before every OS launch.

These controls prove source-derived selection, not child execution, endpoint
custody, the original timing cases or source-checkpoint certification.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import importlib.machinery
from pathlib import Path
import sys

import pytest

from content_manifest import Refused
from control_transport import finite, encode, REQUEST_LIMIT
from controlled_startup import Startup, CASES
from launch_policy import Observation
from source_owner import prepare
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests import test_experimental_bootstrap as bootstrap  # noqa: E402
from tests.test_experimental_session import session as owner_fixture  # noqa: E402
from unrest_harness import experimental_session as session  # noqa: E402
from unrest_harness.experimental_diagnostics import StartupDiagnostics  # noqa: E402

ACTIVE = [None]


class StoppedBeforeExec(RuntimeError):
    pass


def audit(event, args):
    handler = ACTIVE[0]
    if handler is None:
        return
    if event == 'subprocess.Popen':
        handler(args)
        raise StoppedBeforeExec('source selection completed before exec')
    if event in ('os.exec', 'os.posix_spawn', 'os.system', 'os.fork', 'os.forkpty',
                 'socket.bind', 'socket.connect', 'os.kill', 'os.killpg'):
        raise AssertionError('pre-exec source control attempted an external effect')


sys.addaudithook(audit)


class Server:
    sockets = ()
    def __init__(self):
        self.sockets = (self,)
    def getsockname(self):
        return '127.0.0.1', 12345
    def close(self):
        pass
    async def wait_closed(self):
        pass


@pytest.fixture
def context(tmp_path, monkeypatch):
    checkout = Path(__file__).resolve().parents[2]
    units = []
    for module, mode in ((session, 'plain' if type(session.__loader__) is importlib.machinery.SourceFileLoader
                           else 'beartype-passive'), (bootstrap, 'pytest')):
        body = Path(module.__file__).read_bytes()
        units.append(prepare(body, module.__file__, module.__name__, mode, hashlib.sha256(body).hexdigest()))
    gate = Startup(session, bootstrap, *units, checkout, tmp_path, Path(sys.executable),
                   hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest())
    owner = owner_fixture.__wrapped__(tmp_path, None)
    async def start_server(*args, **kwargs):
        return Server()
    monkeypatch.setattr(asyncio, 'start_server', start_server)
    yield gate, owner
    ACTIVE[0] = None


def observation(args):
    executable, vector, cwd, environment = args
    command = len(vector) > 1 and vector[1] == '-c'
    payload = vector[2].encode() if command else Path(vector[1]).read_bytes()
    return Observation(str(executable), hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                       tuple(vector), tuple(sorted(environment.items())), str(cwd),
                       'python-command' if command else 'python-script', hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize('case', CASES)
def test_real_product_caller_and_original_asyncio_options_select_backend_before_exec(context, monkeypatch, case):
    gate, owner = context
    if case == CASES[1]:
        bootstrap.delayed_backend.__wrapped__(monkeypatch)(.5)
    selected = []
    def inspect(args):
        intent = gate.select(case, observation(args))
        request = {'case': case, 'original': intent.original.wire(),
                   'translated': list(intent.translated_argv), 'source_line': intent.original_source_line,
                   'script_sha256': intent.script_sha256}
        finite(request)
        assert __import__('json').loads(encode(request, REQUEST_LIMIT)[4:]) == request
        selected.append(intent)
    ACTIVE[0] = inspect
    async def run():
        try:
            with pytest.raises(StoppedBeforeExec):
                await owner._open_role_owned('worker', StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()
    asyncio.run(run())
    assert len(selected) == 1
    assert selected[0].original_source_line == 506
    assert selected[0].translated_argv[1:3] == ('-I', '-S')
    assert not owner.backends and not owner.roles


@pytest.mark.parametrize('mutation', ['case', 'argv', 'cwd', 'environment', 'payload', 'runtime', 'controlled'])
def test_source_selection_refuses_drift_without_starting_a_child(context, mutation):
    gate, owner = context
    seen = []
    if mutation == 'controlled':
        owner.controlled = False
    def inspect(args):
        observed = observation(args)
        if mutation == 'argv':
            observed = replace(observed, argv=(*observed.argv, 'foreign'))
        elif mutation == 'cwd':
            observed = replace(observed, cwd='/foreign')
        elif mutation == 'environment':
            observed = replace(observed, environment=(*observed.environment, ('FOREIGN', '1')))
        elif mutation == 'payload':
            observed = replace(observed, payload_sha256='0' * 64)
        elif mutation == 'runtime':
            observed = replace(observed, executable_sha256='0' * 64)
        seen.append('preexec')
        gate.select('foreign' if mutation == 'case' else CASES[0], observed)
    ACTIVE[0] = inspect
    async def run():
        try:
            with pytest.raises((Refused, session.LeaseRefused)):
                await owner._open_role_owned('worker', StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()
    asyncio.run(run())
    assert not owner.backends and not owner.roles
    assert seen == ([] if mutation == 'controlled' else ['preexec'])



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


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('mutation', [None, 'relay', 'stderr', 'transport-method'])
def test_actual_acp_preexec_branch_and_original_defaults(context, monkeypatch, case, mutation):
    gate, owner = context
    if case == CASES[1]:
        bootstrap.delayed_backend.__wrapped__(monkeypatch)(.5)
    selected, models = [], []
    def inspect(args):
        if mutation == 'relay':
            args[3]['SYNTHETIC_RELAY'] = '[1, "foreign", 2, "foreign"]'
        elif mutation == 'stderr':
            frames = __import__('source_owner').active_frames()
            try:
                frame = next(frame for frame in frames if frame.f_code is gate.constructor_code)
                frame.f_locals['stderr'] = -1
            finally:
                del frames
        elif mutation == 'transport-method':
            monkeypatch.setattr(session.ControlledTransport, 'argv', lambda self: ())
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
        monkeypatch.setattr(loop, '_make_subprocess_transport', make)
        try:
            with pytest.raises(StoppedBeforeExec if mutation is None else Refused):
                await owner._open_role_owned('worker', StartupDiagnostics())
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
        assert selected[0].original.argv[-1] == '--controlled-local-acp-v1'
    else:
        assert not selected


@pytest.mark.parametrize('mutation', ['environment-key', 'environment-value', 'argv', 'backend-digest', 'option'])
def test_live_context_refuses_callback_objects_without_invoking_them(context, mutation):
    gate, owner = context
    class Trap:
        armed = False
        def __hash__(self):
            return hash('HOME')
        def __eq__(self, other):
            if self.armed:
                raise AssertionError('context equality callback executed')
            return False
    trap = Trap()
    def inspect(args):
        observed = observation(args)
        if mutation == 'environment-key':
            args[3].pop('HOME')
            args[3][trap] = 'foreign'
        elif mutation == 'environment-value':
            args[3]['HOME'] = trap
        elif mutation == 'backend-digest':
            owner.backend_digest = trap
        else:
            frames = __import__('source_owner').active_frames()
            try:
                if mutation == 'argv':
                    frame = next(frame for frame in frames if frame.f_code is gate.open.__code__)
                    frame.f_locals['argv'][1] = trap
                else:
                    frame = next(frame for frame in frames if frame.f_code is gate.constructor_code)
                    frame.f_locals['kwds']['cwd'] = trap
            finally:
                del frames
        trap.armed = True
        gate.select(CASES[0], observed)
    ACTIVE[0] = inspect
    async def run():
        try:
            with pytest.raises(Refused):
                await owner._open_role_owned('worker', StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()
    asyncio.run(run())
    assert not owner.backends and not owner.roles


@pytest.mark.parametrize('case', [
    'tests/test_controlled_python_acp.py::test_single_c1_fixed_timing_protocol_witness',
    'tests/test_experimental_ack_durability.py::test_ack_durability[False--1-None-write]',
])
def test_finite_unconfigured_owner_selection_uses_actual_backend_bytes(tmp_path, monkeypatch, case):
    from controlled_cases import CASES as CONTROLLED
    from tests.test_experimental_finite_orders import CompletionBarriers
    if 'ack_durability' in case:
        case = next(name for name in CONTROLLED if 'test_ack_durability[' in name)
    checkout = Path(__file__).resolve().parents[2]
    tests = __import__(case.split('::')[0].removesuffix('.py').replace('/','.'),fromlist=['x'])
    modules = ((session, 'plain' if type(session.__loader__) is importlib.machinery.SourceFileLoader else 'beartype-passive'), (tests,'pytest'))
    units = [prepare(Path(module.__file__).read_bytes(),module.__file__,module.__name__,mode,
        hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()) for module,mode in modules]
    gate = Startup(session,tests,*units,checkout,tmp_path,Path(sys.executable),
        hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),case=case)
    owner = owner_fixture.__wrapped__(tmp_path,None)
    if 'ack_durability' in case:
        barriers = CompletionBarriers(monkeypatch,tmp_path)
        owner.backend_launcher.write_bytes(barriers.fixture.read_bytes())
        owner.backend_digest = hashlib.sha256(owner.backend_launcher.read_bytes()).hexdigest()
    async def start_server(*args,**kwargs):
        return Server()
    monkeypatch.setattr(asyncio,'start_server',start_server)
    selected = []
    def inspect(args):
        selected.append(gate.select(case,observation(args)))
    ACTIVE[0] = inspect
    async def run():
        try:
            with pytest.raises(StoppedBeforeExec):
                await owner._open_role_owned('validator',StartupDiagnostics())
        finally:
            ACTIVE[0] = None
            await owner.close()
    asyncio.run(run())
    assert len(selected) == 1 and selected[0].original.argv[-1] == 'app-server'
    assert selected[0].original.cwd == str(owner.root/'validator')


def test_controlled_cleanup_keeps_live_original_method_binding(context,monkeypatch):
    from source_root import BootstrapCalls
    gate,_ = context
    calls = object.__new__(BootstrapCalls)
    calls.controlled,calls.startup,calls.anchors = True,gate,{}
    owner = calls.method(gate.unit,session,gate.base,'_SessionOwner','_reap')
    owner.verify_binding()
    async def foreign(*args,**kwargs):
        pass
    monkeypatch.setattr(gate.base,'_reap',foreign)
    with pytest.raises(Refused):
        owner.verify_binding()
