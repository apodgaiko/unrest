"""Original inline catalogue parity, without starting any process."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from content_manifest import Refused
from cleanup_inline import CASES, STARTUP, CLIENT, INFLIGHT, NO_LAUNCH, SLEEP, EXIT, body, child_count, source_site, scheduling_site
from cleanup_launch import TEST


def test_inline_bodies_and_effect_lines_are_original_source():
    file = Path(__file__).resolve().parents[2] / TEST
    tree = ast.parse(file.read_bytes())
    calls = {node.lineno: node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for line in (61, 269, 299, 429):
        assert line in calls
    constants = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is str}
    assert SLEEP in constants and EXIT in constants
    assert len(CASES) == 21 and len(set(CASES)) == 21
    assert (len(STARTUP), len(CLIENT), len(INFLIGHT), len(NO_LAUNCH)) == (9, 3, 2, 7)


@pytest.mark.parametrize('case', CASES)
def test_inline_parameters_keep_original_effect_counts_and_source_sites(case):
    if case in NO_LAUNCH:
        assert child_count(case) == 0 and scheduling_site(case) is None
        with pytest.raises(Refused):
            body(case)
        with pytest.raises(Refused):
            source_site(case)
    else:
        assert body(case) == (EXIT if case in STARTUP and STARTUP[case][1] == 'exit' else SLEEP)
        assert child_count(case) == (1 if case in STARTUP or CLIENT.get(case, (None, None))[1] == 'reader' else 3)
        assert source_site(case) in (61, 269, 299, 429)
    if case in INFLIGHT:
        assert source_site(case, terminal=True) == 1034 and scheduling_site(case) == 478
    else:
        with pytest.raises(Refused):
            source_site(case, terminal=True)


@pytest.mark.parametrize('case', [True, '', 'tests/test_acp_cleanup.py::foreign', CASES[0] + '-foreign'])
def test_no_generic_inline_selection(case):
    with pytest.raises(Refused):
        body(case)


def test_inline_options_and_vectors_are_closed():
    from cleanup_inline import expected, options
    root = {'HOME': '/owned/home', 'TMPDIR': '/owned/tmp', 'PATH': '/usr/bin:/bin'}
    for case in CASES:
        if case in NO_LAUNCH:
            with pytest.raises(Refused):
                expected(case, '/native', 'a' * 64, Path('/source'), root)
            continue
        startup = case in STARTUP
        local = {'kwds': {}, 'stdin': None if startup else -1, 'stdout': -1,
                 'stderr': -1 if startup else None, 'limit': 65536}
        options(case, local)
        result, site = expected(case, '/native', 'a' * 64, Path('/source'), root)
        assert result.argv == ('/native', '-c', body(case)) and result.cwd == '/source'
        assert dict(result.environment) == {**root, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
        assert site == source_site(case)
        for changed in ({**local, 'limit': 8388608}, {**local, 'kwds': {'start_new_session': True}},
                        {**local, 'stdout': True}):
            with pytest.raises(Refused):
                options(case, changed)
    case = next(iter(INFLIGHT))
    terminal = {'kwds': {'cwd': '/owned/pytest/case', 'env': {}}, 'stdin': None,
                'stdout': -1, 'stderr': -2, 'limit': 8388608}
    options(case, terminal, terminal=True)
    result, site = expected(case, '/native', 'a' * 64, Path('/source'), root,
                            base=Path('/owned/pytest/case'), terminal=True)
    assert result.cwd == '/owned/pytest/case' and result.environment == () and site == 1034
    with pytest.raises(Refused):
        options(case, {**terminal, 'kwds': {'cwd': '/owned/pytest/case', 'env': {'FOREIGN': '1'}}}, terminal=True)


@pytest.mark.parametrize('case', NO_LAUNCH)
def test_numeric_cases_cannot_enter_a_child_profile_or_mint_an_intent(tmp_path, case):
    from source_profile import FIELDS, validate
    from test_source_integration import backend_request
    profile = dict.fromkeys(FIELDS)
    profile.update(schema='unrest.bootstrap-source.v1', role='cleanup-acp', case=case, cases=list(NO_LAUNCH))
    with pytest.raises(Refused, match='closed profile'):
        validate(profile, 'cpython.run_file', ('foreign.py',))
    observer, actor, request = backend_request(tmp_path)
    observer.case = request['case'] = case
    with pytest.raises(Refused, match='declared launch case'):
        observer.launch(actor, request)
    assert observer.intents == {}


@pytest.mark.parametrize('case', tuple(STARTUP))
@pytest.mark.asyncio
async def test_original_startup_wrapper_admission_across_its_task_boundary(case, tmp_path, monkeypatch, caplog, mutation=None):
    import asyncio
    import hashlib
    import json
    import os
    import sys
    import types
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from tests import test_acp_cleanup as original
    from unrest_harness import acp_runner
    from cleanup_effects import CleanupCalls
    from cleanup_launch import PINS
    from cleanup_inline import Launches
    from source_owner import active_frames
    checkout = Path(__file__).resolve().parents[2]
    owned = tmp_path / 'owned'
    base = owned / 'pytest' / 'case'
    base.mkdir(parents=True)
    directory = tmp_path / 'profiles'
    directory.mkdir()
    manifest = json.dumps({'schema': 'unrest.guard-content.v1', 'files': [
        {'path': name, 'sha256': pin} for name, pin in sorted(PINS.items())]}).encode()
    (directory / 'source-manifest.json').write_bytes(manifest)
    root = {'HOME': str(owned / 'home'), 'TMPDIR': str(owned / 'tmp'), 'PATH': '/usr/bin:/bin',
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    for name in tuple(os.environ):
        monkeypatch.delenv(name)
    for name, value in {**root, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}.items():
        monkeypatch.setenv(name, value)
    _, variant, role = STARTUP[case]
    item = types.SimpleNamespace(nodeid=case, module=original, obj=original.test_startup_failure_attribution_and_owned_cleanup,
        originalname='test_startup_failure_attribution_and_owned_cleanup', funcargs={
            'tmp_path': base, 'failure': variant, 'role': role})
    policy = types.SimpleNamespace(directory=directory, case=case, children={}, profile={
        'checkout': str(checkout), 'owned': str(owned), 'source_sha256': hashlib.sha256(manifest).hexdigest(),
        'native': sys.executable, 'native_sha256': 'a' * 64, 'environment': root})
    calls = CleanupCalls(policy, item)
    launches = Launches(calls)
    monkeypatch.setattr(acp_runner.ACPNodeRunner, '_find_free_port', staticmethod(lambda: 12345))
    import cleanup_launch
    monkeypatch.setattr(cleanup_launch, 'base_path', lambda value, owned: Path(value))
    admitted = []
    class Stop(BaseException):
        pass
    async def subprocess_exec(factory, program, *args, **kwargs):
        if mutation is not None:
            import source_owner
            frames = active_frames()
            try:
                start_frame = next(frame for frame in frames if frame.f_code.co_qualname.endswith('.<locals>.start'))
                runner = start_frame.f_locals['runner']
                wrapper = vars(runner)['_start_worker_mcp_server']
                cells = dict(zip(wrapper.__code__.co_freevars, wrapper.__closure__, strict=True))
                if mutation == 'wrapper':
                    monkeypatch.setattr(runner, '_start_terminal_reviewer_mcp', lambda **kwargs: None)
                elif mutation == 'class':
                    monkeypatch.setattr(acp_runner, 'ACPNodeRunner', type('ForeignRunner', (), {}))
                elif mutation == 'failure':
                    cells['failure'].cell_contents = 'deadline'
                elif mutation == 'children':
                    cells['children'].cell_contents.append(types.SimpleNamespace(returncode=0))
                elif mutation == 'constructor':
                    monkeypatch.setattr(asyncio, 'create_subprocess_exec', lambda *args, **kwargs: None)
                elif mutation == 'fixture':
                    item.funcargs['tmp_path'] = owned / 'pytest' / 'foreign'
                elif mutation == 'caller':
                    monkeypatch.setattr(source_owner, 'active_frames', lambda: (sys._getframe(),))
                elif mutation == 'case':
                    policy.case = next(value for value in STARTUP if value != case)
            finally:
                del frames
        admitted.append(launches.select(case, (program, [program, *args], kwargs.get('cwd'), kwargs.get('env'))))
        # Release the original cancellation fixture's scheduling barrier without
        # claiming that its readiness/cleanup assertions ran in this reproduction.
        frames = active_frames()
        try:
            frame = next(frame for frame in frames if frame.f_code.co_qualname.endswith('.<locals>.start'))
            runner = frame.f_locals['runner']
            ready = vars(runner)['_wait_for_server_ready']
            closure = dict(zip(ready.__code__.co_freevars, (cell.cell_contents for cell in ready.__closure__), strict=True))
            closure['entered'].set()
        finally:
            del frames
        raise Stop
    monkeypatch.setattr(asyncio.get_running_loop(), 'subprocess_exec', subprocess_exec)
    with pytest.raises(Stop if mutation is None else Refused):
        await asyncio.wait_for(original.test_startup_failure_attribution_and_owned_cleanup(
            base, monkeypatch, role, variant, caplog), 2)
    if mutation is None:
        assert len(admitted) == 1 and admitted[0].original.argv[-1] == body(case)
    else:
        assert admitted == []


@pytest.mark.parametrize('mutation', ('wrapper', 'class', 'failure', 'children', 'constructor', 'fixture', 'caller', 'case'))
@pytest.mark.asyncio
async def test_startup_selector_refuses_wrong_owner_context_before_effect(mutation, tmp_path, monkeypatch, caplog):
    await test_original_startup_wrapper_admission_across_its_task_boundary(
        next(iter(STARTUP)), tmp_path, monkeypatch, caplog, mutation)


@pytest.mark.parametrize('case', tuple(STARTUP))
def test_preflight_only_command_never_matches_a_child_rule(case):
    import hashlib
    from cleanup_inline import expected
    from launch_policy import Observation, match
    root = {'HOME': '/owned/home', 'TMPDIR': '/owned/tmp', 'PATH': '/usr/bin:/bin'}
    result, _ = expected(case, '/native', 'a' * 64, Path('/source'), root)
    inert = Observation('/native', 'a' * 64, ('/native', '-c', 'pass'), result.environment,
                        '/source', 'python-command', hashlib.sha256(b'pass').hexdigest())
    with pytest.raises(Refused):
        match((result,), inert, result.owner, case)


def test_native_instance_dictionary_ignores_custom_accessors():
    from cleanup_inline import instance_fields
    callbacks = []
    class Meta(type):
        def __getattribute__(self, name):
            callbacks.append('metaclass')
            raise AssertionError('custom metaclass access')
    class Instance(metaclass=Meta):
        def __getattribute__(self, name):
            callbacks.append('instance')
            raise AssertionError('custom instance access')
    value = Instance()
    object.__setattr__(value, 'expected', 7)
    callbacks.clear()
    assert instance_fields(value)['expected'] == 7 and callbacks == []
    class Property:
        @property
        def __dict__(self):
            callbacks.append('property')
            raise AssertionError('custom dictionary property')
    with pytest.raises(Refused, match='instance dictionary'):
        instance_fields(Property())
    assert callbacks == []


def test_frame_namespace_refuses_nonprimitive_keys_without_comparison():
    import sys
    from cleanup_inline import frame_fields
    callbacks = []
    class Key:
        def __hash__(self):
            return hash('runner')
        def __eq__(self, other):
            callbacks.append('equality')
            raise AssertionError('custom frame key comparison')
    key = Key()
    frame = sys._getframe()
    frame.f_locals[key] = 7
    try:
        callbacks.clear()
        with pytest.raises(Refused, match='frame fields'):
            frame_fields(frame)
        assert callbacks == []
    finally:
        del frame.f_locals[key]


def negative_probe(tmp_path, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from endpoint_policy import Socket
    from test_source_integration import backend_request
    import source_observer
    observer, actor, _ = backend_request(tmp_path)
    observer.case = next(iter(STARTUP))
    observer.probe_ports = {}
    observer.endpoints = SimpleNamespace(routes={}, tickets={}, connections={})
    fresh = Socket(actor['birth'], 7, 101, 201, 7, 20000, ('0.0.0.0', 0), None)
    observer.bindings = {(actor['birth'], 7): {'socket': fresh, 'tag': 'mcp-probe', 'case': observer.case}}
    bound = replace(fresh, local=('127.0.0.1', 12345))
    monkeypatch.setattr(source_observer, 'acquire_tcp', lambda *args, **kwargs: bound)
    assert observer.dispatch(actor, {'kind': 'bound', 'payload': {'fd': 7}}) == {'ok': True}
    client = replace(fresh, fd=8, inode=102, cookie=202)
    monkeypatch.setattr(source_observer, 'acquire_tcp', lambda *args, **kwargs: client)
    request = {'kind': 'connect', 'payload': {'fd': 8, 'address': ['127.0.0.1', 12345]}}
    return observer, actor, request, client


def test_negative_readiness_attempts_never_mint_connection_authority(tmp_path, monkeypatch):
    observer, actor, request, _ = negative_probe(tmp_path, monkeypatch)
    for _ in range(16):
        assert observer.dispatch(actor, request) == {'ok': True, 'probe': True}
    assert observer.endpoints.routes == observer.endpoints.tickets == observer.endpoints.connections == {}
    with pytest.raises(Refused, match='finite negative readiness probe'):
        observer.dispatch(actor, request)
    assert observer.probe_ports[observer.case]['attempts'] == 16


@pytest.mark.parametrize('mutation', ('port', 'owner', 'uid', 'state', 'remote', 'bound-client', 'case'))
def test_negative_readiness_has_no_generic_loopback_permission(mutation, tmp_path, monkeypatch):
    from dataclasses import replace
    import source_observer
    observer, actor, request, client = negative_probe(tmp_path, monkeypatch)
    if mutation == 'port':
        request['payload']['address'][1] += 1
    elif mutation == 'owner':
        client = replace(client, owner=replace(client.owner, ticks=client.owner.ticks + 1))
    elif mutation == 'uid':
        # Socket's own identity constructor rejects a foreign UID first.
        with pytest.raises(Refused):
            replace(client, uid=20001)
        return
    elif mutation == 'state':
        client = replace(client, state=1, local=('127.0.0.1', 23456), remote=('127.0.0.1', 12345))
    elif mutation == 'remote':
        with pytest.raises(Refused):
            replace(client, remote=('127.0.0.1', 12345))
        return
    elif mutation == 'bound-client':
        client = replace(client, local=('127.0.0.1', 12346))
    else:
        observer.case = next(case for case in STARTUP if case != observer.case)
    monkeypatch.setattr(source_observer, 'acquire_tcp', lambda *args, **kwargs: client)
    with pytest.raises(Refused, match='finite negative readiness probe'):
        observer.dispatch(actor, request)
    assert observer.endpoints.connections == {}


@pytest.mark.parametrize('outcome', ('pending', 'refused', 'connected', 'zero', 'bool'))
def test_negative_probe_socket_hook_never_reports_a_connection(outcome):
    import errno
    from types import SimpleNamespace
    from source_sockets import Hooks
    calls = []
    case = next(iter(STARTUP))
    def refuse(code):
        raise Refused(code)
    policy = SimpleNamespace(profile={'role': 'root', 'case': '<bootstrap>'}, case=case,
        calls=SimpleNamespace(connection=lambda port: None), refuse=refuse)
    hooks = object.__new__(Hooks)
    hooks.policy, hooks.local = policy, SimpleNamespace()
    hooks.descriptor = lambda stream: 8
    def request(kind, payload):
        calls.append(kind)
        assert kind == 'connect'
        return {'ok': True, 'probe': True}
    hooks.rpc = request
    def connect(stream, address):
        if outcome == 'pending':
            raise BlockingIOError(errno.EINPROGRESS, 'controlled pending attempt')
        if outcome == 'refused':
            raise ConnectionRefusedError(errno.ECONNREFUSED, 'controlled refused attempt')
        return None if outcome == 'connected' else 0 if outcome == 'zero' else True
    hooks.original = {'connect': connect}
    error = BlockingIOError if outcome == 'pending' else ConnectionRefusedError if outcome == 'refused' else Refused
    with pytest.raises(error):
        hooks.call('connect', object(), ('127.0.0.1', 12345))
    assert calls == ['connect'] and hooks.local.socket is None


@pytest.mark.parametrize('case', tuple(STARTUP))
def test_inline_leaf_accepts_only_its_exact_once_command(case):
    from source_code import Bodies
    policy = Bodies({'role': 'cleanup-inline', 'case': case, 'execution':{'event':'cpython.run_command','argument':body(case)+'\n'}})
    text = body(case) + '\n'
    with pytest.raises(Refused):
        policy.audit('compile', (b'pass\n', '<string>'))
    assert policy.audit('compile', (text.encode(), '<string>'))
    expected_code = compile(text, '<string>', 'exec', dont_inherit=True)
    assert policy.audit('exec', (expected_code,))
    with pytest.raises(Refused):
        policy.audit('exec', (expected_code,))
    with pytest.raises(Refused):
        policy.audit('compile', (text.encode(), '<string>'))


@pytest.mark.asyncio
async def test_original_mcp_startup_termination_keeps_source_and_process_identity(tmp_path, monkeypatch):
    import asyncio
    import asyncio.unix_events
    import hashlib
    import json
    import types
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from tests import test_acp_cleanup as original
    from tests.test_provider_review import controller_fixture
    from unrest_harness import acp_runner
    from unrest_harness.assets import AssetLoader
    from cleanup_effects import CleanupCalls
    from cleanup_launch import PINS
    case = next(iter(STARTUP))
    data = json.dumps({'schema': 'unrest.guard-content.v1', 'files': [
        {'path': name, 'sha256': pin} for name, pin in sorted(PINS.items())]}).encode()
    (tmp_path / 'source-manifest.json').write_bytes(data)
    native = object()
    transport = object.__new__(asyncio.unix_events._UnixSubprocessTransport)
    transport._closed, transport._pid, transport._proc, transport._returncode = True, 123, native, None
    process = object.__new__(asyncio.subprocess.Process)
    process.pid, process._transport = 123, transport
    policy = types.SimpleNamespace(directory=tmp_path, case=case, children={123: {'process': native}},
        profile={'checkout': str(Path(__file__).resolve().parents[2]), 'owned': str(tmp_path),
                 'source_sha256': hashlib.sha256(data).hexdigest()})
    item = types.SimpleNamespace(nodeid=case, module=original, obj=original.test_startup_failure_attribution_and_owned_cleanup,
                                 originalname='test_startup_failure_attribution_and_owned_cleanup')
    calls = CleanupCalls(policy, item)
    (tmp_path / 'fixture').mkdir()
    _, store, _ = controller_fixture(tmp_path / 'fixture')
    runner = acp_runner.ACPNodeRunner(store.config, AssetLoader(store.config))
    signals = []
    def terminate(self):
        calls.signal(123, 15, False)
        signals.append(123)
    async def close(*args, **kwargs):
        pass
    monkeypatch.setattr(asyncio.subprocess.Process, 'terminate', terminate)
    monkeypatch.setattr(acp_runner, '_close_subprocess', close)
    assert await runner._close_mcp_process(process, {}, terminate=True) == ''
    assert signals == [123]
    transport._proc = object()
    with pytest.raises(Refused, match='process generation'):
        await runner._close_mcp_process(process, {}, terminate=True)
    assert signals == [123]

@pytest.fixture
def inline_context(tmp_path, monkeypatch):
    import hashlib
    import json
    import os
    import sys
    import types
    from cleanup_effects import CleanupCalls
    from cleanup_launch import PINS
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from tests import test_acp_cleanup as original
    checkout = Path(__file__).resolve().parents[2]
    owned = tmp_path / 'owned'
    base = owned / 'pytest' / 'case'
    base.mkdir(parents=True)
    data = json.dumps({'schema': 'unrest.guard-content.v1', 'files': [
        {'path': name, 'sha256': pin} for name, pin in sorted(PINS.items())]}).encode()
    (tmp_path / 'source-manifest.json').write_bytes(data)
    root = {'HOME': str(owned / 'home'), 'TMPDIR': str(owned / 'tmp'), 'PATH': '/usr/bin:/bin',
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    for key in tuple(os.environ):
        monkeypatch.delenv(key)
    import cleanup_launch
    monkeypatch.setattr(cleanup_launch, 'base_path', lambda value, owned: Path(value))
    def context(case):
        name = case.split('::')[1].split('[')[0]
        function = vars(original)[name]
        variant = case.endswith('[True]')
        item = types.SimpleNamespace(nodeid=case, module=original, obj=function, originalname=name,
            funcargs={'tmp_path': base, 'cancel': variant, 'settlement_fault': variant})
        policy = types.SimpleNamespace(directory=tmp_path, case=case, children={}, profile={
            'checkout': str(checkout), 'owned': str(owned), 'source_sha256': hashlib.sha256(data).hexdigest(),
            'native': sys.executable, 'native_sha256': 'a' * 64, 'environment': root})
        for key, value in {**root, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}.items():
            monkeypatch.setenv(key, value)
        return original, function, base, policy, CleanupCalls(policy, item)
    return context


@pytest.mark.parametrize('case', (*CLIENT, *INFLIGHT))
@pytest.mark.parametrize('effect', ('launch', 'signal'))
@pytest.mark.asyncio
async def test_original_client_launch_siblings_without_process_effects(case, inline_context, monkeypatch, effect, mutation=None):
    import asyncio
    import asyncio.unix_events
    import sys
    original, function, base, policy, calls = inline_context(case)
    admitted, signals, checking, failures = [], [], [], []
    class Stop(BaseException):
        pass
    async def wait(self):
        if checking and self.returncode is None:
            raise asyncio.TimeoutError
        return self.returncode
    def terminate(self, sig=15):
        from source_owner import active_frames
        frames = active_frames()
        try:
            owned = any(f.f_code.co_qualname in ('_close_subprocess', 'ACPClient._cleanup.<locals>.finish_terminal') for f in frames)
        finally:
            del frames
        if checking and owned:
            try:
                calls.signal(self.pid, sig, False)
            except BaseException as error:
                failures.append(error)
                raise
            signals.append((self.pid, sig))
        self._transport._returncode = -sig
    def close(transport):
        if type(transport._returncode) is int:
            saved = policy.children[transport._pid]
            # Synthetic acknowledgement exercises source-state consumption only;
            # the native run must still supply its actual parent wait join.
            code = transport._returncode
            saved['wait_raw'] = -code if code < 0 else code << 8
            transport._proc = None
    monkeypatch.setattr(asyncio.unix_events._UnixSubprocessTransport, 'close', close)
    monkeypatch.setattr(asyncio.subprocess.Process, 'wait', wait)
    monkeypatch.setattr(asyncio.subprocess.Process, 'terminate', terminate)
    monkeypatch.setattr(asyncio.subprocess.Process, 'kill', lambda self: terminate(self, 9))
    async def spawn(factory, program, *args, **kwargs):
        if mutation == 'body':
            args = ('-c', SLEEP + ';pass')
        elif mutation == 'case':
            policy.case = case + '-foreign'
        elif mutation == 'caller':
            import source_owner
            monkeypatch.setattr(source_owner, 'active_frames', lambda: (sys._getframe(),))
        try:
            intent = calls.startup.select(case, (program, [program, *args], kwargs.get('cwd'), kwargs.get('env')))
        except BaseException as error:
            failures.append(error)
            raise
        admitted.append(intent)
        if effect == 'launch' and len(admitted) == child_count(case):
            raise Stop
        transport = object.__new__(asyncio.unix_events._UnixSubprocessTransport)
        transport._closed, transport._pid, transport._proc, transport._returncode = True, 100 + len(admitted), object(), None
        policy.children[transport._pid] = {'process': transport._proc, 'case': case}
        protocol = factory()
        protocol.stdout = asyncio.StreamReader()
        protocol.stdout.feed_eof()
        return transport, protocol
    monkeypatch.setattr(asyncio.get_running_loop(), 'subprocess_exec', spawn)
    arguments = [base, monkeypatch]
    if case not in (next(iter(CLIENT)),):
        arguments.append(case.endswith('[True]'))
    # The third inflight launch runs in the original separate producer Task.
    if effect == 'signal':
        from unrest_harness import acp_runner
        original_cleanup = acp_runner.ACPClient.cleanup
        async def cleanup(self):
            checking.append(True)
            try:
                try:
                    await original_cleanup(self)
                except Refused as error:
                    failures.append(error)
                    raise
                except BaseException as error:
                    if (type(error) not in (RuntimeError, asyncio.CancelledError)
                            or type(error) is RuntimeError and error.args not in (
                                ('controlled reader fault',), ('controlled terminal cleanup fault',),
                                ('controlled post-settlement failure',))):
                        failures.append(error)
                        raise
            finally:
                checking.clear()
            raise Stop
        monkeypatch.setattr(acp_runner.ACPClient, 'cleanup', cleanup)
    if case in INFLIGHT and effect == 'launch':
        async def wait_for(awaitable, timeout):
            if awaitable.cr_code.co_qualname != 'Event.wait':
                return await awaitable
            task = asyncio.ensure_future(awaitable)
            for _ in range(100):
                await asyncio.sleep(0)
                if failures:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise failures[0]
                if effect == 'launch' and len(admitted) == 3 or effect == 'signal' and signals:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise Stop
                if task.done():
                    return task.result()
            raise AssertionError('finite no-effect producer did not reach launch')
        monkeypatch.setattr(asyncio, 'wait_for', wait_for)
    with pytest.raises(Refused if mutation else Stop):
        await function(*arguments)
    if mutation:
        assert admitted == [] and not signals
        return
    assert len(admitted) == child_count(case)
    assert not failures
    assert {pid for pid, sig in signals} == (set(range(101, 101 + child_count(case))) if effect == 'signal' else set())
    assert all(type(sig) is int and sig in (9, 15) for pid, sig in signals)
    assert all(value.original.argv == (sys.executable, '-c', SLEEP) for value in admitted)
    if case in INFLIGHT:
        assert admitted[-1].original.cwd == str(base)
        assert admitted[-1].original.environment == ()


@pytest.mark.parametrize('case', (*CLIENT, *INFLIGHT))
@pytest.mark.parametrize('mutation', ('body', 'case', 'caller'))
@pytest.mark.asyncio
async def test_original_client_rejects_foreign_launch_context(case, mutation, inline_context, monkeypatch):
    await test_original_client_launch_siblings_without_process_effects(
        case, inline_context, monkeypatch, 'launch', mutation)


@pytest.mark.parametrize('mutation', (None, 'missing-wait', 'wrong-status', 'wrapper', 'transport', 'case', 'duplicate'))
def test_reaped_inline_child_needs_original_wrapper_and_joined_wait(mutation):
    import asyncio
    import asyncio.unix_events
    import types
    from cleanup_inline import Launches
    case = tuple(CLIENT)[1]
    transport = object.__new__(asyncio.unix_events._UnixSubprocessTransport)
    transport._closed, transport._pid, transport._proc, transport._returncode = True, 123, object(), None
    process = object.__new__(asyncio.subprocess.Process)
    process.pid, process._transport = 123, transport
    saved = {'process': transport._proc, 'case': case}
    policy = types.SimpleNamespace(case=case, children={123: saved})
    launches = object.__new__(Launches)
    launches.policy = policy
    launches.calls = types.SimpleNamespace(policy=policy, transport_class=type(transport))
    launches.children([process], 1)  # Establish the actual live wrapper generation.
    transport._proc, transport._returncode, saved['wait_raw'] = None, -15, 15
    if mutation == 'missing-wait':
        del saved['wait_raw']
    elif mutation == 'wrong-status':
        saved['wait_raw'] = 0
    elif mutation == 'wrapper':
        saved['async_process'] = object()
    elif mutation == 'transport':
        saved['transport'] = object()
    elif mutation == 'case':
        saved['case'] = case + '-foreign'
    children = [process, process] if mutation == 'duplicate' else [process]
    if mutation:
        with pytest.raises(Refused):
            launches.children(children, 2)
    else:
        launches.children(children, 1)
