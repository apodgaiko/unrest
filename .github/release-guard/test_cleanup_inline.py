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
    policy = Bodies({'role': 'cleanup-inline', 'case': case})
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
