"""Original cleanup configuration and finite input/entry mutation controls."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from cleanup_launch import ALL_CASES, RECORDED, FAULTS, CASES, OFFLINE, selection, child_count, module_mode, git_completion, PINS, SCRIPT, environment, expected, scenario, snapshot_path, translated
import cleanup_launch
from content_manifest import Refused
from source_owner import Link


def test_cleanup_original_sources_are_byte_current():
    checkout = Path(__file__).resolve().parents[2]
    for name, pin in PINS.items():
        assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == pin


def test_independent_codex_mock_environment_matches_original_runtime(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from unrest_harness.acp_runner import ACPNodeRunner
    from unrest_harness.assets import AssetLoader
    from unrest_harness.models import Task
    from tests.test_provider_review import controller_fixture
    for key in tuple(__import__('os').environ):
        monkeypatch.delenv(key)
    root = {'HOME': str(tmp_path / 'owned-home'), 'TMPDIR': str(tmp_path / 'owned-tmp'), 'PATH': '/usr/bin:/bin'}
    for key, value in root.items():
        monkeypatch.setenv(key, value)
    _, store, _ = controller_fixture(tmp_path)
    config = replace(store.config, worker_acp_command='/pinned/python /pinned/cleanup.py /owned/scenario.json')
    runtime = ACPNodeRunner(config, AssetLoader(config))._node_runtime('project', 'mission-001',
        Task(id='w1', type='work', body='controlled', targets=[], skill='s'), 'attempt-1', store, None)
    assert runtime.agent_environment == environment(tmp_path, root, agent=True)
    assert {**runtime.runtime_environment, **root, 'UNREST_NODE_ASSIGNMENT': '{"targets":[],"task_type":"work"}'} == environment(tmp_path, root, agent=False)


@pytest.mark.parametrize('case', CASES)
def test_scenario_preserves_original_parameters_and_receipt(tmp_path, case):
    data = json.loads(scenario(case, tmp_path))
    if case == CASES[2]:
        assert data == {'role': 'work', 'no_handoff': True}
    else:
        assert data['receipt'] == str(tmp_path / 'receipt') and data['role'] == 'work'
        if case == CASES[1]:
            assert json.loads(data['raw']) == {'jsonrpc': '2.0', 'id': [], 'result': {}}
        else:
            assert data['raw'] is None
    assert snapshot_path(tmp_path, case).parent == tmp_path


def test_module_and_script_translation_preserve_original_plan(tmp_path):
    root = {'HOME': '/owned/home', 'TMPDIR': '/owned/tmp', 'PATH': '/usr/bin:/bin'}
    result = expected(CASES[0], 'mcp', tmp_path, '/native', 'a' * 64, tmp_path / 'checkout', root, port=12345, descriptor=12)
    assert result.argv[:3] == ('/native', '-m', 'unrest_harness')
    assert result.argv[-4:] == ('--port', '12345', '--sensitive-inventory-fd', '12')
    assert translated(result, tmp_path) == ('/native', '-I', '-S', *result.argv[1:])
    assert 'FASTMCP_CHECK_FOR_UPDATES' not in dict(result.environment)
    assert OFFLINE == {'FASTMCP_CHECK_FOR_UPDATES': 'off'}
    agent = expected(CASES[0], 'cleanup-acp', tmp_path, '/native', 'a' * 64, tmp_path / 'checkout', root)
    assert agent.argv == ('/native', str(tmp_path / 'checkout' / SCRIPT), str(tmp_path / 'scenario.json'))
    assert translated(agent, tmp_path)[-1] == str(snapshot_path(tmp_path, CASES[0]))


@pytest.mark.parametrize('port,descriptor', [(0, 12), (65536, 12), (True, 12), (12345, True), (12345, 2), (12345, 1025)])
def test_module_has_no_generic_port_or_descriptor_permission(tmp_path, port, descriptor):
    with pytest.raises(Refused, match='listener or descriptor'):
        expected(CASES[0], 'mcp', tmp_path, '/native', 'a' * 64, tmp_path, {}, port=port, descriptor=descriptor)


def test_cancel_case_has_no_native_git_permission(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup_launch, 'system_git', lambda: pytest.fail('unexpected Git measurement'))
    with pytest.raises(Refused, match='undeclared launch role'):
        expected(CASES[2], 'git-observe', tmp_path, '/native', 'a' * 64, tmp_path, {})


def test_static_function_link_checks_the_original_descriptor():
    def original():
        return 1
    descriptor = staticmethod(original)
    link = Link(descriptor, '__func__', original, 'static-function')
    link.check()
    with pytest.raises(Refused, match='identity link changed'):
        Link(staticmethod(lambda: 2), '__func__', original, 'static-function').check()


def test_inherited_read_pipe_flags_are_rechecked_after_parent_measurement():
    import os
    import fcntl
    from source_profile import inherited_descriptor
    read, write = os.pipe()
    try:
        info = os.fstat(read)
        row = [[read, info.st_dev, info.st_ino]]
        assert inherited_descriptor(row, read, info, fcntl.fcntl(read, fcntl.F_GETFL), os.getuid()) == row[0]
        fcntl.fcntl(read, fcntl.F_SETFL, os.O_NONBLOCK)
        with pytest.raises(Refused, match='inherited descriptor'):
            inherited_descriptor(row, read, os.fstat(read), fcntl.fcntl(read, fcntl.F_GETFL), os.getuid())
        with pytest.raises(Refused, match='inherited descriptor'):
            inherited_descriptor(row, read, info, 0, os.getuid() + 1)
        output = os.fstat(write)
        with pytest.raises(Refused, match='inherited descriptor'):
            inherited_descriptor([[write, output.st_dev, output.st_ino]], write, output,
                                 fcntl.fcntl(write, fcntl.F_GETFL), os.getuid())
    finally:
        os.close(read)
        os.close(write)


def test_original_free_port_bind_has_its_actual_source_owner(monkeypatch):
    import socket
    from unrest_harness import acp_runner
    from cleanup_effects import CleanupCalls
    from source_calls import Sources
    from source_owner import prepare
    from ordinary_acp import PRODUCT
    checkout = Path(__file__).resolve().parents[2]
    file = checkout / PRODUCT
    unit = prepare(file.read_bytes(), str(file), acp_runner.__name__, Sources.mode(acp_runner), PINS[PRODUCT])
    cls = acp_runner.ACPNodeRunner
    descriptor = vars(cls)['_find_free_port']
    calls = object.__new__(CleanupCalls)
    calls.probe = Sources.owner(unit, acp_runner, descriptor.__func__, 'ACPNodeRunner._find_free_port',
        (Link(cls, '_find_free_port', descriptor), Link(descriptor, '__func__', descriptor.__func__, 'static-function')))
    effects = []
    class Probe:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def bind(self, address):
            assert address == ('127.0.0.1', 0)
            effects.append(calls.listener())
        def getsockname(self):
            return '127.0.0.1', 12345
    monkeypatch.setattr(socket, 'socket', lambda *args: Probe())
    assert cls._find_free_port() == 12345
    assert effects == [{'tag': 'mcp-probe', 'nonce': None}]
    with pytest.raises(Refused, match='free port probe'):
        calls.listener()


@pytest.mark.parametrize('case', ALL_CASES)
@pytest.mark.asyncio
async def test_original_mcp_constructor_options_without_launch(tmp_path, monkeypatch, case):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    import asyncio
    import sys
    import types
    from unrest_harness import acp_runner
    from unrest_harness.assets import AssetLoader
    from unrest_harness.models import Task
    from tests.test_provider_review import controller_fixture
    from cleanup_launch import Launches
    from source_calls import Sources
    checkout = Path(__file__).resolve().parents[2]
    _, store, _ = controller_fixture(tmp_path)
    runner = acp_runner.ACPNodeRunner(store.config, AssetLoader(store.config))
    calls = object.__new__(Sources)
    calls.profile = {'checkout': str(checkout), 'owned': str(tmp_path.parent), 'native': sys.executable,
                     'native_sha256': 'a' * 64, 'environment': {'HOME': '/home', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin'}}
    calls.policy = types.SimpleNamespace(profile=calls.profile, directory=tmp_path)
    calls.pins = PINS
    calls.tests = sys.modules[__name__]
    function = test_original_mcp_constructor_options_without_launch
    calls.test_owner = types.SimpleNamespace(function=function, verify=lambda frame: None, verify_binding=lambda: None)
    _, variant, case_role = selection(case)
    calls.case_item = types.SimpleNamespace(funcargs={'tmp_path': tmp_path, 'fault': variant, 'role': case_role})
    launches = Launches(calls)
    monkeypatch.setattr(cleanup_launch, 'base_path', lambda value, owned: Path(value))
    monkeypatch.setattr(cleanup_launch, 'read_pipe', lambda pid, fd: None)
    observed = []
    class Stop(BaseException):
        pass
    async def subprocess_exec(factory, program, *args, **kwargs):
        observed.append(launches.select(case, (program, [program, *args], kwargs['cwd'], kwargs['env'])))
        raise Stop
    monkeypatch.setattr(asyncio.get_running_loop(), 'subprocess_exec', subprocess_exec)
    env = environment(tmp_path, calls.profile['environment'], agent=False, case=case)
    recorded, _, role = selection(case)
    async def launch_mcp():
            if role == 'terminal_reviewer':
                await runner._start_terminal_reviewer_mcp(project_id='project', mission_id='mission-001',
                    report_path=env['UNREST_TERMINAL_REVIEW_PATH'], workspace_dir=str(tmp_path / 'workspace'),
                    mcp_port=12345, sensitive_inventory=acp_runner.finite_credential_values({}), environment=env)
            else:
                await runner._start_worker_mcp_server(task=Task(id='w1', type=role, body='controlled',
                    targets=['VAL-CLEANUP'] if recorded and role == 'validate' else [], skill='s'),
                    project_id='project', mission_id='mission-001', handoff_path=env['UNREST_HANDOFF_PATH'],
                    workspace_dir=str(tmp_path / 'workspace'), mcp_port=12345,
                    sensitive_inventory=acp_runner.finite_credential_values({}), environment=env)
    with pytest.raises(Stop):
        if case in FAULTS:
            await asyncio.create_task(launch_mcp())
        else:
            await launch_mcp()
    assert len(observed) == 1 and observed[0].original.rule == 'cleanup:mcp'
    (tmp_path / 'scenario.json').write_bytes(scenario(case, tmp_path))
    plan = acp_runner.build_launch_plan(f'{sys.executable} {checkout / SCRIPT} {tmp_path / "scenario.json"}',
        cwd=str(tmp_path / 'workspace'), environment=environment(tmp_path, calls.profile['environment'], agent=True, case=case))
    async def launch_acp():
        return await acp_runner.spawn_launch(plan, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE, limit=8 * 1024 * 1024)
    with pytest.raises(Stop):
        if case in FAULTS:
            await asyncio.create_task(launch_acp())
        else:
            await launch_acp()
    assert len(observed) == 2 and observed[1].original.rule == 'cleanup:cleanup-acp'


@pytest.mark.parametrize('case', ALL_CASES)
def test_cleanup_declaration_preserves_every_original_role_and_payload(tmp_path, case, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from tests.test_acp_cleanup import malformed
    recorded, variant, role = selection(case)
    body = json.loads(scenario(case, tmp_path))
    assert body['role'] == role
    if recorded:
        assert case in RECORDED and body['raw'] == malformed(variant)
        assert body['receipt'] == str(tmp_path / 'receipt')
    else:
        assert body == {'role': role, 'no_handoff': True}
    assert module_mode(case) == {'work': 'worker', 'validate': 'validator', 'terminal_reviewer': 'terminal-reviewer'}[role]
    assert child_count(case) == ((5 if role == 'work' else 4) if recorded else 2)
    assert git_completion(case) is (recorded and role == 'work')
    env = environment(tmp_path, {'HOME': '/home', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin'}, agent=False, case=case)
    if role == 'terminal_reviewer':
        assert not {'UNREST_NODE_ID', 'UNREST_NODE_TYPE', 'UNREST_HANDOFF_PATH', 'UNREST_NODE_ASSIGNMENT'} & env.keys()
        assert env['UNREST_TERMINAL_REVIEW_PATH'].endswith('/terminal-reviews/attempt-1.json')
    else:
        assert env['UNREST_NODE_ID'] == 'w1' and env['UNREST_NODE_TYPE'] == role
        assert json.loads(env['UNREST_NODE_ASSIGNMENT']) == {'targets': ['VAL-CLEANUP'] if recorded and role == 'validate' else [], 'task_type': role}


def test_cleanup_declaration_does_not_admit_adjacent_cases_or_git(tmp_path):
    for case in (CASES[0] + '-foreign', 'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[observer]', True):
        with pytest.raises(Refused):
            selection(case)
    for case in ALL_CASES:
        if not git_completion(case):
            with pytest.raises(Refused, match='undeclared launch role'):
                expected(case, 'git-observe', tmp_path, '/native', 'a' * 64, tmp_path, {})


@pytest.mark.asyncio
async def test_terminal_agent_environment_matches_original_lifecycle(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    import os
    import sys
    import types
    from unrest_harness import acp_runner
    from unrest_harness.assets import AssetLoader
    from tests.test_provider_review import controller_fixture
    for name in tuple(os.environ):
        monkeypatch.delenv(name)
    root = {'HOME': str(tmp_path / 'ambient-home'), 'TMPDIR': str(tmp_path / 'ambient-tmp'), 'PATH': '/usr/bin:/bin'}
    for name, value in root.items():
        monkeypatch.setenv(name, value)
    _, store, _ = controller_fixture(tmp_path)
    command = f'{sys.executable} {Path(__file__).resolve().parents[2] / SCRIPT} {tmp_path / "scenario.json"}'
    config = replace(store.config, terminal_reviewer_acp_command=command)
    runner = acp_runner.ACPNodeRunner(config, AssetLoader(config))
    from source_calls import Sources, nested_signal
    from source_owner import prepare, active_frames
    from ordinary_acp import PRODUCT
    module_file = Path(__file__).resolve().parents[2] / PRODUCT
    unit = prepare(module_file.read_bytes(), str(module_file), acp_runner.__name__, Sources.mode(acp_runner), PINS[PRODUCT])
    signal_calls = object.__new__(Sources)
    signal_calls.startup = types.SimpleNamespace(module=acp_runner, unit=unit)
    signal_calls.cleanup = ()
    captured = {}
    def check_signal(self, pid, sig, group):
        assert pid == 123 and sig == 15 and group is False
        owner = self.cleanup[-1]
        frames = active_frames()
        try:
            frame = next(frame for frame in frames if frame.f_code is owner.function.__code__)
            owner.verify(frame)
            captured['cleanup_owner'] = owner.qualified
        finally:
            del frames
    monkeypatch.setattr(Sources, 'signal', check_signal)
    def cleanup_signal():
        nested_signal(signal_calls, 123, 15, False)
    class Stop(BaseException):
        pass
    async def start(**kwargs):
        captured['mcp'] = kwargs['environment']
        return types.SimpleNamespace(returncode=None, terminate=lambda: cleanup_signal())
    async def ready(*args, **kwargs):
        pass
    async def close(*args, **kwargs):
        pass
    async def launch(plan, **kwargs):
        captured['agent'] = dict(plan.environment)
        raise Stop
    monkeypatch.setattr(runner, '_find_free_port', lambda: 12345)
    monkeypatch.setattr(runner, '_start_terminal_reviewer_mcp', start)
    monkeypatch.setattr(runner, '_wait_for_server_ready', ready)
    monkeypatch.setattr(runner, '_close_mcp_process', close)
    monkeypatch.setattr(acp_runner, 'spawn_launch', launch)
    with pytest.raises(Stop):
        await runner.run_terminal_review('project', 'mission-001', 'attempt-1', store)
    case = next(case for case in ALL_CASES if selection(case)[2] == 'terminal_reviewer')
    assert captured['mcp'] == environment(tmp_path, root, agent=False, case=case)
    assert captured['agent'] == environment(tmp_path, root, agent=True, case=case)
    assert captured['cleanup_owner'] == 'ACPNodeRunner._run_terminal_review_lifecycle.<locals>.finish_mcp'


@pytest.mark.parametrize('qualified', ('ACPNodeRunner.run_node.<locals>.finish_mcp',
    'ACPNodeRunner._run_terminal_review_lifecycle.<locals>.finish_mcp'))
def test_mcp_finalizer_targets_mcp_even_when_agent_is_also_captured(qualified):
    import asyncio
    import asyncio.unix_events
    import types
    from source_calls import Sources
    transport_type = asyncio.unix_events._UnixSubprocessTransport
    def child(pid, original):
        transport = object.__new__(transport_type)
        transport._closed = True
        transport._pid, transport._proc = pid, original
        process = object.__new__(asyncio.subprocess.Process)
        process._transport = transport
        return process
    agent_native, mcp_native = object(), object()
    agent, mcp = child(122, agent_native), child(123, mcp_native)
    calls = object.__new__(Sources)
    calls.process_class, calls.transport_class = asyncio.subprocess.Process, transport_type
    calls.policy = types.SimpleNamespace(children={123: {'process': mcp_native}})
    def finish(process, mcp_process):
        Sources.signal(calls, 123, 15, False)
    calls.cleanup = (types.SimpleNamespace(function=finish, qualified=qualified, verify=lambda frame: None),)
    finish(agent, mcp)
    mcp._transport._proc = agent_native
    with pytest.raises(Refused, match='process generation'):
        finish(agent, mcp)


@pytest.mark.parametrize('mutation', ('role', 'fault', 'root', 'type', 'key'))
@pytest.mark.asyncio
async def test_scheduled_fault_admission_keeps_exact_selected_fixture(mutation, tmp_path, monkeypatch):
    from cleanup_launch import Launches
    original = Launches.select
    callbacks = []
    class Collision:
        def __hash__(self):
            return hash('fault')
        def __eq__(self, other):
            callbacks.append('equality')
            raise AssertionError('untrusted fixture-key callback')
    def changed(self, case, audit):
        values = self.calls.case_item.funcargs
        if mutation == 'role':
            values['role'] = 'terminal_reviewer'
        elif mutation == 'fault':
            values['fault'] = 'cancel'
        elif mutation == 'root':
            values['tmp_path'] = tmp_path.parent / 'foreign-case'
        elif mutation == 'key':
            self.calls.case_item.funcargs = {Collision(): 'reader'}
        else:
            values['tmp_path'] = str(tmp_path)
        return original(self, case, audit)
    monkeypatch.setattr(Launches, 'select', changed)
    with pytest.raises(Refused):
        await test_original_mcp_constructor_options_without_launch(tmp_path, monkeypatch, FAULTS[0])
    assert callbacks == []
