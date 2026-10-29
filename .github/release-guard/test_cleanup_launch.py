"""Original cleanup configuration and finite input/entry mutation controls."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from cleanup_launch import ALL_CASES, RECORDED, SAVED, CREDENTIAL, CASES, OFFLINE, selection, module_mode, git_completion, PINS, SCRIPT, environment, expected, scenario, snapshot_path, translated
import cleanup_launch
from content_manifest import Refused


def test_cleanup_original_sources_are_byte_current():
    checkout = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    for name, pin in PINS.items():
        assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == pin


def test_independent_codex_mock_environment_matches_original_runtime(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
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






@pytest.mark.parametrize('case', ALL_CASES)
def test_cleanup_declaration_preserves_every_original_role_and_payload(tmp_path, case, monkeypatch):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
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
    assert git_completion(case) is (recorded and role == 'work')
    env = environment(tmp_path, {'HOME': '/home', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin'}, agent=False, case=case)
    if role == 'terminal_reviewer':
        assert not {'UNREST_NODE_ID', 'UNREST_NODE_TYPE', 'UNREST_HANDOFF_PATH', 'UNREST_NODE_ASSIGNMENT'} & env.keys()
        assert env['UNREST_TERMINAL_REVIEW_PATH'].endswith('/terminal-reviews/attempt-1.json')
    else:
        assert env['UNREST_NODE_ID'] == 'w1' and env['UNREST_NODE_TYPE'] == role
        assert json.loads(env['UNREST_NODE_ASSIGNMENT']) == {'targets': ['VAL-CLEANUP'] if recorded and role == 'validate' else [], 'task_type': role}


def test_cleanup_declaration_does_not_admit_adjacent_cases_or_git(tmp_path):
    for case in (CASES[0] + '-foreign', 'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[foreign]', True):
        with pytest.raises(Refused):
            selection(case)
    for case in ALL_CASES:
        if not git_completion(case):
            with pytest.raises(Refused, match='undeclared launch role'):
                expected(case, 'git-observe', tmp_path, '/native', 'a' * 64, tmp_path, {})


@pytest.mark.parametrize('credential', (False, True))
@pytest.mark.asyncio
async def test_terminal_agent_environment_matches_original_lifecycle(tmp_path, monkeypatch, credential):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
    import os
    import sys
    import types
    from unrest_harness import acp_runner
    from unrest_harness.assets import AssetLoader
    from tests.test_provider_review import controller_fixture
    for name in tuple(os.environ):
        monkeypatch.delenv(name)
    root = {'HOME': str(tmp_path / 'ambient-home'), 'TMPDIR': str(tmp_path / 'ambient-tmp'), 'PATH': '/usr/bin:/bin'}
    if credential:
        monkeypatch.setenv('OPENAI_API_KEY', 'controlled-secret-observer-value')
    for name, value in root.items():
        monkeypatch.setenv(name, value)
    _, store, _ = controller_fixture(tmp_path)
    command = f'{sys.executable} {next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file()) / SCRIPT} {tmp_path / "scenario.json"}'
    config = replace(store.config, terminal_reviewer_acp_command=command)
    runner = acp_runner.ACPNodeRunner(config, AssetLoader(config))
    captured = {}
    def cleanup_signal():
        captured['cleanup_called']=True
    class Stop(BaseException):
        pass
    async def start(**kwargs):
        captured['mcp'] = kwargs['environment']
        captured['inventory'] = dict(kwargs['sensitive_inventory'])
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
    expected_agent = environment(tmp_path, root, agent=True, case=case)
    if credential:
        expected_agent['OPENAI_API_KEY'] = 'controlled-secret-observer-value'
    assert captured['agent'] == expected_agent
    assert captured['inventory'] == ({'OPENAI_API_KEY': 'controlled-secret-observer-value'} if credential else {})
    assert captured['cleanup_called'] is True






@pytest.mark.parametrize('case', SAVED)
def test_saved_review_scenario_and_credential_declaration(case, tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())))
    from tests.test_acp_cleanup import malformed
    _, variant, role = selection(case)
    assert role == 'terminal_reviewer' and not git_completion(case)
    assert json.loads(scenario(case, tmp_path)) == {'role': role, 'progress': True,
        'receipt': str(tmp_path / 'receipt'), 'raw': malformed('array_id') if variant == 'transport' else None}
    root = {'HOME': '/home', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin'}
    assert not CREDENTIAL.keys() & environment(tmp_path, root, agent=False, case=case).keys()
    assert {key: environment(tmp_path, root, agent=True, case=case)[key] for key in CREDENTIAL} == CREDENTIAL
    for native_role in ('git-init', 'git-commit', 'git-observe'):
        with pytest.raises(Refused):
            expected(case, native_role, tmp_path, '/native', 'a' * 64, tmp_path, root)
