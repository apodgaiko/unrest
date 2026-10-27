"""Original cleanup configuration and finite input/entry mutation controls."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from cleanup_launch import CASES, OFFLINE, PINS, SCRIPT, environment, expected, scenario, snapshot_path, translated
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
