"""Diagnostic-only MCP routes retain exact roles and actual cleanup evidence."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from mcp_inventory import DIAGNOSTICS, proposal
from source_observer import Observer


@pytest.mark.parametrize('case', DIAGNOSTICS)
@pytest.mark.parametrize('change', [None, 'project', 'mission', 'node', 'assignment', 'descendant', 'ACP'])
def test_diagnostic_route_keeps_role_budget_and_bounded_metadata_delegation(tmp_path, monkeypatch, case, change):
    import owned_fixture
    import node_launch
    base = tmp_path / 'case'
    root = Path(__file__).resolve().parents[2]
    first = case == DIAGNOSTICS[0]
    slug = 'missing-handoff-regression' if first else 'worker-mcp-timeout-regression'
    project = '20261030T000000Z-' + slug
    env = {'UNREST_PROJECT_ID': project, 'UNREST_MISSION_ID': 'mission-001',
           'UNREST_NODE_ID': 'w1' if first else 'w-timeout',
           'UNREST_NODE_ASSIGNMENT': '{"targets":["VAL-001"],"task_type":"work"}'}
    calls = []
    monkeypatch.setattr(owned_fixture, 'retain', lambda *args: base)
    monkeypatch.setattr(node_launch, 'proposal', lambda *args: calls.append(args) or 'admitted')
    def root_only(actor):
        if actor['role'] != 'root':
            raise Refused('root only')
    host = SimpleNamespace(case=case, meta={'checkout': str(root)}, fixture_roots={},
                           intents={}, root_only=root_only, meta_environment=lambda: {})
    raw = {'argv': ['/native', '-m', 'unrest_harness'], 'cwd': str(base / 'workspace'), 'environment': env}
    actor = {'role': 'root', 'birth': 'root'}
    if change in ('project', 'mission', 'node', 'assignment'):
        key = {'project': 'UNREST_PROJECT_ID', 'mission': 'UNREST_MISSION_ID',
               'node': 'UNREST_NODE_ID', 'assignment': 'UNREST_NODE_ASSIGNMENT'}[change]
        env[key] = 'foreign'
    elif change == 'descendant':
        actor['role'] = 'mcp'
    elif change == 'ACP':
        raw['argv'] = ['/native', 'mock.py']
    if change in ('descendant','ACP'):
        with pytest.raises(Refused):
            proposal(host, actor, raw)
        assert not calls
    else:
        assert proposal(host, actor, raw) == 'admitted'
        assert calls[0][3] == base / 'workspace'
        assert calls[0][7] == {'work': 1}
        assert calls[0][10:12] == (('--missing-handoff-session-error',), 1)


@pytest.mark.parametrize('ready', [False, True])
def test_missing_handoff_mock_requires_same_root_mcp_ready(tmp_path, monkeypatch, ready):
    import owned_fixture
    import node_launch
    base = tmp_path / 'case'
    monkeypatch.setattr(owned_fixture, 'retain', lambda *args: base)
    monkeypatch.setattr(node_launch, 'proposal', lambda *args: 'admitted')
    case = DIAGNOSTICS[0]
    host = SimpleNamespace(case=case, meta={'checkout': str(Path(__file__).resolve().parents[2])},
        fixture_roots={}, intents={1: {'case': case, 'role': 'mcp', 'parent': 'root', 'pid': 5}},
        actors={5: {'body_ready': ready}}, executed=lambda row: True,
        root_only=lambda actor: None, meta_environment=lambda: {})
    raw = {'argv': ['/native', 'mock.py'], 'cwd': str(base / 'workspace'), 'environment': {
        'UNREST_PROJECT_ID': '20261030T000000Z-missing-handoff-regression',
        'UNREST_MISSION_ID': 'mission-001', 'UNREST_NODE_ID': 'w1'}}
    if ready:
        assert proposal(host, {'birth': 'root'}, raw) == 'admitted'
    else:
        with pytest.raises(Refused, match='before actual MCP ready'):
            proposal(host, {'birth': 'root'}, raw)


@pytest.mark.parametrize('mutation', [None, 'unwaited', 'unattributed', 'wrong-exit', 'unexecuted'])
def test_intentional_pre_ready_timeout_requires_real_reap_and_attributed_termination(monkeypatch, mutation):
    import source_observer
    monkeypatch.setattr(source_observer, 'bound_intent', lambda *args: {'ticket': 1})
    process = SimpleNamespace(terminal=(0, 0, 0 if mutation == 'wrong-exit' else -15),
                              generation=0 if mutation == 'unexecuted' else 1)
    host = SimpleNamespace(ledger=SimpleNamespace(process=lambda birth: process,
        reaped=lambda *args: mutation != 'unwaited'))
    actor = {'case': DIAGNOSTICS[1], 'role': 'mcp', 'birth': 'owned', 'token': 'bound',
             'signals': set() if mutation == 'unattributed' else {15}, 'body_ready': False}
    assert Observer.completed_child(host, actor) is (mutation is None)
