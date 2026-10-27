"""Finite ordinary admission mutations; real original execution is separate CI."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from types import MappingProxyType

import pytest

from content_manifest import Refused
from ordinary_acp import CASES, MOCK, PINS, environment, expected, plain_environment, options
import ordinary_acp
from source_observer import Observer
from process_ledger import Birth
from source_owner import Link


class CallbackTrap:
    def __eq__(self, other):
        pytest.fail('admission invoked caller equality')

    def __ne__(self, other):
        pytest.fail('admission invoked caller inequality')

    def __getitem__(self, key):
        pytest.fail('admission invoked mapping lookup')

    def __len__(self):
        pytest.fail('admission invoked mapping length')

    def __iter__(self):
        pytest.fail('admission invoked caller iteration')

    def __hash__(self):
        return hash('PATH')


def test_original_ordinary_files_are_byte_pinned():
    checkout = Path(__file__).resolve().parents[2]
    for name, pin in PINS.items():
        assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == pin
    assert (checkout / MOCK).read_text().count('from unrest_harness') == 0


def test_mapping_proxy_refuses_custom_underlying_mapping_without_callbacks():
    with pytest.raises(Refused, match='underlying dictionary'):
        plain_environment(MappingProxyType(CallbackTrap()))
    with pytest.raises(Refused, match='primitives'):
        plain_environment(MappingProxyType({'PATH': CallbackTrap()}))
    assert plain_environment(MappingProxyType({'PATH': '/usr/bin:/bin'})) == {'PATH': '/usr/bin:/bin'}


def test_original_test_frame_link_is_live():
    target = object()
    frame = sys._getframe()
    link = Link(frame, 'target', target, 'frame')
    link.check()
    target = object()
    with pytest.raises(Refused, match='identity link changed'):
        link.check()


@pytest.mark.parametrize('case', CASES)
def test_ordinary_independent_environment_and_no_crashed_sibling_route(tmp_path, case):
    root_environment = {'HOME': '/owned/home', 'TMPDIR': '/owned/tmp', 'PATH': '/usr/bin:/bin',
                        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    result = environment(case, tmp_path, root_environment)
    assert set(result) == {'HOME', 'TMPDIR', 'PATH', 'UNREST_CAPABILITY_PROFILE',
        'UNREST_CAPABILITY_POLICY_VERSION', 'UNREST_HOME', 'UNREST_PROJECT_ID', 'UNREST_MISSION_ID',
        'UNREST_NODE_ID', 'UNREST_NODE_TYPE', 'UNREST_HANDOFF_PATH'} | ({'ANTHROPIC_API_KEY'} if case == CASES[2] else set())
    assert 'v-crash' not in result['UNREST_HANDOFF_PATH']
    assert result['UNREST_HOME'] == str(tmp_path / '.unrest')
    assert result['UNREST_CAPABILITY_PROFILE'] == 'safe'


@pytest.mark.parametrize('mutation', ('case', 'site', 'argv', 'cwd', 'environment', 'pin', 'owner', 'script', 'translated'))
def test_host_refuses_ordinary_request_mutations(tmp_path, mutation):
    observer = object.__new__(Observer)
    observer.root_birth = Birth(1, 1, 1, 1, 'test-boot', 20000)
    observer.finished, observer.case, observer.serial = False, CASES[0], 0
    observer.meta = {'owned': str(tmp_path), 'checkout': str(tmp_path / 'checkout')}
    observer.binding = {'entry': {'path': '/pinned/python', 'sha256': 'a' * 64}}
    observer.intents = {}
    cwd = tmp_path / 'pytest/case/workspace'
    cwd.mkdir(parents=True)
    result = expected(CASES[0], 'mock-acp', str(cwd), Path(observer.meta['checkout']), '/pinned/python',
                      'a' * 64, observer.meta_environment(), tmp_path)
    request = {'case': CASES[0], 'source_line': 409, 'script_sha256': PINS[MOCK],
               'original': result.wire(), 'translated': ['/pinned/python', '-I', '-S', *result.argv[1:]]}
    changed = deepcopy(request)
    if mutation == 'case':
        changed['case'] = CASES[1]
    elif mutation == 'site':
        changed['source_line'] += 1
    elif mutation == 'argv':
        changed['original']['argv'].append('--foreign')
    elif mutation == 'cwd':
        changed['original']['cwd'] = str(tmp_path)
    elif mutation == 'environment':
        changed['original']['environment'].append(['FORBIDDEN', '1'])
    elif mutation == 'pin':
        changed['original']['executable_sha256'] = 'b' * 64
    elif mutation == 'owner':
        changed['original']['owner'] = 'unrelated-caller'
    elif mutation == 'script':
        changed['script_sha256'] = 'b' * 64
    else:
        changed['translated'].append('--foreign')
    actor = {'birth': observer.root_birth, 'role': 'root'}
    with pytest.raises(Refused):
        observer.launch(actor, changed)
    assert observer.intents == {}
    assert observer.launch(actor, request)['ok'] is True
    with pytest.raises(Refused):
        observer.launch(actor, request)


def test_native_fixture_keeps_original_executable_and_no_python_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(ordinary_acp, 'system_sleep', lambda: 'b' * 64)
    env = {'HOME': '/home', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    result = expected(CASES[0], 'sleep', str(tmp_path), tmp_path, '/python', 'a' * 64, env, tmp_path)
    assert result.argv == ('/bin/sleep', '30')
    assert result.payload_kind == 'native'
    assert dict(result.environment) == {**env, 'PYTEST_VERSION': pytest.__version__,
                                         'PYTEST_CURRENT_TEST': CASES[0] + ' (call)'}


@pytest.mark.parametrize('field', ('key', 'stdin', 'stdout', 'stderr', 'limit', 'cwd', 'path', 'argv', 'environment'))
def test_constructor_options_refuse_callbacks_before_comparing(field):
    proxy = MappingProxyType({'PATH': '/usr/bin:/bin'})
    plan = {'argv': ('/python', '/mock.py'), 'cwd': '/workspace', 'environment': proxy, 'path': '/usr/bin:/bin'}
    values = {'stdin': -1, 'stdout': -1, 'stderr': -1, 'limit': 8 * 1024 * 1024,
              'kwds': {'cwd': '/workspace', 'env': proxy}}
    trap = CallbackTrap()
    if field == 'key':
        values['kwds'] = {trap: 'foreign'}
    elif field in ('stdin', 'stdout', 'stderr', 'limit'):
        values[field] = trap
    else:
        plan[field] = trap
    with pytest.raises(Refused):
        options(values, 'mock-acp', plan)


def test_ordinary_cleanup_refuses_group_before_observing_any_process():
    from source_root import OrdinaryCalls
    calls = object.__new__(OrdinaryCalls)
    with pytest.raises(Refused, match='no group authority'):
        calls.signal(1, 15, True)


def test_cleanup_qualifier_subclass_never_runs_equality(monkeypatch):
    import source_root
    from types import SimpleNamespace
    class Qualifier(str):
        def __eq__(self, other):
            pytest.fail('qualifier equality callback executed')
    def step():
        return None
    step.__qualname__ = Qualifier('ACPNodeRunner.run_node.<locals>.finish_mcp')
    module = SimpleNamespace()
    frame = SimpleNamespace(f_globals=vars(module), f_code=SimpleNamespace(
        co_qualname='_finish_owned_cleanup.<locals>.finish'), f_locals={'step': step})
    calls = object.__new__(source_root.OrdinaryCalls)
    calls.startup, calls.cleanup = SimpleNamespace(module=module), ()
    monkeypatch.setattr(__import__('source_calls'), 'active_frames', lambda: (frame,))
    monkeypatch.setattr(source_root.Sources, 'signal', lambda *args: None)
    calls.signal(1, 15, False)


def test_exception_cleanup_callsite_stays_exact_original():
    import ast
    source = (Path(__file__).resolve().parents[2] / 'src/unrest_harness/acp_runner.py').read_text()
    nodes = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and node.lineno == 1584]
    assert len(nodes) == 1
    call = nodes[0]
    assert isinstance(call.func, ast.Attribute) and call.func.attr == 'terminate'
    assert isinstance(call.func.value, ast.Name) and call.func.value.id == 'mcp_process'
    assert call.args == [] and call.keywords == []


def test_no_launch_catalogue_preserves_original_parameters_and_ids():
    import ast
    import itertools
    from ordinary_acp import NEGATIVE_CASES, TEST
    tree = ast.parse((Path(__file__).resolve().parents[2] / TEST).read_text())
    names = {case.split('::')[1].split('[')[0] for case in NEGATIVE_CASES}
    collected = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in names:
            continue
        dimensions = []
        for call in reversed(node.decorator_list):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute) or call.func.attr != 'parametrize':
                continue
            values = ast.literal_eval(call.args[1])
            ids = next((ast.literal_eval(key.value) for key in call.keywords if key.arg == 'ids'), None)
            dimensions.append(ids or ['-'.join(value) if isinstance(value, tuple) else str(value) for value in values])
        for values in itertools.product(*dimensions):
            collected.append(TEST + '::' + node.name + ('[' + '-'.join(values) + ']' if values else ''))
    assert tuple(collected) == NEGATIVE_CASES and len(NEGATIVE_CASES) == 39


@pytest.mark.parametrize('case', ordinary_acp.NEGATIVE_CASES)
def test_no_launch_cases_have_no_process_route(tmp_path, case):
    observer = object.__new__(Observer)
    observer.root_birth = Birth(1, 1, 1, 1, 'test-boot', 20000)
    observer.finished, observer.case, observer.intents = False, case, {}
    actor = {'birth': observer.root_birth, 'role': 'root'}
    with pytest.raises(Refused, match='declared launch case'):
        observer.launch(actor, {'case': case, 'original': {}, 'translated': [], 'source_line': 409, 'script_sha256': 'a' * 64})
    assert observer.intents == {}
