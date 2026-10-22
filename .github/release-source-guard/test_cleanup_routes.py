"""Closed original cleanup families; metadata controls never launch a fixture."""
import hashlib
import json
from pathlib import Path
import sys
from types import CodeType, FunctionType, ModuleType, SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from finite import cleanup_routes as routes

ROOT = Path(__file__).resolve().parents[2]


def named(code, name):
    for item in code.co_consts:
        if isinstance(item, CodeType):
            if item.co_name == name:
                return item
            found = named(item, name)
            if found is not None:
                return found
    return None


@pytest.fixture
def model(tmp_path, monkeypatch):
    owner = 'test_cleanup_faults_and_repeated_cancellation'
    source = ROOT / 'tests/test_acp_cleanup.py'
    product = ROOT / 'src/unrest_harness/acp_runner.py'
    fixture = ROOT / 'tests/fixtures/cleanup_acp_process.py'
    code = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True)
    module = ModuleType('cleanup_original_owner_control')
    function = FunctionType(named(code, owner), vars(module))
    setattr(module, owner, function)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    scenario = tmp_path / 'scenario.json'
    task = object()
    environment = {'PATH': '/known/bin'}
    argv = [sys.executable, str(fixture), str(scenario)]
    plan = SimpleNamespace(argv=tuple(argv), cwd=workspace, environment=environment)
    owner_frame = SimpleNamespace(f_code=function.__code__, f_globals=vars(module), f_lineno=245,
                                  f_locals={'tmp_path': tmp_path, 'role': 'work', 'fault': 'reader', 'task': task})
    launch = SimpleNamespace(f_code=SimpleNamespace(co_filename=str(product), co_name='spawn_launch'),
                             f_locals={'plan': plan})
    support = tmp_path / 'runtime_guard.py'
    fallback = support.with_name('fallback_binding.py')
    fallback.write_text("import sys\ndef active_frames():\n    return list(sys.modules['cleanup_original_owner_control']._frames)\n")
    module._frames = [owner_frame, launch]
    state = {'case': routes.FAULT_CASE + '[reader-work]', 'checkout': str(ROOT),
             'owned_root': str(tmp_path), 'class': 'pytest-root', 'guard': str(support),
             'product_pins': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (source, product, fixture)},
             'direct_support': {'files': {str(fallback): hashlib.sha256(fallback.read_bytes()).hexdigest()}},
             'isolated_named': named,
             'isolated_source_code': lambda p: compile(p.read_bytes(), str(p), 'exec', dont_inherit=True)}
    monkeypatch.setattr(routes, 'task_frames', lambda: [owner_frame, launch])
    monkeypatch.setattr(routes, 'current_task', lambda: task)
    events = []
    def refuse(reason):
        raise RuntimeError(reason)
    def select(role='work', fault='reader'):
        owner_frame.f_locals.update(role=role, fault=fault)
        state['case'] = routes.FAULT_CASE + '[' + fault + '-' + role + ']'
        scenario.write_text(json.dumps({'role': role, 'no_handoff': True}))
    select()
    return SimpleNamespace(owner=owner, module=module, source=source, product=product, fixture=fixture,
                           frame=owner_frame, launch=launch, scenario=scenario, task=task,
                           environment=environment, argv=argv, state=state, workspace=workspace,
                           events=events, refuse=refuse, select=select)


@pytest.mark.parametrize('role', ['work', 'validate', 'terminal_reviewer'])
@pytest.mark.parametrize('fault', ['reader', 'client', 'progress', 'cancel', 'primary'])
def test_every_original_fault_parameter_uses_only_its_exact_local_fixture(model, role, fault):
    m = model
    m.select(role, fault)
    result = routes.admit(m.argv, m.workspace, m.environment, m.state, m.events.append, m.refuse)
    assert result == {'class': 'source-cleanup-adapter', 'python': True,
                      'source_binding': {'path': str(m.product), 'line': 409,
                                         'sha256': m.state['product_pins']['src/unrest_harness/acp_runner.py'],
                                         'owner': m.owner}}
    assert m.events[-1]['role'] == role and m.events[-1]['scenario'] == fault


@pytest.mark.parametrize('change', ['case', 'role', 'fault', 'task', 'source', 'scenario',
                                    'fixture', 'argv', 'cwd', 'environment', 'plan'])
def test_scope_and_custody_mutations_cannot_receive_fixture_admission(model, change):
    m = model
    if change == 'case':
        m.state['case'] = routes.FAULT_CASE + '[client-work]'
    elif change in {'role', 'fault'}:
        m.frame.f_locals[change] = 'foreign'
    elif change == 'task':
        m.frame.f_locals['task'] = object()
    elif change == 'source':
        m.state['product_pins']['tests/test_acp_cleanup.py'] = '0' * 64
    elif change == 'scenario':
        m.scenario.write_text(json.dumps({'role': 'work', 'no_handoff': False}))
    elif change == 'fixture':
        m.state['product_pins']['tests/fixtures/cleanup_acp_process.py'] = '0' * 64
    elif change == 'argv':
        m.argv.append('foreign')
    elif change == 'cwd':
        m.workspace = m.workspace.parent
    elif change == 'environment':
        m.environment = {'PATH': '/foreign'}
    else:
        m.launch.f_locals['plan'].argv = ('foreign',)
    with pytest.raises(RuntimeError, match='cleanup_'):
        routes.admit(m.argv, m.workspace, m.environment, m.state, m.events.append, m.refuse)
    assert m.events == []


def test_new_family_never_admits_an_unneeded_git_command(model):
    m = model
    assert routes.admit(['git', 'rev-parse', 'HEAD'], m.workspace, None,
                        m.state, m.events.append, m.refuse) is None
    assert m.events == []


@pytest.mark.parametrize('owner', list(routes.PARAMETERS))
def test_parameter_catalog_matches_frozen_original_decorators(owner):
    import ast
    source = ROOT / 'tests/test_acp_cleanup.py'
    tree = ast.parse(source.read_bytes())
    function = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == owner)
    parameter, values = routes.PARAMETERS[owner]
    declarations = {ast.literal_eval(n.args[0]): ast.literal_eval(n.args[1])
                    for n in function.decorator_list if isinstance(n, ast.Call)}
    assert tuple(declarations[parameter]) == values
    if owner == routes.OBSERVER:
        assert 'role' not in declarations
    else:
        assert declarations['role'] == ['work', 'validate', 'terminal_reviewer']


@pytest.mark.parametrize('role', ['work', 'validate', 'terminal_reviewer'])
@pytest.mark.parametrize('case', ['deep_json', 'array_id', 'object_id', 'success'])
def test_existing_transport_family_keeps_its_exact_scenario_and_plan(model, role, case):
    m = model
    owner = 'test_recorded_transport_failures'
    code = compile(m.source.read_bytes(), str(m.source), 'exec', dont_inherit=True)
    function = FunctionType(named(code, owner), vars(m.module))
    setattr(m.module, owner, function)
    m.frame.f_code = function.__code__
    m.frame.f_locals.update(role=role, case=case, ws=m.workspace)
    m.state['case'] = routes.CASE + '[' + case + '-' + role + ']'
    m.scenario.write_text(json.dumps(routes.scenario_value(owner, case, role, m.scenario.parent)))
    result = routes.admit(m.argv, m.workspace, m.environment, m.state, m.events.append, m.refuse)
    assert result['class'] == 'source-cleanup-adapter'
    assert result['source_binding']['owner'] == owner
    assert m.events[-1]['scenario'] == case and m.events[-1]['role'] == role


@pytest.fixture
def observer_model(model, monkeypatch):
    m = model
    code = compile(m.source.read_bytes(), str(m.source), 'exec', dont_inherit=True)
    fn = FunctionType(named(code, routes.OBSERVER), vars(m.module))
    setattr(m.module, routes.OBSERVER, fn)
    observer = FunctionType(named(fn.__code__, 'observer'), vars(m.module),
                            closure=tuple((lambda value: lambda: value)(None).__closure__[0]
                                          for _ in named(fn.__code__, 'observer').co_freevars))
    product_module = ModuleType('cleanup_product_callback_control')
    from importlib.machinery import SourceFileLoader, ModuleSpec
    loader = SourceFileLoader(product_module.__name__, str(m.product))
    product_module.__loader__ = loader
    product_module.__spec__ = ModuleSpec(product_module.__name__, loader, origin=str(m.product))
    product_code = compile(m.product.read_bytes(), str(m.product), 'exec', dont_inherit=True)
    method = FunctionType(named(product_code, '_run_terminal_review_lifecycle'), vars(product_module))
    product_module.ACPNodeRunner = SimpleNamespace(_run_terminal_review_lifecycle=method)
    monkeypatch.setitem(sys.modules, product_module.__name__, product_module)
    runner, store = object(), object()
    m.frame.f_code = fn.__code__
    m.frame.f_locals = {'tmp_path': m.scenario.parent, 'fault': 'observer', 'observer': observer,
                        'runner': runner, 'store': store}
    callback = SimpleNamespace(f_code=method.__code__, f_globals=vars(product_module),
                                f_locals={'self': runner, 'store': store, 'progress_callback': observer,
                                          'project_id': 'project', 'mission_id': 'mission-001', 'spawn_ts': 'attempt-1'})
    m.module._frames = [m.frame, m.launch, callback]
    monkeypatch.setattr(routes, 'task_frames', lambda: list(m.module._frames))
    m.callback = callback
    def select(fault):
        m.frame.f_locals['fault'] = fault
        m.state['case'] = 'tests/test_acp_cleanup.py::' + routes.OBSERVER + '[' + fault + ']'
        m.scenario.write_text(json.dumps(routes.scenario_value(routes.OBSERVER, fault, 'terminal_reviewer', m.scenario.parent)))
    m.select_observer = select
    select('observer')
    return m


@pytest.mark.parametrize('fault', ['observer', 'cancel', 'transport'])
def test_each_original_saved_observer_variant_keeps_exact_callback_and_scenario(observer_model, fault):
    m = observer_model
    m.select_observer(fault)
    value = routes.admit(m.argv, m.workspace, m.environment, m.state, m.events.append, m.refuse)
    assert value['class'] == 'source-cleanup-adapter'
    assert value['source_binding']['owner'] == routes.OBSERVER
    assert m.events[-1]['role'] == 'terminal_reviewer' and m.events[-1]['scenario'] == fault


@pytest.mark.parametrize('change', ['case', 'parameter', 'callback', 'runner', 'store', 'attempt',
                                   'module', 'code', 'scenario', 'environment', 'cwd', 'argv', 'loader', 'origin'])
def test_saved_observer_custody_mutations_refuse(observer_model, change):
    m = observer_model
    if change == 'case':
        m.state['case'] = m.state['case'].replace('[observer]', '[transport]')
    elif change == 'parameter':
        m.frame.f_locals['fault'] = 'foreign'
    elif change == 'callback':
        m.callback.f_locals['progress_callback'] = object()
    elif change == 'runner':
        m.callback.f_locals['self'] = object()
    elif change == 'store':
        m.callback.f_locals['store'] = object()
    elif change == 'attempt':
        m.callback.f_locals['spawn_ts'] = 'foreign'
    elif change == 'module':
        m.callback.f_globals = dict(m.callback.f_globals)
    elif change == 'code':
        m.callback.f_code = m.frame.f_code
    elif change == 'loader':
        m.callback.f_globals['__loader__'] = object()
    elif change == 'origin':
        m.callback.f_globals['__spec__'].origin = '/foreign'
    elif change == 'scenario':
        m.scenario.write_text('{}')
    elif change == 'environment':
        m.environment = {'PATH': '/foreign'}
    elif change == 'cwd':
        m.workspace = m.workspace.parent
    else:
        m.argv.append('foreign')
    with pytest.raises((RuntimeError, KeyError), match='cleanup_|ACPNodeRunner'):
        routes.admit(m.argv, m.workspace, m.environment, m.state, m.events.append, m.refuse)
    assert m.events == []


def test_every_frozen_owner_of_this_fixture_is_enumerated():
    import ast
    tree = ast.parse((ROOT / 'tests/test_acp_cleanup.py').read_bytes())
    owners = {fn.name for fn in tree.body if isinstance(fn, ast.AsyncFunctionDef)
              and any(isinstance(n, ast.Name) and n.id == 'FIXTURE' for n in ast.walk(fn))}
    assert owners == set(routes.PARAMETERS)


def test_saved_observer_never_receives_git_authority(observer_model):
    m = observer_model
    assert routes.admit(['git', 'rev-parse', 'HEAD'], m.workspace, None,
                        m.state, m.events.append, m.refuse) is None
    assert m.events == []


@pytest.mark.parametrize('mutation', [None, 'maintenance', 'gc', 'omit'])
def test_setup_commit_disables_only_incidental_housekeeping(model, mutation):
    m = model
    owner = 'test_recorded_transport_failures'
    code = compile(m.source.read_bytes(), str(m.source), 'exec', dont_inherit=True)
    function = FunctionType(named(code, owner), vars(m.module))
    setattr(m.module, owner, function)
    m.frame.f_code = function.__code__
    m.frame.f_lineno = 124
    m.frame.f_locals.update(case='success', role='work', ws=m.workspace)
    m.state['case'] = routes.CASE + '[success-work]'
    argv = ['git', '-c', 'user.name=Controlled', '-c',
            'user.email=controlled@example.invalid', '-c', 'maintenance.auto=false',
            '-c', 'gc.auto=0', 'commit', '--allow-empty', '-qm', 'Controlled']
    if mutation == 'maintenance':
        argv[6] = 'maintenance.auto=true'
    elif mutation == 'gc':
        argv[8] = 'gc.auto=1'
    elif mutation == 'omit':
        del argv[5:9]
    if mutation is not None:
        with pytest.raises(RuntimeError, match='cleanup_git_vector_drift'):
            routes.admit(argv, m.workspace, None, m.state, m.events.append, m.refuse)
        assert m.events == []
    else:
        result = routes.admit(argv, m.workspace, None, m.state, m.events.append, m.refuse)
        assert result['class'] == 'source-cleanup-git:124'
        assert result['python'] is False
