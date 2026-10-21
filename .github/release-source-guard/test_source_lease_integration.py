"""Exact source integration controls; these never execute original test cases."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'finite'))
from primary_source_inputs import python_environment
from primary_policy import PYTHON

SUPPORT = Path(__file__).resolve().parent
ROOT = SUPPORT.parent.parent


def pin(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def named(code, name):
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            if item.co_name == name:
                return item
            if (found := named(item, name)) is not None:
                return found
    return None


def shared_dispatch_setup(state, monkeypatch):
    state['guard'] = str(SUPPORT / 'finite/runtime_guard.py')
    state['direct_support'] = {'files': {str(p): pin(p) for p in (SUPPORT / 'finite').glob('*.py')}}
    original = json.loads((SUPPORT / 'finite/source-template.json').read_bytes())
    for cohort in (3, 4):
        state.setdefault(f'cohort{cohort}_full_cases', original[f'cohort{cohort}_full_cases'])
    def checked(path, expected):
        assert pin(Path(path)) == expected
        namespace = {'__file__': str(path)}
        exec(compile(Path(path).read_bytes(), str(path), 'exec', dont_inherit=True), namespace)
        return namespace
    guard = sys.modules.get('runtime_guard')
    if guard is None:
        guard = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.setattr(guard, 'checked_source', checked, raising=False)


def profile(mode='cleanup', controlled=False):
    binding = {'path': '/source/src/unrest_harness/experimental_confinement.py',
               'line': 69, 'sha256': pin(ROOT / 'src/unrest_harness/experimental_confinement.py')}
    original = [PYTHON, '-c',
                'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(30)'
                if mode == 'ignore' else 'import time;time.sleep(30)' if mode == 'cleanup'
                else 'import time;print("ready",flush=True);time.sleep(30)']
    case = ('tests/test_experimental_lease.py::test_owned_ignoring_child_and_unknown_quarantine'
            if mode == 'ignore' else
            'tests/test_experimental_lease.py::test_cleanup_failure_revokes_and_quarantines'
            if mode == 'cleanup' else
            'tests/test_experimental_lease.py::test_close_waits_for_launch_registration[' + mode + ']')
    if controlled:
        case = '.github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status'
    factory = {'mode': mode, 'literal_line': {'ignore': 218, 'cleanup': 399, 'spawn': 559, 'registration': 559}[mode],
               'case': case, 'controlled_guard_method': controlled,
               'owner_source_sha256': pin(ROOT / 'tests/test_experimental_lease.py')}
    def sha(value):
        return hashlib.sha256(value).hexdigest()
    registration = {'class': 'source-lease-owned-child', 'source_binding': binding,
                    'argv_sha256': sha(json.dumps(original).encode())}
    vector = [PYTHON, '-c', 'exact authenticated bootstrap']
    selected = {'registration': registration, 'owner_pid': 17, 'token': 'token',
                'cwd': '/work/owned/pytest/case', 'bootstrap_sha256': sha(vector[2].encode()),
                'transformed_argv_sha256': sha(json.dumps(vector).encode()),
                'environment_sha256': sha(json.dumps({}, sort_keys=True).encode())}
    row = {'kind': 'source_lease_startup_consumption', 'owner_pid': 17,
           'launch_token': 'token', 'source_binding': binding, 'factory': factory,
           'argv': original, 'cwd': selected['cwd'], 'environment': {}}
    context = {'selected': selected, 'events': [row], 'vector': vector, 'parent': 17,
               'cwd': selected['cwd'], 'manifest': {'checkout': '/source', 'owned_root': '/work/owned',
               'runtime': {'realpath': PYTHON, 'paths': [PYTHON]},
               'product_pins': {'tests/test_experimental_lease.py': factory['owner_source_sha256'],
                                'src/unrest_harness/experimental_confinement.py': binding['sha256']}}}
    return registration, context


@pytest.mark.parametrize('mode', ['ignore', 'cleanup', 'spawn', 'registration'])
@pytest.mark.parametrize('controlled', [False, True])
def test_lease_postinit_requires_complete_original_binding(mode, controlled):
    registration, context = profile(mode, controlled)
    env = {}
    assert python_environment(env, registration, [0, 0, 0], lease_context=context) == {'LC_CTYPE': 'C.UTF-8'}
    assert env == {}
    assert python_environment(env, registration, [0, 0, 0]) == {}


@pytest.mark.parametrize('change', ['class', 'source', 'line', 'owner', 'case', 'mode', 'literal',
                                   'token', 'parent', 'cwd', 'alias', 'argv', 'argv-pin', 'runtime',
                                   'bootstrap', 'exec-env', 'duplicate', 'missing', 'owner-pin'])
def test_lease_postinit_mutations_never_get_locale_exemption(change):
    registration, context = copy.deepcopy(profile())
    row = context['events'][0]
    if change == 'class':
        registration['class'] = 'unknown'
    elif change == 'source':
        registration['source_binding'] = {**registration['source_binding'], 'sha256': '0' * 64}
    elif change == 'line':
        registration['source_binding'] = {**registration['source_binding'], 'line': 218}
    elif change == 'owner':
        row['factory']['owner_source_sha256'] = '0' * 64
    elif change == 'case':
        row['factory']['case'] = 'other'
    elif change == 'mode':
        row['factory']['mode'] = 'unknown'
    elif change == 'literal':
        row['factory']['literal_line'] = 218
    elif change == 'token':
        row['launch_token'] = 'other'
    elif change == 'parent':
        row['owner_pid'] = 18
    elif change == 'cwd':
        context['cwd'] = '/foreign'
    elif change == 'alias':
        context['cwd'] = context['selected']['cwd'] = row['cwd'] = '/work/owned/../foreign'
    elif change == 'argv':
        row['argv'][-1] += ';pass'
    elif change == 'argv-pin':
        registration['argv_sha256'] = '0' * 64
    elif change == 'runtime':
        context['manifest']['runtime']['realpath'] = '/foreign'
    elif change == 'bootstrap':
        context['selected']['bootstrap_sha256'] = '0' * 64
    elif change == 'exec-env':
        row['environment'] = {'LANG': 'C'}
    elif change == 'duplicate':
        context['events'].append(copy.deepcopy(row))
    elif change == 'missing':
        context['events'].clear()
    elif change == 'owner-pin':
        context['manifest']['product_pins']['tests/test_experimental_lease.py'] = '0' * 64
    assert python_environment({}, registration, [0, 0, 0], lease_context=context) == {}


@pytest.mark.parametrize('env', [{'LANG': 'C'}, {'LC_ALL': 'C'}, {'LC_CTYPE': 'C'}, {'OTHER': 'x'}])
@pytest.mark.parametrize('flags', [[0, 0, 0], [1, 0, 0], [0, 1, 0], [0, 0, 1]])
def test_original_empty_exec_environment_and_flags_are_exact(env, flags):
    registration, context = profile()
    assert python_environment(env, registration, flags, lease_context=context) == env


@pytest.mark.parametrize('mode', ['ignore', 'cleanup', 'spawn', 'registration'])
@pytest.mark.parametrize('mutation', [None, 'argv', 'env', 'owner', 'code', 'globals', 'parameter', 'case'])
def test_real_controlled_factory_frames_recheck_identity(tmp_path, monkeypatch, mode, mutation):
    from unrest_harness.experimental_confinement import OwnedProcesses
    monkeypatch.syspath_prepend(str(ROOT))
    routes = load('lease_routes_control', SUPPORT / 'finite/lease_routes.py', monkeypatch)
    methods = load('lease_methods_control', SUPPORT / 'multiprocess_guard_methods.py', monkeypatch)
    directory = tmp_path / 'child'
    directory.mkdir()
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'case': routes.METHOD_CASE,
             'runtime': {'realpath': str(Path(sys.executable).resolve()), 'sha256': pin(Path(sys.executable))},
             'product_pins': {name: pin(ROOT / name) for name in (routes.SOURCE, routes.PRODUCT, routes.METHOD)},
             'isolated_named': named,
             'isolated_source_code': lambda path: compile(path.read_bytes(), str(path), 'exec', dont_inherit=True)}
    monkeypatch.chdir(ROOT)
    events = []
    def refuse(reason):
        raise RuntimeError(reason)
    def intercept(argv, **kwargs):
        if mutation == 'argv':
            argv[-1] += ';pass'
        if mutation == 'env':
            kwargs['env']['LANG'] = 'C'
        result = routes.admit(argv, kwargs['cwd'], kwargs['env'], state, events.append, refuse)
        if result is None:
            raise RuntimeError('not selected')
        return result
    monkeypatch.setattr(methods, 'subprocess', None, raising=False)
    import subprocess
    state['lease_popen'] = intercept
    def captured(*args, **kwargs):
        return methods._lease_popen(intercept, mode, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', captured)
    owner_type = type('Impersonator', (OwnedProcesses,), {}) if mutation == 'owner' else OwnedProcesses
    owner = owner_type(types.SimpleNamespace())
    call = methods._lease_launch
    if mutation == 'code':
        call = types.FunctionType(call.__code__.replace(co_name='other'), call.__globals__)
    elif mutation == 'globals':
        call = types.FunctionType(call.__code__, dict(call.__globals__))
    elif mutation == 'parameter':
        mode = 'other'
    elif mutation == 'case':
        state['case'] = 'other'
    if mutation is None:
        result = call(owner, mode, directory)
        assert result['class'] == 'source-lease-owned-child'
        assert result['lease_factory']['mode'] == mode and len(events) == 1
    else:
        with pytest.raises(RuntimeError):
            call(owner, mode, directory)


@pytest.mark.parametrize('cohort', [3, 4])
def test_shared_original_helper_declines_only_other_owner(monkeypatch, cohort):
    release_binding = load('release_binding_control', ROOT / 'tools/release_binding.py', monkeypatch)
    route = load('cohort_control', SUPPORT / f'finite/cohort{cohort}_routes.py', monkeypatch)
    state = {'checkout': str(ROOT), 'case': 'other-owner', f'cohort{cohort}_full_cases': []}
    shared_dispatch_setup(state, monkeypatch)
    observations = []
    def intercept(argv, **kwargs):
        observations.append(route.select(list(argv), kwargs['cwd'], None, state,
                                         lambda event: None, pytest.fail))
        return types.SimpleNamespace(stdout=b'')
    monkeypatch.setattr(release_binding.subprocess, 'run', intercept)
    assert release_binding.tracked_regular_paths(ROOT) == []
    assert observations == [None]


@pytest.mark.parametrize('change', [None, 'env', 'marker', 'root', 'directory', 'alias'])
def test_source_temporary_environment_keeps_exact_generation(tmp_path, monkeypatch, change):
    import os
    from types import SimpleNamespace
    module = load('source_environment_control', SUPPORT / 'finite/source_environment.py', monkeypatch)
    physical = tmp_path / 'owned'
    physical.mkdir()
    (physical / 'tmp').mkdir()
    real_directory = module.directory
    def directory(path):
        return real_directory(physical if path == '/work/owned' else physical / 'tmp')
    monkeypatch.setattr(module, 'directory', directory)
    monkeypatch.setattr(os, 'environ', {'TMPDIR': '/work/owned/tmp', 'FINITE': 'original'})
    state = {'source_selection': 'primary-source', 'class': 'pytest-root', 'token': 'root',
             'checkout': '/source', 'owned_root': '/work/owned', 'case': 'guard-method'}
    saved = module.capture(state)
    state['operation_activation'] = SimpleNamespace(owned_environment=saved)
    os.environ['PYTEST_CURRENT_TEST'] = 'guard-method (call)'
    os.environ['PYTEST_VERSION'] = pytest.__version__
    if change == 'env':
        os.environ['FINITE'] = 'other'
    elif change == 'marker':
        os.environ['PYTEST_CURRENT_TEST'] = 'other (call)'
    elif change == 'root':
        state['owned_root'] = '/work/owned/tmp'
    elif change == 'directory':
        (physical / 'tmp').rename(physical / 'old')
        (physical / 'tmp').mkdir()
    elif change == 'alias':
        (physical / 'tmp').rename(physical / 'old')
        (physical / 'tmp').symlink_to(physical / 'old', target_is_directory=True)
    assert module.matches(state) is (change is None)


@pytest.mark.parametrize('mutation', [None, 'argv', 'owner', 'code', 'globals', 'cwd', 'env'])
def test_shared_route_order_uses_real_helper_and_own_probe_identity(monkeypatch, mutation):
    import os
    import subprocess
    monkeypatch.syspath_prepend(str(ROOT))
    methods = load('binding_methods_control', SUPPORT / 'multiprocess_guard_methods.py', monkeypatch)
    binding = load('binding_control', SUPPORT / 'finite/binding_routes.py', monkeypatch)
    cohorts = [load('order' + str(n), SUPPORT / f'finite/cohort{n}_routes.py', monkeypatch) for n in (4, 3)]
    state = {'checkout': str(ROOT), 'case': str(SUPPORT.relative_to(ROOT)) + '/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status',
             'cohort3_full_cases': [], 'cohort4_full_cases': [],
             'product_pins': {name: pin(ROOT / name) for name in
                 ('tools/release_binding.py', 'tests/test_release_binding.py',
                  '.github/release-source-guard/multiprocess_guard_methods.py')},
             'isolated_named': named,
             'isolated_source_code': lambda path: compile(path.read_bytes(), str(path), 'exec', dont_inherit=True)}
    events, consumed = [], []
    monkeypatch.setitem(sys.modules, 'runtime_guard', types.SimpleNamespace(_STATE=state, append=events.append, digest=lambda p: pin(Path(p))))
    shared_dispatch_setup(state, monkeypatch)
    monkeypatch.chdir(ROOT)
    def refuse(reason):
        raise RuntimeError(reason)
    def intercept(argv, **kwargs):
        cwd, env = kwargs['cwd'], None
        if mutation == 'argv':
            argv = [*argv, '--foreign']
        elif mutation == 'owner':
            state['case'] = 'other'
        elif mutation == 'cwd':
            cwd = ROOT.parent
        elif mutation == 'env':
            env = {'LANG': 'C'}
        assert all(route.select(list(argv), cwd, env, state, events.append, refuse) is None for route in cohorts)
        registered = binding.admit(list(argv), cwd, env, state, events.append, refuse)
        if registered is None:
            raise RuntimeError('not selected')
        consumed.append(registered)
        return types.SimpleNamespace(stdout=b'100644 oid 0\tpyproject.toml\x00100644 oid 0\tuv.lock\x00'
                                     if '--stage' in argv else b'')
    monkeypatch.setattr(subprocess, 'run', intercept)
    call = methods._binding_inventory
    if mutation == 'code':
        call = types.FunctionType(call.__code__.replace(co_name='other'), call.__globals__)
    elif mutation == 'globals':
        call = types.FunctionType(call.__code__, dict(call.__globals__))
    if mutation is None:
        call()
        assert len(consumed) == 2 and events[-1]['kind'] == 'guard_shared_binding_probe'
        assert os.getcwd() == str(ROOT)
    else:
        with pytest.raises(RuntimeError):
            call()


@pytest.mark.parametrize('kind,path,digest', [
    ('canonical-backend', '/source/tests/fixtures/experimental_session_app_server.py',
     'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'),
    ('controlled-acp', '/source/tests/fixtures/controlled_python_acp.py',
     'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be')])
def test_exact_existing_controlled_fixture_mapping_stays_bound(kind, path, digest):
    assert pin(ROOT / path.removeprefix('/source/')) == digest
    registration = {'class': kind, 'source_binding': {'path': path, 'line': 1, 'sha256': digest}}
    assert python_environment({}, registration, [0, 0, 0]) == {'LC_CTYPE': 'C.UTF-8'}
    for key, value in [('path', '/foreign'), ('line', 2), ('sha256', '0' * 64)]:
        other = {**registration, 'source_binding': {**registration['source_binding'], key: value}}
        assert python_environment({}, other, [0, 0, 0]) == {}


def test_extension_keeps_original_callback_for_nonlease(tmp_path, monkeypatch):
    from test_source_activation_composition import setup, Consumed
    h = setup(tmp_path, monkeypatch)
    profile_file = tmp_path / 'profile.json'
    profile_file.write_text('{}')
    h.state['isolated_support'] = {'spec_path': str(profile_file), 'spec_sha256': pin(profile_file)}
    extension = load('integration_activation_control', SUPPORT / 'finite/source_integration_activation.py', monkeypatch)
    current = extension.create(h.state, h.activation.emit, h.activation.refuse, h.activation.ready)
    current.shared = lambda: None
    h.state['operation_activation'] = current
    with pytest.raises(Consumed):
        h.owner.launch(h.vector, h.tmp, {'FINITE': 'original'})
    assert len(current.python_consumed) == 1 and not h.poison
    with pytest.raises(RuntimeError, match='source_lease_activation_caller_drift'):
        current.ordinary_python(h.guard, {}, [], None, {}, {'class': 'source-lease-owned-child'})


def test_new_probe_reducer_requires_refused_child_and_all_lease_modes():
    from primary_source_probe import check_integration_probes
    events = [{'kind': 'guard_source_environment_proof', 'tmpdir': '/work/owned/tmp',
               'source_environment_sha256': pin(SUPPORT / 'finite/source_environment.py'),
               'directories': {'/work/owned': [1, 2, 0o40700, 20000, 20000],
                               '/work/owned/tmp': [1, 3, 0o40700, 20000, 20000]},
               'refused_tmpdir_values': ['/work/owned', '/work/owned/tmp/..'],
               'original_environment_restored': True},
              {'kind': 'guard_refused_acquisition_proof', 'child_pid': 42, 'before_fds': 7,
               'after_fds': 7, 'original_exception_preserved': True},
              {'kind': 'multiprocess_refused_acquisition_wait', 'pid': 42, 'raw_status': 9,
               'numeric_returncode': -9, 'owner_pid': 20, 'original_exception_preserved': True},
              {'kind': 'raw_actual_parent_waitpid', 'pid': 42, 'raw_status': 9},
              {'kind': 'guard_shared_binding_probe', 'path_count': 42, 'original_source_sha256': 'pin'},
              *[{'kind': 'exact_current_binding_registration',
                 'source_binding': {'path': '/source/tools/release_binding.py', 'line': line, 'sha256': 'pin'},
                 'owner': '.github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status'}
                for line in (36, 57)]]
    for child, mode in enumerate(('ignore', 'cleanup', 'spawn', 'registration'), 50):
        events += [{'kind': 'guard_lease_factory_proof', 'child_pid': child, 'mode': mode,
                    'child_returncode': -9 if mode == 'ignore' else -15, 'before_fds': 7, 'after_fds': 7, 'closed': True,
                    'quarantine': mode == 'cleanup'},
                   {'kind': 'source_lease_startup_consumption', 'factory': {'mode': mode},
                    'environment': {}, 'launch_token': mode},
                   {'kind': 'registered', 'pid': child, 'token': mode, 'class': 'source-lease-owned-child'}]
    kernel = {'records': [{'kind': 'kernel_child', 'child': 42, 'identity': {'tgid': 42, 'ppid': 20}}]}
    assert check_integration_probes({'events': events}, kernel) == 42
    for index, event in enumerate(events):
        changed = events[:index] + events[index + 1:]
        with pytest.raises(RuntimeError):
            check_integration_probes({'events': changed}, kernel)
        if 'after_fds' in event:
            changed = copy.deepcopy(events)
            changed[index]['after_fds'] += 1
            with pytest.raises(RuntimeError):
                check_integration_probes({'events': changed}, kernel)


def test_legacy_registry_literal_keeps_its_original_source_anchor():
    registration, context = profile('ignore')
    binding = {'path': '/source/tests/test_experimental_lease.py', 'line': 218,
               'sha256': pin(ROOT / 'tests/test_experimental_lease.py')}
    registration['source_binding'] = binding
    context['events'][0]['source_binding'] = binding
    assert python_environment({}, registration, [0, 0, 0], lease_context=context) == {'LC_CTYPE': 'C.UTF-8'}
    context['events'][0]['factory']['mode'] = 'cleanup'
    assert python_environment({}, registration, [0, 0, 0], lease_context=context) == {}


def test_original_registry_case_is_never_replaced_by_extension_admission(monkeypatch):
    routes = load('legacy_registry_control', SUPPORT / 'finite/lease_routes.py', monkeypatch)
    state = {'case': routes.SOURCE + '::' + routes.ORIGINAL}
    assert routes.admit([], None, {}, state, pytest.fail, pytest.fail) is None


def test_original_captured_popen_callsite_is_not_injected_raise(monkeypatch):
    """Read-only AST proof: no original test/module is executed by this control."""
    import ast
    route = load('lease_AST_control', SUPPORT / 'finite/lease_routes.py', monkeypatch)
    source = ROOT / route.SOURCE
    line = route.popen_callsite(source, route.BARRIER, 'paused_spawn', 'popen')
    assert line == 533 and line != 532
    tree = ast.parse(source.read_bytes())
    assert any(isinstance(n, ast.Raise) and n.lineno == 532 for n in ast.walk(tree))
    assert any(isinstance(n, ast.Call) and n.lineno == line
               and ast.unparse(n) == 'popen(*args, **kwargs)' for n in ast.walk(tree))


@pytest.mark.parametrize('mutation', [None, 'line', 'code', 'globals', 'parameter',
                                     'captured', 'args', 'cwd', 'env', 'flags'])
def test_same_captured_popen_boundary_checks_live_own_frame(monkeypatch, mutation):
    import inspect
    route = load('lease_live_boundary', SUPPORT / 'finite/lease_routes.py', monkeypatch)
    methods = load('lease_live_methods', SUPPORT / 'multiprocess_guard_methods.py', monkeypatch)
    vector, cwd, env = ['exact'], Path('/owned/child'), {}
    expected = {'cwd': cwd, 'env': env, 'stdin': -1, 'stdout': -1, 'stderr': -1,
                'close_fds': True, 'start_new_session': True}
    def refuse(reason):
        raise RuntimeError(reason)
    def intercepted(*args, **kwargs):
        frame = inspect.currentframe().f_back
        code = methods._lease_popen.__code__
        namespace = vars(methods)
        line = route.popen_callsite(SUPPORT / 'multiprocess_guard_methods.py', '_lease_popen', None, 'popen')
        parameter, captured = 'spawn', intercepted
        if mutation == 'line':
            line -= 1
        elif mutation == 'code':
            code = code.replace(co_name='foreign')
        elif mutation == 'globals':
            namespace = dict(namespace)
        elif mutation == 'parameter':
            parameter = 'registration'
        elif mutation == 'captured':
            captured = object()
        route.verify_popen_caller(frame, code, namespace, line, parameter, 'mode',
                                 'popen', captured, vector, cwd, env, refuse)
        return 'checked'
    supplied = dict(expected)
    arguments = [vector]
    if mutation == 'args':
        arguments = [['foreign']]
    elif mutation == 'cwd':
        supplied['cwd'] = Path('/foreign')
    elif mutation == 'env':
        supplied['env'] = {'OTHER': 'x'}
    elif mutation == 'flags':
        supplied['start_new_session'] = False
    if mutation is None:
        assert methods._lease_popen(intercepted, 'spawn', *arguments, **supplied) == 'checked'
    else:
        with pytest.raises(RuntimeError, match='lease_original_caller_drift'):
            methods._lease_popen(intercepted, 'spawn', *arguments, **supplied)


@pytest.mark.parametrize('mutation', [None, 'binding', 'resolver-refusal', 'outside'])
def test_inflight_activation_rechecks_live_binding_and_keeps_actual_anchor(tmp_path, monkeypatch, mutation):
    from test_source_activation_composition import setup, Consumed
    h = setup(tmp_path, monkeypatch)
    profile_file = tmp_path / 'profile.json'
    profile_file.write_text('{}')
    h.state['isolated_support'] = {'spec_path': str(profile_file), 'spec_sha256': pin(profile_file)}
    h.state['case'] = ('tests/test_acp_cleanup.py::'
                       'test_inflight_terminal_registration_before_inventory[False]')
    registration = {'class': 'inline:test_acp_cleanup.py:51', 'python': True,
                    'source_binding': {'path': str(h.source), 'line': 421,
                                       'sha256': pin(h.source)}}
    checked = h.guard.checked_source
    frames = [object()]
    calls = []
    def resolve(argv, cwd, environment, state, actual_frames, refuse):
        assert argv == h.vector and cwd == h.tmp and environment == {'FINITE': 'original'}
        assert state is h.state and actual_frames is frames
        calls.append('resolved')
        if mutation == 'resolver-refusal':
            refuse('inflight_owner_or_vector_drift')
        return ({**registration, 'source_binding': {}} if mutation == 'binding'
                else dict(registration))
    def support(path, digest):
        if Path(path).name == 'cleanup_routes.py':
            assert digest == pin(Path(path))
            return {'task_frames': lambda: frames}
        if Path(path).name == 'inflight_cleanup.py':
            assert digest == pin(Path(path))
            return {'admit': resolve}
        return checked(path, digest)
    monkeypatch.setattr(h.guard, 'checked_source', support)
    extension = load('inflight_activation_control', SUPPORT / 'finite/source_integration_activation.py', monkeypatch)
    current = extension.create(h.state, h.activation.emit, h.activation.refuse, h.activation.ready)
    current.shared = lambda: calls.append('shared')
    # Isolate the integration callback; the preceding controls exercise the
    # unchanged launch-token consumption through the real guard frame.
    current.python_launch = lambda *args: (h.guard, {'launch_token': 'exact'})
    with pytest.raises(Consumed if mutation is None else RuntimeError):
        if mutation == 'outside':
            current.ordinary_python(h.guard, {}, h.vector, h.tmp, {'FINITE': 'original'}, registration)
        else:
            current.before_python(h.vector, h.tmp, {'FINITE': 'original'}, registration)
    if mutation is None:
        assert calls == ['resolved', 'shared'] and not h.poison
        assert h.events[-1]['source_binding'] == registration['source_binding']
        assert h.events[-1]['launch_token'] == 'exact'
    else:
        assert 'shared' not in calls and h.poison
    if mutation != 'outside':
        assert frames == []
