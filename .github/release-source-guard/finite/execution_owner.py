"""Resolve finite nested execution ownership without changing outer custody."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import sys
import types


def codes(code):
    yield code
    for child in code.co_consts:
        if isinstance(child, types.CodeType):
            yield from codes(child)


def resolve(state, refuse, frames):
    custody = state.get('case', '')
    payload = state.get('registered_payload')
    kind = state.get('class', '')
    probe = kind == 'source-execution-owner-probe'
    if not kind.startswith('reference:') and not probe:
        return custody
    guard = sys.modules['runtime_guard']
    root = Path(state['checkout'])
    original = state['product_pins']
    if probe:
        owner = '.github/release-source-guard/multiprocess_guard_methods.py'
        target = '.github/release-source-guard/nested_owner_methods.py'
        row = {'module': owner, 'source_sha256': original[owner],
               'external_ordered_nodes': [target + '::test_nested_owner']}
        tree = ast.parse((root / owner).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == '_nested_owner_probe')
        call = next(n for n in ast.walk(function) if isinstance(n, ast.Call)
                    and ast.unparse(n.func) == 'subprocess.run')
        binding = {'path': str(root / owner), 'line': call.lineno,
                   'sha256': original[owner], 'function': '_nested_owner_probe'}
        outer_owners = ['test_owned_exit17_keeps_raw_status']
    else:
        path = Path(state['guard']).with_name('source_bindings.py')
        data = guard.checked_source(path, state['direct_support']['files'][str(path)])['DATA']
        rows = [row for row in data['selections'] if kind == 'reference:' + row['module']]
        if len(rows) != 1:
            refuse('execution_owner_selection_ambiguous')
        row = rows[0]
        binding = data['bindings']['reference']
        if (binding['sha256'] != original.get('tests/contracts/conftest.py')
                or hashlib.sha256((root / 'tests/contracts/conftest.py').read_bytes()).hexdigest()
                   != binding['sha256']):
            refuse('execution_owner_reference_source_drift')
        outer_owners = [n.name for n in ast.parse((root / row['module']).read_bytes()).body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and any(a.arg == 'lean_reference_run' for a in n.args.args)]
    source = root / row['module']
    # The bootstrap authenticated this token and outer case before publishing
    # registered_payload. Join them again; an environment marker grants nothing.
    if (payload is None or payload.get('token') != state.get('token')
            or not state.get('token') or payload.get('case') != custody
            or payload.get('class') != kind or payload.get('mode') != 'module'
            or payload.get('target') != 'pytest' or payload.get('isolated') is not False
            or hashlib.sha256(source.read_bytes()).hexdigest() != row['source_sha256']
            or original.get(row['module']) != row['source_sha256']
            or payload.get('source_binding') != binding):
        refuse('execution_owner_custody_payload_drift')
    original_args = payload.get('orig_argv', [])
    args = original_args[2:]
    if custody.split('[')[0] not in [row['module'] + '::' + name for name in outer_owners]:
        refuse('execution_owner_outer_identity_drift')
    if payload.get('sys_argv', [])[1:] != args[1:]:
        refuse('execution_owner_live_vector_drift')
    prefix = ['pytest', '-q', '-ra', '-p', 'no:cacheprovider']
    nodes = row['external_ordered_nodes']
    if (args[:5] != prefix or len(args) != 6 + len(nodes)
            or args[6:] != nodes or not args[5].startswith('--junitxml=')):
        refuse('execution_owner_selection_drift')
    report = Path(args[5].removeprefix('--junitxml='))
    if (not report.is_absolute() or report.name != 'pytest.xml'
            or not report.parent.is_relative_to(Path(state['owned_root']))
            or report.parent == Path(state['owned_root'])
            or report.resolve() != report or payload.get('path0') != str(root)
            or original_args != [sys.executable, '-m', *args]):
        refuse('execution_owner_vector_custody_drift')
    marker = os.environ.get('PYTEST_CURRENT_TEST', '')
    if not marker.endswith(' (call)'):
        refuse('execution_owner_marker_drift')
    selected = marker.removesuffix(' (call)')
    finite_cases = set(state.get('cohort3_full_cases', ())) | set(
        state.get('cohort4_full_cases', ()))
    matches = [node for node in nodes if selected == node or (selected in finite_cases
               and selected.split('[')[0] == node)]
    if len(matches) != 1:
        refuse('execution_owner_unselected_node')
    relative, *parts = selected.split('[')[0].split('::')
    owner_source = root / relative
    pin = original.get(relative)
    if pin is None or hashlib.sha256(owner_source.read_bytes()).hexdigest() != pin:
        refuse('execution_owner_source_drift')
    namespaces = [f.f_globals for f in frames if Path(f.f_code.co_filename) == owner_source]
    module = sys.modules.get(namespaces[0].get('__name__')) if namespaces else None
    obj = module
    for part in parts:
        obj = getattr(obj, part, None)
    qualname = '.'.join(parts)
    expected = list(codes(state['isolated_source_code'](owner_source)))
    code = next((c for c in expected if c.co_qualname == qualname), None)
    if (module is None or not isinstance(obj, types.FunctionType)
            or obj.__globals__ is not vars(module) or obj.__code__ != code):
        refuse('execution_owner_code_globals_drift')
    live = [f for f in frames if Path(f.f_code.co_filename) == owner_source
            and (f.f_code.co_qualname == qualname
                 or f.f_code.co_qualname.startswith(qualname + '.<locals>.'))]
    if not live or any(f.f_globals is not vars(module) or f.f_code not in expected for f in live):
        refuse('execution_owner_live_caller_drift')
    return selected


def current(state, refuse):
    if (not state.get('class', '').startswith('reference:')
            and state.get('class') != 'source-execution-owner-probe'):
        return state.get('case', '')
    # Include suspended coroutine owners used by production spawn_launch.
    path = Path(state['guard']).with_name('fallback_binding.py')
    guard = sys.modules['runtime_guard']
    frames = guard.checked_source(path, state['direct_support']['files'][str(path)])['active_frames']()
    try:
        return resolve(state, refuse, frames)
    finally:
        frames.clear()


COHORT2_SERVER_CASES = frozenset(
(   'tests/test_acp_runner.py::test_real_mcp_inventory_fd_redacts_before_crash_and_restart[worker]',
    'tests/test_completion_ownership.py::test_role_interrupted_publication[validate-after]',
    'tests/test_completion_ownership.py::test_role_interrupted_publication[validate-before]',
    'tests/test_completion_ownership.py::test_role_interrupted_publication[work-after]',
    'tests/test_completion_ownership.py::test_role_interrupted_publication[work-before]',
    'tests/test_completion_ownership.py::test_role_process_ownership[both-invalid-validate-targets2]',
    'tests/test_completion_ownership.py::test_role_process_ownership[both-invalid-work-targets0]',
    'tests/test_completion_ownership.py::test_role_process_ownership[both-invalid-work-targets1]',
    'tests/test_completion_ownership.py::test_role_process_ownership[exhausted-validate-targets2]',
    'tests/test_completion_ownership.py::test_role_process_ownership[exhausted-work-targets0]',
    'tests/test_completion_ownership.py::test_role_process_ownership[exhausted-work-targets1]',
    'tests/test_completion_ownership.py::test_role_process_ownership[invalid-validate-targets2]',
    'tests/test_completion_ownership.py::test_role_process_ownership[invalid-work-targets0]',
    'tests/test_completion_ownership.py::test_role_process_ownership[invalid-work-targets1]',
    'tests/test_completion_ownership.py::test_role_process_ownership[valid-validate-targets2]',
    'tests/test_completion_ownership.py::test_role_process_ownership[valid-work-targets0]',
    'tests/test_completion_ownership.py::test_role_process_ownership[valid-work-targets1]',
    'tests/test_completion_setup.py::test_real_roles_first_use[distinct-validate-targets2]',
    'tests/test_completion_setup.py::test_real_roles_first_use[distinct-work-targets0]',
    'tests/test_completion_setup.py::test_real_roles_first_use[distinct-work-targets1]',
    'tests/test_completion_setup.py::test_real_roles_first_use[invalid-invalid-validate-targets2]',
    'tests/test_completion_setup.py::test_real_roles_first_use[invalid-invalid-work-targets0]',
    'tests/test_completion_setup.py::test_real_roles_first_use[invalid-invalid-work-targets1]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-invalid-validate-targets2]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-invalid-work-targets0]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-invalid-work-targets1]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-valid-validate-targets2]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-valid-work-targets0]',
    'tests/test_completion_setup.py::test_real_roles_first_use[valid-valid-work-targets1]')
)


def shared_family(state, case, relative, line, refuse):
    """Dispatch a shared physical site by exact finite owner, never grant it."""
    if (relative, line) == ('src/unrest_harness/server.py', 266):
        choices = [cohort for cohort, cases in (
            (2, COHORT2_SERVER_CASES), (3, state['cohort3_full_cases'])) if case in cases]
    elif (relative, line) == ('tools/release_binding.py', 36):
        choices = [cohort for cohort in (3, 4) if case in state[f'cohort{cohort}_full_cases']]
    else:
        raise RuntimeError('execution_owner_not_shared_site')
    if len(choices) > 1:
        refuse('execution_owner_shared_dispatch_ambiguous')
    return choices[0] if choices else None
