"""Exact original workspace Git calls used by the two local fixture modules."""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import types

WORKSPACE = 'src/unrest_harness/workspaces.py'
AUTHORITY = 'src/unrest_harness/accepted_point_authority.py'


def codes(code):
    yield code
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            yield from codes(value)


def admit(argv, cwd, env, state, append, refuse):
    data_path = Path(state['guard']).with_name('workspace_git_data.py')
    body = data_path.read_bytes()
    if hashlib.sha256(body).hexdigest() != state['direct_support']['files'][str(data_path)]:
        refuse('workspace_git_data_drift')
    data = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(body).body
            if isinstance(n, ast.Assign)}
    pins, sites = data['PINS'], data['SITES']
    case = state.get('case')
    if case not in (*data['CASES'], *data['ADDITIONAL_CASES']):
        return None
    if case in data['ADDITIONAL_CASES']:
        case_source = case.split('::', 1)[0]
        case_pin = data['CASE_PINS'][case_source]
        if (state['product_pins'].get(case_source) != case_pin
                or hashlib.sha256((Path(state['checkout']) / case_source).read_bytes()).hexdigest() != case_pin):
            refuse('workspace_git_case_source_drift')
    root = Path(state['checkout'])
    frame = inspect.currentframe()
    try:
        while frame is not None and not (
                frame.f_code.co_filename == str(root / WORKSPACE)
                and (frame.f_code.co_name, frame.f_lineno) in {('_git', 222), ('_inventory', 1002), ('_build_integration_commit', 650)}
                or frame.f_code.co_filename == str(root / AUTHORITY)
                and (frame.f_code.co_name, frame.f_lineno) == ('_validate_git_index', 386)):
            frame = frame.f_back
        if frame is None:
            return None
        for name, pin in pins.items():
            if state['product_pins'].get(name) != pin or hashlib.sha256((root / name).read_bytes()).hexdigest() != pin:
                refuse('workspace_git_source_drift')
        relative = str(Path(frame.f_code.co_filename).relative_to(root))
        compiled = state['isolated_source_code'](root / relative)
        module = sys.modules.get(frame.f_globals.get('__name__'))
        if module is None or vars(module) is not frame.f_globals:
            refuse('workspace_git_module_drift')
        name = frame.f_code.co_name
        if relative == WORKSPACE:
            instance = frame.f_locals.get('self')
            cls = frame.f_globals.get('WorkspaceManager')
            function = getattr(cls, name, None)
            if (type(instance) is not cls or not isinstance(function, types.FunctionType)
                    or function.__globals__ is not frame.f_globals or function.__code__ is not frame.f_code
                    or frame.f_code not in tuple(codes(compiled))):
                refuse('workspace_git_method_identity')
            if name == '_git':
                caller = frame.f_back
                if (caller is not None and caller.f_code.co_filename == str(root / 'tests/test_workspaces.py')
                        and caller.f_code.co_name == 'fail_remove'
                        and state['case'] == 'tests/test_workspaces.py::test_mutated_patch_artifact_and_cleanup_failure_are_retained'):
                    wrapper = getattr(instance, '_git')
                    original = caller.f_locals.get('original_git')
                    wrapper_codes = state['isolated_source_code'](root / 'tests/test_workspaces.py')
                    if (not isinstance(wrapper, types.FunctionType) or wrapper.__code__ is not caller.f_code
                            or wrapper.__globals__ is not caller.f_globals
                            or caller.f_code not in tuple(codes(wrapper_codes))
                            or not isinstance(original, types.MethodType) or original.__self__ is not instance
                            or original.__func__ is not function
                            or caller.f_locals.get('arguments') != frame.f_locals['arguments']):
                        refuse('workspace_git_cleanup_wrapper')
                    caller = caller.f_back
                if (caller is None or caller.f_code.co_filename != str(root / WORKSPACE)
                        or caller.f_globals is not frame.f_globals or caller.f_locals.get('self') is not instance
                        or caller.f_code not in tuple(codes(compiled))):
                    refuse('workspace_git_caller_identity')
                calls = [n for n in ast.walk(ast.parse((root / WORKSPACE).read_bytes()))
                         if isinstance(n, ast.Call) and ast.unparse(n.func) == 'self._git'
                         and n.lineno <= caller.f_lineno <= n.end_lineno]
                if len(calls) != 1:
                    refuse('workspace_git_callsite')
                call = calls[0]
                site = sites.get(call.lineno)
                if (site is None or site[0] != caller.f_code.co_name
                        or site[1] != hashlib.sha256(ast.dump(call, include_attributes=False).encode()).hexdigest()
                        or any(k.arg is None for k in call.keywords)):
                    refuse('workspace_git_expression')
                arguments = eval(compile(ast.fix_missing_locations(ast.Expression(ast.Tuple(elts=call.args, ctx=ast.Load()))),
                                         str(root / WORKSPACE), 'eval'), caller.f_globals, caller.f_locals)
                kwargs = {k.arg: eval(compile(ast.Expression(k.value), str(root / WORKSPACE), 'eval'),
                                      caller.f_globals, caller.f_locals) for k in call.keywords}
                expected_cwd = kwargs.get('cwd') or instance.repository
                expected_env = kwargs.get('env')
                if (arguments != frame.f_locals['arguments']
                        or expected_cwd != (frame.f_locals['cwd'] or instance.repository)
                        or expected_env != frame.f_locals['env']):
                    refuse('workspace_git_arguments')
                vector = ['git', *arguments]
                expected_env = dict(expected_env) if expected_env is not None else None
            elif name == '_build_integration_commit':
                call = None
                vector = ['git', 'commit-tree', frame.f_locals['tree'], '-p', frame.f_locals['predecessor']]
                expected_cwd, expected_env = frame.f_locals['integration_tree'], frame.f_locals['environment']
                run_frame = inspect.currentframe()
                original_run = sys.modules['runtime_guard']._ORIGINAL_RUN
                while run_frame is not None and run_frame.f_code is not original_run.__code__:
                    run_frame = run_frame.f_back
                if (run_frame is None or run_frame.f_globals is not original_run.__globals__
                        or run_frame.f_locals.get('input') != frame.f_locals['message']):
                    refuse('workspace_git_commit_input')
            else:
                call = None
                vector = ['git', 'status', '--porcelain=v1', '-z', '--untracked-files=all']
                expected_cwd, expected_env = frame.f_locals['worktree'], None
        else:
            function = frame.f_globals.get(name)
            if (not isinstance(function, types.FunctionType) or function.__globals__ is not frame.f_globals
                    or function.__code__ is not frame.f_code or frame.f_code not in tuple(codes(compiled))):
                refuse('workspace_git_validation_identity')
            call = None
            vector = ['git', 'diff', '--cached', '--check']
            expected_cwd, expected_env = frame.f_locals['worktree'], None
        directory = Path(expected_cwd)
        if (argv != vector or env != expected_env or cwd != expected_cwd
                or len(vector) > 64 or any(type(v) is not str for v in vector)
                or sum(len(v.encode()) for v in vector) > 32768
                or directory.resolve() != directory
                or not directory.is_relative_to(Path(state['owned_root']) / 'pytest')
                or os.getcwd() != state['checkout']):
            refuse('workspace_git_vector_context')
        binding = {'path': str(root / relative), 'line': frame.f_lineno,
                   'sha256': pins[relative], 'function': name}
        if call is not None:
            binding.update(caller_line=call.lineno, caller=site[0], expression_ast_sha256=site[1])
        if name == '_build_integration_commit':
            binding['stdin_sha256'] = hashlib.sha256(frame.f_locals['message'].encode()).hexdigest()
        append({'kind': 'concrete_workspace_git_registration', 'source_binding': binding,
                'argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(dict(os.environ) if env is None else env,
                                                                 sort_keys=True).encode()).hexdigest(),
                'cwd': str(directory)})
        return {'class': 'source-workspace-bound-git', 'python': False, 'source_binding': binding}
    finally:
        del frame
