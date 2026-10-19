"""Two immutable lease factory variants through the original production owner."""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import sys

SOURCE = 'tests/test_experimental_lease.py'
PRODUCT = 'src/unrest_harness/experimental_confinement.py'
CLEANUP = 'test_cleanup_failure_revokes_and_quarantines'
BARRIER = 'test_close_waits_for_launch_registration'
METHOD = '.github/release-source-guard/multiprocess_guard_methods.py'
METHOD_CASE = METHOD + '::test_owned_exit17_keeps_raw_status'
CASES = {SOURCE + '::' + CLEANUP: ('cleanup', 399),
         **{SOURCE + '::' + BARRIER + '[' + mode + ']': (mode, 559)
            for mode in ('spawn', 'registration')}}


def admit(argv, cwd, env, state, append, refuse):
    case = state.get('case')
    controlled = case == METHOD_CASE
    if case not in CASES and not controlled:
        return None
    root = Path(state['checkout'])
    source, product = root / SOURCE, root / PRODUCT
    frame = inspect.currentframe()
    stack = []
    try:
        while frame:
            stack.append(frame)
            frame = frame.f_back
        factories = [f for f in stack if f.f_code.co_filename == str(product)
                     and f.f_code.co_name == 'launch_local']
        if not factories:
            return None
        if len(factories) != 1:
            refuse('lease_factory_ambiguous')
        factory = factories[0]
        module = sys.modules.get('unrest_harness.experimental_confinement')
        tests = sys.modules.get('tests.test_experimental_lease')
        for path, relative in ((source, SOURCE), (product, PRODUCT)):
            if hashlib.sha256(path.read_bytes()).hexdigest() != state['product_pins'][relative]:
                refuse('lease_factory_source_drift')
        if module is None or (tests is None and not controlled):
            refuse('lease_factory_module_drift')
        function = module.OwnedProcesses.launch_local
        if (factory.f_globals is not vars(module) or function.__globals__ is not vars(module)
                or function.__code__ is not factory.f_code or factory.f_lineno != 69
                or function.__code__ != state['isolated_named'](
                    state['isolated_source_code'](product), 'launch_local')):
            refuse('lease_factory_code_drift')
        if controlled:
            method_source = root / METHOD
            pin = state['product_pins'][METHOD]
            if hashlib.sha256(method_source.read_bytes()).hexdigest() != pin:
                refuse('lease_method_source_drift')
            matched = [f for f in stack if f.f_code.co_filename == str(method_source)
                       and f.f_code.co_name == '_lease_launch']
            if len(matched) != 1:
                refuse('lease_method_caller_missing')
            caller = matched[0]
            methods = sys.modules.get(caller.f_globals.get('__name__'))
            fn = getattr(methods, '_lease_launch', None)
            if (methods is None or vars(methods) is not caller.f_globals or fn is None
                    or fn.__globals__ is not caller.f_globals or fn.__code__ is not caller.f_code
                    or fn.__code__ != state['isolated_named'](
                        state['isolated_source_code'](method_source), '_lease_launch')):
                refuse('lease_method_code_globals_drift')
            mode = caller.f_locals.get('mode')
            if mode not in ('cleanup', 'spawn', 'registration'):
                refuse('lease_method_parameter_drift')
            line = 399 if mode == 'cleanup' else 559
            if (caller.f_locals.get('owner') is not factory.f_locals.get('self')
                    or caller.f_locals.get('directory') != cwd):
                refuse('lease_method_owner_drift')
        else:
            mode, line = CASES[case]
            owner_name = CLEANUP if mode == 'cleanup' else BARRIER
            owner = getattr(tests, owner_name)
            owner_code = state['isolated_named'](state['isolated_source_code'](source), owner_name)
            if owner.__globals__ is not vars(tests) or owner.__code__ != owner_code:
                refuse('lease_original_owner_drift')
            callers = [f for f in stack if f.f_code.co_filename == str(source)]
            if mode == 'cleanup':
                matched = [f for f in callers if f.f_code is owner.__code__ and f.f_lineno == line]
            else:
                expected = state['isolated_named'](owner_code, 'paused_spawn')
                matched = [f for f in callers if f.f_code == expected and f.f_lineno == 532
                           and f.f_locals.get('barrier') == mode]
            if len(matched) != 1 or matched[0].f_globals is not vars(tests):
                refuse('lease_original_caller_drift')
        tree = ast.parse(source.read_bytes())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line
                    and ast.unparse(n.func) == ('owner.launch_local' if mode == 'cleanup'
                                              else 'pool.submit'))
        vector = node.args[0 if mode == 'cleanup' else 1]
        if (not isinstance(vector, ast.List) or len(vector.elts) != 3
                or ast.unparse(vector.elts[0]) != 'sys.executable'):
            refuse('lease_literal_shape_drift')
        expected_argv = [sys.executable, *(ast.literal_eval(n) for n in vector.elts[1:])]
        local = factory.f_locals
        owner_instance = local.get('self')
        directory = Path(cwd) if isinstance(cwd, (str, os.PathLike)) else None
        if (argv != expected_argv or local.get('command') != argv
                or local.get('cwd') != cwd or local.get('env') is not env or env != {}
                or directory is None or not directory.is_absolute() or directory.resolve() != directory
                or not directory.is_relative_to(Path(state['owned_root']))
                or directory == Path(state['owned_root']) or os.getcwd() != state['checkout']
                or type(owner_instance) is not module.OwnedProcesses
                or owner_instance.closed or owner_instance.quarantined
                or (not controlled and mode == 'cleanup' and (matched[0].f_locals.get('owner') is not owner_instance
                                          or matched[0].f_locals.get('tmp_path') != cwd))
                or str(Path(argv[0]).resolve()) != state['runtime']['realpath']
                or hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest() != state['runtime']['sha256']):
            refuse('lease_factory_vector_environment_drift')
        binding = {'path': str(product), 'line': 69, 'sha256': state['product_pins'][PRODUCT]}
        append({'kind': 'exact_lease_factory_registration', 'source_binding': binding,
                'owner_source_sha256': state['product_pins'][SOURCE], 'case': case,
                'literal_line': line, 'mode': mode, 'controlled_guard_method': controlled})
        return {'class': 'source-lease-owned-child', 'python': True, 'source_binding': binding,
                'lease_factory': {'mode': mode, 'literal_line': line, 'case': case,
                                  'controlled_guard_method': controlled,
                                  'owner_source_sha256': state['product_pins'][SOURCE]}}
    finally:
        stack.clear()
        del frame
