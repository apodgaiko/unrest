"""Two exact own-identity launches for supplementary execution-owner proof."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import sys

METHOD = '.github/release-source-guard/multiprocess_guard_methods.py'
NESTED = '.github/release-source-guard/nested_owner_methods.py'
OUTER = METHOD + '::test_owned_exit17_keeps_raw_status'
INNER = NESTED + '::test_nested_owner'


def admit(argv, cwd, env, state, append, refuse):
    if state.get('case') != OUTER:
        return None
    own = child_relative(argv, cwd, env, state, append, refuse)
    if own is not None:
        return own
    nested = state.get('class') == 'source-execution-owner-probe'
    relative, name = (NESTED, 'test_nested_owner') if nested else (METHOD, '_nested_owner_probe')
    root = Path(state['checkout'])
    source = root / relative
    guard = sys.modules['runtime_guard']
    path = Path(state['guard']).with_name('fallback_binding.py')
    frames = guard.checked_source(path, state['direct_support']['files'][str(path)])['active_frames']()
    try:
        callers = [f for f in frames if Path(f.f_code.co_filename) == source
                   and f.f_code.co_name == name]
        if not callers:
            return None
        if len(callers) != 1:
            refuse('owner_probe_ambiguous_caller')
        caller = callers[0]
        module = sys.modules.get(caller.f_globals.get('__name__'))
        fn = getattr(module, name, None)
        pin = state['product_pins'][relative]
        if (hashlib.sha256(source.read_bytes()).hexdigest() != pin or module is None
                or vars(module) is not caller.f_globals or fn is None
                or fn.__globals__ is not caller.f_globals or fn.__code__ is not caller.f_code
                or fn.__code__ != state['isolated_named'](state['isolated_source_code'](source), name)):
            refuse('owner_probe_code_globals_drift')
        tree = ast.parse(source.read_bytes())
        owner = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
        calls = [n for n in ast.walk(owner) if isinstance(n, ast.Call)
                 and ast.unparse(n.func) == 'subprocess.run']
        if len(calls) != 1 or caller.f_lineno != calls[0].lineno:
            refuse('owner_probe_callsite_drift')
        work = Path(caller.f_locals['directory'])
        if (cwd != root or env is not None or os.getcwd() != str(root)
                or not work.is_relative_to(Path(state['owned_root']))
                or work.resolve() != work or work == Path(state['owned_root'])):
            refuse('owner_probe_root_environment_drift')
        expected = ([sys.executable, '-I', '-S', '-c', 'pass'] if nested else
                    [sys.executable, '-m', 'pytest', '-q', '-ra', '-p', 'no:cacheprovider',
                     '--junitxml=' + str(work / 'pytest.xml'), INNER])
        if argv != expected:
            refuse('owner_probe_vector_drift')
        if nested:
            path = Path(state['guard']).with_name('execution_owner.py')
            selected = guard.checked_source(path, state['direct_support']['files'][str(path)])['resolve'](
                state, refuse, frames)
            if selected != INNER:
                refuse('owner_probe_selection_drift')
        binding = {'path': str(source), 'line': calls[0].lineno, 'sha256': pin, 'function': name}
        append({'kind': 'execution_owner_probe_registration', 'source_binding': binding,
                'custody_case': state['case'], 'execution_owner': INNER if nested else OUTER})
        return {'class': 'source-execution-owner-leaf' if nested else 'source-execution-owner-probe',
                'python': True, 'source_binding': binding}
    finally:
        frames.clear()


def child_relative(argv, cwd, env, state, append, refuse):
    relative = '.github/release-source-guard/child_relative_methods.py'
    source = Path(state['checkout']) / relative
    frame = sys._getframe(1)
    while frame is not None and not (frame.f_code.co_filename == str(source)
                                      and frame.f_code.co_name in {'probe', 'postfork', 'fault_probe'}):
        frame = frame.f_back
    if frame is None:
        return None
    if frame.f_code.co_name == 'fault_probe' and frame.f_locals.get('mode') not in {'wrongcwd', 'nonsearchable'}:
        refuse('child_relative_probe_mode')
    module = sys.modules.get('child_relative_methods')
    pin = state['product_pins'][relative]
    name = frame.f_code.co_name
    fn = getattr(module, name, None)
    syntax = ast.parse(source.read_bytes())
    calls = [n for n in ast.walk(syntax) if isinstance(n, ast.Call)
             and ast.unparse(n.func) == ('subprocess.run' if name == 'probe' else 'subprocess.Popen')
             and any(isinstance(owner, ast.FunctionDef) and owner.name == name
                     and n in ast.walk(owner) for owner in syntax.body)]
    program = 'pass' if name in {'probe', 'fault_probe'} else ast.literal_eval(next(
        node.value for node in syntax.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'BARRIER' for target in node.targets)))
    if (len(calls) != 1 or frame.f_lineno != calls[0].lineno or fn is None
            or frame.f_globals is not vars(module) or frame.f_code is not fn.__code__
            or fn.__code__ != state['isolated_named'](
                compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), name)
            or hashlib.sha256(source.read_bytes()).hexdigest() != pin
            or argv != [sys.executable, '-I', '-S', '-c', program] or cwd is not None
            or env is not None or os.getcwd() != state['checkout']):
        refuse('child_relative_probe_binding')
    return {'class': 'source-child-relative-probe', 'python': True,
            'source_binding': {'path': str(source), 'line': calls[0].lineno, 'sha256': pin}}
