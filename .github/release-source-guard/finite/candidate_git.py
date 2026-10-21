"""Original candidate fixture Git calls, bound to their unchanged source frames."""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import types
import sys

SOURCE = 'tests/test_experimental_candidate.py'
CLASS = 'source-candidate-fixture-git'


def environment(root):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LC_ALL': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_AUTHOR_DATE': '2000-01-01T00:00:00+0000',
            'GIT_COMMITTER_DATE': '2000-01-01T00:00:00+0000'}


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state['checkout']) / SOURCE
    frame = inspect.currentframe()
    try:
        while frame and not (frame.f_code.co_filename == str(source)
                             and frame.f_code.co_name == 'git'):
            frame = frame.f_back
        if frame is None:
            return None
        body = source.read_bytes()
        pin = state['product_pins'][SOURCE]
        codes = state['isolated_source_code'](source)
        function = frame.f_globals.get('git')
        caller = frame.f_back
        if (hashlib.sha256(body).hexdigest() != pin
                or not isinstance(function, types.FunctionType)
                or sys.modules.get(function.__module__) is None
                or vars(sys.modules[function.__module__]) is not frame.f_globals
                or function.__globals__ is not frame.f_globals
                or function.__code__ is not frame.f_code
                or function.__code__ != state['isolated_named'](codes, 'git')
                or function.__defaults__ is not None or function.__kwdefaults__ is not None
                or frame.f_lineno != 21 or caller is None
                or caller.f_code.co_filename != str(source)
                or caller.f_globals is not frame.f_globals
                or not state.get('case', '').startswith(SOURCE + '::test_')):
            refuse('candidate_fixture_git_callable')
        owner = frame.f_globals.get(caller.f_code.co_name)
        owner = getattr(owner, '__wrapped__', owner)
        if (not isinstance(owner, types.FunctionType)
                or owner.__globals__ is not caller.f_globals
                or owner.__code__ is not caller.f_code
                or caller.f_code != state['isolated_named'](codes, caller.f_code.co_name)):
            refuse('candidate_fixture_git_owner')
        calls = [node for node in ast.walk(ast.parse(body))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == 'git' and node.lineno <= caller.f_lineno <= node.end_lineno]
        if len(calls) != 1 or calls[0].keywords or any(isinstance(a, ast.Starred) for a in calls[0].args):
            refuse('candidate_fixture_git_callsite')
        call = calls[0]
        # Only the actual, freshly byte-checked original call expression is evaluated.
        values = [eval(compile(ast.Expression(a), str(source), 'eval'),
                       caller.f_globals, caller.f_locals) for a in call.args]
        directory = frame.f_locals.get('root')
        arguments = frame.f_locals.get('args')
        if (not isinstance(directory, Path) or directory.resolve() != directory
                or not directory.is_relative_to(Path(state['owned_root']) / 'pytest')
                or directory.name != 'repository' or cwd != directory
                or not values or values[0] != directory or tuple(values[1:]) != arguments
                or type(arguments) is not tuple or any(type(a) is not str for a in arguments)
                or argv != ['/usr/bin/git', *arguments] or env != environment(directory)):
            refuse('candidate_fixture_git_vector_context')
        binding = {'path': str(source), 'line': 21, 'sha256': pin, 'function': 'git',
                   'caller': caller.f_code.co_name, 'caller_line': call.lineno,
                   'expression_ast_sha256': hashlib.sha256(ast.dump(call, include_attributes=False).encode()).hexdigest()}
        append({'kind': 'concrete_candidate_fixture_git_registration', 'source_binding': binding,
                'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest(),
                'cwd': str(directory), 'executable_sha256': state['copy_git']['/usr/bin/git']})
        return {'class': CLASS, 'python': False, 'source_binding': binding}
    finally:
        del frame
