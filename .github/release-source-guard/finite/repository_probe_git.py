"""One read-only Git query from the original CLI import positive control."""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import shutil
import sys
import types

KIND = 'original-cli-import:_import_probe'


def compiled(module, source):
    from importlib.machinery import SourceFileLoader
    from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
    loader = module.__loader__
    spec = module.__spec__
    if (type(loader) not in (SourceFileLoader, BeartypeSourceFileLoader)
            or spec is None or spec.loader is not loader
            or Path(spec.origin).resolve() != source or Path(loader.path).resolve() != source
            or loader.name != module.__name__):
        return None
    body = source.read_bytes()
    return (loader.source_to_code(body, str(source), _optimize=sys.flags.optimize)
            if type(loader) is BeartypeSourceFileLoader else compile(
                body, str(source), 'exec', dont_inherit=True, optimize=sys.flags.optimize))


def function_frame(module, source, function, expected, frames, line):
    function = inspect.unwrap(function)
    if (not isinstance(function, types.FunctionType) or function.__globals__ is not vars(module)
            or function.__code__ != expected):
        return None
    selected = {id(frame): frame for frame in frames if frame.f_code is function.__code__
                and frame.f_globals is vars(module) and frame.f_lineno == line
                and Path(frame.f_code.co_filename) == source}
    return next(iter(selected.values())) if len(selected) == 1 else None


def admit(argv, cwd, env, state, append, refuse, frames):
    root = Path(state['checkout'])
    payload = state.get('registered_payload')
    if (state.get('class') != KIND or state.get('phase') != 'READY' or not state.get('token')
            or type(payload) is not dict or payload.get('token') != state['token']
            or payload.get('class') != KIND or payload.get('case') != state.get('case')
            or payload.get('mode') != 'inline' or payload.get('isolated') is not False
            or payload.get('path0') != '' or not sys.path or sys.path[0] != ''
            or cwd is not None or env is not None or Path.cwd() != root
            or argv != ['git', '-C', str(root), 'rev-parse', '--show-toplevel']):
        return None
    guard = sys.modules['runtime_guard']
    if guard._STATE is not state:
        return None
    environment = guard.inherited_environment()
    if any(key.startswith('GIT_') for key in environment):
        return None
    guard.require_ready(state['token'])
    source = root / 'src/unrest_harness/repository_contract.py'
    cli_source = root / 'src/unrest_harness/cli.py'
    original = root / 'tests/test_repository_contract.py'
    for path in (source, cli_source, original):
        if hashlib.sha256(path.read_bytes()).hexdigest() != state['product_pins'].get(str(path.relative_to(root))):
            return None
    binding = {'path': str(original), 'line': 518,
               'sha256': state['product_pins']['tests/test_repository_contract.py']}
    if payload.get('source_binding') != binding:
        return None
    syntax = ast.parse(original.read_bytes())
    owners = [node for node in syntax.body if isinstance(node, ast.FunctionDef) and node.name == '_import_probe']
    literals = [node.value for owner in owners for node in owner.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'script' for target in node.targets)]
    if len(owners) != 1 or len(literals) != 1:
        return None
    body = ast.literal_eval(literals[0])
    expected_argv = [sys.executable, '-c', body, json.dumps(()), json.dumps(('check-repository',))]
    if (payload.get('target') != body or payload.get('orig_argv') != expected_argv
            or payload.get('sys_argv') != ['-c', *expected_argv[3:]] or sys.argv != payload['sys_argv']):
        return None
    expected_payload = compile(body, '<string>', 'exec', dont_inherit=True)
    if state.get('payload_code') != expected_payload:
        return None
    calls = [node for node in ast.walk(ast.parse(body)) if isinstance(node, ast.Call)
             and ast.unparse(node.func) == 'cli.main']
    live = [frame for frame in frames if frame.f_code is state['payload_code']
            and frame.f_globals is state.get('payload_globals')]
    if (len(calls) != 1 or len(live) != 1 or live[0].f_lineno != calls[0].lineno
            or live[0].f_locals.get('arguments') != ['check-repository']
            or live[0].f_locals.get('blocked') != ()):
        return None
    module = sys.modules.get('unrest_harness.repository_contract')
    cli = sys.modules.get('unrest_harness.cli')
    if module is None or cli is None or live[0].f_locals.get('cli') is not cli.cli:
        return None
    code = compiled(module, source)
    cli_code = compiled(cli, cli_source)
    if code is None or cli_code is None:
        return None
    named = state['isolated_named']
    command = cli.cli.commands.get('check-repository')
    if command is not cli.check_repository_cmd:
        return None
    checker = function_frame(module, source, module.find_repository_root,
                             named(code, 'find_repository_root'), frames, 507)
    caller = function_frame(cli, cli_source, command.callback,
                            named(cli_code, 'check_repository_cmd'), frames, 129)
    if checker is None or caller is None or checker.f_locals.get('start') != root:
        return None
    executable = shutil.which('git', path=environment.get('PATH'))
    if (executable is None or hashlib.sha256(Path(executable).read_bytes()).hexdigest()
            != state['copy_git'].get(executable)):
        return None
    result = {'path': str(source), 'line': 507, 'function': 'find_repository_root',
              'sha256': state['product_pins']['src/unrest_harness/repository_contract.py'],
              'probe_source_sha256': binding['sha256'],
              'probe_literal_sha256': hashlib.sha256(body.encode()).hexdigest()}
    append({'kind': 'exact_original_import_probe_git_registration', 'source_binding': result,
            'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()})
    return {'class': 'source-original-import-probe-git', 'python': False, 'source_binding': result}
