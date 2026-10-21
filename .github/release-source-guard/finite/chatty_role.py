"""Exact two-mode original oversized-stream substitution, with real role pipe custody."""
from __future__ import annotations

import asyncio
import asyncio.subprocess
import hashlib
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import sys
import types

SOURCE = 'tests/test_acp_runner.py'
PIN = 'b6f1c200a94c1107d6059baae0eb646dd5a113cc304d7062b29aec8263dd52d0'
PRODUCT = 'src/unrest_harness/acp_runner.py'
PRODUCT_PIN = '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'
OWNER = 'test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained'
BODY = ("import sys; sys.stdout.write('stdout-cause-oversized-child-secret-' + 'o'*524288); "
        "sys.stdout.flush(); sys.stderr.write('stderr-cause-oversized-child-secret-' + 'e'*524288); "
        "sys.stderr.flush()")


def bind(argv, cwd, environment, state, role, factory, fd, expected, refuse):
    prefix = SOURCE + '::' + OWNER
    if state.get('case') not in {prefix + '[worker]', prefix + '[terminal-reviewer]'}:
        return None
    source = Path(state['checkout']) / SOURCE
    product = Path(state['checkout']) / PRODUCT
    if (state['product_pins'].get(SOURCE) != PIN or hashlib.sha256(source.read_bytes()).hexdigest() != PIN
            or state['product_pins'].get(PRODUCT) != PRODUCT_PIN
            or hashlib.sha256(product.read_bytes()).hexdigest() != PRODUCT_PIN):
        refuse('chatty_role_source_drift')
    support = Path(state['guard']).with_name('fallback_binding.py')
    guard = sys.modules['runtime_guard']
    frames = guard.checked_source(support, state['direct_support']['files'][str(support)])['active_frames']()
    try:
        code = state['isolated_source_code'](source)
        owner_code = state['isolated_named'](code, OWNER)
        spy_code = state['isolated_named'](owner_code, 'spawn_chatty')
        owners = {id(f): f for f in frames if f.f_code == owner_code and f.f_code.co_filename == str(source)}
        spies = {id(f): f for f in frames if f.f_code == spy_code and f.f_code.co_filename == str(source)}
        if len(owners) != 1 or len(spies) != 1:
            refuse('chatty_role_live_owner')
        owner, spy = next(iter(owners.values())), next(iter(spies.values()))
        module = sys.modules.get(owner.f_globals.get('__name__'))
        function = getattr(module, OWNER, None)
        local = owner.f_locals
        substitute = local.get('spawn_chatty')
        original = asyncio.subprocess.create_subprocess_exec
        library = sys.modules[original.__module__]
        library_code = compile(Path(library.__file__).read_bytes(), library.__file__, 'exec', dont_inherit=True)
        product_module = sys.modules.get(factory.f_globals.get('__name__'))
        loader = getattr(product_module, '__loader__', None)
        from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
        specification = getattr(product_module, '__spec__', None)
        if (product_module is None or vars(product_module) is not factory.f_globals
                or type(loader) not in {SourceFileLoader, BeartypeSourceFileLoader}
                or specification is None or specification.loader is not loader
                or Path(specification.origin).resolve() != product
                or Path(loader.path).resolve() != product or loader.name != product_module.__name__):
            refuse('chatty_role_factory_source')
        factory_code = type(loader).source_to_code(loader, product.read_bytes(), str(product))
        method = '_start_worker_mcp_server' if role == 'worker' else '_start_terminal_reviewer_mcp'
        options = spy.f_locals.get('kwargs', {})
        workspace = local.get('workspace')
        if (module is None or vars(module) is not owner.f_globals or spy.f_globals is not owner.f_globals
                or not isinstance(function, types.FunctionType) or function.__code__ is not owner.f_code
                or function.__globals__ is not owner.f_globals
                or not isinstance(substitute, types.FunctionType) or substitute.__code__ is not spy.f_code
                or substitute.__globals__ is not owner.f_globals
                or asyncio.create_subprocess_exec is not substitute
                or local.get('mode') != role or state['case'] != prefix + '[' + role + ']'
                or local.get('secret_name') != 'ANTHROPIC_API_KEY' or local.get('secret') != 'oversized-child-secret'
                or local.get('original_spawn') is not original or spy.f_locals.get('original_spawn') is not original
                or original.__globals__ is not vars(library)
                or original.__code__ != state['isolated_named'](library_code, 'create_subprocess_exec')
                or spy.f_lineno != 341 or argv != [sys.executable, '-c', BODY]
                or factory.f_code != state['isolated_named'](factory_code, method)
                or factory.f_locals.get('self') is not local.get('runner')
                or list(spy.f_locals.get('args', ())) != expected
                or factory.f_locals.get('cmd') != expected
                or factory.f_locals.get('mcp_port') != 43210
                or not isinstance(workspace, Path) or workspace.resolve() != workspace
                or not workspace.is_relative_to(Path(state['owned_root']))
                or cwd != str(workspace) or options.get('cwd') != cwd
                or options.get('env') is not environment
                or options.get('pass_fds') != (fd,)
                or options.get('stdout') != asyncio.subprocess.PIPE
                or options.get('stderr') != asyncio.subprocess.PIPE
                or options.get('limit') != factory.f_globals.get('SUBPROCESS_STREAM_LIMIT')
                or factory.f_locals.get('environment') != {'PATH': os.environ['PATH']}
                or factory.f_locals.get('sensitive_inventory') != {'ANTHROPIC_API_KEY': 'oversized-child-secret'}
                or os.getcwd() != state['checkout']):
            refuse('chatty_role_fixture_binding')
        return {'path': str(source), 'line': 341, 'sha256': PIN}
    finally:
        frames.clear()
