"""Bind the original two-child registration-order proof's captured spawn alias."""
from __future__ import annotations

import asyncio.subprocess
import hashlib
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import sys
import types

OWNER = 'test_inflight_terminal_registration_before_inventory'
SOURCE = 'tests/test_acp_cleanup.py'
BODY = 'import time; time.sleep(30)'


def admit(argv, cwd, environment, state, frames, refuse):
    prefix = SOURCE + '::' + OWNER
    if state.get('case') not in {prefix + '[False]', prefix + '[True]'}:
        return None
    root = Path(state['checkout'])
    source = root / SOURCE
    pin = hashlib.sha256(source.read_bytes()).hexdigest()
    if pin != state['product_pins'][SOURCE]:
        refuse('inflight_source_drift')
    code = state['isolated_source_code'](source)
    owners = {id(f): f for f in frames if f.f_code.co_filename == str(source)
              and f.f_code == state['isolated_named'](code, OWNER)}
    if len(owners) != 1:
        refuse('inflight_live_owner')
    owner = next(iter(owners.values()))
    module = sys.modules.get(owner.f_globals.get('__name__'))
    function = getattr(module, OWNER, None)
    local = owner.f_locals
    fault = local.get('settlement_fault')
    temporary = local['tmp_path']
    alias = local.get('spawn')
    original = asyncio.subprocess.create_subprocess_exec
    library = sys.modules[original.__module__]
    library_code = compile(Path(library.__file__).read_bytes(), library.__file__, 'exec', dont_inherit=True)
    if (module is None or vars(module) is not owner.f_globals
            or not isinstance(function, types.FunctionType) or function.__code__ is not owner.f_code
            or function.__globals__ is not owner.f_globals or type(fault) is not bool
            or state['case'] != prefix + '[' + str(fault) + ']'
            or alias is not original or original.__globals__ is not vars(library)
            or original.__code__ != state['isolated_named'](library_code, 'create_subprocess_exec')
            or argv != [sys.executable, '-c', BODY] or os.getcwd() != str(root)
            or temporary.resolve() != temporary
            or not temporary.is_relative_to(Path(state['owned_root']))):
        refuse('inflight_owner_or_vector_drift')
    initial = owner.f_lineno == 421
    if initial:
        if cwd is not None or environment is not None:
            refuse('inflight_initial_context')
        binding = {'path': str(source), 'line': 421, 'sha256': pin}
    else:
        paused = next((f for f in frames if f.f_code.co_filename == str(source)
                       and f.f_code == state['isolated_named'](code, 'paused_spawn')), None)
        product = root / 'src/unrest_harness/acp_runner.py'
        call = next((f for f in frames if f.f_code.co_filename == str(product)
                     and f.f_code.co_name == '_handle_terminal_create'), None)
        if paused is None or paused.f_lineno != 434 or call is None:
            refuse('inflight_terminal_chain')
        product_pin = hashlib.sha256(product.read_bytes()).hexdigest()
        product_module = sys.modules.get(call.f_globals.get('__name__'))
        loader = getattr(product_module, '__loader__', None)
        from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
        specification = getattr(product_module, '__spec__', None)
        if (product_pin != state['product_pins']['src/unrest_harness/acp_runner.py']
                or product_module is None or vars(product_module) is not call.f_globals
                or type(loader) not in {SourceFileLoader, BeartypeSourceFileLoader}
                or specification is None or specification.loader is not loader
                or Path(specification.origin).resolve() != product
                or Path(loader.path).resolve() != product or loader.name != product_module.__name__):
            refuse('inflight_product_drift')
        product_code = type(loader).source_to_code(loader, product.read_bytes(), str(product))
        client = local['client']
        children = local['children']
        if (call.f_code != state['isolated_named'](product_code, '_handle_terminal_create')
                or not 1034 <= call.f_lineno <= 1042
                or call.f_locals.get('self') is not client or len(children) != 2
                or client._process is not children[0]
                or client._terminals['existing'].process is not children[1]
                or list(paused.f_locals['args']) != argv
                or paused.f_locals.get('spawn') is not alias
                or cwd != str(temporary) or environment != {}
                or paused.f_locals['kwargs'].get('cwd') != cwd
                or paused.f_locals['kwargs'].get('env') != environment):
            refuse('inflight_terminal_context')
        binding = {'path': str(product), 'line': 1034, 'sha256': product_pin}
    return {'class': 'inline:test_acp_cleanup.py:51', 'python': True, 'source_binding': binding}
