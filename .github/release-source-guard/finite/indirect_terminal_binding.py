"""Bind the original redaction request to its genuine ACP terminal handler."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import sys
import types

CASE = 'tests/test_capability_policy.py::test_raw_acp_terminal_protocol_redacts_credential_values'
OUTER = 'tests/contracts/test_lean_evidence_crosswalk.py::test_crosswalk_is_complete_and_every_mapped_node_passes'
NESTED_MODULES = frozenset({
    'tests/contracts/test_lean_evidence_crosswalk.py',
    'tests/contracts/test_lean_provider_security.py',
    'tests/contracts/test_retained_boundaries.py',
})
OWNER = CASE.split('::')[1]
VECTOR = ['-c', "import os; print(os.environ['ZAI_API_KEY'])"]


def authenticated_frame(frames, source, module, function, expected, line):
    if (not isinstance(function, types.FunctionType)
            or function.__globals__ is not vars(module) or function.__code__ != expected
            or Path(module.__file__).resolve() != source):
        return None
    selected = {id(f): f for f in frames if f.f_code is function.__code__
                and f.f_globals is vars(module) and f.f_lineno == line
                and Path(f.f_code.co_filename) == source}
    return next(iter(selected.values())) if len(selected) == 1 else None


def matches(registration, argv, cwd, environment, state, frames):
    # This adds no registry entry and grants no permission to arbitrary ACP calls.
    guard = sys.modules['runtime_guard']
    root = Path(state['checkout'])
    original = root / 'tests/test_capability_policy.py'
    product = root / 'src/unrest_harness/acp_runner.py'
    bound = registration['source_binding']
    if (registration['class'] != 'reference-descendant:terminal-redaction'
            or registration['argv'] != VECTOR or registration['python'] is not True
            or registration['caller_bindings'] != []
            or bound != {'path': str(original), 'line': 549,
                         'sha256': state['product_pins'].get('tests/test_capability_policy.py')}
            or state.get('phase') != 'READY' or not state.get('token')
            or os.getcwd() != str(root)):
        return None
    guard.require_ready(state['token'])
    if state.get('case') != CASE:
        outer_module = state.get('case', '').split('::', 1)[0]
        if (outer_module not in NESTED_MODULES
                or state.get('class') != 'reference:' + outer_module):
            return None
        # All three existing reference selections contain this exact leaf.
        # The resolver still authenticates their bytes, ordered nodes, payload,
        # token and live leaf frame; an outer case label grants nothing.
        support = Path(state['guard']).with_name('execution_owner.py')
        resolve = guard.checked_source(support, state['direct_support']['files'][str(support)])['resolve']
        if resolve(state, guard.refuse, frames) != CASE:
            return None
    elif (state.get('class') != 'pytest-root' or state['token'] != 'root'
          or state.get('registered_payload') is not None):
        return None
    for path in (original, product):
        if hashlib.sha256(path.read_bytes()).hexdigest() != state['product_pins'].get(
                str(path.relative_to(root))):
            return None
    module = sys.modules.get('unrest_harness.acp_runner')
    owners = {f.f_globals.get('__name__') for f in frames
              if Path(f.f_code.co_filename) == original}
    if module is None or len(owners) != 1:
        return None
    owner_module = sys.modules.get(next(iter(owners)))
    if owner_module is None:
        return None
    named = state['isolated_named']
    owner_code = named(state['isolated_source_code'](original), OWNER)
    # Product modules are not pytest-rewritten. Compile with the same loader
    # discipline as fallback_binding, including the supported beartype loader.
    loader = module.__loader__
    specification = module.__spec__
    from importlib.machinery import SourceFileLoader
    from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
    if (type(loader) not in (SourceFileLoader, BeartypeSourceFileLoader)
            or specification is None or specification.loader is not loader
            or Path(specification.origin).resolve() != product
            or Path(loader.path).resolve() != product or loader.name != module.__name__):
        return None
    code = (loader.source_to_code(product.read_bytes(), str(product), _optimize=sys.flags.optimize)
            if type(loader) is BeartypeSourceFileLoader else compile(
                product.read_bytes(), str(product), 'exec', dont_inherit=True,
                optimize=sys.flags.optimize))
    handler = module.ACPClient.__dict__.get('_handle_terminal_create')
    call = authenticated_frame(frames, original, owner_module,
                               getattr(owner_module, OWNER, None), owner_code, 546)
    launch = authenticated_frame(frames, product, module, handler,
                                 named(named(code, 'ACPClient'), '_handle_terminal_create'), 1034)
    if call is None or launch is None:
        return None
    # The request literal is the only accepted indirect syntax. The registry's
    # line points inside it; it is not a direct subprocess call at that line.
    syntax = ast.parse(original.read_bytes())
    calls = [n for n in ast.walk(syntax) if isinstance(n, ast.Call) and n.lineno == 546
             and ast.unparse(n.func) == 'client._handle_terminal_create']
    if (len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords
            or ast.unparse(calls[0].args[0]) !=
            "{'command': sys.executable, 'args': ['-c', \"import os; print(os.environ['ZAI_API_KEY'])\"]}"):
        return None
    local = launch.f_locals
    client = call.f_locals.get('client')
    request = local.get('params')
    expected = {'command': sys.executable, 'args': VECTOR}
    if (type(client) is not module.ACPClient or local.get('self') is not client
            or getattr(client._handle_terminal_create, '__func__', None) is not handler
            or type(request) is not dict or request != expected
            or type(request.get('args')) is not list
            or local.get('args') is not request['args']
            or local.get('command') != request['command']
            or local.get('env') is not environment
            or type(environment) is not dict
            or environment != call.f_locals.get('terminal_environment')
            or client._terminal_environment != environment
            or client._policy is not call.f_locals.get('policy')
            or client._policy.role != 'worker' or not client._policy.process.enabled
            or cwd != str(local.get('cwd')) or cwd != client._working_dir
            or Path(cwd) != Path(call.f_locals['tmp_path']) / 'workspace'
            or not Path(cwd).resolve().is_relative_to(Path(state['owned_root']).resolve())
            or argv != [sys.executable, *VECTOR]
            or argv[0] not in state['runtime']['paths']
            or str(Path(argv[0]).resolve()) != state['runtime']['realpath']
            or hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest() != state['runtime']['sha256']):
        return None
    return {'source': str(original), 'line': 546, 'function': OWNER,
            'globals_module': owner_module.__name__, 'handler_source': str(product),
            'handler_line': 1034, 'token': state['token']}
