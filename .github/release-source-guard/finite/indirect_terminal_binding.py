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
ENV_OWNER = 'test_real_terminal_create_excludes_raw_wrappers_and_preserves_transform'
ENV_CASE = 'tests/test_capability_policy.py::' + ENV_OWNER
ENV_NAMES = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CODEX_API_KEY', 'GLM_API_KEY',
             'OPENAI_API_KEY', 'ZAI_API_KEY', *(f'UNRELATED_ALIAS_{i}' for i in range(6)),
             'HOME', 'TEMP', 'SSL_CERT_DIR', 'NO_PROXY', 'TMP')
ENV_SCRIPT = (f'import json, os; names = {ENV_NAMES!r}; '
              'print(json.dumps({name: os.environ.get(name) for name in names}))')
ENV_VECTOR = ['-c', ENV_SCRIPT]
ENV_CASES = frozenset(ENV_CASE + '[' + profile + '-' + role + '-' + provider + ']'
    for profile in ('safe', 'unsafe-development-unrestricted')
    for role in ('worker', 'validator', 'terminal_reviewer') for provider in ('claude', 'codex'))

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
    # Only these original literal requests may reach the actual ACP handler.
    guard = sys.modules['runtime_guard']
    root = Path(state['checkout'])
    original = root / 'tests/test_capability_policy.py'
    product = root / 'src/unrest_harness/acp_runner.py'
    bound = registration['source_binding']
    transform = registration['class'] == 'reference-descendant:terminal-environment'
    vector = ENV_VECTOR if transform else VECTOR
    owner = ENV_OWNER if transform else OWNER
    owner_line, binding_line = (625, 628) if transform else (546, 549)
    case_matches = state.get('case') in ENV_CASES if transform else state.get('case') == CASE
    if (registration['class'] not in {'reference-descendant:terminal-redaction', 'reference-descendant:terminal-environment'}
            or registration['argv'] != vector or registration['python'] is not True
            or registration['caller_bindings'] != []
            or bound != {'path': str(original), 'line': binding_line,
                         'sha256': state['product_pins'].get('tests/test_capability_policy.py')}
            or state.get('phase') != 'READY' or not state.get('token')
            or os.getcwd() != str(root)):
        return None
    guard.require_ready(state['token'])
    if not case_matches:
        if transform:
            return None
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
    owner_code = named(state['isolated_source_code'](original), owner)
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
                               getattr(owner_module, owner, None), owner_code, owner_line)
    launch = authenticated_frame(frames, product, module, handler,
                                 named(named(code, 'ACPClient'), '_handle_terminal_create'), 1034)
    if call is None or launch is None:
        return None
    # The request literal is the only accepted indirect syntax. The registry's
    # line points inside it; it is not a direct subprocess call at that line.
    syntax = ast.parse(original.read_bytes())
    calls = [n for n in ast.walk(syntax) if isinstance(n, ast.Call) and n.lineno == owner_line
             and ast.unparse(n.func) == 'client._handle_terminal_create']
    expected_syntax = ("{'command': sys.executable, 'args': ['-c', script]}" if transform else
                       "{'command': sys.executable, 'args': ['-c', \"import os; print(os.environ['ZAI_API_KEY'])\"]}")
    if (len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords
            or ast.unparse(calls[0].args[0]) != expected_syntax):
        return None
    local = launch.f_locals
    client = call.f_locals.get('client')
    request = local.get('params')
    expected = {'command': sys.executable, 'args': vector}
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
            or (not transform and client._policy.role != 'worker') or not client._policy.process.enabled
            or cwd != str(local.get('cwd')) or cwd != client._working_dir
            or Path(cwd) != Path(call.f_locals['tmp_path']) / 'workspace'
            or not Path(cwd).resolve().is_relative_to(Path(state['owned_root']).resolve())
            or argv != [sys.executable, *vector]
            or argv[0] not in state['runtime']['paths']
            or str(Path(argv[0]).resolve()) != state['runtime']['realpath']
            or hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest() != state['runtime']['sha256']):
        return None
    if transform:
        values = call.f_locals
        if (state['case'] != ENV_CASE + '[' + values['profile'] + '-' + values['role'] + '-' + values['provider_name'] + ']'
                or values['script'] != ENV_SCRIPT or tuple(values['observed_names']) != ENV_NAMES
                or client._policy.role != values['role'] or client._policy.profile != values['profile']
                or client._policy.provider != values['provider_name']
                or environment != {'PATH': os.environ['PATH'], 'SSL_CERT_DIR': 'MONKEY',
                                   'NO_PROXY': 'ordinary-equal-free-value',
                                   'TMP': 'dGVybWluYWwtc2VudGluZWwtMS1hbnRocm9waWNfYXV0aF90b2tlbg=='}):
            return None
    return {'source': str(original), 'line': owner_line, 'function': owner,
            'globals_module': owner_module.__name__, 'handler_source': str(product),
            'handler_line': 1034, 'token': state['token']}
