"""Current candidate inventory's original helper chain, outside historical owners."""
from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
import sys

OWNERS = ('test_binding_rejects_coherent_fake_digest',
          'test_current_candidate_binding_hashes_exact_current_source')


def admit(argv, cwd, env, state, append, refuse):
    prefix = 'tests/test_release_binding.py::'
    method = '.github/release-source-guard/multiprocess_guard_methods.py'
    controlled = state.get('case') == method + '::test_owned_exit17_keeps_raw_status'
    if state.get('case') not in [prefix + name for name in OWNERS] and not controlled:
        return None
    root = Path(state['checkout'])
    source = root / 'tools/release_binding.py'
    tests = sys.modules.get('tests.test_release_binding')
    stack = []
    frame = inspect.currentframe()
    try:
        while frame:
            stack.append(frame)
            frame = frame.f_back
        helpers = [f for f in stack if f.f_code.co_filename == str(source)
                   and (f.f_code.co_name, f.f_lineno) in
                   (('tracked_regular_paths', 36), ('candidate_regular_paths', 57))]
        if not helpers:
            return None
        helper = helpers[0]
        if not controlled and tests is None:
            refuse('current_binding_module_drift')
        module = sys.modules.get('_guard_binding_inventory') if controlled else tests.release_binding
        if module is None:
            refuse('current_binding_module_drift')
        test_source = root / 'tests/test_release_binding.py'
        for path in (source, test_source):
            if hashlib.sha256(path.read_bytes()).hexdigest() != state['product_pins'][str(path.relative_to(root))]:
                refuse('current_binding_source_drift')
        method_source = root / method
        if controlled and hashlib.sha256(method_source.read_bytes()).hexdigest() != state['product_pins'][method]:
            refuse('current_binding_method_source_drift')
        chain = [f for f in stack if f.f_code.co_filename in
                 (str(source), str(method_source) if controlled else str(test_source))
                 and (not controlled or f.f_code.co_filename == str(source)
                      or f.f_code.co_name == '_binding_inventory')]
        owner = '_binding_inventory' if controlled else state['case'].removeprefix(prefix)
        expected_chain = (['tracked_regular_paths', 'candidate_regular_paths', '_computed', owner]
                          if helper.f_lineno == 36 else ['candidate_regular_paths', '_computed', owner])
        if controlled:
            expected_chain = (['tracked_regular_paths', 'candidate_regular_paths', owner]
                              if helper.f_lineno == 36 else ['candidate_regular_paths', owner])
        # The second original test also directly calls candidate_regular_paths.
        direct = owner == OWNERS[1] and [f.f_code.co_name for f in chain] == expected_chain[:-2] + [owner]
        if not direct and [f.f_code.co_name for f in chain] != expected_chain:
            refuse('current_binding_owner_chain_drift')
        for call in chain:
            container = (module if call.f_code.co_filename == str(source) else
                         sys.modules.get(call.f_globals.get('__name__')) if controlled else tests)
            if container is None:
                refuse('current_binding_method_module_drift')
            function = getattr(container, call.f_code.co_name)
            path = source if container is module else method_source if controlled else test_source
            if (call.f_globals is not vars(container) or function.__globals__ is not vars(container)
                    or function.__code__ is not call.f_code
                    or call.f_code != state['isolated_named'](state['isolated_source_code'](path), call.f_code.co_name)):
                refuse('current_binding_code_globals_drift')
        vector = (['git', 'ls-files', '--stage', '-z'] if helper.f_lineno == 36
                  else ['git', 'ls-files', '--others', '--exclude-standard', '-z'])
        if (argv != vector or cwd != root or env is not None or Path.cwd() != root
                or helper.f_locals.get('repository') != root
                or helper.f_locals.get('revision') is not None):
            refuse('current_binding_vector_environment_drift')
        binding = {'path': str(source), 'line': helper.f_lineno,
                   'sha256': state['product_pins']['tools/release_binding.py']}
        append({'kind': 'exact_current_binding_registration', 'source_binding': binding,
                'owner': state['case'], 'owner_source_sha256': state['product_pins']['tests/test_release_binding.py']})
        return {'class': 'source-current-binding-git', 'python': False, 'source_binding': binding}
    finally:
        stack.clear()
        del frame
