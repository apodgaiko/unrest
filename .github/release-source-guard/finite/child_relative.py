"""Single-use Method C context after existing finite SOURCE admission."""
from __future__ import annotations

import ast
import dis
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import weakref

STDLIB = 'e4049ed91ed101b09b0dc96bbf234f646c1728090d643a474b024276cc2a028c'
NATIVE = '925e5f643c0c5f9d5e897d6faca9af7d9f7dbe624b7d31cab4d97dde15a748af'
LIBRARY = '9dfc25c8ade9fb31dbeb1f5e79ac693d588245e2dbb8fa7ebd939db6231fe06d'
APPLICABLE = frozenset({
    'canonical-backend', "source-controlled-backend-postimage", 'source-canonical-stdlib-backend',
    'composed-http-role:orchestrator',
    'composed-http-role:terminal-reviewer',
    'composed-http-role:validator',
    'composed-http-role:worker',
    'controlled-acp',
    'executor-fixture-descendant',
    'inline:test_acp_cleanup.py:50',
    'inline:test_acp_cleanup.py:51',
    'inline:test_acp_runner.py:63',
    'inline:test_acp_runner.py:67',
    'inline:test_acp_runner.py:69',
    'inline:test_experimental_session.py:342',
    'inline:test_experimental_session.py:377',
    'inline:test_experimental_session.py:489',
    'isolated-role-startup',
    'nested-pytest-module',
    'ordinary-session-fixture',
    'original-cli-import:_import_probe',
    'original-cli-import:test_mcp_help_does_not_import_repository_modules',
    'original-inline:tests/test_repository_contract.py:519',
    'original-inline:tests/test_repository_contract.py:568',
    'original-inline:tests/test_runtime_observability.py:505',
    'original-inline:tests/test_server.py:4962',
    'original-inline:tests/test_server.py:719',
    'public-cli-module',
    'reference-descendant:console-help',
    'reference-descendant:mcp-import',
    'reference-descendant:ordinary-mock-acp',
    'reference-descendant:repository-cli:--help',
    'reference-descendant:repository-cli:check-repository',
    'reference-descendant:repository-cli:init:--help',
    'reference-descendant:repository-cli:list-projects',
    'reference-descendant:status-cli:--help',
    'reference-descendant:status-cli:list-projects',
    'reference-descendant:status-cli:observe-project:--help',
    'reference-descendant:stderr-redaction',
    'reference-descendant:terminal-redaction',
    'reference-descendant:terminal-environment',
    'reference-integrity:test_fails',
    'reference-integrity:test_passes',
    'reference-integrity:test_skips',
    'reference-integrity:test_waits',
    'reference:tests/contracts/test_lean_evidence_crosswalk.py',
    'reference:tests/contracts/test_lean_lifecycle.py',
    'reference:tests/contracts/test_lean_package.py',
    'reference:tests/contracts/test_lean_persistence.py',
    'reference:tests/contracts/test_lean_provider_security.py',
    'reference:tests/contracts/test_lean_repository.py',
    'reference:tests/contracts/test_lean_scheduling.py',
    'reference:tests/contracts/test_lean_status.py',
    'reference:tests/contracts/test_retained_boundaries.py',
    'restart-custodian',
    'server-module-help',
    'simulated-flow-helper',
    'source-approval-adapter',
    'source-approval-mcp',
    'source-approval-python-backend',
    'source-approval-relay',
    'source-benchmark-five-run',
    'source-checker',
    'source-checker-empty-archive-control',
    'source-child-relative-probe',
    'source-cleanup-adapter',
    'source-cli-matrix',
    'source-cohort2:mock-agent',
    'source-cohort2:ownership-stdio',
    'source-cohort2:src/unrest_harness/server.py:266',
    'source-cohort2:tests/test_acp_runner.py:1080',
    'source-cohort2:tests/test_acp_runner.py:1383',
    'source-cohort2:tests/test_acp_runner.py:1843',
    'source-cohort2:tests/test_acp_runner.py:214',
    'source-cohort2:tests/test_acp_runner.py:2209',
    'source-cohort2:tests/test_acp_runner.py:2268',
    'source-cohort2:tests/test_acp_runner.py:413',
    'source-cohort2:tests/test_acp_runner.py:465',
    'source-cohort2:tests/test_acp_runner.py:544',
    'source-cohort2:tests/test_acp_runner.py:632',
    'source-cohort2:tests/test_acp_runner.py:70',
    'source-cohort2:tests/test_completion_ownership.py:108',
    'source-cohort2:tests/test_completion_ownership.py:134',
    'source-cohort2:tests/test_completion_ownership.py:135',
    'source-cohort2:tests/test_completion_ownership.py:33',
    'source-cohort2:tests/test_completion_ownership.py:34',
    'source-cohort2:tests/test_completion_ownership.py:99',
    'source-cohort2:tests/test_completion_setup.py:131',
    'source-cohort2:tests/test_completion_setup.py:132',
    'source-cohort2:tests/test_coordinator.py:1046',
    'source-cohort2:tests/test_coordinator.py:1047',
    'source-cohort2:tests/test_coordinator.py:1448',
    'source-cohort2:tests/test_coordinator.py:214',
    'source-cohort2:tests/test_experimental_session.py:347',
    'source-cohort2:tests/test_experimental_session.py:381',
    'source-cohort2:tests/test_experimental_session.py:490',
    'source-cohort2:tests/test_lean_provider_security_runtime.py:388',
    'source-cohort3:mock-agent',
    'source-cohort3:src/unrest_harness/server.py:266',
    'source-cohort3:tests/test_provider_review.py:55',
    'source-cohort3:tests/test_provider_review_frames.py:69',
    'source-cohort3:tests/test_provider_review_frames.py:70',
    'source-cohort3:tests/test_release_binding.py:119',
    'source-cohort3:tests/test_release_binding.py:130',
    'source-cohort3:tests/test_release_binding.py:144',
    'source-cohort3:tests/test_repository_contract.py:67',
    'source-cohort3:tests/test_repository_contract.py:70',
    'source-cohort3:tests/test_repository_contract.py:82',
    'source-cohort3:tests/test_repository_contract.py:87',
    'source-cohort3:tests/test_runtime_observability.py:527',
    'source-cohort3:tests/test_server.py:110',
    'source-cohort3:tests/test_server.py:1208',
    'source-cohort3:tests/test_server.py:1745',
    'source-cohort3:tests/test_server.py:1746',
    'source-cohort3:tests/test_server.py:1847',
    'source-cohort3:tests/test_server.py:1848',
    'source-cohort3:tests/test_server.py:1968',
    'source-cohort3:tests/test_server.py:1969',
    'source-cohort3:tests/test_server.py:2144',
    'source-cohort3:tests/test_server.py:2145',
    'source-cohort3:tests/test_server.py:2335',
    'source-cohort3:tests/test_server.py:2336',
    'source-cohort3:tests/test_server.py:2337',
    'source-cohort3:tests/test_server.py:2373',
    'source-cohort3:tests/test_server.py:2465',
    'source-cohort3:tests/test_server.py:2466',
    'source-cohort3:tests/test_server.py:3284',
    'source-cohort3:tests/test_server.py:3565',
    'source-cohort3:tests/test_server.py:3566',
    'source-cohort3:tests/test_server.py:3786',
    'source-cohort3:tests/test_server.py:3787',
    'source-cohort3:tests/test_server.py:4285',
    'source-cohort3:tests/test_server.py:4286',
    'source-cohort3:tests/test_server.py:4554',
    'source-cohort3:tests/test_server.py:4555',
    'source-cohort3:tests/test_server.py:4820',
    'source-cohort3:tests/test_server.py:4821',
    'source-cohort3:tests/test_server.py:4937',
    'source-cohort3:tests/test_server.py:4938',
    'source-cohort3:tests/test_server.py:5041',
    'source-cohort3:tests/test_server.py:5042',
    'source-cohort3:tests/test_server.py:5403',
    'source-cohort3:tests/test_server.py:5404',
    'source-cohort3:tests/test_server.py:5436',
    'source-cohort3:tests/test_server.py:5437',
    'source-cohort3:tests/test_server.py:5465',
    'source-cohort3:tests/test_server.py:5466',
    'source-cohort3:tools/release_binding.py:36',
    'source-cohort4:desktop-stdio',
    'source-cohort4:tests/test_stranded_recovery.py:416',
    'source-cohort4:tests/test_v021_release_records.py:31',
    'source-cohort4:tests/test_v021_release_records.py:45',
    'source-cohort4:tests/test_v045_release_records.py:130',
    'source-cohort4:tests/test_v045_release_records.py:172',
    'source-cohort4:tests/test_v045_release_records.py:186',
    'source-cohort4:tests/test_v046_measurement_helpers.py:106',
    'source-cohort4:tools/release_binding.py:36',
    'source-cohort4:tools/release_binding.py:57',
    'source-completion-helper:test_consumed_marker_survives_recovery_interruption',
    'source-completion-helper:test_process_dies_during_first_setup',
    'source-completion-helper:test_real_roles_first_use',
    'source-composed-adapter',
    'source-console-server-help',
    'source-copied-repository-cli',
    'source-crash-controller',
    'source-execution-owner-leaf',
    'source-execution-owner-probe',
    'source-extracted-oracle',
    'source-foreign-journal-owner',
    'source-installed-lifecycle',
    'source-installed-provenance',
    'source-installed-provider-matrix',
    'source-isolated-precaptured-refusal',
    'source-lease-owned-child',
    'source-measurement-fixture',
    'source-owned-role:terminal-reviewer',
    'source-owned-role:validator',
    'source-owned-role:worker',
    'source-project-projection',
    'source-recovery-cli',
    'source-recovery-role',
    'source-registered-workspace-cli',
    'source-run-worker',
    'source-seeded-environment-helper',
    'source-session-child',
    'source-session-helper:timeout',
    'source-speed-nested-exact',
    'source-storage-fresh-reader',
    'source-workspace-owned-sleep',
})
VERSION = '3.13.12 (main, Apr  7 2026, 04:52:38) [GCC 12.2.0]'


def named(code, name):
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            if item.co_name == name:
                return item
            result = named(item, name)
            if result is not None:
                return result
    return None




def same_options(before, after):
    return (before.keys() == after.keys()
            and all(type(before[key]) is type(after[key]) and before[key] == after[key]
                    for key in before))


def matches_saved(saved, launch, handle, options):
    value = saved['value']
    environment = options.get('env')
    return (saved['handle']() is handle
            and value['registration_id'] == id(launch['registration'])
            and value['registration'] == json.dumps(launch['registration'], sort_keys=True)
            and value['argv_id'] == id(launch['argv']) and value['argv'] == launch['argv']
            and same_options(value['options'], options)
            and value['environment'] == (None if environment is None else dict(environment)))

def consume(launch, handle, argv, options, activation, constructor, used, refuse):
    """Validate data from the caller-authenticated core frame; grants no launch."""
    token = launch['launch_token']
    registration = launch['registration']
    if (launch.get('original_init') is not constructor or launch.get('handle') is not handle
            or launch.get('child_argv') is not argv or launch.get('activation') is not activation
            or token not in activation.python_consumed or registration['class'] not in APPLICABLE
            or not same_options(options, launch['kwargs']) or options.get('cwd') is not None
            or not registration['python']):
        refuse('child_relative_launch_binding')
    if token in used:
        refuse('child_relative_reused_context')
    if any(options.get(key) is not None for key in
           ('preexec_fn', 'user', 'group', 'extra_groups', 'executable')) or options.get('shell'):
        refuse('child_relative_custom_options')
    used.add(token)
    return token, registration


def expected_runtime(runtime_pin):
    return {'platform': 'linux', 'version': VERSION, 'implementation': 'cpython',
            'uids': (20000, 20000, 20000), 'gids': (20000, 20000, 20000),
            'stdlib': STDLIB, 'native': NATIVE, 'library': LIBRARY, 'use_spawn': True, 'use_vfork': True,
            'runtime': runtime_pin}


def validate_runtime(actual, runtime_pin, refuse):
    if actual != expected_runtime(runtime_pin):
        refuse('child_relative_runtime')


def stock_matches(stock, code, defaults, keyword_defaults):
    return (type(stock) is types.FunctionType and stock.__globals__ is vars(subprocess)
            and stock.__code__ == code and stock.__closure__ is None
            and stock.__defaults__ == defaults and stock.__kwdefaults__ == keyword_defaults)

def admission_offsets(core):
    """Locate only the unchanged guard's original admission call instruction."""
    syntax = ast.parse(Path(core.co_filename).read_bytes())
    owners = [node for node in ast.walk(syntax) if isinstance(node, ast.FunctionDef)
              and node.name == 'initialize_inner']
    calls = [node.value for owner in owners for node in ast.walk(owner)
             if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Tuple)
             and [getattr(item, 'id', None) for item in node.targets[0].elts] == ['registration', 'argv']
             and isinstance(node.value, ast.Call)]
    expected = ast.parse('admit(args, kwargs.get("cwd"), kwargs.get("env"))', mode='eval').body
    if len(owners) != 1 or len(calls) != 1 or ast.dump(calls[0]) != ast.dump(expected):
        raise RuntimeError('child_relative_admission_source')
    call = calls[0]
    position = (call.lineno, call.end_lineno, call.col_offset, call.end_col_offset)
    instructions = [item for item in dis.get_instructions(core, show_caches=True)
                    if tuple(item.positions) == position and item.opname in {'CALL', 'CACHE'}]
    if len([item for item in instructions if item.opname == 'CALL']) != 1:
        raise RuntimeError('child_relative_admission_instruction')
    return frozenset(item.offset for item in instructions)


def install(state, activation, emit, refuse, checked):
    guard = sys.modules['runtime_guard']
    current = inspect.currentframe()
    caller = current.f_back if current else None
    origin = Path(state['guard']).with_name('source_integration_activation.py')
    if (caller is None or caller.f_code != named(compile(origin.read_bytes(), str(origin),
                                                        'exec', dont_inherit=True), 'create')
            or caller.f_globals.get('__file__') != str(origin)
            or caller.f_locals.get('state') is not state
            or caller.f_locals.get('activation') is not activation
            or guard.digest(origin) != state['direct_support']['files'][str(origin)]):
        refuse('child_relative_install_context')
    shared = activation.shared.__func__
    shared_code, shared_globals = shared.__code__, shared.__globals__
    if (shared_code != named(compile(origin.read_bytes(), str(origin), 'exec',
                                    dont_inherit=True), 'shared')
            or shared_globals is not caller.f_globals):
        refuse('child_relative_shared_callback')
    captured = subprocess.Popen.__init__
    support = state['operation_support']
    operations = state['operations']
    selected_source = Path(support['path'])
    if (support['path'] not in {'/guard/primary_operations.py', '/guard/primary_operation_journal.py'}
            or guard.digest(selected_source) != support['sha256']):
        refuse('child_relative_operation_selection')
    # The journal specialization inherits this exact constructor and native
    # route. Its selection does not make any new constructor acceptable.
    operations_source = Path('/guard/primary_operations.py')
    if guard.digest(operations_source) != '6b0c993facb604cbb0978e0bea20c14b02493654e07bb4331604ac536e8d26be':
        refuse('child_relative_operation_constructor_source')
    operations_code = compile(operations_source.read_bytes(), str(operations_source),
                              'exec', dont_inherit=True)
    namespace = operations.__init__.__globals__
    cells = dict(zip(captured.__code__.co_freevars, captured.__closure__ or ()))
    if (captured.__code__ != named(operations_code, 'native_init')
            or captured.__globals__ is not namespace
            or set(cells) != {'guard', 'initialize', 'native_init', 'original_init', 'require_ready', 'self', 'state'}
            or cells['guard'].cell_contents is not guard
            or cells['state'].cell_contents is not state
            or cells['self'].cell_contents is not operations
            or cells['native_init'].cell_contents is not captured):
        refuse('child_relative_existing_constructor')
    stock = cells['original_init'].cell_contents
    route = operations.native_executable.__func__
    if (route.__code__ != named(operations_code, 'native_executable')
            or route.__globals__ is not namespace):
        refuse('child_relative_native_route')
    captured_code = captured.__code__
    captured_cells = {key: cell.cell_contents for key, cell in cells.items()}
    source = Path(subprocess.__file__)
    stock_code = named(named(compile(source.read_bytes(), str(source), 'exec',
                                     dont_inherit=True), 'Popen'), '__init__')
    if (type(stock) is not types.FunctionType or stock.__globals__ is not vars(subprocess)
            or stock.__code__ != stock_code or stock.__closure__ is not None):
        refuse('child_relative_saved_constructor')
    syntax = ast.parse(source.read_bytes())
    cls = next(node for node in syntax.body if isinstance(node, ast.ClassDef) and node.name == 'Popen')
    initializer = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                       and node.name == '__init__')
    defaults = tuple(ast.literal_eval(node) for node in initializer.args.defaults)
    keyword_defaults = {argument.arg: ast.literal_eval(value) for argument, value in
                        zip(initializer.args.kwonlyargs, initializer.args.kw_defaults, strict=True)}
    if not stock_matches(stock, stock_code, defaults, keyword_defaults):
        refuse('child_relative_saved_constructor_defaults')
    execute = subprocess.Popen._execute_child
    # Both platform branches occur in the compiled class; only the actual
    # stock function's code can select the hosted POSIX implementation.
    class_code = named(compile(source.read_bytes(), str(source), 'exec',
                               dont_inherit=True), 'Popen')
    execute_codes = tuple(code for code in class_code.co_consts
                          if isinstance(code, types.CodeType) and code.co_name == '_execute_child')
    fork_exec = subprocess._fork_exec
    core = named(compile(Path(state['guard']).read_bytes(), state['guard'], 'exec',
                         dont_inherit=True), 'initialize_inner')
    admission = admission_offsets(core)
    observe = checked('child_relative_view.py')['view']
    used = set()
    contexts = {}

    def frame_check(frame):
        if (frame is None or frame.f_code != core
                or frame.f_code is not captured_cells['initialize']
                or frame.f_globals is not vars(guard)
                or frame.f_locals.get('state') is not state
                or guard._STATE is not state
                or guard.digest(state['guard']) != state['guard_sha256']):
            refuse('child_relative_core_frame')
        return frame.f_locals

    def capture():
        current = inspect.currentframe()
        caller = current.f_back if current else None
        if (caller is None or caller.f_code is not shared_code or caller.f_globals is not shared_globals
                or activation.shared.__func__ is not shared or shared.__code__ is not shared_code
                or shared.__globals__ is not shared_globals
                or caller.f_locals.get('self') is not activation):
            refuse('child_relative_capture_caller')
        frame = caller.f_back
        while frame is not None and frame.f_code is not captured_cells['initialize']:
            frame = frame.f_back
        if frame is None:
            return
        launch = frame_check(frame)
        if 'registration' not in launch:
            # Operations validate shared inputs while the original admit call
            # is still resolving. This phase cannot capture or consume custody.
            if (frame.f_lasti not in admission
                    or any(name in launch for name in ('argv', 'launch_token', 'child_argv', 'activation'))):
                refuse('child_relative_capture_phase')
            return
        registration = launch['registration']
        if not registration['python'] or launch['kwargs'].get('cwd') is not None:
            return
        token = launch['launch_token']
        if launch.get('activation') is not activation or token not in activation.python_consumed:
            refuse('child_relative_capture_context')
        if token in used:
            refuse('child_relative_reused_context')
        options = dict(launch['kwargs'])
        env = options.get('env')
        value = {'registration_id': id(registration),
                 'registration': json.dumps(registration, sort_keys=True),
                 'argv_id': id(launch['argv']), 'argv': list(launch['argv']),
                 'options': options, 'environment': None if env is None else dict(env),
                 'facts': None}
        try:
            value['facts'] = observe()
        except (OSError, RuntimeError, KeyError, ValueError):
            return
        existing = contexts.get(token)
        if existing is not None:
            if existing['handle']() is not launch['handle'] or existing['value'] != value:
                refuse('child_relative_capture_drift')
            return
        contexts[token] = {'handle': weakref.ref(launch['handle']), 'value': value}

    def constructor(handle, args, *positional, **kwargs):
        current = inspect.currentframe()
        frame = current.f_back if current else None
        launch = frame_check(frame)
        if (launch.get('original_init') is not constructor or launch.get('handle') is not handle
                or launch.get('child_argv') is not args or positional
                or guard._LOCAL.launch is not args):
            refuse('child_relative_constructor_context')
        token = launch['launch_token']
        registration = launch['registration']
        if (captured.__code__ is not captured_code or captured.__globals__ is not namespace
                or any(cells[key].cell_contents is not value for key, value in captured_cells.items())
                or operations.native_executable.__func__ is not route
                or route.__code__ != named(operations_code, 'native_executable')
                or route.__globals__ is not namespace or state['operations'] is not operations):
            refuse('child_relative_existing_constructor_drift')
        captured_cells['require_ready'](state['token'])
        selected = route(operations, registration, launch['argv'], kwargs.get('cwd'), kwargs.get('env'))
        if selected is not None:
            if registration['python']:
                refuse('child_relative_python_native_route')
            return stock(handle, args, **{**kwargs, 'executable': selected})
        if not registration['python']:
            native = checked('native_relative.py')
            if native['prepare'](launch, kwargs, state, observe, emit, refuse):
                if (hashlib.sha256(source.read_bytes()).hexdigest() != STDLIB
                        or not stock_matches(stock, stock_code, defaults, keyword_defaults)
                        or subprocess.Popen._execute_child is not execute
                        or execute.__code__ not in execute_codes
                        or execute.__globals__ is not vars(subprocess)
                        or subprocess._fork_exec is not fork_exec):
                    refuse('native_relative_stock_constructor_drift')
                # Relative chdir selects stock fork/exec without changing the
                # inherited directory or permitting the denied posix_spawn API.
                return stock(handle, args, **{**kwargs, 'cwd': '.'})
            return stock(handle, args, **kwargs)
        if kwargs.get('cwd') is not None:
            return stock(handle, args, **kwargs)
        token, registration = consume(launch, handle, args, kwargs, activation, constructor,
                                      used, refuse)
        if registration['class'] in {'source-approval-relay', 'source-approval-python-backend'}:
            approval = checked('approval_routes.py')
            owned_cwd = checked('approval_owned_cwd.py')
            try:
                owned = owned_cwd['prepare'](launch, kwargs, state, approval['selected_mode'](state.get('case')), emit)
            except (OSError, RuntimeError, KeyError, ValueError, TypeError):
                refuse('approval_owned_cwd_constructor_binding')
                raise RuntimeError('refusal callback returned')
            if owned:
                try:
                    if (hashlib.sha256(source.read_bytes()).hexdigest() != STDLIB
                            or not stock_matches(stock, stock_code, defaults, keyword_defaults)
                            or subprocess.Popen._execute_child is not execute
                            or execute.__code__ not in execute_codes
                            or execute.__globals__ is not vars(subprocess)
                            or subprocess._fork_exec is not fork_exec):
                        refuse('approval_owned_cwd_stock_constructor_drift')
                    return stock(handle, args, **{**kwargs, 'cwd': '.'})
                except BaseException as error:
                    trace, frames = error.__traceback__, []
                    while trace is not None and len(frames) < 8:
                        frames.append({'file_sha256': hashlib.sha256(trace.tb_frame.f_code.co_filename.encode()).hexdigest(),
                                       'line': trace.tb_lineno})
                        trace = trace.tb_next
                    name = type(error).__name__
                    number = getattr(error, 'errno', None)
                    emit({'kind': 'approval_owned_cwd_constructor_error', 'token': token,
                          'class': registration['class'], 'frames': frames,
                          'error_class': name if name in {'OSError', 'PermissionError', 'FileNotFoundError',
                              'TypeError', 'ValueError', 'RuntimeError', 'AssertionError', 'GuardRefusal', 'KeyError'} else 'other',
                          'errno': number if type(number) is int and -4095 <= number <= 4095 else None})
                    raise
        saved = contexts.pop(token, None)
        if saved is None:
            refuse('child_relative_missing_context')
        value = saved['value']
        if not matches_saved(saved, launch, handle, kwargs):
            refuse('child_relative_saved_context_drift')
        try:
            facts = observe()
        except (OSError, RuntimeError, KeyError, ValueError):
            refuse('child_relative_source_context')
            raise RuntimeError('refusal callback returned')
        import _posixsubprocess
        actual_runtime = {
            'platform': sys.platform, 'version': sys.version, 'implementation': sys.implementation.name,
            'uids': os.getresuid(), 'gids': os.getresgid(),
            'stdlib': hashlib.sha256(source.read_bytes()).hexdigest(),
            'native': hashlib.sha256(Path(_posixsubprocess.__file__).read_bytes()).hexdigest(),
            'library': hashlib.sha256(Path('/usr/local/lib/libpython3.13.so.1.0').read_bytes()).hexdigest(),
            'use_spawn': subprocess._USE_POSIX_SPAWN, 'use_vfork': subprocess._USE_VFORK,
            'runtime': guard.digest(state['runtime']['realpath'])}
        validate_runtime(actual_runtime, state['runtime']['sha256'], refuse)
        if (not stock_matches(stock, stock_code, defaults, keyword_defaults)
                or subprocess.Popen._execute_child is not execute or execute.__code__ not in execute_codes
                or execute.__globals__ is not vars(subprocess) or subprocess._fork_exec is not fork_exec
                or _posixsubprocess.fork_exec is not fork_exec):
            refuse('child_relative_runtime')
        if facts != value['facts'] or observe() != facts:
            refuse('child_relative_parent_cwd_drift')
        emit({'kind': 'child_relative_constructor', 'token': token,
              'class': registration['class'], 'original_cwd': None, 'constructor_cwd': '.',
              'parent_view': facts, 'argv_sha256': hashlib.sha256(json.dumps(args).encode()).hexdigest(),
              'stock_stdlib_sha256': STDLIB, 'stock_native_sha256': NATIVE,
              'stock_library_sha256': LIBRARY, 'runtime': actual_runtime})
        # No catch/retry: stock chdir and constructor errors retain their errno.
        return stock(handle, args, **{**kwargs, 'cwd': '.'})

    subprocess.Popen.__init__ = constructor
    return capture
