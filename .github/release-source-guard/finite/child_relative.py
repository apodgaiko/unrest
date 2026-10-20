"""Single-use Method C context after existing finite SOURCE admission."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import types

STDLIB = 'e4049ed91ed101b09b0dc96bbf234f646c1728090d643a474b024276cc2a028c'
NATIVE = '925e5f643c0c5f9d5e897d6faca9af7d9f7dbe624b7d31cab4d97dde15a748af'
APPLICABLE = frozenset({
    'canonical-backend',
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
    'source-cohort2:tests/test_acp_runner.py:1079',
    'source-cohort2:tests/test_acp_runner.py:1380',
    'source-cohort2:tests/test_acp_runner.py:1840',
    'source-cohort2:tests/test_acp_runner.py:214',
    'source-cohort2:tests/test_acp_runner.py:2206',
    'source-cohort2:tests/test_acp_runner.py:2265',
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



def consume(launch, handle, argv, options, activation, constructor, used, refuse):
    """Validate data from the caller-authenticated core frame; grants no launch."""
    token = launch['launch_token']
    registration = launch['registration']
    if (launch.get('original_init') is not constructor or launch.get('handle') is not handle
            or launch.get('child_argv') is not argv or launch.get('activation') is not activation
            or token not in activation.python_consumed or registration['class'] not in APPLICABLE
            or options != launch['kwargs'] or options.get('cwd') is not None
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
            'stdlib': STDLIB, 'native': NATIVE, 'use_spawn': True, 'use_vfork': True,
            'runtime': runtime_pin}


def validate_runtime(actual, runtime_pin, refuse):
    if actual != expected_runtime(runtime_pin):
        refuse('child_relative_runtime')

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
    captured = subprocess.Popen.__init__
    support = state['operation_support']
    operations = state['operations']
    operations_source = Path(support['path'])
    operations_code = compile(operations_source.read_bytes(), str(operations_source),
                              'exec', dont_inherit=True)
    namespace = operations.__init__.__globals__
    cells = dict(zip(captured.__code__.co_freevars, captured.__closure__ or ()))
    if (support['path'] != '/guard/primary_operations.py'
            or guard.digest(operations_source) != support['sha256']
            or captured.__code__ != named(operations_code, 'native_init')
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
    defaults = stock.__defaults__
    keyword_defaults = dict(stock.__kwdefaults__) if stock.__kwdefaults__ is not None else None
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
    observe = checked('child_relative_view.py')['view']
    used = set()

    def frame_check(frame):
        if (frame is None or frame.f_code != core or frame.f_globals is not vars(guard)
                or frame.f_locals.get('state') is not state
                or guard._STATE is not state
                or guard.digest(state['guard']) != state['guard_sha256']):
            refuse('child_relative_core_frame')
        return frame.f_locals

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
        if not registration['python'] or kwargs.get('cwd') is not None:
            return stock(handle, args, **kwargs)
        token, registration = consume(launch, handle, args, kwargs, activation, constructor,
                                      used, refuse)
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
            'use_spawn': subprocess._USE_POSIX_SPAWN, 'use_vfork': subprocess._USE_VFORK,
            'runtime': guard.digest(state['runtime']['realpath'])}
        validate_runtime(actual_runtime, state['runtime']['sha256'], refuse)
        if (stock.__code__ != stock_code or stock.__globals__ is not vars(subprocess)
                or stock.__defaults__ != defaults or stock.__kwdefaults__ != keyword_defaults
                or subprocess.Popen._execute_child is not execute or execute.__code__ not in execute_codes
                or execute.__globals__ is not vars(subprocess) or subprocess._fork_exec is not fork_exec
                or _posixsubprocess.fork_exec is not fork_exec):
            refuse('child_relative_runtime')
        if observe() != facts:
            refuse('child_relative_parent_cwd_drift')
        emit({'kind': 'child_relative_constructor', 'token': token,
              'class': registration['class'], 'original_cwd': None, 'constructor_cwd': '.',
              'parent_view': facts, 'argv_sha256': hashlib.sha256(json.dumps(args).encode()).hexdigest(),
              'stock_stdlib_sha256': STDLIB, 'stock_native_sha256': NATIVE})
        # No catch/retry: stock chdir and constructor errors retain their errno.
        return stock(handle, args, **{**kwargs, 'cwd': '.'})

    subprocess.Popen.__init__ = constructor
    return constructor
