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
APPLICABLE = frozenset(['canonical-backend', 'composed-http-role:orchestrator', 'composed-http-role:terminal-reviewer', 'composed-http-role:validator', 'composed-http-role:worker', 'controlled-acp', 'executor-fixture-descendant', 'inline:test_acp_cleanup.py:50', 'inline:test_acp_cleanup.py:51', 'inline:test_acp_runner.py:63', 'inline:test_acp_runner.py:67', 'inline:test_acp_runner.py:69', 'inline:test_experimental_session.py:342', 'inline:test_experimental_session.py:377', 'inline:test_experimental_session.py:489', 'isolated-role-startup', 'nested-pytest-module', 'ordinary-session-fixture', 'original-cli-import:_import_probe', 'original-cli-import:test_mcp_help_does_not_import_repository_modules', 'original-inline:tests/test_repository_contract.py:519', 'original-inline:tests/test_repository_contract.py:568', 'original-inline:tests/test_runtime_observability.py:505', 'original-inline:tests/test_server.py:4962', 'original-inline:tests/test_server.py:719', 'public-cli-module', 'reference-descendant:console-help', 'reference-descendant:mcp-import', 'reference-descendant:ordinary-mock-acp', 'reference-descendant:repository-cli:--help', 'reference-descendant:repository-cli:check-repository', 'reference-descendant:repository-cli:init:--help', 'reference-descendant:repository-cli:list-projects', 'reference-descendant:status-cli:--help', 'reference-descendant:status-cli:list-projects', 'reference-descendant:status-cli:observe-project:--help', 'reference-descendant:stderr-redaction', 'reference-descendant:terminal-redaction', 'server-module-help', 'simulated-flow-helper', 'source-approval-adapter', 'source-approval-mcp', 'source-approval-python-backend', 'source-approval-relay', 'source-benchmark-five-run', 'source-checker-empty-archive-control', 'source-child-relative-probe', 'source-cleanup-adapter', 'source-cohort2:mock-agent', 'source-cohort2:ownership-stdio', 'source-cohort2:src/unrest_harness/server.py:266', 'source-cohort2:tests/test_acp_runner.py:1079', 'source-cohort2:tests/test_acp_runner.py:1380', 'source-cohort2:tests/test_acp_runner.py:1840', 'source-cohort2:tests/test_acp_runner.py:214', 'source-cohort2:tests/test_acp_runner.py:2206', 'source-cohort2:tests/test_acp_runner.py:2265', 'source-cohort2:tests/test_acp_runner.py:413', 'source-cohort2:tests/test_acp_runner.py:465', 'source-cohort2:tests/test_acp_runner.py:544', 'source-cohort2:tests/test_acp_runner.py:632', 'source-cohort2:tests/test_acp_runner.py:70', 'source-cohort2:tests/test_completion_ownership.py:108', 'source-cohort2:tests/test_completion_ownership.py:134', 'source-cohort2:tests/test_completion_ownership.py:135', 'source-cohort2:tests/test_completion_ownership.py:33', 'source-cohort2:tests/test_completion_ownership.py:34', 'source-cohort2:tests/test_completion_ownership.py:99', 'source-cohort2:tests/test_completion_setup.py:131', 'source-cohort2:tests/test_completion_setup.py:132', 'source-cohort2:tests/test_coordinator.py:1046', 'source-cohort2:tests/test_coordinator.py:1047', 'source-cohort2:tests/test_coordinator.py:1448', 'source-cohort2:tests/test_coordinator.py:214', 'source-cohort2:tests/test_experimental_session.py:347', 'source-cohort2:tests/test_experimental_session.py:381', 'source-cohort2:tests/test_experimental_session.py:490', 'source-cohort2:tests/test_lean_provider_security_runtime.py:388', 'source-cohort3:mock-agent', 'source-cohort3:src/unrest_harness/server.py:266', 'source-cohort3:tests/test_provider_review.py:55', 'source-cohort3:tests/test_provider_review_frames.py:69', 'source-cohort3:tests/test_provider_review_frames.py:70', 'source-cohort3:tests/test_release_binding.py:119', 'source-cohort3:tests/test_release_binding.py:130', 'source-cohort3:tests/test_release_binding.py:144', 'source-cohort3:tests/test_repository_contract.py:67', 'source-cohort3:tests/test_repository_contract.py:70', 'source-cohort3:tests/test_repository_contract.py:82', 'source-cohort3:tests/test_repository_contract.py:87', 'source-cohort3:tests/test_runtime_observability.py:527', 'source-cohort3:tests/test_server.py:110', 'source-cohort3:tests/test_server.py:1208', 'source-cohort3:tests/test_server.py:1745', 'source-cohort3:tests/test_server.py:1746', 'source-cohort3:tests/test_server.py:1847', 'source-cohort3:tests/test_server.py:1848', 'source-cohort3:tests/test_server.py:1968', 'source-cohort3:tests/test_server.py:1969', 'source-cohort3:tests/test_server.py:2144', 'source-cohort3:tests/test_server.py:2145', 'source-cohort3:tests/test_server.py:2335', 'source-cohort3:tests/test_server.py:2336', 'source-cohort3:tests/test_server.py:2337', 'source-cohort3:tests/test_server.py:2373', 'source-cohort3:tests/test_server.py:2465', 'source-cohort3:tests/test_server.py:2466', 'source-cohort3:tests/test_server.py:3284', 'source-cohort3:tests/test_server.py:3565', 'source-cohort3:tests/test_server.py:3566', 'source-cohort3:tests/test_server.py:3786', 'source-cohort3:tests/test_server.py:3787', 'source-cohort3:tests/test_server.py:4285', 'source-cohort3:tests/test_server.py:4286', 'source-cohort3:tests/test_server.py:4554', 'source-cohort3:tests/test_server.py:4555', 'source-cohort3:tests/test_server.py:4820', 'source-cohort3:tests/test_server.py:4821', 'source-cohort3:tests/test_server.py:4937', 'source-cohort3:tests/test_server.py:4938', 'source-cohort3:tests/test_server.py:5041', 'source-cohort3:tests/test_server.py:5042', 'source-cohort3:tests/test_server.py:5403', 'source-cohort3:tests/test_server.py:5404', 'source-cohort3:tests/test_server.py:5436', 'source-cohort3:tests/test_server.py:5437', 'source-cohort3:tests/test_server.py:5465', 'source-cohort3:tests/test_server.py:5466', 'source-cohort3:tools/release_binding.py:36', 'source-cohort4:desktop-stdio', 'source-cohort4:tests/test_stranded_recovery.py:416', 'source-cohort4:tests/test_v021_release_records.py:31', 'source-cohort4:tests/test_v021_release_records.py:45', 'source-cohort4:tests/test_v045_release_records.py:130', 'source-cohort4:tests/test_v045_release_records.py:172', 'source-cohort4:tests/test_v045_release_records.py:186', 'source-cohort4:tests/test_v046_measurement_helpers.py:106', 'source-cohort4:tools/release_binding.py:36', 'source-cohort4:tools/release_binding.py:57', 'source-completion-helper:test_consumed_marker_survives_recovery_interruption', 'source-completion-helper:test_process_dies_during_first_setup', 'source-completion-helper:test_real_roles_first_use', 'source-composed-adapter', 'source-console-server-help', 'source-copied-repository-cli', 'source-crash-controller', 'source-execution-owner-leaf', 'source-execution-owner-probe', 'source-foreign-journal-owner', 'source-isolated-precaptured-refusal', 'source-lease-owned-child', 'source-measurement-fixture', 'source-owned-role:terminal-reviewer', 'source-owned-role:validator', 'source-owned-role:worker', 'source-project-projection', 'source-recovery-cli', 'source-recovery-role', 'source-registered-workspace-cli', 'source-run-worker', 'source-seeded-environment-helper', 'source-session-child', 'source-session-helper:timeout', 'source-speed-nested-exact', 'source-storage-fresh-reader', 'source-workspace-owned-sleep'])
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


def install(state, activation, emit, refuse, checked):
    guard = sys.modules['runtime_guard']
    stock = subprocess.Popen.__init__
    source = Path(subprocess.__file__)
    stock_code = named(named(compile(source.read_bytes(), str(source), 'exec',
                                     dont_inherit=True), 'Popen'), '__init__')
    if (type(stock) is not types.FunctionType or stock.__globals__ is not vars(subprocess)
            or stock.__code__ != stock_code or stock.__closure__ is not None):
        refuse('child_relative_saved_constructor')
    defaults, keyword_defaults = stock.__defaults__, stock.__kwdefaults__
    execute = subprocess.Popen._execute_child
    execute_code = named(named(compile(source.read_bytes(), str(source), 'exec',
                                       dont_inherit=True), 'Popen'), '_execute_child')
    fork_exec = subprocess._fork_exec
    core = named(compile(Path(state['guard']).read_bytes(), state['guard'], 'exec',
                         dont_inherit=True), 'initialize_inner')
    observe = checked('child_relative_view.py')['view']
    pending = {}
    used = set()

    def frame_check(frame):
        if (frame is None or frame.f_code != core or frame.f_globals is not vars(guard)
                or frame.f_locals.get('state') is not state
                or guard._STATE is not state
                or guard.digest(state['guard']) != state['guard_sha256']):
            refuse('child_relative_core_frame')
        return frame.f_locals

    def arm(argv, cwd, environment, registration):
        current = inspect.currentframe()
        frame = (current.f_back.f_back.f_back
                 if current and current.f_back and current.f_back.f_back else None)
        launch = frame_check(frame)
        if (launch.get('activation') is not activation
                or launch.get('registration') is not registration
                or launch.get('argv') is not argv or launch['kwargs'].get('cwd') != cwd
                or launch['kwargs'].get('env') is not environment):
            refuse('child_relative_activation_context')
        if cwd is not None:
            return
        token = launch['launch_token']
        if token not in activation.python_consumed or token in pending or token in used:
            refuse('child_relative_reused_context')
        # Prior activation completed the existing registry/resolver checks. A cwd
        # match alone cannot create a registration or bypass their owner binding.
        if not registration['python'] or registration['class'] not in APPLICABLE:
            refuse('child_relative_nonpython_context')
        try:
            facts = observe()
        except (OSError, RuntimeError, KeyError, ValueError):
            # Preserve stock behavior outside the immutable source namespace.
            return
        pending[token] = (launch['handle'], registration, argv,
                          dict(launch['kwargs']), facts)

    def constructor(handle, args, *positional, **kwargs):
        current = inspect.currentframe()
        frame = current.f_back if current else None
        launch = frame_check(frame)
        if (launch.get('original_init') is not constructor or launch.get('handle') is not handle
                or launch.get('child_argv') is not args or positional
                or guard._LOCAL.launch is not args):
            refuse('child_relative_constructor_context')
        token = launch['launch_token']
        context = pending.pop(token, None)
        if context is None:
            if token in used:
                refuse('child_relative_reused_context')
            return stock(handle, args, **kwargs)
        used.add(token)
        saved_handle, registration, argv, options, facts = context
        if (handle is not saved_handle or registration is not launch['registration']
                or argv is not launch['argv'] or options != kwargs
                or kwargs.get('cwd') is not None or not registration['python']
                or launch.get('activation') is not activation):
            refuse('child_relative_launch_binding')
        if any(kwargs.get(key) is not None for key in
               ('preexec_fn', 'user', 'group', 'extra_groups', 'executable')) or kwargs.get('shell'):
            refuse('child_relative_custom_options')
        import _posixsubprocess
        if (sys.platform != 'linux' or sys.version != VERSION or sys.implementation.name != 'cpython'
                or os.getresuid() != (20000, 20000, 20000)
                or os.getresgid() != (20000, 20000, 20000)
                or hashlib.sha256(source.read_bytes()).hexdigest() != STDLIB
                or hashlib.sha256(Path(_posixsubprocess.__file__).read_bytes()).hexdigest() != NATIVE
                or not subprocess._USE_POSIX_SPAWN or not subprocess._USE_VFORK
                or stock.__code__ != stock_code or stock.__globals__ is not vars(subprocess)
                or stock.__defaults__ != defaults or stock.__kwdefaults__ != keyword_defaults
                or subprocess.Popen._execute_child is not execute or execute.__code__ != execute_code
                or execute.__globals__ is not vars(subprocess) or subprocess._fork_exec is not fork_exec
                or _posixsubprocess.fork_exec is not fork_exec
                or guard.digest(state['runtime']['realpath']) != state['runtime']['sha256']):
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
    return arm
