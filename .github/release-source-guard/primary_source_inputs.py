"""Closed SOURCE activation input; TEST probes never carry release authority."""
from __future__ import annotations

import hashlib
import json
import re
import shlex

from primary_policy import (SHELL, SHELL_FLAGS, SOURCE_BUDGET, TEST_SELECTIONS, TEST_SEAM_CASES, TEST_SEAM_ROOT_SECONDS, canonical, sha)


def require_full_input(value, script, workflow):
    from checkpoint_receipt import DEFINITION_FIELDS
    if (type(value) is not dict or set(value) != {
            'schema', 'definition', 'source_carrier_sha256', 'package_closure_sha256',
            'final_closure_sha256', 'source_checkpoint_ready', 'selected_carrier'}
            or value['schema'] != 'unrest.v046.primary-source-input.v1'
            or value['source_checkpoint_ready'] is not True
            or value['selected_carrier'] != value['source_carrier_sha256']):
        raise RuntimeError('primary_source_readiness_closure_missing')
    definition = value['definition']
    if (type(definition) is not dict or set(definition) != set(DEFINITION_FIELDS)
            or definition['workflow_sha256'] != sha(workflow.encode())
            or definition['source_command_sha256'] != sha(script.rstrip(b'\n'))
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key])
                   for key in ('source_carrier_sha256', 'package_closure_sha256', 'final_closure_sha256'))
            or any(type(pin) is not str or not re.fullmatch(
                '[0-9a-f]{40}' if key in {'head_sha', 'source_tree'} else '[0-9a-f]{64}', pin)
                for key, pin in definition.items())):
        raise RuntimeError('primary_source_readiness_binding')


def test_plan(script, workflow, mode):
    if mode not in {'TEST-positive', 'TEST-poison'}:
        raise RuntimeError('primary_source_test_identity')
    allowed = [('env -u CODEX_PATH uv run pytest -q ' + ' '.join(cases)).encode()
               for cases in TEST_SELECTIONS]
    if script not in allowed:
        raise RuntimeError('primary_source_test_script')
    seam_script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(TEST_SEAM_CASES)).encode()
    return {'schema': 'unrest.v046.primary-script-plan.v1',
            'duty': 'TEST-source-' + mode.removeprefix('TEST-'),
            'script_sha256': sha(script), 'workflow_sha256': sha(workflow.encode()),
            'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
            'commands': [shlex.split(script.decode())], 'source_checkpoint_ready': False,
            'selected_carrier': None, 'timeout_seconds': (TEST_SEAM_ROOT_SECONDS if script == seam_script else 180),
            'source_mode': mode, 'source_budget': SOURCE_BUDGET,
            'source_input_sha256': hashlib.sha256(canonical({'mode': mode})).hexdigest()}


def decode(body):
    value = json.loads(body)
    if canonical(value) != body:
        raise RuntimeError('primary_source_input_serialization')
    return value


def python_flags(vector, environment):
    flags = vector[1:vector.index('-c')]
    if any(flag not in {'-I', '-S', '-B', '-u'} for flag in flags):
        raise RuntimeError('source_python_flags')
    return [int('-I' in flags), int('-S' in flags),
            int('-B' in flags or ('-I' not in flags and bool(environment.get('PYTHONDONTWRITEBYTECODE'))))]


def python_environment(environment, registration, flags, *, lease_context=None):
    """Post-init locale bytes for exact source fixture registrations.

    Exec still consumes the exact original environment. The pinned CPython
    image coerces its absent C locale before exposing os.environ. Exec and
    post-init environments remain independently exact; this grants no launch.
    """
    if registration['class'] == 'source-lease-owned-child' and lease_context is None:
        lease_context = lease_profile_context(environment, registration, flags)
    controlled = {
        'canonical-backend': ('/source/tests/fixtures/experimental_session_app_server.py',
                              'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'),
        'controlled-acp': ('/source/tests/fixtures/controlled_python_acp.py',
                           'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'),
    }.get(registration['class'])
    binding = registration['source_binding']
    exact_controlled = (controlled is not None and flags == [0, 0, 0]
                        and binding == {'path': controlled[0], 'line': 1, 'sha256': controlled[1]})
    # This already-admitted literal prints a synthetic credential locally.
    # Stock CPython coerces its two-key environment before the Python audit
    # boundary. Keep exec bytes exact and describe only that post-init state.
    exact_terminal = (flags == [0, 0, 0] and registration == {
        'class': 'reference-descendant:terminal-redaction', 'python': True,
        'argv': ['-c', "import os; print(os.environ['ZAI_API_KEY'])"],
        'checkout_cwd': True, 'caller_bindings': [],
        'source_binding': {'path': '/source/tests/test_capability_policy.py', 'line': 549,
                           'sha256': 'ed83ec28c4830354cd4ab0876d6832a0187d211982964d2cf80f449992b46bb6'},
    } and set(environment) == {'PATH', 'ZAI_API_KEY'}
        and isinstance(environment['PATH'], str) and bool(environment['PATH'])
        and isinstance(environment['ZAI_API_KEY'], str)
        and sha(environment['ZAI_API_KEY'].encode()) == 'cff06f8f3a6f4faf5b5da8f3500efc21bdf18e2522e178b8a43f27739ba5d45a')
    isolated = (registration['class'] == 'isolated-role-startup'
                and binding['path'] == '/source/tests/test_stdio_startup.py' and flags[0] == 1)
    if ((isolated or exact_controlled or exact_terminal or exact_lease_environment(
            environment, registration, flags, lease_context))
            and not any(key in environment for key in ('LC_CTYPE', 'LC_ALL', 'LANG'))):
        return {**environment, 'LC_CTYPE': 'C.UTF-8'}
    return dict(environment)


def exact_lease_environment(environment, registration, flags, context):
    """Join the admitted factory to its token-bound pre-exec consumption.

    This maps only the two original empty-env literals. The kernel authority
    already consumed the exact transformed argv, runtime and source binding;
    the join below also requires the immutable original owner/parameter/vector.
    """
    if (registration['class'] != 'source-lease-owned-child' or context is None
            or environment != {} or flags != [0, 0, 0]):
        return False
    from primary_policy import PYTHON
    from pathlib import PurePosixPath
    binding = {'path': '/source/src/unrest_harness/experimental_confinement.py',
               'line': 69, 'sha256': '25f3e7184ff560cb58067d211aba24c5ca18af50ff04f93c3fd3007796c3dc08'}
    legacy_binding = {'path': '/source/tests/test_experimental_lease.py', 'line': 218,
                      'sha256': '01461f79560224089da8c906362bfc9606b3a3c620760c29def6c10f8dbe1d5f'}
    if registration['source_binding'] not in (binding, legacy_binding):
        return False
    selected, manifest = context['selected'], context['manifest']
    runtime = manifest['runtime']
    vector = context['vector']
    if (manifest['checkout'] != '/source' or manifest['owned_root'] != '/work/owned'
            or runtime['realpath'] != PYTHON or len(vector) != 3 or vector[1] != '-c'
            or vector[0] not in runtime['paths'] or context['cwd'] != selected['cwd']
            or selected['registration'] != registration
            or selected['owner_pid'] != context['parent']
            or selected['transformed_argv_sha256'] != sha(json.dumps(vector).encode())
            or selected['bootstrap_sha256'] != sha(vector[2].encode())
            or selected['environment_sha256'] != sha(json.dumps({}, sort_keys=True).encode())):
        return False
    rows = [row for row in context['events']
            if row['kind'] == 'source_lease_startup_consumption'
            and row['owner_pid'] == context['parent']
            and row['launch_token'] == selected['token']]
    if len(rows) != 1:
        return False
    row = rows[0]
    factory = row['factory']
    mode = factory['mode']
    if mode not in {'ignore', 'cleanup', 'spawn', 'registration'}:
        return False
    literal = {'ignore': 218, 'cleanup': 399, 'spawn': 559, 'registration': 559}[mode]
    case = ('tests/test_experimental_lease.py::test_owned_ignoring_child_and_unknown_quarantine'
            if mode == 'ignore' else
            'tests/test_experimental_lease.py::test_cleanup_failure_revokes_and_quarantines'
            if mode == 'cleanup' else
            'tests/test_experimental_lease.py::test_close_waits_for_launch_registration[' + mode + ']')
    if factory['controlled_guard_method'] is True:
        case = ('.github/release-source-guard/multiprocess_guard_methods.py::'
                'test_owned_exit17_keeps_raw_status')
    elif factory['controlled_guard_method'] is not False:
        return False
    expected_factory = {'mode': mode, 'literal_line': literal, 'case': case,
                        'controlled_guard_method': factory['controlled_guard_method'],
                        'owner_source_sha256': '01461f79560224089da8c906362bfc9606b3a3c620760c29def6c10f8dbe1d5f'}
    original = [vector[0], '-c',
                'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(30)'
                if mode == 'ignore' else 'import time;time.sleep(30)' if mode == 'cleanup'
                else 'import time;print("ready",flush=True);time.sleep(30)']
    directory = PurePosixPath(context['cwd'])
    actual_binding = registration['source_binding']
    if actual_binding == legacy_binding and (mode != 'ignore' or factory['controlled_guard_method']):
        return False
    return (row['source_binding'] == actual_binding and factory == expected_factory
            and registration['argv_sha256'] == sha(json.dumps(original).encode())
            and row['argv'] == original and row['environment'] == {}
            and row['cwd'] == str(directory) == context['cwd']
            and directory.is_relative_to('/work/owned') and directory != PurePosixPath('/work/owned')
            and '..' not in directory.parts
            and manifest['product_pins']['tests/test_experimental_lease.py'] == factory['owner_source_sha256']
            and manifest['product_pins']['src/unrest_harness/experimental_confinement.py'] == binding['sha256'])


def lease_profile_context(environment, registration, flags):
    """Read only the unchanged original profile producer's live bound frame."""
    import inspect
    from pathlib import Path
    import sys
    import types
    frame = inspect.currentframe()
    try:
        caller = frame.f_back.f_back if frame is not None and frame.f_back else None
        module = sys.modules.get('primary_authority')
        source = Path('/guard/primary_authority.py')
        if (caller is None or module is None or caller.f_globals is not vars(module)
                or caller.f_code is not module.Authority.profile.__code__
                or caller.f_code.co_filename != str(source)
                or sha(source.read_bytes()) != '8660867109287601279c2014157ce3cd704d9e0afb96334a188447a892c87f4c'):
            return None
        original = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True)
        cls = next(value for value in original.co_consts
                   if isinstance(value, types.CodeType) and value.co_name == 'Authority')
        expected = next(value for value in cls.co_consts
                        if isinstance(value, types.CodeType) and value.co_name == 'profile')
        local = caller.f_locals
        owner = local.get('self')
        if (caller.f_code != expected or type(owner) is not module.Authority
                or local.get('role') != 'source-bootstrap'
                or local.get('environment') is not environment or local.get('flags') is not flags
                or owner.source.bound[local['pid']]['registration'] is not registration):
            return None
        return {'selected': owner.source.bound[local['pid']],
                'events': owner.source.supervisor.events(), 'manifest': owner.source.manifest,
                'vector': local['vector'], 'cwd': local['cwd'], 'parent': local['parent']}
    finally:
        del frame
