"""Closed original provider-session fixtures; no provider executable admission."""
from __future__ import annotations

import hashlib
from pathlib import Path

from content_manifest import Refused
from launch_policy import build_expected

TEST = 'tests/test_provider_sessions.py'
PRODUCT = 'src/unrest_harness/provider_sessions.py'
SCRIPT = 'tests/mock_provider_session_acp.py'
ROLES = ('inquiry_branch', 'inquiry_synthesis', 'candidate_author', 'independent_evaluator', 'independent_reviewer')


def node(name):
    return TEST + '::test_' + name


PLAN = tuple(node('every_session_role_preflights_and_spawns_one_identical_plan[' + role + ']') for role in ROLES)
ARGS = {
    node('clean_exit_zero_without_response_is_failed_unknown_work'): ('-c', 'pass'),
    node('success_keeps_content_private_redacted_and_mode_0600'): ('--echo-credential', 'ANTHROPIC_API_KEY'),
    node('provider_session_parses_final_acp_message_after_progress'): ('--progress',),
    node('raw_response_limit_survives_credential_redaction'): ('--oversize-credential',),
    node('invalid_or_oversize_output_fails_closed[--invalid-1024-invalid_structured_output]'): ('--invalid',),
    node('invalid_or_oversize_output_fails_closed[--payload-size 4096-128-output_limit_exceeded]'): ('--payload-size', '4096'),
    node('cancel_event_returns_typed_result_and_stops_adapter'): ('--sleep', '30'),
    node('timeout_kills_adapter_process_group'): ('--sleep', '30'),
    node('unknown_stop_reason_and_stderr_are_private_and_bounded'): ('--stderr-size', '100000', '--stop-reason', 'provider-private-detail'),
}
INVALID = tuple(node('every_role_maps_each_launch_category_with_private_safe_diagnostic[startup_failed-' + role + ']') for role in ROLES)
INVALID_BYTES = b'invalid executable format\n'
LIVE = (*PLAN, *INVALID, *ARGS)
TIMEOUT = node('timeout_kills_adapter_process_group')
CASES = (*PLAN,
    *(node('every_session_role_maps_preflight_rejection_without_spawn[' + role + ']') for role in ROLES),
    *(node('every_role_maps_each_launch_category_with_private_safe_diagnostic[' + category + '-' + role + ']')
      for category in ('invalid_command', 'missing', 'directory', 'not_executable', 'startup_failed') for role in ROLES),
    *(node('explicit_empty_command_is_invalid_without_fallback[' + role + ']') for role in ROLES),
    node('clean_exit_zero_without_response_is_failed_unknown_work'), node('response_limit_has_a_non_bypassable_65536_byte_ceiling'),
    *(node('structured_session_roles_are_read_only_even_in_unsafe_profile[' + role + '-' + profile + ']')
      for role in ROLES for profile in ('safe', 'unsafe-development-unrestricted')),
    node('role_provider_mapping_preserves_separate_authorities'),
    *(node('every_session_role_has_a_bundled_structured_prompt[' + role + ']') for role in ROLES),
    *tuple(ARGS)[1:3], node('acp_message_ids_select_final_json_without_hiding_prior_bytes'), tuple(ARGS)[3],
    node('acp_final_message_still_requires_whole_json_and_complete_ids'), *tuple(ARGS)[4:],
    node('private_artifact_cannot_escape_caller_root'))
GROUPS = (CASES, (TIMEOUT,))
PINS = {'tests/test_provider_sessions.py': 'a6f8e62dd6ed4dce983bcc11f4ed5d600e92c36f5f1500be1fbae4317fe9145e', 'src/unrest_harness/provider_sessions.py': '7ecb0826e0c6a6b322f08209676d0b8e673688b64dd4c2aa3aad212ddc7cd7cc', 'tests/mock_provider_session_acp.py': 'cf4070d08c7d60b028f56c87bdcf4271238f0275212d6a13b681664738eb3fdd', 'src/unrest_harness/acp_runner.py': '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'}


def expected(case, cwd, checkout, owned, native, pin, root_environment, *, child=False):
    if type(case) is not str or case not in LIVE or type(cwd) is not str:
        raise Refused('session closed original launch case')
    workspace = Path(cwd)
    if (not workspace.is_absolute() or workspace.resolve() != workspace or workspace.name != 'workspace'
            or workspace.parent.parent != owned / 'pytest'):
        raise Refused('session owned workspace')
    base = workspace.parent
    if type(child) is not bool or child and case != TIMEOUT:
        raise Refused('session closed descendant case')
    args = () if case in (*PLAN, *INVALID) else ARGS[case]
    if child:
        args = ('--child', str(base / 'child.stopped'))
    elif case == TIMEOUT:
        args = (*args, '--child-pid-path', str(base / 'child.pid'), '--child-stop-path', str(base / 'child.stopped'))
    environment = {key: root_environment[key] for key in ('HOME', 'TMPDIR', 'PATH')}
    if case == node('success_keeps_content_private_redacted_and_mode_0600'):
        environment['ANTHROPIC_API_KEY'] = 'provider-session-secret-7f21d9'
    elif case == node('raw_response_limit_survives_credential_redaction'):
        environment['ANTHROPIC_API_KEY'] = 's' * 100
    inline = args == ('-c', 'pass')
    argv = (native, *args) if inline else (native, str(checkout / SCRIPT), *args)
    invalid = case in INVALID
    if invalid:
        argv, pin = (str(base / 'private-canary-startup_failed'),), hashlib.sha256(INVALID_BYTES).hexdigest()
    return build_expected(
        'session:' + ('child' if child else 'adapter'), case,
        argv[0], pin,
        argv,
        tuple(sorted(environment.items())),
        cwd, 'expected-exec-failure' if invalid else 'python-command' if inline else 'python-script', None if inline or invalid else PINS[SCRIPT],
    )
