"""Keep seven original absolute sleep fixtures on the audited stock fork/exec path."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import TypedDict

SOURCE = 'tests/test_acp_runner.py'
PIN = 'b6f1c200a94c1107d6059baae0eb646dd5a113cc304d7062b29aec8263dd52d0'
OWNER = 'test_full_jobs_and_handoffs_preserve_complete_format_templates'
CLASS = 'source-cohort2:' + SOURCE + ':544'
CASES = frozenset(SOURCE + '::' + OWNER + '[' + role + '-' + provider + ']'
                  for role in ('worker', 'validator') for provider in ('claude', 'codex'))
class Site(TypedDict):
    function: str
    cases: tuple[str, ...]
    stdio: int


SITES: dict[int, Site] = {544: {'function': 'test_full_jobs_and_handoffs_preserve_complete_format_templates.<locals>._no_op_server', 'cases': ('tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[worker-claude]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[worker-codex]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[validator-claude]', 'tests/test_acp_runner.py::test_full_jobs_and_handoffs_preserve_complete_format_templates[validator-codex]'), 'stdio': -3}, 632: {'function': 'test_full_jobs_do_not_infer_credentials_inside_format_fields.<locals>._no_op_server', 'cases': ('tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[worker-claude]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[worker-codex]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[validator-claude]', 'tests/test_acp_runner.py::test_full_jobs_do_not_infer_credentials_inside_format_fields[validator-codex]'), 'stdio': -3}, 1079: {'function': 'test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success.<locals>._start_fixture', 'cases': ('tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[claude]', 'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[codex]'), 'stdio': -1}, 1380: {'function': 'test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling.<locals>._start_fixture', 'cases': ('tests/test_acp_runner.py::test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[claude]', 'tests/test_acp_runner.py::test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[codex]'), 'stdio': -1}, 1840: {'function': 'test_owned_node_launch_uses_one_identical_plan.<locals>.no_op_server', 'cases': ('tests/test_acp_runner.py::test_owned_node_launch_uses_one_identical_plan[work]', 'tests/test_acp_runner.py::test_owned_node_launch_uses_one_identical_plan[validate]'), 'stdio': -3}, 2206: {'function': 'test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol.<locals>.no_op_server', 'cases': ('tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[work]', 'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[validate]'), 'stdio': -3}, 2265: {'function': 'test_terminal_real_startup_failure_is_safe_and_starts_no_protocol.<locals>.no_op_server', 'cases': ('tests/test_acp_runner.py::test_terminal_real_startup_failure_is_safe_and_starts_no_protocol',), 'stdio': -3}}
ALL_CASES = frozenset(case for site in SITES.values() for case in site["cases"])
VECTOR = ['/bin/sleep', '30']


def binding(checkout, line=544):
    site = SITES[line]
    return {'path': str(Path(checkout) / SOURCE), 'line': line, 'sha256': PIN,
            'function': site['function']}


def site_for(registration, case, checkout):
    source = registration.get('source_binding', {})
    line = source.get('line')
    if type(line) is not int or line not in SITES:
        return None
    site = SITES[line]
    if (registration.get('class') != 'source-cohort2:' + SOURCE + ':' + str(line)
            or source != binding(checkout, line) or case not in site['cases']):
        return None
    return site


def validate(registration, vector, options, case, checkout):
    site = site_for(registration, case, checkout)
    if (site is None or registration.get('python') is not False or vector != VECTOR
            or options != {'shell': False, 'stdin': None,
                           'stdout': site['stdio'], 'stderr': site['stdio'],
                           'universal_newlines': False, 'bufsize': 0}):
        raise RuntimeError('native_relative_original_fixture_required')


def prepare(launch, options, state, observe, emit, refuse):
    registration = launch['registration']
    if registration.get('class') not in {'source-cohort2:' + SOURCE + ':' + str(line) for line in SITES}:
        return False
    try:
        validate(registration, launch['argv'], options, state.get('case'), state['checkout'])
        path = Path(state['checkout']) / SOURCE
        if (state['product_pins'].get(SOURCE) != PIN
                or hashlib.sha256(path.read_bytes()).hexdigest() != PIN
                or launch['child_argv'] != VECTOR or os.getcwd() != state['checkout']):
            raise RuntimeError('native_relative_source_context')
        facts = observe()
        if facts != observe():
            raise RuntimeError('native_relative_parent_cwd_drift')
    except (OSError, RuntimeError, KeyError, ValueError, TypeError) as error:
        refuse(str(error))
        raise RuntimeError('refusal callback returned') from error
    emit({'kind': 'native_relative_constructor', 'token': launch['launch_token'],
          'class': registration['class'], 'source_binding': registration['source_binding'],
          'argv_sha256': hashlib.sha256(json.dumps(VECTOR).encode()).hexdigest(),
          'original_cwd': None, 'constructor_cwd': '.', 'parent_view': facts})
    return True
