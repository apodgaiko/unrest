"""Keep one original absolute sleep fixture on the audited stock fork/exec path."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SOURCE = 'tests/test_acp_runner.py'
PIN = 'b6f1c200a94c1107d6059baae0eb646dd5a113cc304d7062b29aec8263dd52d0'
OWNER = 'test_full_jobs_and_handoffs_preserve_complete_format_templates'
CLASS = 'source-cohort2:' + SOURCE + ':544'
CASES = frozenset(SOURCE + '::' + OWNER + '[' + role + '-' + provider + ']'
                  for role in ('worker', 'validator') for provider in ('claude', 'codex'))
VECTOR = ['/bin/sleep', '30']


def binding(checkout):
    return {'path': str(Path(checkout) / SOURCE), 'line': 544, 'sha256': PIN,
            'function': OWNER + '.<locals>._no_op_server'}


def validate(registration, vector, options, case, checkout):
    if (registration.get('class') != CLASS or registration.get('python') is not False
            or registration.get('source_binding') != binding(checkout)
            or vector != VECTOR or case not in CASES
            or options != {'shell': False, 'stdin': None, 'stdout': -3, 'stderr': -3,
                           'universal_newlines': False, 'bufsize': 0}):
        raise RuntimeError('native_relative_original_fixture_required')


def prepare(launch, options, state, observe, emit, refuse):
    registration = launch['registration']
    if registration.get('class') != CLASS:
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
          'class': CLASS, 'source_binding': registration['source_binding'],
          'argv_sha256': hashlib.sha256(json.dumps(VECTOR).encode()).hexdigest(),
          'original_cwd': None, 'constructor_cwd': '.', 'parent_view': facts})
    return True
