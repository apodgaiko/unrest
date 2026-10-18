"""Closed SOURCE activation input; TEST probes never carry release authority."""
from __future__ import annotations

import hashlib
import json
import re
import shlex

from primary_policy import (SHELL, SHELL_FLAGS, SOURCE_BUDGET, TEST_CASE, canonical, sha)


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
    expected = ('env -u CODEX_PATH uv run pytest -q ' + TEST_CASE).encode()
    if script != expected:
        raise RuntimeError('primary_source_test_script')
    return {'schema': 'unrest.v046.primary-script-plan.v1',
            'duty': 'TEST-source-' + mode.removeprefix('TEST-'),
            'script_sha256': sha(script), 'workflow_sha256': sha(workflow.encode()),
            'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
            'commands': [shlex.split(script.decode())], 'source_checkpoint_ready': False,
            'selected_carrier': None, 'timeout_seconds': 180,
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


def python_environment(environment, registration, flags):
    """Post-init locale bytes for the existing isolated startup source fixture.

    Exec still consumes the exact original environment. The pinned CPython
    image coerces its absent C locale before exposing os.environ under -I.
    """
    if (registration['class'] == 'isolated-role-startup'
            and registration['source_binding']['path'] == '/source/tests/test_stdio_startup.py'
            and flags[0] == 1
            and not any(key in environment for key in ('LC_CTYPE', 'LC_ALL', 'LANG'))):
        return {**environment, 'LC_CTYPE': 'C.UTF-8'}
    return dict(environment)
