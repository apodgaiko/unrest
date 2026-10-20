"""Exact post-init CPython locale state for the existing local redaction leaf."""
import ast
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from finite.registry import COMMANDS
from primary_source_inputs import python_environment

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    registration = deepcopy(next(row for row in COMMANDS
                                  if row['class'] == 'reference-descendant:terminal-redaction'))
    source = ROOT / 'tests/test_capability_policy.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == registration['source_binding']['sha256']
    owner = next(node for node in ast.parse(source.read_bytes()).body
                 if isinstance(node, ast.AsyncFunctionDef)
                 and node.name == 'test_raw_acp_terminal_protocol_redacts_credential_values')
    secret = next(ast.literal_eval(node.value) for node in owner.body
                  if isinstance(node, ast.Assign) and any(
                      isinstance(target, ast.Name) and target.id == 'secret' for target in node.targets))
    return registration, {'PATH': '/source/.venv/bin:/usr/bin:/bin', 'ZAI_API_KEY': secret}


def test_existing_literal_exec_bytes_remain_exact_and_postinit_is_explicit():
    registration, environment = fixture()
    before = deepcopy((registration, environment))
    assert python_environment(environment, registration, [0, 0, 0]) == {
        **environment, 'LC_CTYPE': 'C.UTF-8'}
    assert (registration, environment) == before


@pytest.mark.parametrize('change', ['class', 'python', 'argv', 'cwd', 'callers', 'path',
                                    'line', 'source', 'extra', 'missing'])
def test_registration_mutations_cannot_select_the_locale_transition(change):
    registration, environment = fixture()
    if change == 'class':
        registration['class'] = 'terminal-other'
    elif change == 'python':
        registration['python'] = False
    elif change == 'argv':
        registration['argv'] = ['-c', 'pass']
    elif change == 'cwd':
        registration['checkout_cwd'] = False
    elif change == 'callers':
        registration['caller_bindings'] = ['other']
    elif change == 'extra':
        registration['extra'] = True
    elif change == 'missing':
        del registration['caller_bindings']
    else:
        key, value = {'path': ('path', '/foreign/test.py'), 'line': ('line', 548),
                      'source': ('sha256', '0' * 64)}[change]
        registration['source_binding'][key] = value
    assert python_environment(environment, registration, [0, 0, 0]) == environment


@pytest.mark.parametrize('change', ['secret', 'secret-type', 'path-empty', 'path-type',
                                    'missing-secret', 'extra', 'LANG', 'LC_ALL', 'LC_CTYPE'])
def test_only_the_original_two_key_environment_can_be_normalized(change):
    registration, environment = fixture()
    if change == 'secret':
        environment['ZAI_API_KEY'] = 'other-value'
    elif change == 'secret-type':
        environment['ZAI_API_KEY'] = None
    elif change == 'path-empty':
        environment['PATH'] = ''
    elif change == 'path-type':
        environment['PATH'] = None
    elif change == 'missing-secret':
        del environment['ZAI_API_KEY']
    else:
        environment[change] = 'C'
    assert python_environment(environment, registration, [0, 0, 0]) == environment


@pytest.mark.parametrize('flags', [[1, 0, 0], [0, 1, 0], [0, 0, 1], [1, 1, 1]])
def test_no_other_interpreter_flags_receive_this_transition(flags):
    registration, environment = fixture()
    assert python_environment(environment, registration, flags) == environment
