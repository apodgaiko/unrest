"""Original registry identity remains required before the native terminal leaf."""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import registry_native_custody as native


def context():
    entries = ast.literal_eval(ast.parse((Path(__file__).parent / 'finite/registry.py').read_bytes()).body[1].value)
    body = '"""registry"""\nCOMMANDS = ' + repr(entries)
    entry = native.entry_from(body)
    environment = {'PATH': '/source/.venv/bin:/usr/bin:/bin'}
    registration = {'class': native.CLASS, 'source_binding': deepcopy(native.BINDING),
                    'case': sorted(native.CASES)[0], 'owner_pid': 20, 'token': 'actual'}
    selected = {'registration': registration, 'owner_pid': 20, 'token': 'actual', 'cwd': '/source',
                'bootstrap_sha256': None,
                'transformed_argv_sha256': hashlib.sha256(json.dumps(native.VECTOR).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
    return entry, selected, environment


def test_exact_existing_native_terminal_registration():
    entry, selected, environment = context()
    assert native.eligible(selected, native.VECTOR, environment, '/source', entry)


@pytest.mark.parametrize('field', ['class', 'source_binding', 'case', 'owner_pid', 'token',
                                  'bootstrap_sha256', 'cwd', 'transformed_argv_sha256', 'environment_sha256',
                                  'vector', 'environment'])
def test_unknown_contexts_never_gain_native_authority(field):
    entry, selected, environment = context()
    vector = list(native.VECTOR)
    if field in {'class', 'source_binding', 'case', 'owner_pid', 'token'}:
        selected['registration'][field] = 'foreign'
    elif field == 'vector':
        vector.append('--foreign')
    elif field == 'environment':
        environment['LD_PRELOAD'] = '/foreign'
    else:
        selected[field] = 'foreign'
    assert not native.eligible(selected, vector, environment, '/source', entry)


@pytest.mark.parametrize('field', ['class', 'python', 'argv', 'executable', 'checkout_cwd', 'source_binding', 'caller_bindings'])
def test_changed_registry_entry_is_not_a_literal_native_leaf(field):
    entry, _, _ = context()
    entry[field] = 'foreign'
    body = '"""registry"""\nCOMMANDS = ' + repr([entry])
    with pytest.raises(RuntimeError):
        native.entry_from(body)
