"""Small deterministic reproduction of overlapping custody launches."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

SUPPORT = Path(__file__).parent
sys.path.insert(0, str(SUPPORT))
from test_orders_git import selected  # noqa: E402
from finite import orders_git  # noqa: E402
import orders_git_custody as custody  # noqa: E402


def token_pair(selection):
    full = selection['registration']
    binding = {'kind': 'orders_custody_launch_binding', **full,
               'argv_sha256': selection['transformed_argv_sha256'],
               'environment_sha256': selection['environment_sha256'],
               'bootstrap_sha256': None, 'cwd': selection['cwd']}
    admitted = {k: v for k, v in full.items() if k not in ('python', 'caller_binding')}
    admitted['argv_sha256'] = selection['transformed_argv_sha256']
    selected_value = {**selection, 'registration': admitted}
    actual = {k: v for k, v in selection.items() if k != 'registration'}
    actual['kind'] = 'actual_launch_binding'
    return selected_value, binding, actual


@pytest.mark.parametrize('order', [(0, 1, 2, 3), (1, 0, 2, 3), (0, 1, 3, 2), (1, 0, 3, 2)])
def test_two_concurrent_launches_keep_their_own_caller(tmp_path, order):
    first, vector, env, cwd, manifest = selected(tmp_path)
    second = deepcopy(first)
    second['token'] = second['registration']['token'] = 'other-token'
    left, left_binding, left_actual = token_pair(first)
    right, right_binding, right_actual = token_pair(second)
    rows = [left_binding, right_binding, left_actual, right_actual]
    events = [rows[i] for i in order]
    for selection in (left, right):
        joined = custody.join_registration(selection, events)
        assert joined is not None
        assert custody.eligible(joined, vector, env, cwd, manifest, str(SUPPORT.parent.parent))
        assert joined['registration']['token'] == selection['token']
    # The old same-owner launch-window heuristic rejects one of these exact
    # interleavings. No thread order supplies custody in the corrected join.


@pytest.mark.parametrize('change', [None, 'class', 'python', 'case', 'token', 'environment', 'source', 'caller'])
def test_token_emitter_retains_exact_registration(tmp_path, change):
    selection, vector, env, cwd, manifest = selected(tmp_path)
    registration = deepcopy(selection['registration'])
    token = 'a' * 32
    state = {'case': registration['case']}
    if change == 'class':
        registration['class'] = 'foreign'
    elif change == 'python':
        registration['python'] = True
    elif change == 'case':
        registration['case'] = 'foreign'
    elif change == 'token':
        token = 'invalid'
    elif change == 'environment':
        env = {**env, 'GIT_CONFIG_GLOBAL': '/foreign'}
    elif change in ('source', 'caller'):
        registration[change + '_binding'] = None
    emitted = []
    def refuse(reason):
        raise RuntimeError(reason)
    if change is not None:
        with pytest.raises(RuntimeError, match='orders_git_launch_binding_context'):
            orders_git.bind_launch(registration, vector, cwd, env, state, token, emitted.append, refuse)
        assert emitted == []
    else:
        orders_git.bind_launch(registration, vector, cwd, env, state, token, emitted.append, refuse)
        assert len(emitted) == 1
        value = emitted[0]
        assert value['token'] == token and value['caller_binding'] == registration['caller_binding']
        assert value['source_binding'] == registration['source_binding']
        assert value['argv_sha256'] == hashlib.sha256(json.dumps(vector).encode()).hexdigest()
        assert value['environment_sha256'] == selection['environment_sha256']
        registration['caller_binding']['line'] = 999
        assert value['caller_binding']['line'] != 999
