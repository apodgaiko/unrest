"""Literal reconstruction and location controls; no process admission proof."""
from dataclasses import replace
import hashlib

import pytest

from content_manifest import Refused
from git_commands import build, FIELDS, FIXED, ROLES

REPO = '/owned/project'
LEASE = REPO + '/.unrest-runtime/workspaces/trees/one'
INTEGRATION = REPO + '/.unrest-runtime/workspaces/integration-abcdefgh'
ROLLBACK = REPO + '/.unrest-runtime/evolution/rollback-abcdefgh'
BASE, TREE, NEW = '1' * 40, '2' * 40, '3' * 40
DATE = '2026-10-27T00:00:00+00:00'
PATCH = '4' * 64
OPERANDS = {'revision': BASE, 'tree': LEASE, 'patch': REPO + '/.unrest/workspaces/patches/' + PATCH + '.patch',
    'tree_id': TREE, 'new': NEW, 'old': BASE, 'new_location': INTEGRATION, 'date': DATE,
    'new_inputs': (TREE, BASE, DATE, '6' * 64), 'leases': (('lease:a', 'sha256:' + PATCH), ('lease:b', 'sha256:' + '5' * 64))}
LOCATIONS = {'parent': REPO, 'lease': LEASE, 'integration': INTEGRATION, 'rollback': ROLLBACK}


def fields(operation):
    result = {name: OPERANDS[name] for name in FIELDS[operation]}
    if operation == 'integration-add':
        result['tree'] = INTEGRATION
    if operation == 'rollback-add':
        result['tree'] = ROLLBACK
    return result


@pytest.mark.parametrize('operation', tuple(FIELDS))
def test_every_closed_operation_is_built_without_observed_argv(operation):
    cwd = LOCATIONS[ROLES[operation][0]]
    result = build(operation, REPO, cwd, fields(operation), family='evolution' if operation.startswith('rollback-') else 'workspaces')
    assert result.argv[0] == 'git' and result.cwd == cwd
    if operation in FIXED:
        assert result.argv[1:] == FIXED[operation]
    assert not result.additions or operation == 'commit-tree'
    assert result.stdin is None or operation == 'commit-tree'


@pytest.mark.parametrize('operation', tuple(FIELDS))
def test_location_roles_do_not_grant_commands_at_a_neighboring_tree(operation):
    for role, cwd in LOCATIONS.items():
        if role not in ROLES[operation]:
            with pytest.raises(Refused, match='location role|rollback location family'):
                build(operation, REPO, cwd, fields(operation), family='workspaces')
    with pytest.raises(Refused, match='operation location'):
        build(operation, REPO, REPO + '/.unrest-runtime/arbitrary', fields(operation), family='workspaces')


@pytest.mark.parametrize('family,label,email', (('workspaces', 'Workspace Test', 'workspace@example.test'),
                                               ('evolution', 'Evolution Test', 'evolution@example.test')))
def test_original_fixture_identity_is_family_specific(family, label, email):
    assert build('config-name', REPO, REPO, {}, family=family).argv == ('git', 'config', 'user.name', label)
    assert build('config-email', REPO, REPO, {}, family=family).argv == ('git', 'config', 'user.email', email)


def test_integration_message_environment_and_causal_locations_are_exact():
    result = build('commit-tree', REPO, INTEGRATION, fields('commit-tree'), family='workspaces')
    assert result.argv == ('git', 'commit-tree', TREE, '-p', BASE)
    message = 'Integrate Unrest workspaces\n\nlease:a sha256:' + PATCH + '\nlease:b sha256:' + '5' * 64 + '\n'
    assert result.stdin == message
    assert hashlib.sha256(result.stdin.encode()).hexdigest() == hashlib.sha256(message.encode()).hexdigest()
    assert dict(result.additions) == {'GIT_AUTHOR_NAME': 'Unrest parent integration authority',
        'GIT_COMMITTER_NAME': 'Unrest parent integration authority', 'GIT_AUTHOR_EMAIL': 'unrest@localhost',
        'GIT_COMMITTER_EMAIL': 'unrest@localhost', 'GIT_AUTHOR_DATE': DATE, 'GIT_COMMITTER_DATE': DATE}
    assert result.requires == ((INTEGRATION, 'tree', TREE, ()), ('parent', 'commit', BASE, ()), ('parent', 'date', DATE, (BASE,)))
    assert result != replace(result, stdin=message + '\n')


def test_promotion_and_rollback_have_distinct_causal_roles():
    promotion = build('update-parent', REPO, REPO, fields('update-parent'), family='workspaces')
    rollback = build('rollback-update', REPO, REPO, {'new': BASE, 'old': NEW}, family='evolution')
    assert promotion.argv == ('git', 'update-ref', 'refs/heads/main', NEW, BASE)
    assert promotion.requires == (('parent', 'commit', BASE, ()), (INTEGRATION, 'integration-commit', NEW, OPERANDS['new_inputs']))
    assert rollback.argv == ('git', 'update-ref', 'refs/heads/main', BASE, NEW)
    assert rollback.requires == (('parent', 'commit', NEW, ()), ('parent', 'commit', BASE, ()))


@pytest.mark.parametrize('mutation', ('extra', 'missing', 'bool', 'wrong-tree', 'parent-tree', 'patch-scope', 'patch-digest', 'lease-order', 'lease-duplicate'))
def test_swapped_operands_are_refused_before_command_construction(mutation):
    operation = 'lease-add'
    data = fields(operation)
    if mutation == 'extra':
        data['extra'] = 'value'
    elif mutation == 'missing':
        data.pop('revision')
    elif mutation == 'bool':
        data['revision'] = True
    elif mutation == 'wrong-tree':
        data['tree'] = INTEGRATION
    elif mutation == 'parent-tree':
        data['tree'] = REPO
    elif mutation.startswith('patch-'):
        operation, data = 'apply', fields('apply')
        data['patch'] = REPO + '/foreign/' + PATCH + '.patch' if mutation == 'patch-scope' else data['patch'].replace(PATCH, 'x' * 64)
    else:
        operation, data = 'commit-tree', fields('commit-tree')
        data['leases'] = tuple(reversed(data['leases'])) if mutation == 'lease-order' else (data['leases'][0],) * 2
    cwd = INTEGRATION if operation in ('apply', 'commit-tree') else REPO
    with pytest.raises(Refused):
        build(operation, REPO, cwd, data, family='workspaces')


class CallbackTrap:
    def __eq__(self, other):
        pytest.fail('Git builder invoked caller equality')


def test_family_and_dependency_inputs_are_primitive_and_predecessor_bound():
    with pytest.raises(Refused):
        build('head', REPO, REPO, {}, family=CallbackTrap())
    for dependency in ((TREE, NEW, DATE, '6' * 64), (TREE, BASE, 'invalid-date', '6' * 64), True):
        data = fields('update-parent')
        data['new_inputs'] = dependency
        with pytest.raises(Refused):
            build('update-parent', REPO, REPO, data, family='workspaces')
    with pytest.raises(Refused, match='rollback family'):
        build('rollback-add', REPO, REPO, fields('rollback-add'), family='workspaces')


@pytest.mark.parametrize('operation,cwd,data', (('check-index', ROLLBACK, {}),
    ('remove-tree', REPO, {'tree': ROLLBACK})))
def test_rollback_execution_and_target_locations_are_evolution_only(operation, cwd, data):
    with pytest.raises(Refused, match='rollback .*family'):
        build(operation, REPO, cwd, data, family='workspaces')
    assert build(operation, REPO, cwd, data, family='evolution').argv[0] == 'git'
