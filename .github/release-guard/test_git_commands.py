"""Literal reconstruction and location controls; no process admission proof."""
from dataclasses import replace
import hashlib

import pytest

from content_manifest import Refused
from git_policy import COMMAND_FIXED as FIXED
from test_git_vectors import build,FIELDS

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
def test_every_closed_operation_matches_its_literal_vector(operation):
    cwd = LEASE if operation in ('stage-child','commit-child') else REPO
    result = build(operation, REPO, cwd, fields(operation), family='evolution' if operation.startswith('rollback-') else 'workspaces')
    assert result.argv[0] == 'git' and result.cwd == cwd
    if operation in FIXED:
        assert result.argv[1:] == FIXED[operation]
    assert not result.additions or operation == 'commit-tree'
    assert result.stdin is None or operation == 'commit-tree'


@pytest.mark.parametrize('operation', tuple(FIELDS))
def test_directory_spelling_does_not_predict_application_roles(operation):
    family='evolution' if operation.startswith('rollback-') else 'workspaces'
    for cwd in (*LOCATIONS.values(),REPO+'/.unrest-runtime/ordinary/deep-scratch'):
        assert build(operation,REPO,cwd,fields(operation),family=family).cwd==cwd
    for cwd in (REPO+'/.unrest-runtime',REPO+'/foreign',REPO+'-neighbor/.unrest-runtime/x'):
        with pytest.raises(Refused,match='operation location'):
            build(operation,REPO,cwd,fields(operation),family=family)


@pytest.mark.parametrize('family,label,email', (('workspaces', 'Workspace Test', 'workspace@example.test'),
                                               ('evolution', 'Evolution Test', 'evolution@example.test')))
def test_original_fixture_identity_is_family_specific(family, label, email):
    assert build('config-name', REPO, REPO, {}, family=family).argv == ('git', 'config', 'user.name', label)
    assert build('config-email', REPO, REPO, {}, family=family).argv == ('git', 'config', 'user.email', email)


def test_integration_message_environment_and_data_operands_are_exact():
    result = build('commit-tree', REPO, INTEGRATION, fields('commit-tree'), family='workspaces')
    assert result.argv == ('git', 'commit-tree', TREE, '-p', BASE)
    message = 'Integrate Unrest workspaces\n\nlease:a sha256:' + PATCH + '\nlease:b sha256:' + '5' * 64 + '\n'
    assert result.stdin == message
    assert hashlib.sha256(result.stdin.encode()).hexdigest() == hashlib.sha256(message.encode()).hexdigest()
    assert dict(result.additions) == {'GIT_AUTHOR_NAME': 'Unrest parent integration authority',
        'GIT_COMMITTER_NAME': 'Unrest parent integration authority', 'GIT_AUTHOR_EMAIL': 'unrest@localhost',
        'GIT_COMMITTER_EMAIL': 'unrest@localhost', 'GIT_AUTHOR_DATE': DATE, 'GIT_COMMITTER_DATE': DATE}
    assert result != replace(result, stdin=message + '\n')


def test_promotion_and_rollback_have_retain_literal_ref_and_operand_positions():
    promotion = build('update-parent', REPO, REPO, fields('update-parent'), family='workspaces')
    rollback = build('rollback-update', REPO, REPO, {'new': BASE, 'old': NEW}, family='evolution')
    assert promotion.argv == ('git', 'update-ref', 'refs/heads/main', NEW, BASE)
    assert rollback.argv == ('git', 'update-ref', 'refs/heads/main', BASE, NEW)


@pytest.mark.parametrize('mutation', ('extra', 'missing', 'bool', 'runtime-root', 'parent-tree', 'patch-scope', 'patch-digest', 'lease-order', 'lease-duplicate'))
def test_swapped_operands_are_refused_at_complete_vector_matching(mutation):
    operation = 'lease-add'
    data = fields(operation)
    if mutation == 'extra':
        data['extra'] = 'value'
    elif mutation == 'missing':
        data.pop('revision')
    elif mutation == 'bool':
        data['revision'] = True
    elif mutation == 'runtime-root':
        data['tree'] = REPO+'/.unrest-runtime'
    elif mutation == 'parent-tree':
        data['tree'] = REPO
    elif mutation.startswith('patch-'):
        operation, data = 'apply', fields('apply')
        data['patch'] = REPO + '/foreign/' + PATCH + '.patch' if mutation == 'patch-scope' else data['patch'].replace(PATCH, 'x' * 64)
    else:
        operation, data = 'commit-tree', fields('commit-tree')
        data['leases'] = tuple(reversed(data['leases'])) if mutation == 'lease-order' else (data['leases'][0],) * 2
    cwd = INTEGRATION if operation in ('apply', 'commit-tree') else REPO
    if mutation in ('lease-order','lease-duplicate'):
        value=build(operation,REPO,cwd,data,family='workspaces')
        assert value.argv==('git','commit-tree',TREE,'-p',BASE) and value.stdin
    else:
        with pytest.raises(Refused):
            build(operation,REPO,cwd,data,family='workspaces')


class CallbackTrap:
    def __eq__(self, other):
        pytest.fail('Git builder invoked caller equality')


def test_family_is_primitive_and_rollback_forms_stay_scoped():
    with pytest.raises(Refused):
        build('head', REPO, REPO, {}, family=CallbackTrap())
    assert build('rollback-add', REPO, REPO, fields('rollback-add'), family='workspaces').argv==build('rollback-add', REPO, REPO, fields('rollback-add'), family='evolution').argv


@pytest.mark.parametrize('operation',('lease-add','integration-add','rollback-add','remove-tree'))
@pytest.mark.parametrize('target',(REPO,REPO+'/.unrest-runtime',REPO+'/foreign',REPO+'-neighbor/.unrest-runtime/x'))
def test_worktree_targets_cannot_remove_repository_or_runtime_root(operation,target):
    data=fields(operation)
    data['tree']=target
    with pytest.raises(Refused,match='operation location'):
        build(operation,REPO,REPO,data,family='evolution')


def test_owned_workspace_literal_command_derives_its_inline_digest():
    import hashlib
    from git_policy import SITE_OWNED_BODY as OWNED_BODY, SITE_CASES as CASES
    from launch_policy import build_expected
    assert build_expected(CASES[7], '/native/python', 'a' * 64, ('/native/python', '-c', OWNED_BODY), (), REPO, 'python-command', None).payload_sha256 == hashlib.sha256(OWNED_BODY.encode()).hexdigest()



def test_commit_input_is_bounded_data_without_a_second_lease_parser():
    from git_policy import command_match
    from test_git_vectors import render
    vector,_,environment=render('commit-tree',REPO,fields('commit-tree'),family='workspaces')
    for message in ('ordinary message','unsorted\nrepeated\nrepeated\n','λ'*8192):
        assert command_match('commit-tree',REPO,INTEGRATION,vector,message,environment,family='workspaces').stdin==message
    for message in ('λ'*8193,'x'*16385,'x\0y',None,True):
        with pytest.raises(Refused):
            command_match('commit-tree',REPO,INTEGRATION,vector,message,environment,family='workspaces')


def test_local_operation_union_has_one_canonical_label_for_each_vector():
    from git_policy import LOCAL_OPERATIONS,COMMAND_OPERATIONS
    assert set(LOCAL_OPERATIONS)==(set(COMMAND_OPERATIONS)-{'rollback-add','rollback-update','rollback-reset'})|{'fixture-extra'}
    assert len(LOCAL_OPERATIONS)==len(set(LOCAL_OPERATIONS))
