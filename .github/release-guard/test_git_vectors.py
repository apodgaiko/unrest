"""Test-only literal vectors; native admission uses git_commands.match, never this renderer."""
from git_policy import command_match as match

FIELDS = {'inside': (), 'top': (), 'head': (), 'head-tree': (), 'parent-ref': (), 'clean': (), 'inventory': (), 'stage-return': (), 'write-tree': (), 'check-index': (), 'prune': (), 'init': (), 'config-name': (), 'config-email': (), 'stage-base': (), 'commit-base': (), 'stage-advance': (), 'commit-advance': (), 'stage-child': (), 'commit-child': (), 'verify-base': ('revision',), 'lease-add': ('tree', 'revision'), 'integration-add': ('tree', 'revision'), 'rollback-add': ('tree', 'revision'), 'checkout': ('revision',), 'diff-return': ('revision',), 'apply': ('patch',), 'date': ('revision',), 'commit-tree': ('tree_id', 'revision', 'date', 'leases'), 'update-parent': ('new', 'old'), 'reset-parent': ('revision',), 'rollback-update': ('new', 'old'), 'rollback-reset': ('revision',), 'remove-tree': ('tree',)}

SAMPLES = {
    'inside': ('git', 'rev-parse', '--is-inside-work-tree'),
    'top': ('git', 'rev-parse', '--show-toplevel'),
    'head': ('git', 'rev-parse', 'HEAD'),
    'head-tree': ('git', 'rev-parse', 'HEAD^{tree}'),
    'parent-ref': ('git', 'symbolic-ref', '--quiet', 'HEAD'),
    'clean': ('git', 'status', '--porcelain=v1', '--untracked-files=all'),
    'inventory': ('git', 'status', '--porcelain=v1', '-z', '--untracked-files=all'),
    'stage-return': ('git', 'add', '-A', '--', '.'),
    'write-tree': ('git', 'write-tree'),
    'check-index': ('git', 'diff', '--cached', '--check'),
    'prune': ('git', 'worktree', 'prune'),
    'init': ('git', 'init', '-b', 'main'),
    'config-name': ('git', 'config', 'user.name', 'Workspace Test'),
    'config-email': ('git', 'config', 'user.email', 'workspace@example.test'),
    'stage-base': ('git', 'add', 'README.md'),
    'commit-base': ('git', 'commit', '-m', 'base'),
    'stage-advance': ('git', 'add', 'advance.txt'),
    'commit-advance': ('git', 'commit', '-m', 'advance parent'),
    'stage-child': ('git', 'add', 'child.txt'),
    'commit-child': ('git', 'commit', '-m', 'child self commit'),
    'verify-base': ('git', 'rev-parse', '--verify', '1111111111111111111111111111111111111111^{commit}'),
    'lease-add': ('git', 'worktree', 'add', '--detach', '--no-checkout', '/owned/project/.unrest-runtime/workspaces/trees/one', '1111111111111111111111111111111111111111'),
    'integration-add': ('git', 'worktree', 'add', '--detach', '/owned/project/.unrest-runtime/workspaces/integration-abcdefgh', '1111111111111111111111111111111111111111'),
    'rollback-add': ('git', 'worktree', 'add', '--detach', '/owned/project/.unrest-runtime/evolution/rollback-abcdefgh', '1111111111111111111111111111111111111111'),
    'checkout': ('git', 'checkout', '--detach', '1111111111111111111111111111111111111111'),
    'diff-return': ('git', 'diff', '--cached', '--binary', '--no-ext-diff', '1111111111111111111111111111111111111111'),
    'apply': ('git', 'apply', '--index', '--binary', '/owned/project/.unrest/workspaces/patches/4444444444444444444444444444444444444444444444444444444444444444.patch'),
    'date': ('git', 'show', '-s', '--format=%aI', '1111111111111111111111111111111111111111'),
    'commit-tree': ('git', 'commit-tree', '2222222222222222222222222222222222222222', '-p', '1111111111111111111111111111111111111111'),
    'update-parent': ('git', 'update-ref', 'refs/heads/main', '3333333333333333333333333333333333333333', '1111111111111111111111111111111111111111'),
    'reset-parent': ('git', 'reset', '--hard', '1111111111111111111111111111111111111111'),
    'rollback-update': ('git', 'update-ref', 'refs/heads/main', '3333333333333333333333333333333333333333', '1111111111111111111111111111111111111111'),
    'rollback-reset': ('git', 'reset', '--hard', '1111111111111111111111111111111111111111'),
    'remove-tree': ('git', 'worktree', 'remove', '--force', '/owned/project/.unrest-runtime/workspaces/trees/one'),
}

POSITIONS={
    'lease-add':{'tree':5,'revision':6},'integration-add':{'tree':4,'revision':5},
    'rollback-add':{'tree':4,'revision':5},'remove-tree':{'tree':4},
    'verify-base':{'revision':3},'checkout':{'revision':3},'diff-return':{'revision':5},
    'date':{'revision':4},'apply':{'patch':4},'update-parent':{'new':3,'old':4},
    'rollback-update':{'new':3,'old':4},'reset-parent':{'revision':3},'rollback-reset':{'revision':3},
    'commit-tree':{'tree_id':2,'revision':4},
}


def render(operation,repository,data,*,family='workspaces',fixture=None,branch='main'):
    vector=[value.replace('/owned/project',repository) for value in SAMPLES[operation]]
    for field,index in POSITIONS.get(operation,{}).items():
        vector[index]=data.get(field,'')
    if operation=='verify-base':
        vector[3]+='^{commit}'
    if operation in ('update-parent','rollback-update'):
        vector[2]='refs/heads/'+branch
    if operation=='config-name':
        vector[-1]='Workspace Test' if family=='workspaces' else 'Evolution Test'
    elif operation=='config-email':
        vector[-1]='workspace@example.test' if family=='workspaces' else 'evolution@example.test'
    if fixture is not None and operation in ('init','config-name','config-email','stage-base','commit-base'):
        vector=['git',*fixture.commands[('init','config-name','config-email','stage-base','commit-base').index(operation)]]
    if 'extra' in data:
        vector.append(data['extra'])
    stdin=None
    environment={}
    if operation=='commit-tree':
        stdin='Integrate Unrest workspaces\n\n'+'\n'.join(' '.join(row) for row in data['leases'])+'\n'
        environment.update(GIT_AUTHOR_NAME='Unrest parent integration authority',GIT_AUTHOR_EMAIL='unrest@localhost',
            GIT_COMMITTER_NAME='Unrest parent integration authority',GIT_COMMITTER_EMAIL='unrest@localhost',
            GIT_AUTHOR_DATE=data['date'],GIT_COMMITTER_DATE=data['date'])
    return vector,stdin,environment


def build(operation,repository,location,data,*,family,fixture=None,branch='main'):
    vector,stdin,environment=render(operation,repository,data,family=family,branch=branch)
    return match(repository,location,vector,stdin,environment)[1]
