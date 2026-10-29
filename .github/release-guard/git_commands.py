"""Closed Git commands for the workspace/evolution launch families.

The independent observer validates filesystem custody and process state.
The matcher interprets no expressions and admits only complete closed argv forms.
Dynamic data operands remain scoped; the product tests own Git value semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from content_manifest import Refused
from git_operands import date_text, digest, text


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: str
    additions: tuple[tuple[str, str], ...] = ()
    stdin: str | None = None


FIXED = {
    'inside': ('rev-parse', '--is-inside-work-tree'),
    'top': ('rev-parse', '--show-toplevel'),
    'head': ('rev-parse', 'HEAD'),
    'head-tree': ('rev-parse', 'HEAD^{tree}'),
    'parent-ref': ('symbolic-ref', '--quiet', 'HEAD'),
    'clean': ('status', '--porcelain=v1', '--untracked-files=all'),
    'inventory': ('status', '--porcelain=v1', '-z', '--untracked-files=all'),
    'stage-return': ('add', '-A', '--', '.'),
    'write-tree': ('write-tree',),
    'check-index': ('diff', '--cached', '--check'),
    'prune': ('worktree', 'prune'),
}
OPERATIONS = (*FIXED,
    'init', 'config-name', 'config-email', 'stage-base',
    'commit-base', 'stage-advance', 'commit-advance', 'stage-child',
    'commit-child', 'verify-base', 'lease-add', 'integration-add',
    'rollback-add', 'checkout', 'diff-return', 'apply',
    'date', 'commit-tree', 'update-parent', 'reset-parent',
    'rollback-update', 'rollback-reset', 'remove-tree',
)


def path(value):
    text(value)
    p = PurePosixPath(value)
    if not value.startswith('/') or value.startswith('//') or str(p) != value or '..' in p.parts:
        raise Refused('git command canonical path')
    return p


def location_role(repo, cwd):
    if cwd == repo:
        return 'parent'
    if cwd.parent == repo / '.unrest-runtime/workspaces/trees':
        if cwd.name and all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in cwd.name):
            return 'lease'
    for role, parent, prefix in (('integration', repo / '.unrest-runtime/workspaces', 'integration-'),
                                  ('rollback', repo / '.unrest-runtime/evolution', 'rollback-')):
        suffix = cwd.name.removeprefix(prefix)
        if cwd.parent == parent and cwd.name.startswith(prefix) and len(suffix) == 8 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in suffix):
            return role
    raise Refused('git operation location')


ROLES = {**dict.fromkeys(OPERATIONS, ('parent',)),
    'top': ('parent', 'lease'), 'head': ('parent', 'lease'),
    **dict.fromkeys(('inventory', 'stage-return', 'checkout', 'diff-return', 'stage-child', 'commit-child'), ('lease',)),
    **dict.fromkeys(('apply', 'write-tree', 'commit-tree'), ('integration',)),
    'check-index': ('integration', 'rollback')}


def match(operation, repository, location, argv, stdin, environment, *, family, fixture=None, branch="main"):
    """Match one closed complete vector; dynamic operands grant no extra forms."""
    if type(family) is not str or family not in ('workspaces','evolution') or type(operation) is not str or operation not in OPERATIONS:
        raise Refused('git closed operation')
    if type(argv) is not list or not argv or any(type(value) is not str for value in argv) or argv[0]!='git':
        raise Refused('git literal argument vector')
    repo,cwd=path(repository),path(location)
    role=location_role(repo,cwd)
    if role=='rollback' and family!='evolution':
        raise Refused('git rollback location family')
    if role not in ROLES[operation]:
        raise Refused('git operation location role')
    args=tuple(argv[1:])
    additions=()
    if operation in FIXED:
        if args!=FIXED[operation]:
            raise Refused('git fixed command')
    elif operation in ('init','config-name','config-email','stage-base','commit-base','stage-advance','commit-advance','stage-child','commit-child'):
        label='Workspace' if family=='workspaces' else 'Evolution'
        expected={'init':('init','-b','main'),'config-name':('config','user.name',label+' Test'),
            'config-email':('config','user.email',family.removesuffix('s')+'@example.test'),
            'stage-base':('add','README.md'),'commit-base':('commit','-m','base'),
            'stage-advance':('add','advance.txt'),'commit-advance':('commit','-m','advance parent'),
            'stage-child':('add','child.txt'),'commit-child':('commit','-m','child self commit')}[operation]
        if fixture is not None and operation in ('init','config-name','config-email','stage-base','commit-base'):
            expected=fixture.commands[('init','config-name','config-email','stage-base','commit-base').index(operation)]
        if (args!=expected or (operation in ('stage-child','commit-child'))!=(cwd!=repo)
                or family=='evolution' and operation in ('stage-child','commit-child','stage-advance','commit-advance')):
            raise Refused('git fixture command or family')
    else:
        match operation,args:
            case ('lease-add',('worktree','add','--detach','--no-checkout',tree,revision)) | (('integration-add'|'rollback-add'),('worktree','add','--detach',tree,revision)):
                tree=path(tree)
                target={'lease-add':'lease','integration-add':'integration','rollback-add':'rollback'}[operation]
                if location_role(repo,tree)!=target or target=='rollback' and family!='evolution':
                    raise Refused('git add tree scope or rollback family')
                digest(revision)
            case ('remove-tree',('worktree','remove','--force',tree)):
                target=location_role(repo,path(tree))
                if target not in ('lease','integration','rollback') or target=='rollback' and family!='evolution':
                    raise Refused('git remove tree scope or rollback target family')
            case ('verify-base',('rev-parse','--verify',revision)) if revision.endswith('^{commit}'):
                digest(revision[:-9])
            case ('checkout',('checkout','--detach',revision)) | ('diff-return',('diff','--cached','--binary','--no-ext-diff',revision)) | ('date',('show','-s','--format=%aI',revision)):
                digest(revision)
            case (('reset-parent'|'rollback-reset'),('reset','--hard',revision)):
                digest(revision)
                if operation=='rollback-reset' and family!='evolution':
                    raise Refused('git rollback family')
            case ('apply',('apply','--index','--binary',patch)):
                patch=path(patch)
                if patch.parent!=repo/'.unrest/workspaces/patches' or patch.suffix!='.patch':
                    raise Refused('git patch scope')
                digest(patch.stem,64)
            case (('update-parent'|'rollback-update'),('update-ref',reference,new,old)):
                if branch not in ('main','master') or reference!='refs/heads/'+branch or operation=='rollback-update' and family!='evolution':
                    raise Refused('git update reference or rollback family')
                digest(new)
                digest(old)
            case ('commit-tree',('commit-tree',tree,'-p',revision)):
                digest(tree)
                digest(revision)
                date=environment.get('GIT_AUTHOR_DATE')
                date_text(date)
                if type(stdin) is not str or len(stdin)>16384 or not stdin.startswith('Integrate Unrest workspaces\n\n') or not stdin.endswith('\n'):
                    raise Refused('Git finite commit input')
                rows=stdin[len('Integrate Unrest workspaces\n\n'):-1].split('\n')
                import re
                if (not 0<len(rows)<=128 or rows!=sorted(rows) or len(set(row.split(' ')[0] for row in rows))!=len(rows)
                        or any(len(row.split(' ',1)[0])>4096 or re.fullmatch(r'lease:[A-Za-z0-9_-]+ sha256:[a-f0-9]{64}',row) is None for row in rows)):
                    raise Refused('git commit deterministic lease identity')
                additions=tuple(sorted({'GIT_AUTHOR_NAME':'Unrest parent integration authority','GIT_AUTHOR_EMAIL':'unrest@localhost',
                    'GIT_COMMITTER_NAME':'Unrest parent integration authority','GIT_COMMITTER_EMAIL':'unrest@localhost',
                    'GIT_AUTHOR_DATE':date,'GIT_COMMITTER_DATE':date}.items()))
            case _:
                raise Refused('Git proposal does not match a template')
    if operation!='commit-tree' and stdin is not None:
        raise Refused('git unexpected command input')
    return Command(tuple(argv),str(cwd),additions,stdin)
