"""Closed Git commands for the workspace/evolution launch families.

The independent observer validates filesystem custody and process state.
This builder interprets no expressions and accepts no argv.
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
FIELDS = {**dict.fromkeys(FIXED, ()), 'init': (), 'config-name': (), 'config-email': (),
    'stage-base': (), 'commit-base': (), 'stage-advance': (), 'commit-advance': (),
    'stage-child': (), 'commit-child': (), 'verify-base': ('revision',),
    'lease-add': ('tree', 'revision'), 'integration-add': ('tree', 'revision'),
    'rollback-add': ('tree', 'revision'), 'checkout': ('revision',),
    'diff-return': ('revision',), 'apply': ('patch',), 'date': ('revision',),
    'commit-tree': ('tree_id', 'revision', 'date', 'leases'),
    'update-parent': ('new', 'old'), 'reset-parent': ('revision',),
    'rollback-update': ('new', 'old'), 'rollback-reset': ('revision',),
    'remove-tree': ('tree',)}


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


ROLES = {**dict.fromkeys(FIELDS, ('parent',)),
    'top': ('parent', 'lease'), 'head': ('parent', 'lease'),
    **dict.fromkeys(('inventory', 'stage-return', 'checkout', 'diff-return', 'stage-child', 'commit-child'), ('lease',)),
    **dict.fromkeys(('apply', 'write-tree', 'commit-tree'), ('integration',)),
    'check-index': ('integration', 'rollback')}


def build(operation, repository, location, fields, *, family):
    if type(operation) is not str or operation not in FIELDS or type(family) is not str or family not in ('workspaces', 'evolution'):
        raise Refused('git closed operation')
    repo, cwd = path(repository), path(location)
    if type(fields) is not dict or any(type(k) is not str for k in fields) or set(fields) != set(FIELDS[operation]):
        raise Refused('git operation operands')
    role = location_role(repo, cwd)
    if role == 'rollback' and family != 'evolution':
        raise Refused('git rollback location family')
    if role not in ROLES[operation]:
        raise Refused('git operation location role')
    for key, value in fields.items():
        if key != 'leases':
            text(value)
    args: tuple[str,...] = ()
    additions: tuple[tuple[str,str],...] = ()
    stdin: str | None = None
    if operation in ('rollback-add', 'rollback-update', 'rollback-reset') and family != 'evolution':
        raise Refused('git rollback family')
    if operation in FIXED:
        args = FIXED[operation]
    elif operation in ('init', 'config-name', 'config-email', 'stage-base', 'commit-base',
                       'stage-advance', 'commit-advance', 'stage-child', 'commit-child'):
        label = 'Workspace' if family == 'workspaces' else 'Evolution'
        args = {'init': ('init', '-b', 'main'), 'config-name': ('config', 'user.name', label + ' Test'),
            'config-email': ('config', 'user.email', family.removesuffix('s') + '@example.test'),
            'stage-base': ('add', 'README.md'), 'commit-base': ('commit', '-m', 'base'),
            'stage-advance': ('add', 'advance.txt'), 'commit-advance': ('commit', '-m', 'advance parent'),
            'stage-child': ('add', 'child.txt'), 'commit-child': ('commit', '-m', 'child self commit')}[operation]
        if (operation in ('stage-child', 'commit-child')) != (cwd != repo):
            raise Refused('git fixture location')
        if family == 'evolution' and operation in ('stage-child', 'commit-child', 'stage-advance', 'commit-advance'):
            raise Refused('git fixture family')
    elif operation in ('lease-add', 'integration-add', 'rollback-add', 'remove-tree'):
        tree = path(fields['tree'])
        parent = repo / '.unrest-runtime' / ('evolution' if operation == 'rollback-add' else 'workspaces')
        if operation == 'lease-add':
            parent /= 'trees'
        if operation == 'remove-tree':
            parents = (repo / '.unrest-runtime/workspaces', repo / '.unrest-runtime/workspaces/trees', repo / '.unrest-runtime/evolution')
            if tree.parent not in parents or location_role(repo, tree) not in ('lease', 'integration', 'rollback'):
                raise Refused('git remove tree scope')
            if location_role(repo, tree) == 'rollback' and family != 'evolution':
                raise Refused('git rollback target family')
            args = ('worktree', 'remove', '--force', str(tree))
        else:
            if tree.parent != parent or cwd != repo or location_role(repo, tree) != {'lease-add': 'lease', 'integration-add': 'integration', 'rollback-add': 'rollback'}[operation]:
                raise Refused('git add tree scope')
            if operation != 'lease-add':
                prefix = 'integration-' if operation == 'integration-add' else 'rollback-'
                suffix = tree.name.removeprefix(prefix)
                if not tree.name.startswith(prefix) or len(suffix) != 8 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in suffix):
                    raise Refused('git temporary tree name')
            revision = digest(fields['revision'])
            args = ('worktree', 'add', '--detach', *(('--no-checkout',) if operation == 'lease-add' else ()), str(tree), revision)
    elif operation in ('verify-base', 'checkout', 'diff-return', 'date', 'reset-parent', 'rollback-reset'):
        revision = digest(fields['revision'])
        args = {'verify-base': ('rev-parse', '--verify', revision + '^{commit}'),
            'checkout': ('checkout', '--detach', revision), 'diff-return': ('diff', '--cached', '--binary', '--no-ext-diff', revision),
            'date': ('show', '-s', '--format=%aI', revision), 'reset-parent': ('reset', '--hard', revision), 'rollback-reset': ('reset', '--hard', revision)}[operation]
    elif operation == 'apply':
        patch = path(fields['patch'])
        if patch.parent != repo / '.unrest/workspaces/patches' or patch.suffix != '.patch':
            raise Refused('git patch scope')
        digest(patch.stem, 64)
        args = ('apply', '--index', '--binary', str(patch))
    elif operation in ('update-parent', 'rollback-update'):
        new, old = digest(fields['new']), digest(fields['old'])
        args = ('update-ref', 'refs/heads/main', new, old)
    elif operation == 'commit-tree':
        tree, revision, date, leases = fields['tree_id'], digest(fields['revision']), fields['date'], fields['leases']
        digest(tree)
        date_text(date)
        if type(leases) is not tuple or not 0 < len(leases) <= 128:
            raise Refused('git commit lease set')
        rows = []
        for row in leases:
            if type(row) is not tuple or len(row) != 2:
                raise Refused('git commit lease row')
            lease, patch = row
            text(lease)
            if not lease.startswith('lease:') or not lease[6:] or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in lease[6:]):
                raise Refused('git commit lease identity')
            if type(patch) is not str or not patch.startswith('sha256:'):
                raise Refused('git commit patch identity')
            digest(patch[7:], 64)
            rows.append((lease, patch))
        if rows != sorted(rows) or len({row[0] for row in rows}) != len(rows):
            raise Refused('git commit deterministic lease order')
        stdin = 'Integrate Unrest workspaces\n\n' + '\n'.join(f'{lease} {patch}' for lease, patch in rows) + '\n'
        additions = tuple(sorted({'GIT_AUTHOR_NAME': 'Unrest parent integration authority', 'GIT_AUTHOR_EMAIL': 'unrest@localhost',
            'GIT_COMMITTER_NAME': 'Unrest parent integration authority', 'GIT_COMMITTER_EMAIL': 'unrest@localhost',
            'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date}.items()))
        args = ('commit-tree', tree, '-p', revision)
    return Command(('git', *args), str(cwd), additions, stdin)
