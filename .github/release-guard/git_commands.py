"""Closed Git commands for original workspace/evolution call sites.

Call-site ownership, original subprocess options and filesystem custody belong to
source selection. This builder interprets no expressions and accepts no argv.
Its causal requirements must be resolved by the observer before admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import PurePosixPath

from content_manifest import Refused
from git_values import digest, text


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: str
    additions: tuple[tuple[str, str], ...] = ()
    stdin: str | None = None
    requires: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()
    produces: tuple[str, str, tuple[str, ...]] | None = None


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
    'update-parent': ('new', 'old', 'new_location', 'new_inputs'), 'reset-parent': ('revision', 'new_location', 'new_inputs'),
    'rollback-update': ('new', 'old'), 'rollback-reset': ('revision',),
    'remove-tree': ('tree',)}


def path(value):
    text(value)
    p = PurePosixPath(value)
    if not value.startswith('/') or value.startswith('//') or str(p) != value or '..' in p.parts:
        raise Refused('git command canonical path')
    return p


def integration_inputs(value):
    if type(value) is not tuple or len(value) != 4:
        raise Refused('git integration dependencies')
    tree, predecessor, date, message = value
    digest(tree)
    digest(predecessor)
    text(date)
    digest(message, 64)
    try:
        parsed = datetime.fromisoformat(date)
    except ValueError:
        raise Refused('git integration date') from None
    if parsed.tzinfo is None or parsed.isoformat() != date:
        raise Refused('git integration date')
    return value


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
        if key not in ('leases', 'new_inputs'):
            text(value)
    args, requirements, output, additions, stdin = (), (), None, (), None
    origin = 'parent' if role == 'parent' else str(cwd)
    if operation in ('rollback-add', 'rollback-update', 'rollback-reset') and family != 'evolution':
        raise Refused('git rollback family')
    if operation in FIXED:
        args = FIXED[operation]
        kind = {'head': 'commit', 'head-tree': 'tree', 'write-tree': 'tree'}.get(operation)
        output = None if kind is None else (origin, kind, ())
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
            requirements = (('parent', 'commit', revision, ()),)
            args = ('worktree', 'add', '--detach', *(('--no-checkout',) if operation == 'lease-add' else ()), str(tree), revision)
    elif operation in ('verify-base', 'checkout', 'diff-return', 'date', 'reset-parent', 'rollback-reset'):
        revision = digest(fields['revision'])
        requirements = ((fields['new_location'], 'integration-commit', revision, integration_inputs(fields['new_inputs'])),) if operation == 'reset-parent' else (('parent', 'commit', revision, ()),)
        if operation == 'reset-parent' and location_role(repo, path(fields['new_location'])) != 'integration':
            raise Refused('git reset producer location')
        args = {'verify-base': ('rev-parse', '--verify', revision + '^{commit}'),
            'checkout': ('checkout', '--detach', revision), 'diff-return': ('diff', '--cached', '--binary', '--no-ext-diff', revision),
            'date': ('show', '-s', '--format=%aI', revision), 'reset-parent': ('reset', '--hard', revision), 'rollback-reset': ('reset', '--hard', revision)}[operation]
        output = ('parent', 'commit', ()) if operation == 'verify-base' else ('parent', 'date', (revision,)) if operation == 'date' else None
    elif operation == 'apply':
        patch = path(fields['patch'])
        if patch.parent != repo / '.unrest/workspaces/patches' or patch.suffix != '.patch':
            raise Refused('git patch scope')
        digest(patch.stem, 64)
        args = ('apply', '--index', '--binary', str(patch))
    elif operation in ('update-parent', 'rollback-update'):
        new, old = digest(fields['new']), digest(fields['old'])
        if operation == 'update-parent':
            if location_role(repo, path(fields['new_location'])) != 'integration':
                raise Refused('git update producer location')
            inputs = integration_inputs(fields['new_inputs'])
            if inputs[1] != old:
                raise Refused('git integration predecessor')
            requirements = (('parent', 'commit', old, ()), (fields['new_location'], 'integration-commit', new, inputs))
        else:
            requirements = (('parent', 'commit', old, ()), ('parent', 'commit', new, ()))
        args = ('update-ref', 'refs/heads/main', new, old)
    elif operation == 'commit-tree':
        tree, revision, date, leases = fields['tree_id'], digest(fields['revision']), fields['date'], fields['leases']
        digest(tree)
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
        requirements = ((str(cwd), 'tree', tree, ()), ('parent', 'commit', revision, ()), ('parent', 'date', date, (revision,)))
        inputs = integration_inputs((tree, revision, date, hashlib.sha256(stdin.encode()).hexdigest()))
        args, output = ('commit-tree', tree, '-p', revision), (str(cwd), 'integration-commit', inputs)
    return Command(('git', *args), str(cwd), additions, stdin, requirements, output)
