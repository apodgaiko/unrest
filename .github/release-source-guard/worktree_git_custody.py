"""One stock update-ref child of the original owned detached-worktree launch."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re

from finite.linux_identity import identity
from linux_git import regular

IMAGE = '/usr/lib/git-core/git'
SOURCE = 'src/unrest_harness/workspaces.py'


def metadata(parent, selected, vector, environment, cwd, manifest, checkout='/source'):
    data_path = Path(__file__).parent / 'finite/workspace_git_data.py'
    body = data_path.read_bytes()
    if hashlib.sha256(body).hexdigest() != manifest['direct_support']['files'].get('/guard/finite/workspace_git_data.py'):
        return False
    data = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(body).body if isinstance(n, ast.Assign)}
    pin = data['PINS'][SOURCE]
    registration = selected.get('registration', {})
    binding = registration.get('source_binding', {})
    expected_binding = {'path': checkout + '/' + SOURCE, 'sha256': pin, 'function': '_git', 'line': 222,
                        'caller': 'lease_workspace', 'caller_line': 314,
                        'expression_ast_sha256': data['SITES'][314][1]}
    argv = parent['argv']
    if (binding != expected_binding or registration.get('class') != 'source-workspace-bound-git'
            or manifest['product_pins'].get(SOURCE) != pin
            or hashlib.sha256(Path(binding['path']).read_bytes()).hexdigest() != pin
            or len(argv) != 7 or argv[:5] != ['git', 'worktree', 'add', '--detach', '--no-checkout']
            or not re.fullmatch('[0-9a-f]{40}', argv[6])
            or vector != [IMAGE, 'update-ref', 'HEAD', argv[6]]
            or selected.get('bootstrap_sha256') is not None
            or selected.get('owner_pid') != registration.get('owner_pid')
            or not selected.get('token') or selected['token'] != registration.get('token')
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(argv).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(parent['environment'], sort_keys=True).encode()).hexdigest()
            or parent['cwd'] != cwd or selected.get('cwd') != cwd):
        return False
    repository, tree = Path(cwd), Path(argv[5])
    if (repository.resolve() != repository or not repository.is_relative_to(Path(manifest['owned_root']) / 'pytest')
            or tree.parent != repository / '.unrest-runtime/workspaces/trees'
            or tree.resolve() != tree or not tree.is_dir() or not re.fullmatch('[A-Za-z0-9_-]+', tree.name)):
        return False
    common = repository / '.git'
    admin = common / 'worktrees' / tree.name
    if any(p.resolve() != p or not p.is_dir() for p in (common, admin)):
        return False
    if (regular(tree / '.git', 4096) != ('gitdir: ' + str(admin) + '\n').encode()
            or regular(admin / 'gitdir', 4096) != (str(tree / '.git') + '\n').encode()
            or regular(admin / 'commondir', 256) != b'../..\n'):
        return False
    head = admin / 'HEAD'
    if head.resolve() != head or not head.is_file() or regular(head, 64) != b'0' * 40 + b'\n':
        return False
    expected = {**parent['environment'], 'GIT_DIR': str(tree / '.git'), 'GIT_WORK_TREE': str(tree),
                'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                'PATH': '/usr/lib/git-core:' + parent['environment']['PATH']}
    return environment == expected


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != IMAGE or len(vector) != 4 or vector[:3] != [IMAGE, 'update-ref', 'HEAD']:
        return False
    parent = trace.identities[pid]['ppid']
    context, selected = authority.native_context.get(parent), authority.bound.get(parent)
    consumed = getattr(authority, 'worktree_ref_parents', set())
    if context is None or selected is None or parent in consumed:
        return False
    before = identity(parent)
    saved = authority.contexts.get(parent)
    if (saved is None or before != saved['identity']
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['git_maintenance_sha256']
            or Path('/proc/' + str(parent) + '/cwd').resolve() != Path(cwd)
            or not metadata(context, selected, vector, environment, cwd, authority.manifest)
            or identity(parent) != before):
        return False
    child = identity(pid)
    if child['ppid'] != parent:
        return False
    consumed.add(parent)
    authority.worktree_ref_parents = consumed
    authority.contexts[pid] = {'role': 'source-worktree-update-ref', 'identity': child}
    authority.pipe_records.append({'kind': 'worktree_update_ref_child', 'pid': pid, 'identity': child,
                                   'parent_identity': before, 'original_worktree_token': selected['token'],
                                   'executable_sha256': authority.manifest['git_maintenance_sha256']})
    return True
