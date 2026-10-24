"""Finite observed update-ref and integration-reset children of owned worktrees."""
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
    registration = selected.get('registration', {})
    binding = registration.get('source_binding', {})
    relative = binding.get('path', '').removeprefix(checkout + '/')
    site = binding.get('caller_line') if relative == SOURCE else binding.get('line')
    if (relative, site) not in {(SOURCE, 314), (SOURCE, 616), ('src/unrest_harness/evolution.py', 1881)}:
        return False
    pin = data['PINS'][relative]
    expected_binding = {'path': checkout + '/' + SOURCE, 'sha256': pin, 'function': '_git', 'line': 222,
                        'caller': 'lease_workspace' if site == 314 else '_build_integration_commit', 'caller_line': site,
                        'expression_ast_sha256': data['SITES'][site][1] if site in {314, 616} else data['ROLLBACK_AST']}
    expected_class = 'source-workspace-bound-git'
    if site == 1881:
        expected_binding = {'path': checkout + '/' + relative, 'sha256': pin, 'line': 1881,
                            'expression_ast_sha256': data['ROLLBACK_AST']}
        expected_class = 'source-git:' + relative + ':1881'
    argv = parent['argv']
    if (binding != expected_binding or registration.get('class') != expected_class
            or manifest['product_pins'].get(relative) != pin
            or hashlib.sha256(Path(binding['path']).read_bytes()).hexdigest() != pin
            or len(argv) != (7 if site == 314 else 6)
            or argv[:-2] != (['git', 'worktree', 'add', '--detach', '--no-checkout'] if site == 314 else ['git', 'worktree', 'add', '--detach'])
            or not re.fullmatch('[0-9a-f]{40}', argv[-1])
            or (vector != [IMAGE, 'update-ref', 'HEAD', argv[-1]]
                and not (site in {616, 1881} and vector == [IMAGE, 'reset', '--hard', '--no-recurse-submodules']))
            or selected.get('bootstrap_sha256') is not None
            or selected.get('owner_pid') != registration.get('owner_pid')
            or not selected.get('token') or selected['token'] != registration.get('token')
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(argv).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(parent['environment'], sort_keys=True).encode()).hexdigest()
            or parent['cwd'] != cwd or selected.get('cwd') != cwd):
        return False
    repository, tree = Path(cwd), Path(argv[-2])
    if (repository.resolve() != repository or not repository.is_relative_to(Path(manifest['owned_root']) / 'pytest')
            or tree.parent != repository / ('.unrest-runtime/workspaces/trees' if site == 314 else '.unrest-runtime/workspaces' if site == 616 else '.unrest-runtime/evolution')
            or (site != 314 and not re.fullmatch(('integration-' if site == 616 else 'rollback-') + '[a-z0-9_]{8}', tree.name))
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
    expected_head = b'0' * 40 + b'\n' if vector[1] == 'update-ref' else (argv[-1] + '\n').encode()
    if head.resolve() != head or not head.is_file() or regular(head, 64) != expected_head:
        return False
    expected = {**parent['environment'], 'GIT_DIR': str(tree / '.git'), 'GIT_WORK_TREE': str(tree),
                'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                'PATH': '/usr/lib/git-core:' + parent['environment']['PATH']}
    return environment == expected


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if (path != IMAGE or len(vector) != 4
            or (vector[:3] != [IMAGE, 'update-ref', 'HEAD']
                and vector != [IMAGE, 'reset', '--hard', '--no-recurse-submodules'])):
        return False
    parent = trace.identities[pid]['ppid']
    context, selected = authority.native_context.get(parent), authority.bound.get(parent)
    consumed = getattr(authority, 'worktree_ref_parents', set())
    operation = (parent, vector[1])
    if context is None or selected is None or operation in consumed:
        return False
    before = identity(parent)
    saved = authority.contexts.get(parent)
    if (saved is None or before != saved['identity']
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['git_maintenance_sha256']
            or Path('/proc/' + str(parent) + '/cwd').resolve() != Path(cwd)
            or not metadata(context, selected, vector, environment, cwd, authority.manifest)
            or identity(parent) != before):
        return False
    prior_wait = None
    if vector[1] == 'reset':
        previous = getattr(authority, 'worktree_ref_children', {}).get(parent)
        if previous is None or previous['parent_identity'] != before or previous['token'] != selected['token']:
            return False
        current_records = trace.records[previous['trace_records']:]
        waits = [row for row in current_records if row.get('kind') == 'original_parent_wait4'
                 and row.get('parent_tgid') == parent and row.get('child') == previous['pid']
                 and row.get('raw') == 0 and row.get('normalized') == 0]
        exits = [row for row in current_records if row.get('kind') == 'tracer_terminal_wait'
                 and row.get('pid') == previous['pid'] and row.get('raw') == 0 and row.get('normalized') == 0
                 and all(row.get('identity', {}).get(key) == previous['identity'].get(key)
                         for key in ('pid', 'ppid', 'start_ticks', 'boot_id'))]
        if len(waits) != 1 or len(exits) != 1:
            return False
        prior_wait = hashlib.sha256(json.dumps(waits[0], sort_keys=True).encode()).hexdigest()
    child = identity(pid)
    if child['ppid'] != parent:
        return False
    consumed.add(operation)
    authority.worktree_ref_parents = consumed
    if vector[1] == 'update-ref':
        children = getattr(authority, 'worktree_ref_children', {})
        children[parent] = {'pid': pid, 'identity': child, 'parent_identity': before, 'token': selected['token'], 'trace_records': len(trace.records)}
        authority.worktree_ref_children = children
    authority.contexts[pid] = {'role': 'source-worktree-child', 'identity': child}
    authority.pipe_records.append({'kind': 'worktree_git_child', 'operation': vector[1], 'pid': pid, 'identity': child,
                                   'prior_actual_wait_sha256': prior_wait,
                                   'parent_identity': before, 'original_worktree_token': selected['token'],
                                   'executable_sha256': authority.manifest['git_maintenance_sha256']})
    return True
