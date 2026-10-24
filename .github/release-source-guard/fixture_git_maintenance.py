"""Finite stock maintenance children of the original literal local Git fixtures."""
from __future__ import annotations

import ast
import configparser
import hashlib
import json
from pathlib import Path
import re
import zlib

from finite.linux_identity import identity
from linux_git import regular

VECTOR = ['/usr/lib/git-core/git', 'maintenance', 'run', '--auto', '--no-quiet']


def metadata(parent, selected, environment, cwd, manifest, checkout='/source'):
    registration = selected.get('registration', {})
    binding = registration.get('source_binding', {})
    source = binding.get('path', '')
    prefix = checkout + '/'
    if not source.startswith(prefix):
        return False
    relative = source.removeprefix(prefix)
    data_path = Path(__file__).parent / 'finite/workspace_git_data.py'
    body = data_path.read_bytes()
    expected_pin = manifest['direct_support']['files'].get('/guard/finite/workspace_git_data.py')
    if hashlib.sha256(body).hexdigest() != expected_pin:
        return False
    data = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(body).body
            if isinstance(n, ast.Assign)}
    site = data['FIXTURE_COMMITS'].get((relative, binding.get('caller_line')))
    if (site is None or binding.get('line') != site['helper_line'] or binding.get('caller') != site['caller'] or binding.get('function') != '_git'
            or binding.get('expression_ast_sha256') != site['expression_ast_sha256']
            or not registration.get('case', '').startswith(relative + '::')
            or registration.get('class') != 'source-literal-git:' + relative + ':' + str(binding['caller_line'])
            or binding.get('sha256') != site['source_sha256']
            or manifest['product_pins'].get(relative) != site['source_sha256']
            or hashlib.sha256(Path(source).read_bytes()).hexdigest() != site['source_sha256']
            or registration.get('python') is not False or selected.get('bootstrap_sha256') is not None
            or selected.get('owner_pid') != registration.get('owner_pid')
            or selected.get('token') is None or selected['token'] != registration.get('token')
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(parent['argv']).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(parent['environment'], sort_keys=True).encode()).hexdigest()
            or parent['argv'] != site['vector'] or parent['cwd'] != cwd or selected.get('cwd') != cwd):
        return False
    root = Path(cwd)
    if root.resolve() != root or not root.is_relative_to(Path(manifest['owned_root']) / 'pytest'):
        return False
    git = root / '.git'
    linked = (relative, binding['caller_line']) == ('tests/test_workspaces.py', 325)
    if linked:
        if (git.is_symlink() or not git.is_file()
                or registration['case'] != 'tests/test_workspaces.py::test_child_commit_is_not_parent_authority'):
            return False
        repository = root.parents[3]
        if root != repository / '.unrest-runtime/workspaces/trees/self-merge':
            return False
        common = repository / '.git'
        admin = common / 'worktrees/self-merge'
        if any(path.resolve() != path or not path.is_dir() for path in (common, admin)):
            return False
        if (regular(git, 4096) != ('gitdir: ' + str(admin) + '\n').encode()
                or regular(admin / 'commondir', 256) != b'../..\n'
                or regular(admin / 'gitdir', 4096) != (str(git) + '\n').encode()):
            return False
        oid = regular(admin / 'HEAD', 64).decode().strip()
        git = common
    else:
        if git.is_symlink() or not git.is_dir() or git.resolve() != git:
            return False
        if regular(git / 'HEAD', 256) != b'ref: refs/heads/main\n':
            return False
        reference = git / 'refs/heads/main'
        if reference.resolve() != reference:
            return False
        oid = regular(reference, 64).decode().strip()
    config = configparser.RawConfigParser(strict=True)
    config.read_string(regular(git / 'config', 4096).decode())
    if (config.defaults() or set(config.sections()) != {'core', 'user'}
            or dict(config['core']) != {'repositoryformatversion': '0', 'filemode': 'true',
                                       'bare': 'false', 'logallrefupdates': 'true'}
            or dict(config['user']) != {'name': site['user'], 'email': site['email']}):
        return False
    if not re.fullmatch('[0-9a-f]{40}', oid):
        return False
    object_path = git / 'objects' / oid[:2] / oid[2:]
    if object_path.resolve() != object_path:
        return False
    decoder = zlib.decompressobj()
    raw = decoder.decompress(regular(object_path, 16384), 16385)
    header, separator, commit = raw.partition(b'\0')
    author = re.search(rb'^author ' + re.escape((site['user'] + ' <' + site['email'] + '> ').encode())
                       + rb'([0-9]+ [+-][0-9]{4})$', commit, re.MULTILINE)
    committer = re.search(rb'^committer ' + re.escape((site['user'] + ' <' + site['email'] + '> ').encode())
                          + rb'[0-9]+ [+-][0-9]{4}$', commit, re.MULTILINE)
    if (len(raw) > 16384 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or hashlib.sha1(raw).hexdigest() != oid or not separator
            or header != b'commit ' + str(len(commit)).encode() or author is None or committer is None
            or not commit.endswith(b'\n\n' + site['vector'][-1].encode() + b'\n')):
        return False
    expected = {**parent['environment'], 'PATH': '/usr/lib/git-core:' + parent['environment']['PATH'],
                'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                'GIT_AUTHOR_NAME': site['user'], 'GIT_AUTHOR_EMAIL': site['email'],
                'GIT_AUTHOR_DATE': '@' + author.group(1).decode()}
    return environment == expected


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != VECTOR[0] or vector != VECTOR:
        return False
    parent = trace.identities[pid]['ppid']
    context = authority.native_context.get(parent)
    selected = authority.bound.get(parent)
    if context is None or selected is None or parent in authority.maintenance:
        return False
    before = identity(parent)
    saved = authority.contexts.get(parent)
    if (saved is None or before != saved['identity']
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['git_maintenance_sha256']
            or Path('/proc/' + str(parent) + '/cwd').resolve() != Path(cwd)
            or not metadata(context, selected, environment, cwd, authority.manifest)
            or identity(parent) != before):
        return False
    child = identity(pid)
    if child['ppid'] != parent:
        return False
    authority.maintenance.add(parent)
    authority.contexts[pid] = {'role': 'source-git-maintenance', 'identity': child}
    authority.pipe_records.append({'kind': 'fixture_git_maintenance_child', 'pid': pid,
                                   'token': selected['token'], 'identity': child,
                                   'parent_identity': before,
                                   'executable_sha256': authority.manifest['git_maintenance_sha256']})
    return True
