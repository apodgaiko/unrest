"""One observed stock maintenance child of each exact original candidate commit."""
from __future__ import annotations

import configparser
import hashlib
from pathlib import Path
import re
import zlib

from finite.candidate_git import SOURCE, environment as fixture_environment
from finite.linux_identity import identity
from linux_git import regular
from candidate_git_custody import eligible

VECTOR = ['/usr/lib/git-core/git', 'maintenance', 'run', '--auto', '--no-quiet']
SITES = {('repo', 41): 'base', ('repo', 46): 'candidate',
         ('test_unsupported_tree_entries', 402): 'unsupported',
         ('test_executable_tracked_file_and_nested_extra', 454): 'executable'}


def metadata(parent, environment, cwd, owned_root):
    registration = parent['candidate_registration']
    binding = registration['source_binding']
    message = SITES.get((binding.get('caller'), binding.get('caller_line')))
    root = Path(cwd)
    if (message is None or parent['argv'] != ['/usr/bin/git', 'commit', '-m', message]
            or parent['cwd'] != cwd or parent['environment'] != fixture_environment(root)
            or root.resolve() != root or root.name != 'repository'
            or not root.is_relative_to(Path(owned_root) / 'pytest')
            or (binding['caller'] != 'repo' and registration['case'].split('[', 1)[0]
                != SOURCE + '::' + binding['caller'])):
        return False
    git = root / '.git'
    if git.is_symlink() or not git.is_dir():
        return False
    config = configparser.RawConfigParser(strict=True)
    config.read_string(regular(git / 'config', 4096).decode())
    if (config.defaults() or set(config.sections()) != {'core', 'user'}
            or dict(config['core']) != {'repositoryformatversion': '0', 'filemode': 'true',
                                       'bare': 'false', 'logallrefupdates': 'true'}
            or dict(config['user']) != {'name': 'Fixture', 'email': 'fixture@example.invalid'}
            or regular(git / 'HEAD', 256) != b'ref: refs/heads/main\n'):
        return False
    reference = git / 'refs/heads/main'
    if reference.resolve() != reference:
        return False
    oid = regular(reference, 64).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', oid):
        return False
    object_path = git / 'objects' / oid[:2] / oid[2:]
    if object_path.resolve() != object_path:
        return False
    decoder = zlib.decompressobj()
    raw = decoder.decompress(regular(object_path, 16384), 16385)
    header, separator, commit = raw.partition(b'\0')
    if (len(raw) > 16384 or not decoder.eof or decoder.unused_data
            or hashlib.sha1(raw).hexdigest() != oid or not separator
            or header != b'commit ' + str(len(commit)).encode()
            or b'\nauthor Fixture <fixture@example.invalid> 946684800 +0000\n' not in commit
            or b'\ncommitter Fixture <fixture@example.invalid> 946684800 +0000\n' not in commit
            or not commit.endswith(b'\n\n' + message.encode() + b'\n')):
        return False
    expected = {**parent['environment'], 'PATH': '/usr/lib/git-core:/usr/bin:/bin',
                'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                'GIT_AUTHOR_DATE': '@946684800 +0000'}
    return environment == expected


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != VECTOR[0] or vector != VECTOR:
        return False
    parent = trace.identities[pid]['ppid']
    context = authority.native_context.get(parent)
    selected = authority.bound.get(parent)
    if (context is None or selected is None or parent in authority.maintenance
            or context.get('candidate_registration') != selected.get('registration')
            or not eligible(selected, context['argv'], context['environment'], context['cwd'],
                            '/source', authority.manifest['owned_root'], authority.manifest['product_pins'])):
        return False
    before = identity(parent)
    if (before != authority.contexts[parent]['identity']
            or Path('/proc/' + str(pid) + '/cwd').resolve() != Path(cwd)
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['git_maintenance_sha256']
            or not metadata(context, environment, cwd, authority.manifest['owned_root'])
            or identity(parent) != before):
        return False
    authority.maintenance.add(parent)
    authority.contexts[pid] = {'role': 'source-git-maintenance', 'identity': identity(pid)}
    authority.pipe_records.append({'kind': 'candidate_git_maintenance_child', 'pid': pid,
                                   'identity': identity(pid), 'parent_identity': before,
                                   'original_commit_token': selected['token'],
                                   'executable_sha256': authority.manifest['git_maintenance_sha256']})
    return True
