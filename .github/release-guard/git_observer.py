"""Independent Git declarations, owned metadata and causal stdout/wait joins."""
from __future__ import annotations

from contextlib import ExitStack
import configparser
import os
from pathlib import Path
import stat

from content_manifest import Refused, native_digest, _root, _directory_key
from git_commands import location_role
from git_sites import CASES, OPERATIONS
from git_values import Values

HOME_CONFIG = b'[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n'
SETUP = ('init', 'config-name', 'config-email', 'stage-base', 'commit-base')


def regular(file, maximum=4096, uid=20000):
    with ExitStack() as stack:
        parent, chain = _root(stack, file.parent)
        fd = os.open(file.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o6022 or not 0 < before.st_size <= maximum):
            raise Refused('git metadata custody')
        raw = os.read(fd, maximum + 1)
        def key(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != before.st_size or key(before) != key(os.fstat(fd))
                or key(before) != key(os.stat(file.name, dir_fd=parent, follow_symlinks=False))):
            raise Refused('git metadata read race')
        for ancestor, part, child, expected in reversed(chain):
            if expected != _directory_key(os.fstat(child)) or expected != _directory_key(os.stat(part, dir_fd=ancestor, follow_symlinks=False)):
                raise Refused('git metadata ancestor changed')
        return raw


def image(file='/usr/bin/git'):
    target = Path(file)
    if str(target.resolve(strict=True)) != file:
        raise Refused('git native image alias')
    for member in (target, *target.parents):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('git native image custody')
        if member == target:
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise Refused('git native executable')
        elif not stat.S_ISDIR(info.st_mode):
            raise Refused('git native ancestor')
    return native_digest(target)


class Git:
    def __init__(self, observer):
        self.host = observer
        self.values = Values(observer.ledger)
        self.repositories, self.commands, self.last = {}, {}, {}
        self.helpers = {}
        self.custody_roots = {}

    def repository(self, repository, operation, family):
        root = Path(repository)
        owned = Path(self.host.meta['owned'])
        if (root.name != 'project' or root.parent.parent != owned / 'pytest'
                or str(root.resolve(strict=True)) != repository):
            raise Refused('git original repository location')
        identities = []
        for directory in (root.parent, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or stat.S_IMODE(info.st_mode) & 0o6022:
                raise Refused('git repository custody')
            identities.append((info.st_dev, info.st_ino, info.st_uid))
        slot = self.repositories.get(self.host.case)
        if slot is None:
            if operation != 'init' or (root / '.git').exists():
                raise Refused('git first original fixture operation')
            slot = {'path': repository, 'identities': identities, 'setup': 0}
            self.repositories[self.host.case] = slot
        if slot['path'] != repository or slot['identities'] != identities:
            raise Refused('git repository generation')
        if slot['setup'] < len(SETUP):
            if operation != SETUP[slot['setup']]:
                raise Refused('git fixture setup order')
        if slot['setup']:
            parser = configparser.RawConfigParser(strict=True)
            parser.read_string(regular(root / '.git/config').decode('utf-8'))
            user = {} if slot['setup'] == 1 else {'name': 'Workspace Test' if family == 'workspaces' else 'Evolution Test'}
            if slot['setup'] >= 3:
                user['email'] = 'workspace@example.test' if family == 'workspaces' else 'evolution@example.test'
            if (parser.defaults() or set(parser.sections()) != ({'core', 'user'} if user else {'core'})
                    or dict(parser['core']) != {'repositoryformatversion': '0', 'filemode': 'true', 'bare': 'false', 'logallrefupdates': 'true'}
                    or user and dict(parser['user']) != user
                    or regular(root / '.git/HEAD', 256) != b'ref: refs/heads/main\n'):
                raise Refused('git original repository configuration')
        if regular(owned / 'home/.gitconfig', uid=20001) != HOME_CONFIG:
            raise Refused('git immutable diagnostic home configuration')
        if slot['setup'] < len(SETUP):
            slot['setup'] += 1
        return root

    def location(self, root, location):
        path = Path(location)
        role = location_role(root, path)
        if role == 'parent':
            return
        common, admin = root / '.git', root / '.git/worktrees' / path.name
        if (not path.is_dir() or str(path.resolve(strict=True)) != location
                or not admin.is_dir() or admin.resolve(strict=True) != admin
                or regular(path / '.git') != ('gitdir: ' + str(admin) + '\n').encode()
                or regular(admin / 'gitdir') != (str(path / '.git') + '\n').encode()
                or regular(admin / 'commondir') != b'../..\n' or common.resolve(strict=True) != common):
            raise Refused('git linked worktree backlinks')

    def launch(self, actor, operation, repository, command, expected, vector):
        host = self.host
        host.root_only(actor)
        if host.case not in CASES:
            raise Refused('Git finite case')
        if operation=='owned-process':
            return self.owned_launch(actor,repository,expected,vector)
        family='workspaces' if host.case.startswith('tests/test_workspaces.py::') else 'evolution'
        if operation not in OPERATIONS[family]:
            raise Refused('Git finite operation declaration')
        previous = self.last.get(host.case)
        if previous is not None and (not previous['consumed'] or not host.ledger.reaped(previous['birth'], previous['token'])
                or not self.values.descendants_reaped(previous['birth'])
                or previous['command'].produces is not None and not previous.get('value_observed')):
            raise Refused('git next command before original parent/output join')
        root = self.repository(repository, operation, family)
        self.location(root, command.cwd)
        for location, kind, value, inputs in command.requires:
            self.values.require(host.case, str(root), location, kind, value, inputs)
        answer = host.admit_launch(actor,expected,'git-command',vector,None,maximum=128)
        if answer is None:
            return None
        intent = host.intents[answer['ticket']]
        intent.update(command=command, repository=str(root), operation=operation)
        self.commands[intent['token']] = intent
        self.last[host.case] = intent
        return answer

    def command(self, pid, token):
        if type(pid) is not int or type(token) is not str:
            raise Refused('git command identity primitives')
        intent = self.commands.get(token)
        if intent is None or intent['pid'] != pid or intent['case'] != self.host.case:
            raise Refused('git command identity')
        return intent

    def seal_pipe(self, actor, payload):
        host = self.host
        host.root_only(actor)
        if type(payload) is not dict or set(payload) != {'pid', 'token', 'fd', 'dev', 'ino'}:
            raise Refused('git producer pipe schema')
        intent = self.command(payload['pid'], payload['token'])
        fd = payload['fd']
        if (type(fd) is not int or not 3 <= fd <= 1024 or intent['command'].produces is None
                or intent['token'] != payload['token'] or intent.get('pipe') is not None
                or not host.actors[intent['pid']]['returned']):
            raise Refused('git producer pipe generation')
        info = (Path('/proc') / str(actor['birth'].pid) / 'fd' / str(fd)).stat()
        if (not stat.S_ISFIFO(info.st_mode) or (info.st_dev, info.st_ino) != intent['stdout']
                or any(type(payload[k]) is not int for k in ('dev', 'ino'))
                or (payload['dev'], payload['ino']) != intent['stdout']):
            raise Refused('git original stdout pipe')
        intent['pipe'] = (fd, info.st_dev, info.st_ino)
        return {'ok': True}

    def output(self, actor, payload):
        host = self.host
        host.root_only(actor)
        if type(payload) is not dict or set(payload) != {'pid', 'token', 'pipe', 'stdout'}:
            raise Refused('git original stdout schema')
        intent = self.command(payload['pid'], payload['token'])
        if (type(payload['pipe']) is not list or any(type(v) is not int for v in payload['pipe'])
                or tuple(payload['pipe']) != intent.get('pipe') or intent['token'] != payload['token']
                or intent['command'].produces is None):
            raise Refused('git stdout pipe join')
        location, kind, inputs = intent['command'].produces
        value = self.values.observe(intent['birth'], intent['token'], host.case, intent['repository'],
            location, kind, payload['stdout'], inputs=inputs)
        intent['value_observed'] = True
        return {'ok': True, 'value': value.value}


    def reserve_helper(self, birth, parent):
        host = self.host
        process = host.ledger.process(parent)
        intent = self.commands.get(process.token)
        if (intent is None or not intent['consumed'] or intent['case'] != host.case
                or intent['operation'] not in ('integration-add', 'rollback-add')
                or process.exit is not None or process.terminal is not None):
            raise Refused('git child outside original worktree creation')
        siblings = host.ledger.children.get(parent, ())
        if list(siblings) != [birth]:
            raise Refused('git single current checkout helper')
        tree, revision = intent['command'].argv[-2:]
        root, worktree = Path(intent['repository']), Path(tree)
        self.location(root, tree)
        expected_head = revision.encode() + b'\n'
        if regular(root / '.git/worktrees' / worktree.name / 'HEAD', 64) != expected_head:
            raise Refused('git helper detached HEAD phase')
        executable = '/usr/lib/git-core/git'
        if image(executable) != self.pin:
            raise Refused('git helper exact native image')
        environment = {**intent['environment'], 'GIT_DIR': str(worktree / '.git'), 'GIT_WORK_TREE': tree,
            'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
            'PATH': '/usr/lib/git-core:' + intent['environment']['PATH']}
        vector = [executable, 'reset', '--hard', '--no-recurse-submodules']
        host.serial += 1
        child = {'case': host.case, 'role': 'git-helper', 'parent': parent, 'environment': environment,
            'cwd': intent['cwd'], 'translated': vector, 'token': os.urandom(16).hex(), 'consumed': False,
            'pid': None, 'executable': executable, 'executable_sha256': self.pin, 'inherited': [], 'port': None}
        host.intents[host.serial] = child
        self.helpers[birth] = child

    def reaped(self, actor):
        birth = actor['birth']
        if actor['role'] == 'git-helper':
            process = self.host.ledger.process(birth)
            return self.values.native_child_reaped(process.parent, birth, actor['case'], process.pins)
        if actor['role'] in ('git-command','git-custody'):
            intent = self.commands[actor['token']]
            if intent['command'].produces is not None and not intent.get('value_observed'):
                return False
        return self.host.ledger.reaped(birth, actor['token'])


    def owned_launch(self, actor, repository, expected, vector):
        host = self.host
        if host.case != CASES[7] or self.repositories.get(host.case, {}).get('path') != repository:
            raise Refused('workspace owned launch scope')
        cwd = repository + '/.unrest-runtime/workspaces/trees/process'
        self.location(Path(repository), cwd)
        return host.admit_launch(actor,expected,'workspace-owned',vector,expected.payload_sha256)
