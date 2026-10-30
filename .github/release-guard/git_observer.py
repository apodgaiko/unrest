"""Independent finite Git declarations, owned metadata and actual parent waits."""
from __future__ import annotations

import os
from pathlib import Path
import stat

from content_manifest import Refused, native_digest, read_regular
from git_commands import location_role
from git_sites import CASES, OPERATIONS

HOME_CONFIG = b'[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n'


def regular(file, maximum=4096, uid=20000):
    return read_regular(file,maximum,uid=uid,minimum=1,forbidden=0o6022)[0]


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


def issue(host,actor,raw,command,environment,*,role='git-command',maximum=128,fields=None):
    from launch_policy import build_expected,admit_expected
    if raw['executable']!='/usr/bin/git' or raw['stdin']!=command.stdin:
        raise Refused('Git exact executable and input')
    expected=build_expected(host.case,'/usr/bin/git',image(),command.argv,
        tuple(sorted(environment.items())),command.cwd,'native')
    vector=['/usr/bin/git',*command.argv[1:]]
    answer=admit_expected(host,actor,raw,expected,role,vector,maximum=maximum,fields=fields)
    if answer is not None and fields is not None:
        host.git.commands[answer['token']]=host.intents[answer['ticket']]
    return answer


class Git:
    def __init__(self, observer):
        self.host = observer
        self.repositories, self.commands = {}, {}
        self.helpers = {}
        self.custody_roots = {}

    def repository(self, repository, operation, family):
        root = Path(repository)
        owned = Path(self.host.meta['owned'])
        from git_fixtures import SLOTS,fixture as declared_fixture,root as fixture_root
        fixture=declared_fixture(self.host.case) if self.host.case in SLOTS else None
        if fixture is not None:
            fixture_root(self.host,self.host.case,repository)
        if (((root.name != 'project' or root.parent.parent != owned / 'pytest') if fixture is None else root.name not in SLOTS[self.host.case])
                or str(root.resolve(strict=True)) != repository):
            raise Refused('git original repository location')
        identities = []
        for directory in (root.parent, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or stat.S_IMODE(info.st_mode) & 0o6022:
                raise Refused('git repository custody')
            identities.append((info.st_dev, info.st_ino, info.st_uid))
        key=(self.host.case,repository)
        slot = self.repositories.get(key)
        if slot is None:
            if operation != 'init' or (root / '.git').exists():
                raise Refused('git first original fixture operation')
            slot = {'path': repository, 'identities': identities}
            self.repositories[key] = slot
        if slot['path'] != repository or slot['identities'] != identities:
            raise Refused('git repository generation')
        metadata=root/'.git'
        if not metadata.exists() and not metadata.is_symlink():
            if operation!='init':
                raise Refused('git declared metadata missing')
        else:
            info=metadata.lstat()
            if (not stat.S_ISDIR(info.st_mode) or metadata.resolve(strict=True)!=metadata
                    or info.st_uid!=20000 or info.st_mode&0o6022):
                raise Refused('git declared metadata directory')
        return root

    def location(self, root, location):
        path = Path(location)
        location_role(root, path)
        if not path.is_dir() or str(path.resolve(strict=True)) != location:
            raise Refused('git original worktree directory')

    def launch(self, actor, operation, repository, command, raw, environment):
        host = self.host
        host.root_only(actor)
        if host.case not in CASES:
            raise Refused('Git finite case')
        from git_fixtures import SLOTS,fixture as declared_fixture
        family=declared_fixture(host.case).family if host.case in SLOTS else 'workspaces' if host.case.startswith('tests/test_workspaces.py::') else 'evolution'
        if operation not in OPERATIONS[family]:
            raise Refused('Git finite operation declaration')
        root = self.repository(repository, operation, family)
        self.location(root, command.cwd)
        return issue(host,actor,raw,command,environment,
            fields={'command':command,'repository':str(root),'operation':operation})

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
        tree = intent['command'].argv[-2]
        root, worktree = Path(intent['repository']), Path(tree)
        self.location(root, tree)
        executable = '/usr/lib/git-core/git'
        pin=intent['executable_sha256']
        if image(executable) != pin:
            raise Refused('git helper exact native image')
        environment = {**intent['environment'], 'GIT_DIR': str(worktree / '.git'), 'GIT_WORK_TREE': tree,
            'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
            'PATH': '/usr/lib/git-core:' + intent['environment']['PATH']}
        vector = [executable, 'reset', '--hard', '--no-recurse-submodules']
        host.serial += 1
        child = {'ticket':host.serial,'case': host.case, 'role': 'git-helper', 'parent': parent, 'environment': environment,
            'cwd': intent['cwd'], 'translated': vector, 'token': os.urandom(16).hex(), 'consumed': False,
            'pid': None, 'executable': executable, 'executable_sha256': pin, 'inherited': [], 'port': None}
        host.intents[host.serial] = child
        self.helpers[birth] = child

    def native_child_reaped(self,parent,birth,case,pins):
        ledger=self.host.ledger
        child,owner=ledger.process(birth),ledger.process(parent)
        return (child.parent==parent and child.case==owner.case==case
            and child.command_class=='native-git-helper' and owner.command_class in ('native-git-command','native-git-helper')
            and child.pins==owner.pins==pins and child.generation==child.registered_generation==1
            and owner.generation==owner.registered_generation==1 and ledger.reaped(birth,child.life_token)
            and child.terminal[2]==0 and child.parent_wait[3]==0)

    def reaped(self, actor):
        birth = actor['birth']
        if actor['role'] == 'git-helper':
            process = self.host.ledger.process(birth)
            return self.native_child_reaped(process.parent, birth, actor['case'], process.pins)
        return self.host.ledger.reaped(birth, actor['token'])


    def owned_launch(self, actor, repository, expected, vector):
        host = self.host
        if host.case != CASES[7] or self.repositories.get((host.case,repository), {}).get('path') != repository:
            raise Refused('workspace owned launch scope')
        cwd = repository + '/.unrest-runtime/workspaces/trees/process'
        self.location(Path(repository), cwd)
        return host.admit_launch(actor,expected,'workspace-owned',vector,expected.payload_sha256)
