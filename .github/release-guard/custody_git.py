"""Closed native Git family used by the original controlled custody helper.

Only disposable repositories, fixed templates and the pinned original helper
are valid. No remote, URL, external diff, hook or user configuration is admitted.
"""
from __future__ import annotations

import configparser
from pathlib import Path
import stat

from content_manifest import Refused
from controlled_cases import CASES
from controlled_pairs import limits
from cohort_cases import CASES as COHORT, EXTRA
from git_commands import Command
from git_observer import regular
from git_operands import digest

ENVIRONMENT = {
    'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
    'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
    'GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid',
    'GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid',
    'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000',
}
PREFIX = ('/usr/bin/git','--no-replace-objects','-c','maintenance.auto=false','-c','gc.auto=0')
FIXED = (
    ('init','--initial-branch=main','--object-format=sha1'), ('add','.'),
    ('commit','-m','finite fixture'), ('commit','-m','base'), ('rev-parse','HEAD'),
    ('commit','--allow-empty','-m','sealed candidate'),
    ('commit','--allow-empty','-m','authored lane integration'),
)


def command(case, argv, cwd, owned):
    if type(case) is not str or case not in (*CASES,*COHORT) or type(argv) is not tuple or any(type(v) is not str for v in argv):
        raise Refused('custody Git finite command primitives')
    if type(cwd) is not str or str(Path(cwd).resolve()) != cwd or not Path(cwd).is_relative_to(owned/'pytest'):
        raise Refused('custody Git owned repository')
    if argv[:len(PREFIX)] != PREFIX:
        raise Refused('custody Git literal executable and prefix')
    args = argv[len(PREFIX):]
    if args not in (*FIXED,*EXTRA.get(case,())):
        if args[:2] == ('add','--'):
            if args[2:] not in (('a',),('b',),('lane_a.txt',),('lane_b.txt',)):
                raise Refused('custody Git exact authored scope')
        elif len(args) == 4 and args[:3] == ('diff','--cached','--name-only'):
            digest(args[3])
        else:
            raise Refused('custody Git undeclared template')
    kind = 'head' if args == ('rev-parse','HEAD') else 'commit' if args[0] == 'commit' else 'other'
    return Command(argv,cwd),kind


def repository(cwd, owned, *, initialize):
    root = Path(cwd)
    if str(root.resolve(strict=True)) != cwd or not root.is_relative_to(owned/'pytest'):
        raise Refused('custody Git repository alias')
    identities = []
    base = owned/'pytest'
    for path in (root,*(parent for parent in root.parents if parent.is_relative_to(base))):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or info.st_mode & 0o6022:
            raise Refused('custody Git directory custody')
        identities.append((str(path),info.st_dev,info.st_ino,info.st_uid))
    metadata = root/'.git'
    if initialize:
        if metadata.exists() or metadata.is_symlink():
            raise Refused('custody Git repeated initialization')
        return tuple(identities),None
    info = metadata.lstat()
    if (not stat.S_ISDIR(info.st_mode) or metadata.resolve(strict=True) != metadata
            or info.st_uid != 20000 or info.st_mode & 0o6022):
        raise Refused('custody Git metadata generation')
    metadata_identity = info.st_dev,info.st_ino,info.st_uid
    parser = configparser.RawConfigParser(strict=True)
    parser.read_string(regular(metadata/'config').decode('utf-8'))
    if (parser.defaults() or parser.sections() != ['core'] or dict(parser['core']) != {
            'repositoryformatversion':'0','filemode':'true','bare':'false','logallrefupdates':'true'}):
        raise Refused('custody Git fixed local configuration')
    for name in ('objects/info/alternates','objects/info/http-alternates','info/grafts','shallow','commondir'):
        member = metadata/name
        if member.exists() or member.is_symlink():
            raise Refused('custody Git external metadata')
    for member in (metadata/'hooks').iterdir():
        if not member.name.endswith('.sample'):
            raise Refused('custody Git active hook')
        regular(member,65536)
    return tuple(identities),metadata_identity


def launch(host,actor,result,kind,expected):
    from cohort_controller import parent
    parent(host,actor)
    prior = [v for v in host.intents.values() if v['case'] == host.case and v['role'] == 'git-custody']
    from cohort_controller import CASES as CRASH
    maximum=4 if host.case in CRASH else COHORT[host.case][1] if host.case in COHORT else 12+8*limits(host.case)[0]
    if len(prior) >= maximum:
        raise Refused('custody Git finite case command bound')
    identity = repository(result.cwd,Path(host.meta['owned']),initialize=result.argv[len(PREFIX)] == 'init')
    key = host.case,result.cwd
    previous = host.git.custody_roots.get(key)
    if previous is not None and (previous[0] != identity[0] or previous[1] is not None and previous[1] != identity[1]):
        raise Refused('custody Git replaced repository generation')
    host.git.custody_roots[key] = identity
    answer = host.admit_launch(actor,expected,'git-custody',list(result.argv),None,maximum=maximum)
    if answer is None:
        return None
    intent = host.intents[answer['ticket']]
    intent.update(command=result,repository=result.cwd,operation='custody-'+kind)
    host.git.commands[intent['token']] = intent
    return answer
