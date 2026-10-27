"""Closed native Git family used by the original controlled custody helper.

Only disposable repositories, fixed templates and the pinned original helper
are valid. No remote, URL, external diff, hook or user configuration is admitted.
"""
from __future__ import annotations

import configparser
import importlib
from pathlib import Path
import stat
import subprocess

from content_manifest import Refused
from controlled_cases import CASES
from controlled_pairs import limits
from controlled_startup import Intent
from git_commands import Command
from git_observer import image, regular
from git_values import digest
from launch_policy import Observation, Rule, match, render
from source_owner import Link, active_frames, frame_fields, _namespace

SOURCE = 'src/unrest_harness/experimental_custody.py'
PIN = '1daba7ee49702f680d342f542f2e670fba0fb953234b7e4358a497f7abcae9a1'
ENVIRONMENT = {
    'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
    'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
    'GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid',
    'GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid',
    'GIT_AUTHOR_DATE':'2000-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2000-01-01T00:00:00+0000',
}
FIXED = (
    ('init','--initial-branch=main','--object-format=sha1'), ('add','.'),
    ('commit','-m','finite fixture'), ('commit','-m','base'), ('rev-parse','HEAD'),
    ('commit','--allow-empty','-m','sealed candidate'),
    ('commit','--allow-empty','-m','authored lane integration'),
)


def command(case, argv, cwd, owned):
    if type(case) is not str or case not in CASES or type(argv) is not tuple or any(type(v) is not str for v in argv):
        raise Refused('custody Git finite command primitives')
    if type(cwd) is not str or str(Path(cwd).resolve()) != cwd or not Path(cwd).is_relative_to(owned/'pytest'):
        raise Refused('custody Git owned repository')
    if argv[:2] != ('/usr/bin/git','--no-replace-objects'):
        raise Refused('custody Git literal executable and prefix')
    args = argv[2:]
    if args not in FIXED:
        if args[:2] == ('add','--'):
            if args[2:] not in (('a',),('b',),('lane_a.txt',),('lane_b.txt',)):
                raise Refused('custody Git exact authored scope')
        elif len(args) == 4 and args[:3] == ('diff','--cached','--name-only'):
            digest(args[3])
        else:
            raise Refused('custody Git undeclared template')
    kind = 'head' if args == ('rev-parse','HEAD') else 'commit' if args[0] == 'commit' else 'other'
    return Command(argv,cwd,produces=(cwd,'commit',()) if kind == 'head' else None),kind


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


class Calls:
    def __init__(self,calls):
        self.calls = calls
        self.module = importlib.import_module('unrest_harness.experimental_custody')
        if calls.pins[SOURCE] != PIN:
            raise Refused('custody Git original source bytes')
        unit = calls.unit(SOURCE,self.module,calls.mode(self.module))
        self.function = vars(self.module)['git']
        self.owner = calls.owner(unit,self.module,self.function,'git',(Link(self.module,'git',self.function),))
        self.run,self.run_code,self.run_globals = subprocess.run,subprocess.run.__code__,subprocess.run.__globals__
        self.pending = None

    def select(self,case,arguments):
        executable,vector,cwd,environment = arguments
        frames = active_frames()
        try:
            local = frame_fields(self.owner.current(frames,line=38))
            root,args = local.get('root'),local.get('arguments')
            if type(root) is not type(Path('/')) or type(args) is not tuple or any(type(v) is not str for v in args):
                raise Refused('custody Git original helper operands')
            result,_ = command(case,('/usr/bin/git','--no-replace-objects',*args),str(root),Path(self.calls.profile['owned']))
            constructors = [f for f in frames if f.f_code is self.run_code and f.f_globals is self.run_globals]
            if len(constructors) != 1 or subprocess.run is not self.run:
                raise Refused('custody Git original subprocess caller')
            options = frame_fields(constructors[0])
            popenargs,keywords = options.get('popenargs'),options.get('kwargs')
            if (type(popenargs) is not tuple or len(popenargs) != 1 or type(popenargs[0]) is not list
                    or any(type(value) is not str for value in popenargs[0]) or tuple(popenargs[0]) != result.argv
                    or type(keywords) is not dict):
                raise Refused('custody Git original subprocess containers')
            keywords = _namespace(keywords)
            env = keywords.get('env')
            if (set(keywords) != {'cwd','env','stdin','stdout','stderr'} or type(keywords['cwd']) is not type(root)
                    or keywords['cwd'] != root or type(env) is not dict
                    or any(type(key) is not str or type(value) is not str for key,value in env.items())
                    or env != ENVIRONMENT
                    or any(type(keywords[key]) is not int or keywords[key] != value
                        for key,value in (('stdin',-3),('stdout',-1),('stderr',-3)))
                    or type(options.get('timeout')) is not int or options['timeout'] != 5
                    or options.get('check') is not True or options.get('input') is not None):
                raise Refused('custody Git original subprocess options')
            expected = render(Rule('custody:git',SOURCE+':git',(case,),'/usr/bin/git',image(),result.argv,
                tuple(sorted(ENVIRONMENT.items())),str(root),'native',None),case,SOURCE+':git',{}, {})
            if (type(executable) is not str or type(vector) is not list or any(type(value) is not str for value in vector)
                    or type(environment) is not dict or type(cwd) is not type(root)
                    or any(type(key) is not str or type(value) is not str for key,value in environment.items())):
                raise Refused('custody Git audit primitives')
            match((expected,),Observation(executable,image(),tuple(vector),tuple(sorted(environment.items())),str(cwd),'native',expected.payload_sha256),expected.owner,case)
            self.pending = result
            return Intent(expected,expected.argv,38,None)
        finally:
            del frames


def launch(host,actor,payload):
    host.root_only(actor)
    original = payload['original']
    result,kind = command(host.case,tuple(original['argv']),original['cwd'],Path(host.meta['owned']))
    prior = [v for v in host.intents.values() if v['case'] == host.case and v['role'] == 'git-custody']
    if len(prior) >= 12+8*limits(host.case)[0]:
        raise Refused('custody Git finite case command bound')
    if any(not v['consumed'] or not host.ledger.reaped(v['birth'],v['token']) for v in prior):
        raise Refused('custody Git previous command actual wait')
    if result.argv[2:5] == ('diff','--cached','--name-only') and not any(
            row.case == host.case and row.kind == 'commit' and row.value == result.argv[-1]
            for row in host.git.values.values):
        raise Refused('custody Git diff without an actual prior commit producer')
    identity = repository(result.cwd,Path(host.meta['owned']),initialize=result.argv[2] == 'init')
    key = host.case,result.cwd
    previous = host.git.custody_roots.get(key)
    if previous is not None and (previous[0] != identity[0] or previous[1] is not None and previous[1] != identity[1]):
        raise Refused('custody Git replaced repository generation')
    host.git.custody_roots[key] = identity
    expected = render(Rule('custody:git',SOURCE+':git',(host.case,),'/usr/bin/git',image(),result.argv,
        tuple(sorted(ENVIRONMENT.items())),result.cwd,'native',None),host.case,SOURCE+':git',{}, {})
    answer = host.admit_launch(actor,payload,expected,'git-custody',38,list(result.argv),None,maximum=12+8*limits(host.case)[0])
    intent = host.intents[answer['ticket']]
    intent.update(command=result,repository=result.cwd,operation='custody-'+kind)
    host.git.commands[intent['token']] = intent
    return answer


def reserve_helper(host,birth,parent):
    """One stock auto-maintenance child of an already admitted commit only."""
    import os
    process = host.ledger.process(parent)
    intent = host.git.commands.get(process.token)
    if (intent is None or intent['case'] != host.case or intent['operation'] != 'custody-commit'
            or not intent['consumed'] or process.exit is not None or process.terminal is not None
            or list(host.ledger.children.get(parent,())) != [birth]):
        raise Refused('custody Git helper original commit generation')
    current = repository(intent['cwd'],Path(host.meta['owned']),initialize=False)
    if current != host.git.custody_roots.get((host.case,intent['cwd'])):
        raise Refused('custody Git helper replaced repository generation')
    executable = '/usr/lib/git-core/git'
    pin = image(executable)
    if pin != intent['executable_sha256']:
        raise Refused('custody Git helper same pinned image')
    environment = {**intent['environment'],'GIT_EXEC_PATH':'/usr/lib/git-core','GIT_PREFIX':'',
        'PATH':'/usr/lib/git-core:'+intent['environment']['PATH'],
        'GIT_NO_REPLACE_OBJECTS':'1','GIT_AUTHOR_DATE':'@946684800 +0000'}
    host.serial += 1
    child = {'case':host.case,'role':'git-helper','parent':parent,'environment':environment,
        'cwd':intent['cwd'],'translated':[executable,'maintenance','run','--auto','--no-quiet','--detach'],
        'token':os.urandom(16).hex(),'consumed':False,'pid':None,'executable':executable,
        'executable_sha256':pin,'inherited':[],'port':None}
    host.intents[host.serial] = child
    host.git.helpers[birth] = child
