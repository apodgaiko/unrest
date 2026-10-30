"""Exact original LaunchPlan cases; matching never grants a generic shell."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from content_manifest import Refused, refuse_if
from git_policy import image, regular
from launch_policy import Expected, build_expected

OWNER = 20000
TEST = 'tests/test_launch_preflight.py'
NAMES = (
    'test_relative_and_empty_path_entries_use_launch_cwd[tools]',
    'test_relative_and_empty_path_entries_use_launch_cwd[]',
    'test_real_direct_launch_preserves_original_argv0[relative]',
    'test_real_direct_launch_preserves_original_argv0[absolute]',
    'test_real_bare_launch_uses_later_valid_path_candidate',
    'test_real_spawn_preserves_exact_plan_fields',
    'test_direct_plan_copies_mutable_inputs_before_real_spawn',
    'test_plan_preserves_legal_empty_environment_name_and_equals_value',
    'test_real_invalid_format_is_distinct_safe_startup_failure',
)
CASES = tuple(TEST+'::'+name for name in NAMES)
PYTHON = CASES[5]
INVALID = CASES[-1]
CODE = ('import json,os,sys,pathlib;'
        'pathlib.Path(sys.argv[1]).write_text(json.dumps({'
        "'argv':sys.argv[2:],'cwd':os.getcwd(),'path':os.environ.get('PATH'),"
        "'marker':os.environ.get('MARKER')}))")
INVALID_BODY = b'this is executable but has no executable format\n'


@dataclass(frozen=True)
class Plan:
    expected: Expected
    attempts: tuple[str,...]
    image: tuple[str,str]
    role: str

    @property
    def vector(self):
        value=self.expected.argv
        return (self.expected.executable,'-I','-S',*value[1:]) if self.role=='plan-python' else value


def script(file,body):
    if stat.S_IMODE(file.lstat().st_mode)!=0o700 or regular(file,maximum=4096,uid=OWNER)!=body:
        raise Refused('preflight original owned script bytes or mode')
    return hashlib.sha256(body).hexdigest()


def shell():
    alias=Path('/bin/sh')
    if (alias.resolve(strict=True)!=Path('/usr/bin/dash') or not alias.is_symlink()
            or alias.lstat().st_uid!=0 or alias.lstat().st_nlink!=1 or os.readlink(alias)!='dash'):
        raise Refused('preflight original shell alias')
    return '/usr/bin/dash',image('/usr/bin/dash')


def expected(case,cwd,owned,native,native_pin):
    refuse_if(type(case) is not str or case not in CASES or type(cwd) is not str, 'preflight exact case')
    root=Path(cwd)
    if (str(root.resolve())!=cwd or not root.is_relative_to(owned/'pytest') or root==owned/'pytest'):
        raise Refused('preflight original fixture root')
    env={}
    role='plan-native'
    kind='native'
    payload=None
    if case in CASES[:2]:
        entry='tools' if case==CASES[0] else ''
        target=root/entry/'adapter'
        pin=script(target,b'#!/bin/sh\nexit 0\n')
        vector=('adapter',)
        env={'PATH':entry}
        attempts=(str(Path(entry)/'adapter'),)
        tool=shell()
    elif case in CASES[2:4]:
        target=root/'adapter'
        pin=script(target,b'#!/bin/sh\nprintf "%s" "$0" > "$1"\n')
        argv0='./adapter' if case==CASES[2] else str(target)
        vector=(argv0,str(root/'argv0.txt'))
        env={'PATH':str(root/'decoy')}
        attempts=(argv0,)
        tool=shell()
    elif case in (CASES[4],CASES[6]):
        target=root/'selected/adapter'
        body=b'#!/bin/sh\nprintf selected > "$1"\n' if case==CASES[4] else b'#!/bin/sh\nprintf "selected" > "$1"\n'
        pin=script(target,body)
        vector=('adapter',str(root/'selected.txt'))
        env={'PATH':str(root/'selected')}
        attempts=(str(target),)
        if case==CASES[4]:
            blocked=root/'blocked/adapter'
            info=blocked.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=OWNER or blocked.is_symlink() or tuple(blocked.iterdir()):
                raise Refused('preflight original blocked PATH directory')
            env['PATH']=str(root/'blocked')+':'+str(root/'selected')
            attempts=(str(blocked),str(target))
        else:
            env['MARKER']='before'
        tool=shell()
    elif case==PYTHON:
        alias=root/'adapter'
        info=alias.lstat()
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid!=OWNER or info.st_nlink!=1
                or os.readlink(alias)!=native or alias.resolve(strict=True)!=Path(native)):
            raise Refused('preflight original fixed interpreter alias')
        target=Path(native)
        pin=native_pin
        role='plan-python'
        kind='python-command'
        vector=('adapter','-c',CODE,str(root/'capture.json'),'quoted argument')
        env={'PATH':cwd,'MARKER':'exact'}
        attempts=(str(alias),)
        tool=(native,native_pin)
    elif case==CASES[7]:
        target=Path('/usr/bin/true')
        pin=image(str(target))
        vector=(str(target),)
        env={'':'empty-name','VALUE':'before=after'}
        attempts=(str(target),)
        tool=(str(target),pin)
    else:
        target=root/'invalid-format'
        pin=script(target,INVALID_BODY)
        role='plan-invalid'
        kind='expected-exec-failure'
        vector=('./invalid-format',)
        attempts=('./invalid-format',)
        tool=(str(target),pin)
    return Plan(build_expected(case, str(target), pin, vector, tuple(sorted(env.items())), cwd, kind, payload),attempts,tool,role)
