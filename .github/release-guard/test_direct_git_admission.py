"""Observer-selected commands retain custody and causal joins without reserialization."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from git_commands import Command
from git_observer import Git
from git_sites import CASES
from process_ledger import Ledger
from launch_policy import Rule,render


@pytest.mark.parametrize('failure',[None,'pending','unreaped','descendant','output','input','repository','location'])
def test_selected_git_command_still_requires_every_custody_and_causal_join(failure):
    calls=[]
    host=SimpleNamespace(case=CASES[0],root_only=lambda actor:None,intents={},
        ledger=Ledger('synthetic-direct-git'))
    git=Git(host)
    host.ledger.reaped=lambda *args:failure!='unreaped'
    command=Command(('git','rev-parse','HEAD'),'/owned/project',requires=(('/owned/project','commit','a'*40,()),))
    value=render(Rule('git:head','git:head',(host.case,),'/usr/bin/git','b'*64,
        command.argv,(),command.cwd,'native'),host.case,'git:head',{}, {})
    if failure in ('pending','unreaped','descendant','output'):
        git.last[host.case]={'consumed':failure!='pending','birth':'old','token':'old',
            'command':Command(('git','rev-parse','HEAD'),command.cwd,produces=('parent','commit',())),
            'value_observed':failure!='output'}
    def required(*args):
        calls.append(('required',args))
        if failure=='input':
            raise Refused('missing input')
    git.values=SimpleNamespace(descendants_reaped=lambda *args:failure!='descendant',require=required)
    def repository(*args):
        calls.append(('repository',args))
        if failure=='repository':
            raise Refused('repository generation')
        return Path(command.cwd)
    def location(*args):
        calls.append(('location',args))
        if failure=='location':
            raise Refused('worktree generation')
    git.repository,git.location=repository,location
    def admit(actor,expected,role,vector,pin,**kwargs):
        calls.append(('admit',(expected,role,vector,pin)))
        host.intents[1]={'token':'new'}
        return {'ok':True,'ticket':1,'token':'new'}
    host.admit_launch=admit
    if failure:
        with pytest.raises(Refused):
            git.launch({},'head',command.cwd,command,value,list(command.argv))
        assert not host.intents and all(kind!='admit' for kind,_ in calls)
    else:
        assert git.launch({},'head',command.cwd,command,value,list(command.argv))['ok'] is True
        assert [kind for kind,_ in calls]==['repository','location','required','admit']
        assert calls[2][1]==(host.case,command.cwd,command.cwd,'commit','a'*40,())
        assert calls[3][1]==(value,'git-command',list(command.argv),None)
        assert git.commands['new'] is git.last[host.case] is host.intents[1]
        assert host.intents[1]['command'] is command
