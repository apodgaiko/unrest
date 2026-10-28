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


@pytest.mark.parametrize('matching',[False,True])
def test_checkout_helper_uses_its_consumed_parent_image_pin(monkeypatch,matching):
    import git_observer
    from process_ledger import Birth
    parent=Birth(20,20,1,100,'boot',20000)
    child=Birth(21,21,20,101,'boot',20000)
    tree='/owned/project/tree'
    revision='c'*40
    intent={'consumed':True,'case':CASES[0],'operation':'integration-add',
        'command':Command(('git','worktree','add','--detach',tree,revision),'/owned/project'),
        'repository':'/owned/project','environment':{'PATH':'/usr/bin:/bin'},'cwd':'/owned/project',
        'executable_sha256':'a'*64}
    host=SimpleNamespace(case=CASES[0],serial=0,intents={},
        ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(token='parent',exit=None,terminal=None),
            children={parent:[child]}))
    git=object.__new__(Git)
    git.host,git.commands,git.helpers=host,{'parent':intent},{}
    git.location=lambda *args:None
    monkeypatch.setattr(git_observer,'regular',lambda *args:revision.encode()+b'\n')
    monkeypatch.setattr(git_observer,'image',lambda executable:('a' if matching else 'b')*64)
    if matching:
        git.reserve_helper(child,parent)
        assert host.intents[1]['executable_sha256']==intent['executable_sha256']
        assert host.intents[1]['parent']==parent and git.helpers[child] is host.intents[1]
    else:
        with pytest.raises(Refused,match='exact native image'):
            git.reserve_helper(child,parent)
        assert not host.intents and not git.helpers
